"""
FastAPI Backend for Project Atlas

Provides REST API endpoints for the frontend to trigger extension analysis
and retrieve results.
"""

import base64
import mimetypes
import os
from pathlib import Path

# Load .env from project root so DB_BACKEND, SUPABASE_*, etc. are set before config/database init
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if (_PROJECT_ROOT / ".env").exists():
    from dotenv import load_dotenv
    load_dotenv(_PROJECT_ROOT / ".env")

import json
import logging
from typing import Optional, Dict, Any
from datetime import datetime, timezone, timedelta

from fastapi import FastAPI, HTTPException, BackgroundTasks, Response, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel
import shutil

from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from extension_shield.core.report_generator import ReportGenerator

from extension_shield.workflow.graph import build_graph
from extension_shield.workflow.state import WorkflowState, WorkflowStatus
from extension_shield.api.database import db, SupabaseDatabase
from extension_shield.api.supabase_auth import get_current_user_id as _get_current_user_id
from extension_shield.core.config import get_settings
from extension_shield.api.csp_middleware import CSPMiddleware
from extension_shield.core.report_view_model import build_report_view_model, build_consumer_insights
from extension_shield.governance.tool_adapters import SignalPackBuilder
from extension_shield.scoring.engine import ScoringEngine

# Initialize logger
logger = logging.getLogger(__name__)

# Import safe JSON utilities from shared module
from extension_shield.utils.json_encoder import (
    safe_json_dumps,
    safe_json_dump,
    sanitize_for_json,
)


def _build_report_view_model_safe(
    manifest: Dict[str, Any],
    analysis_results: Dict[str, Any],
    metadata: Optional[Dict[str, Any]],
    extension_id: str,
    scan_id: str,
) -> Dict[str, Any]:
    """Safely build report view model, returning empty dict on any error."""
    try:
        return build_report_view_model(
            manifest=manifest,
            analysis_results=analysis_results,
            metadata=metadata,
            extension_id=extension_id,
            scan_id=scan_id,
        )
    except Exception as exc:
        # LLM failures should not fail the entire scan - use fallbacks
        logger.warning("Failed to build report_view_model, using empty dict: %s", exc)
        return {}


def _upgrade_legacy_payload(payload: Dict[str, Any], extension_id: str) -> Dict[str, Any]:
    """
    Upgrade a legacy payload to include scoring_v2 and report_view_model.
    
    Args:
        payload: The legacy payload (may be missing scoring_v2 and report_view_model)
        extension_id: Extension ID for building SignalPack
        
    Returns:
        The (possibly upgraded) payload. The input dict may be mutated in-place.
    """
    has_scoring_v2_before = bool(payload.get("scoring_v2") or payload.get("governance_bundle", {}).get("scoring_v2"))
    has_report_view_model_before = bool(payload.get("report_view_model"))
    has_consumer_insights_before = bool(payload.get("report_view_model", {}).get("consumer_insights"))
    upgraded = False
    
    # If scoring_v2, report_view_model, and consumer_insights already exist, we *usually*
    # don't need an upgrade. However, if the scoring engine version changed, we should
    # recompute scoring/report so cached scans reflect the latest deterministic gates
    # (e.g., new compliance checks).
    force_recompute = False
    try:
        existing_scoring = payload.get("scoring_v2") or payload.get("governance_bundle", {}).get("scoring_v2") or {}
        existing_version = (existing_scoring or {}).get("scoring_version")
        if isinstance(existing_version, str) and existing_version and existing_version != ScoringEngine.VERSION:
            force_recompute = True
    except Exception:
        force_recompute = False

    if has_scoring_v2_before and has_report_view_model_before and has_consumer_insights_before and not force_recompute:
        logger.info("[UPGRADE] extension_id=%s, results_payload_upgraded=false, has_scoring_v2=%s→%s, has_report_view_model=%s→%s, has_consumer_insights=%s→%s",
                    extension_id, has_scoring_v2_before, has_scoring_v2_before, has_report_view_model_before, has_report_view_model_before,
                    has_consumer_insights_before, has_consumer_insights_before)
        return payload
    
    logger.info("[UPGRADE] Upgrading legacy payload for extension_id=%s (has_scoring_v2=%s, has_report_view_model=%s)",
                extension_id, has_scoring_v2_before, has_report_view_model_before)
    
    try:
        # Extract available data
        manifest = payload.get("manifest") or {}
        metadata = payload.get("metadata") or {}
        
        # Build analysis_results dict from legacy fields
        analysis_results = {
            "permissions_analysis": payload.get("permissions_analysis") or {},
            "javascript_analysis": payload.get("sast_results") or {},
            "webstore_analysis": payload.get("webstore_analysis") or {},
            "virustotal_analysis": payload.get("virustotal_analysis") or {},
            "entropy_analysis": payload.get("entropy_analysis") or {},
            "impact_analysis": payload.get("impact_analysis") or {},
            "privacy_compliance": payload.get("privacy_compliance") or {},
            "executive_summary": payload.get("summary") or {},
        }
        
        # Build SignalPack from legacy data
        signal_pack_builder = SignalPackBuilder()
        signal_pack = signal_pack_builder.build(
            scan_id=extension_id,
            analysis_results=analysis_results,
            metadata=metadata,
            manifest=manifest,
            extension_id=extension_id,
        )
        
        # Compute scoring_v2 if missing or if we need to force a recompute
        if (not has_scoring_v2_before) or force_recompute:
            user_count = metadata.get("user_count") or metadata.get("users") or signal_pack.webstore_stats.installs
            scoring_engine = ScoringEngine(weights_version="v1")
            scoring_result = scoring_engine.calculate_scores(
                signal_pack=signal_pack,
                manifest=manifest,
                user_count=user_count if isinstance(user_count, int) else None,
                permissions_analysis=analysis_results.get("permissions_analysis"),
            )

            scoring_v2_payload = scoring_result.model_dump_for_api()
            scoring_v2_payload["weights_version"] = "v1"
            # Include gate results (used by frontend modals). Keep stable minimal shape.
            gate_results = scoring_engine.get_gate_results() or []
            scoring_v2_payload["gate_results"] = [
                {
                    "gate_id": g.gate_id,
                    "decision": g.decision,
                    "triggered": g.triggered,
                    "confidence": g.confidence,
                    "reasons": g.reasons,
                }
                for g in gate_results
            ]

            payload["scoring_v2"] = scoring_v2_payload
            logger.info("[UPGRADE] Built scoring_v2 for extension_id=%s (force=%s)", extension_id, force_recompute)
            upgraded = True
        
        # Build report_view_model if missing OR when we recompute scoring (avoid mismatched UI)
        if (not has_report_view_model_before) or force_recompute:
            report_view_model = build_report_view_model(
                manifest=manifest,
                analysis_results=analysis_results,
                metadata=metadata,
                extension_id=extension_id,
                scan_id=extension_id,
            )
            payload["report_view_model"] = report_view_model
            logger.info("[UPGRADE] Built report_view_model for extension_id=%s (force=%s)", extension_id, force_recompute)
            upgraded = True
        
        # Ensure consumer_insights exists (double-check)
        _ensure_consumer_insights(payload)
        
        final_has_scoring_v2 = bool(payload.get("scoring_v2"))
        final_has_report_view_model = bool(payload.get("report_view_model"))
        final_has_consumer_insights = bool(payload.get("report_view_model", {}).get("consumer_insights"))
        logger.info("[UPGRADE] extension_id=%s, results_payload_upgraded=%s, has_scoring_v2=%s→%s, has_report_view_model=%s→%s, has_consumer_insights=%s→%s",
                    extension_id, upgraded, has_scoring_v2_before, final_has_scoring_v2, has_report_view_model_before, final_has_report_view_model,
                    has_consumer_insights_before, final_has_consumer_insights)
        return payload
        
    except Exception as exc:
        logger.error("[UPGRADE] Failed to upgrade legacy payload for extension_id=%s: %s", extension_id, exc)
        # Best-effort: still ensure consumer_insights is attached if possible
        try:
            _ensure_consumer_insights(payload)
        except Exception:
            # Swallow secondary errors – primary failure is already logged
            pass
        final_has_scoring_v2 = bool(payload.get("scoring_v2") or payload.get("governance_bundle", {}).get("scoring_v2"))
        final_has_report_view_model = bool(payload.get("report_view_model"))
        final_has_consumer_insights = bool(payload.get("report_view_model", {}).get("consumer_insights"))
        logger.info("[UPGRADE] extension_id=%s, results_payload_upgraded=false (error), has_scoring_v2=%s→%s, has_report_view_model=%s→%s, has_consumer_insights=%s→%s",
                    extension_id, has_scoring_v2_before, final_has_scoring_v2, has_report_view_model_before, final_has_report_view_model,
                    has_consumer_insights_before, final_has_consumer_insights)
        return payload


def _ensure_consumer_insights(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Ensure payload.report_view_model.consumer_insights exists.
    If missing, compute it from available data in the payload.
    
    Returns:
        The payload dict (for chaining). The input dict may be mutated in-place.
    """
    # Ensure report_view_model exists
    if "report_view_model" not in payload:
        payload["report_view_model"] = {}
    
    rvm = payload["report_view_model"]
    
    # If consumer_insights already exists, we're done
    if rvm.get("consumer_insights") is not None:
        logger.info("consumer_insights_attached=true (already present)")
        return payload
    
    # Extract parameters for build_consumer_insights
    # Try multiple possible locations for each field
    
    # scoring_v2: from scoring_v2 or governance_bundle.scoring_v2
    scoring_v2 = payload.get("scoring_v2")
    if not scoring_v2:
        governance_bundle = payload.get("governance_bundle", {})
        if isinstance(governance_bundle, dict):
            scoring_v2 = governance_bundle.get("scoring_v2")
    
    # capability_flags: from report_view_model.evidence.capability_flags or top-level
    capability_flags = None
    if isinstance(rvm.get("evidence"), dict):
        capability_flags = rvm["evidence"].get("capability_flags")
    if not capability_flags:
        capability_flags = payload.get("capability_flags")
    
    # host_access_summary: from report_view_model.evidence.host_access_summary or top-level
    host_access_summary = None
    if isinstance(rvm.get("evidence"), dict):
        host_access_summary = rvm["evidence"].get("host_access_summary")
    if not host_access_summary:
        host_access_summary = payload.get("host_access_summary")
    
    # permissions_analysis: from top-level or report_view_model.evidence.permissions_summary
    permissions_analysis = payload.get("permissions_analysis")
    if not permissions_analysis and isinstance(rvm.get("evidence"), dict):
        permissions_analysis = rvm["evidence"].get("permissions_summary")
    
    # webstore_metadata: from metadata or report_view_model.evidence.webstore_metadata
    webstore_metadata = payload.get("metadata")
    if not webstore_metadata and isinstance(rvm.get("evidence"), dict):
        webstore_metadata = rvm["evidence"].get("webstore_metadata")
    
    # network_evidence: from top-level or report_view_model.evidence.network_evidence
    network_evidence = payload.get("network_evidence")
    if not network_evidence and isinstance(rvm.get("evidence"), dict):
        network_evidence = rvm["evidence"].get("network_evidence")
    
    # external_domains: from top-level or report_view_model.evidence.external_domains
    external_domains = payload.get("external_domains")
    if not external_domains and isinstance(rvm.get("evidence"), dict):
        external_domains = rvm["evidence"].get("external_domains")
    
    # Compute consumer_insights
    try:
        consumer_insights = build_consumer_insights(
            scoring_v2=scoring_v2,
            capability_flags=capability_flags,
            host_access_summary=host_access_summary,
            permissions_analysis=permissions_analysis or {},
            webstore_metadata=webstore_metadata or {},
            network_evidence=network_evidence,
            external_domains=external_domains,
        )
        rvm["consumer_insights"] = consumer_insights
        logger.info("consumer_insights_attached=true (computed)")
    except Exception as exc:
        logger.warning("Failed to compute consumer_insights: %s", exc)
        logger.info("consumer_insights_attached=false")

    # Also ensure consumer_summary exists (verdict/reasons/access/action format)
    if rvm.get("consumer_summary") is None:
        try:
            from extension_shield.core.report_view_model import build_consumer_summary
            rvm["consumer_summary"] = build_consumer_summary(
                report_view_model=rvm,
                scoring_v2=scoring_v2,
            )
            logger.info("consumer_summary_attached=true (computed)")
        except Exception as exc:
            logger.warning("Failed to compute consumer_summary: %s", exc)

    return payload


def _log_get_scan_results_return_shape(path: str, payload: Dict[str, Any]) -> None:
    """
    Unified debug log for the final payload returned by get_scan_results().
    """
    if not isinstance(payload, dict):
        logger.info(
            "[DEBUG get_scan_results return_shape] path=%s payload_type=%s (non-dict)",
            path,
            type(payload).__name__,
        )
        return

    payload_keys = sorted(list(payload.keys()))
    has_report_view_model = "report_view_model" in payload
    report_view_model = payload.get("report_view_model")
    has_consumer_insights = bool(
        isinstance(report_view_model, dict)
        and report_view_model.get("consumer_insights") is not None
    )
    has_scoring_v2 = "scoring_v2" in payload

    rvm_type = type(report_view_model).__name__ if report_view_model is not None else None
    rvm_keys = sorted(list(report_view_model.keys())) if isinstance(report_view_model, dict) else None

    logger.info(
        "[DEBUG get_scan_results return_shape] path=%s keys=%s has_report_view_model=%s "
        "has_consumer_insights=%s has_scoring_v2=%s report_view_model_type=%s report_view_model_keys=%s",
        path,
        payload_keys,
        has_report_view_model,
        has_consumer_insights,
        has_scoring_v2,
        rvm_type,
        rvm_keys,
    )

# Pydantic models for request/response
class ScanRequest(BaseModel):
    """Request model for triggering a scan."""

    url: str


class ScanStatusResponse(BaseModel):
    """Response model for scan status."""

    scanned: bool
    status: Optional[str] = None
    extension_id: Optional[str] = None
    error: Optional[str] = None
    error_code: Optional[int] = None


class FileContentResponse(BaseModel):
    """Response model for file content."""

    content: str
    file_path: str


class FileListResponse(BaseModel):
    """Response model for file list."""

    files: list[str]

class PageViewEvent(BaseModel):
    """Request model for privacy-first pageview telemetry (no PII)."""

    path: str

# Initialize FastAPI app
app = FastAPI(
    title="Project Atlas API",
    description="REST API for Chrome extension security analysis",
    version="1.0.0",
)

# Global rate limiting toggle
RATE_LIMIT_ENABLED = os.getenv("RATE_LIMIT_ENABLED", "true").lower() in ("1", "true", "yes")
limiter = None
if RATE_LIMIT_ENABLED:
    limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])
    app.state.limiter = limiter
    app.add_middleware(SlowAPIMiddleware)


def _rate_limit(limit: str):
    """Return a limiter decorator if enabled, otherwise no-op."""
    if RATE_LIMIT_ENABLED and limiter:
        return limiter.limit(limit)
    def _noop(func):
        return func
    return _noop


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})


@app.middleware("http")
async def attach_user_context(request: Request, call_next):
    """
    Best-effort auth context.
    If token is missing/invalid, user_id will be None.
    """
    try:
        request.state.user_id = _get_current_user_id(request)
    except Exception:
        request.state.user_id = None
    return await call_next(request)


@app.middleware("http")
async def domain_redirect_middleware(request: Request, call_next):
    """
    Redirect non-canonical domains to extensionshield.com.
    
    This middleware handles:
    - extensionscanner.com -> extensionshield.com
    Note: extensionaudit.com will be added in the future.
    
    Preserves path and query parameters.
    """
    host = request.headers.get("host", "").lower()
    canonical_domain = "extensionshield.com"
    # Note: extensionaudit.com will be added in the future
    non_canonical_domains = ["extensionscanner.com"]
    
    # Check if this is a non-canonical domain
    if any(host.startswith(domain) for domain in non_canonical_domains):
        # Preserve path and query string
        path = request.url.path
        query = request.url.query
        redirect_url = f"https://{canonical_domain}{path}"
        if query:
            redirect_url += f"?{query}"
        
        # Return 301 permanent redirect
        return RedirectResponse(url=redirect_url, status_code=301)
    
    return await call_next(request)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to all responses."""
    response = await call_next(request)
    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    # HSTS only for HTTPS (check if request is secure)
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # Note: CSP is now handled by CSPMiddleware (added below)
    return response

# Configure CORS
_cors_env = os.getenv("CORS_ORIGINS", "").strip()
if _cors_env:
    allowed_origins = [o.strip() for o in _cors_env.split(",") if o.strip()]
else:
    allowed_origins = [
        "http://localhost:5173",  # Vite dev server (default)
        "http://localhost:5174",  # Vite fallback port
        "http://localhost:5175",  # Vite fallback port
        "http://localhost:5176",  # Vite fallback port
        "http://localhost:5177",  # Vite fallback port
        "http://localhost:3000",  # Alternative dev port
        "http://localhost:8007",  # Same-origin in container
    ]
print(f"CORS allowed origins: {allowed_origins}")
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Static files directory for React frontend (in container)
# IMPORTANT: Define STATIC_DIR BEFORE CSP middleware so it can detect production mode
STATIC_DIR = Path(__file__).parent.parent.parent.parent / "static"
# Frontend public directory for development (serves data files)
FRONTEND_PUBLIC_DIR = Path(__file__).parent.parent.parent.parent / "frontend" / "public"

# Add CSP middleware (after CORS, after STATIC_DIR is defined)
# Check if we're in development mode (when STATIC_DIR doesn't exist or is empty)
_is_dev = not (STATIC_DIR.exists() and (STATIC_DIR / "index.html").exists())
if _is_dev:
    print(f"⚠️  CSP: Development mode detected (STATIC_DIR={STATIC_DIR}, exists={STATIC_DIR.exists()})")
else:
    print(f"✅ CSP: Production mode detected (STATIC_DIR={STATIC_DIR}, index.html exists)")
app.add_middleware(CSPMiddleware, is_dev=_is_dev)

# Storage for scan results (in-memory cache + database persistence)
scan_results: Dict[str, Dict[str, Any]] = {}
scan_status: Dict[str, str] = {}
# extension_id -> authenticated user_id (Supabase `sub`) at scan trigger time
scan_user_ids: Dict[str, Optional[str]] = {}

# -----------------------------------------------------------------------------
# Daily deep-scan limit (placeholder, in-memory)
# -----------------------------------------------------------------------------
DAILY_DEEP_SCAN_LIMIT = 2
# deep_scan_usage[user_id][YYYY-MM-DD] = used_count
deep_scan_usage: Dict[str, Dict[str, int]] = {}


def _get_user_id(request: Request) -> str:
    """
    Best-effort user identifier.

    Prefer Supabase-authenticated user_id (JWT `sub`) when available.
    If absent, allow an optional `X-User-Id` header for local/dev usage.
    No IP-based fallback (privacy-first).
    """
    state_user = getattr(getattr(request, "state", None), "user_id", None)
    if state_user:
        return str(state_user)

    header_user = request.headers.get("x-user-id") or request.headers.get("X-User-Id")
    if header_user:
        return header_user.strip()

    return "anon"


def _require_admin_key(request: Request) -> None:
    """
    Verify X-Admin-Key header matches ADMIN_API_KEY.
    
    Raises HTTPException(403) if:
    - Header is missing
    - Key doesn't match ADMIN_API_KEY
    - ADMIN_API_KEY is not configured
    """
    settings = get_settings()
    admin_key = settings.admin_api_key
    
    if not admin_key:
        raise HTTPException(
            status_code=403,
            detail="Admin API key is not configured"
        )
    
    provided_key = request.headers.get("X-Admin-Key") or request.headers.get("x-admin-key")
    if not provided_key:
        raise HTTPException(
            status_code=403,
            detail="X-Admin-Key header is required"
        )
    
    if provided_key != admin_key:
        raise HTTPException(
            status_code=403,
            detail="Invalid admin API key"
        )


def _deep_scan_limit_status(user_id: str) -> Dict[str, Any]:
    """Get deep scan limit status. Returns unlimited in local/dev environments."""
    settings = get_settings()
    now = datetime.now(timezone.utc)
    day_key = now.strftime("%Y-%m-%d")
    used = deep_scan_usage.get(user_id, {}).get(day_key, 0)
    
    # In development/local, return unlimited
    if not settings.is_prod():
        return {
            "limit": 999999,
            "used": used,
            "remaining": 999999,
            "day_key": day_key,
            "reset_at": (datetime(now.year, now.month, now.day, tzinfo=timezone.utc) + timedelta(days=1)).isoformat(),
        }
    
    remaining = max(0, DAILY_DEEP_SCAN_LIMIT - used)
    reset_at = datetime(now.year, now.month, now.day, tzinfo=timezone.utc) + timedelta(days=1)
    return {
        "limit": DAILY_DEEP_SCAN_LIMIT,
        "used": used,
        "remaining": remaining,
        "day_key": day_key,
        "reset_at": reset_at.isoformat(),
    }


def _consume_deep_scan(user_id: str) -> Dict[str, Any]:
    status = _deep_scan_limit_status(user_id)
    if status["remaining"] <= 0:
        return status
    day_key = status["day_key"]
    deep_scan_usage.setdefault(user_id, {})
    deep_scan_usage[user_id][day_key] = deep_scan_usage[user_id].get(day_key, 0) + 1
    return _deep_scan_limit_status(user_id)


def _has_cached_results(extension_id: str) -> bool:
    if extension_id in scan_results:
        return True

    # Database lookup (fast path for cached lookups)
    try:
        existing = db.get_scan_result(extension_id)
        if existing:
            return True
    except Exception:
        # If DB is unavailable, fall back to file check below.
        pass

    # File fallback
    result_file = RESULTS_DIR / f"{extension_id}_results.json"
    return result_file.exists()


# -----------------------------------------------------------------------------
# Enterprise pilot request (placeholder, in-memory)
# -----------------------------------------------------------------------------
class EnterprisePilotRequest(BaseModel):
    name: str
    email: str
    company: str
    notes: Optional[str] = None


enterprise_pilot_requests: list[Dict[str, Any]] = []


# Load existing results from database on startup
def load_existing_results():
    """Load existing scan results from database into memory cache."""
    history = db.get_scan_history(limit=100)
    for item in history:
        ext_id = item.get("extension_id")
        if ext_id:
            scan_status[ext_id] = item.get("status", "completed")


load_existing_results()

# Directory for storing analysis results
# Use centralized config (maps current behavior)
_settings = get_settings()
STORAGE_PATH = _settings.extension_storage_path
RESULTS_DIR = _settings.paths.results_dir  # Convert to absolute path
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

# Base64 SVG placeholder for extension icons when local file is missing (e.g. ephemeral storage on Railway)
_EXTENSION_ICON_PLACEHOLDER_B64 = (
    "PHN2ZyB3aWR0aD0iNjQiIGhlaWdodD0iNjQiIHZpZXdCb3g9IjAgMCA2NCA2NCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4K"
    "ICA8cmVjdCB3aWR0aD0iNjQiIGhlaWdodD0iNjQiIHJ4PSIxMiIgZmlsbD0iIzJBMkEzNSIvPgogIDxwYXRoIGQ9Ik0zMiAxNkMyNC4yNjggMTYgMTggMjIuMjY4IDE4IDMwQzE4IDMxLjY1NyAxOC4zMjEgMzMuMjI5IDE4LjkwOSAzNC42NjdMMjIuOTg0IDM0LjY2N0MyMy43MyAzNC42NjcgMjQuMzMzIDM1LjI3IDI0LjMzMyAzNi4wMTZWNDAuMDkxQzI0LjMzMyA0MC44MzggMjMuNzMgNDEuNDQxIDIyLjk4NCA0MS40NDFIMTguOTA5QzIwLjU3MSA0NS42ODcgMjQuMzMzIDQ5LjIyNCAyOC45NTkgNTAuNDg2VjQ2LjQxMUMyOC45NTkgNDUuNjY1IDI5LjU2MiA0NS4wNjIgMzAuMzA4IDQ1LjA2MkgzNC4zODNDMzUuMTMgNDUuMDYyIDM1LjczMyA0NC40NTkgMzUuNzMzIDQzLjcxM1YzOS42MzhDMzUuNzMzIDM4Ljg5MSAzNi4zMzYgMzguMjg4IDM3LjA4MyAzOC4yODhINDEuMTU3QzQxLjkwNCAzOC4yODggNDIuNTA3IDM3LjY4NSA0Mi41MDcgMzYuOTM4VjMyLjg2NEM0Mi41MDcgMzIuMTE3IDQzLjExIDMxLjUxNCA0My44NTcgMzEuNTE0SDQ3LjkzMkM0Ny45NzggMzEuMDE1IDQ4IDMwLjUxIDQ4IDMwQzQ4IDIyLjI2OCA0MS43MzIgMTYgMzIgMTZaIiBmaWxsPSIjNEE5MEU2Ii8+CiAgPGNpcmNsZSBjeD0iMjYiIGN5PSIyNiIgcj0iMyIgZmlsbD0iI0ZGRkZGRiIvPgo8L3N2Zz4="
)
_MAX_ICON_BYTES_FOR_DB = 2 * 1024 * 1024


def _extension_icon_placeholder_response() -> Response:
    """Return placeholder extension icon when local file is missing (e.g. ephemeral storage)."""
    svg_bytes = base64.b64decode(_EXTENSION_ICON_PLACEHOLDER_B64)
    return Response(
        content=svg_bytes,
        media_type="image/svg+xml",
        headers={
            # Don't cache placeholders aggressively; icon may become available moments later.
            "Cache-Control": "no-store, max-age=0",
            "Pragma": "no-cache",
            "Access-Control-Allow-Origin": "*",
            "X-Extension-Icon-Source": "placeholder",
        },
    )


def _normalize_image_media_type(media_type: Optional[str]) -> str:
    """Normalize media type for icon responses."""
    if not media_type or not isinstance(media_type, str):
        return "image/png"
    normalized = media_type.strip().lower()
    if not normalized.startswith("image/"):
        return "image/png"
    return normalized


def _extension_icon_response_from_base64(
    icon_base64: Optional[str], icon_media_type: Optional[str]
) -> Optional[Response]:
    """Build an image response from persisted base64 icon data."""
    if not icon_base64:
        return None
    try:
        icon_bytes = base64.b64decode(icon_base64)
    except Exception:
        logger.warning("[ICON] Failed to decode persisted icon_base64")
        return None

    return Response(
        content=icon_bytes,
        media_type=_normalize_image_media_type(icon_media_type),
        headers={
            "Cache-Control": "public, max-age=86400",
            "Access-Control-Allow-Origin": "*",
            "X-Extension-Icon-Source": "db_blob",
        },
    )


def _extension_icon_file_response(icon_file_path: str) -> FileResponse:
    """Build a file response with normalized icon media type and cache headers."""
    guessed_media_type, _ = mimetypes.guess_type(icon_file_path)
    return FileResponse(
        icon_file_path,
        media_type=_normalize_image_media_type(guessed_media_type),
        headers={
            "Cache-Control": "public, max-age=86400",
            "Access-Control-Allow-Origin": "*",
            "X-Extension-Icon-Source": "filesystem",
        },
    )


def _load_icon_record_from_db(extension_id: str) -> Dict[str, Optional[str]]:
    """
    Load icon-related fields for an extension from DB.
    Works for both SQLite and Supabase, and gracefully handles older schemas.
    """
    record: Dict[str, Optional[str]] = {
        "extracted_path": None,
        "icon_path": None,
        "icon_base64": None,
        "icon_media_type": None,
    }
    try:
        if hasattr(db, "get_connection"):
            with db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("PRAGMA table_info(scan_results)")
                columns = [row[1] for row in cursor.fetchall()]
                selected_columns = ["extracted_path"]
                if "icon_path" in columns:
                    selected_columns.append("icon_path")
                if "icon_base64" in columns:
                    selected_columns.append("icon_base64")
                if "icon_media_type" in columns:
                    selected_columns.append("icon_media_type")

                cursor.execute(
                    f"SELECT {', '.join(selected_columns)} FROM scan_results WHERE extension_id = ? LIMIT 1",
                    (extension_id,),
                )
                row = cursor.fetchone()
                if row:
                    for idx, col_name in enumerate(selected_columns):
                        record[col_name] = row[idx] if len(row) > idx else None
        else:
            row = db.get_scan_result(extension_id)
            if row:
                record["extracted_path"] = row.get("extracted_path")
                record["icon_path"] = row.get("icon_path")
                record["icon_base64"] = row.get("icon_base64")
                record["icon_media_type"] = row.get("icon_media_type")
    except Exception as exc:
        logger.debug("[ICON] Could not load icon record from database: %s", exc)
    return record


def _extract_icon_blob_for_storage(
    icon_path: Optional[str], extracted_path: Optional[str]
) -> tuple[Optional[str], Optional[str]]:
    """Encode icon bytes to base64 for DB persistence (production-safe fallback)."""
    if not icon_path or not extracted_path:
        return None, None
    try:
        abs_extracted_path = os.path.abspath(extracted_path)
        candidate_path = (
            os.path.abspath(icon_path)
            if os.path.isabs(icon_path)
            else os.path.abspath(os.path.join(extracted_path, icon_path))
        )

        # Security check: icon must stay inside extracted extension dir.
        if os.path.commonpath([abs_extracted_path, candidate_path]) != abs_extracted_path:
            logger.warning("[ICON] Refusing out-of-bounds icon path for persistence: %s", icon_path)
            return None, None
        if not os.path.isfile(candidate_path):
            return None, None

        with open(candidate_path, "rb") as icon_file:
            icon_bytes = icon_file.read()
        if not icon_bytes:
            return None, None
        if len(icon_bytes) > _MAX_ICON_BYTES_FOR_DB:
            logger.warning(
                "[ICON] Skipping icon persistence for oversized icon (%s bytes): %s",
                len(icon_bytes),
                candidate_path,
            )
            return None, None

        icon_b64 = base64.b64encode(icon_bytes).decode("ascii")
        guessed_media_type, _ = mimetypes.guess_type(candidate_path)
        media_type = _normalize_image_media_type(guessed_media_type)
        return icon_b64, media_type
    except Exception as exc:
        logger.warning("[ICON] Failed to persist icon bytes for %s: %s", icon_path, exc)
        return None, None


def _storage_relative_extracted_path(extension_dir: Optional[str]) -> Optional[str]:
    """
    Return extracted_path in a form resolvable on any backend: basename of the
    extracted directory (e.g. extracted_<id>.crx_123). Icon endpoint joins this
    with extension_storage_path so icons work when DB is Supabase and storage is local.
    """
    if not extension_dir:
        return None
    return os.path.basename(extension_dir.rstrip(os.sep))


def extract_extension_id(url: str) -> Optional[str]:
    """Extract extension ID from Chrome Web Store URL."""
    import re

    match = re.search(r"/detail/(?:[^/]+/)?([a-z]{32})", url)
    return match.group(1) if match else None


def extract_icon_path(manifest: Dict[str, Any], extracted_path: Optional[str]) -> Optional[str]:
    """
    Extract icon path from manifest.json.
    
    Returns the relative path to the icon file (e.g., "icons/128.png")
    based on manifest.json icons field, or None if not found.
    
    Args:
        manifest: Parsed manifest.json dict
        extracted_path: Path to extracted extension directory (for validation)
    
    Returns:
        Relative icon path (e.g., "icons/128.png") or None
    """
    if not manifest or not isinstance(manifest, dict):
        return None
    
    icons = manifest.get("icons", {})
    if not icons or not isinstance(icons, dict):
        return None
    
    # Get the largest icon (prefer 128, then 64, then 48, etc.)
    icon_sizes = ["128", "64", "48", "32", "16", "96", "256", "38", "19"]
    for size in icon_sizes:
        if size in icons:
            icon_path = icons[size]
            if isinstance(icon_path, str):
                # Validate path exists if extracted_path is available
                if extracted_path:
                    full_path = os.path.join(extracted_path, icon_path)
                    if os.path.exists(full_path):
                        return icon_path
                else:
                    # Return path even if we can't validate (for database storage)
                    return icon_path
    
    return None


def _relpath_from_extracted(extracted_path: str, abs_path: str) -> Optional[str]:
    """Return a safe, normalized (POSIX) relpath within extracted_path."""
    try:
        rel = os.path.relpath(abs_path, start=extracted_path)
    except Exception:
        return None
    # Guard: must stay within extracted_path
    if rel.startswith(".."):
        return None
    return rel.replace(os.sep, "/")


def _find_icon_path_on_disk(
    extracted_path: Optional[str], manifest: Optional[Dict[str, Any]] = None
) -> Optional[str]:
    """
    Find a real icon file path inside an extracted extension directory.

    This is used at scan completion to persist icon bytes even when manifest.icons is missing
    or points to a non-existent file. It intentionally mirrors the icon endpoint's fallback
    search strategy, but returns a relative path suitable for DB storage (e.g. "icons/128.png").
    """
    if not extracted_path:
        return None
    if not os.path.isdir(extracted_path):
        return None

    ex = extracted_path
    ex_abs = os.path.abspath(ex)

    def _candidate(rel_parts: list[str]) -> Optional[str]:
        abs_path = os.path.abspath(os.path.join(ex, *rel_parts))
        if os.path.commonpath([ex_abs, abs_path]) != ex_abs:
            return None
        if os.path.isfile(abs_path):
            return _relpath_from_extracted(ex, abs_path)
        return None

    # 1) If manifest provides icon paths, try all of them (largest-first if keys are numeric).
    icons = (manifest or {}).get("icons") if isinstance(manifest, dict) else None
    if isinstance(icons, dict) and icons:
        def _key_to_int(k: Any) -> int:
            try:
                return int(str(k))
            except Exception:
                return -1

        # Prefer numeric keys (sizes) descending; otherwise preserve insertion order.
        icon_items = list(icons.items())
        if any(_key_to_int(k) >= 0 for k, _ in icon_items):
            icon_items.sort(key=lambda kv: _key_to_int(kv[0]), reverse=True)

        for _, rel in icon_items:
            if isinstance(rel, str) and rel:
                found = _candidate([rel])
                if found:
                    return found

    # 2) Common conventions (icons/, root, images/)
    icon_sizes = ["256", "128", "96", "64", "48", "32", "16"]
    exts = [".png", ".jpg", ".jpeg", ".webp", ".svg"]

    # icons/<size>.(png|...)
    for size in icon_sizes:
        for ext in exts:
            found = _candidate(["icons", f"{size}{ext}"])
            if found:
                return found
            found = _candidate(["icons", f"icon{size}{ext}"])
            if found:
                return found

    # root icon files
    for size in icon_sizes:
        for ext in exts:
            for name in (f"icon{size}{ext}", f"{size}{ext}", f"icon_{size}{ext}"):
                found = _candidate([name])
                if found:
                    return found

    # images/ common names
    for name in (
        "icon256.png",
        "icon128.png",
        "icon96.png",
        "icon64.png",
        "icon48.png",
        "icon32.png",
        "icon16.png",
        "icon.png",
        "logo.png",
        "logo.svg",
    ):
        found = _candidate(["images", name])
        if found:
            return found

    # 3) Last resort: pick the largest-looking image in icons/ or images/
    for folder in ("icons", "images"):
        folder_abs = os.path.join(ex, folder)
        if not os.path.isdir(folder_abs):
            continue
        try:
            candidates = []
            for item in os.listdir(folder_abs):
                lower = item.lower()
                if not any(lower.endswith(ext) for ext in exts):
                    continue
                abs_path = os.path.abspath(os.path.join(folder_abs, item))
                if os.path.commonpath([ex_abs, abs_path]) != ex_abs:
                    continue
                if not os.path.isfile(abs_path):
                    continue
                try:
                    size_bytes = os.path.getsize(abs_path)
                except Exception:
                    size_bytes = 0
                candidates.append((size_bytes, abs_path))
            if candidates:
                candidates.sort(key=lambda t: t[0], reverse=True)
                rel = _relpath_from_extracted(ex, candidates[0][1])
                if rel:
                    return rel
        except Exception:
            continue

    return None


async def run_analysis_workflow(url: str, extension_id: str):
    """Run the analysis workflow in the background."""
    workflow_start = datetime.now()
    logger.info("[TIMELINE] scan_started → extension_id=%s, url=%s", extension_id, url)
    
    try:
        # Update status
        scan_status[extension_id] = "running"
        logger.info("[TIMELINE] status_set_to_running → extension_id=%s", extension_id)

        # Build and run workflow
        logger.info("[TIMELINE] building_workflow_graph → extension_id=%s", extension_id)
        graph = build_graph()
        logger.info("[TIMELINE] workflow_graph_built → extension_id=%s", extension_id)

        initial_state: WorkflowState = {
            "workflow_id": extension_id,
            "chrome_extension_path": url,
            "extension_dir": None,
            "downloaded_crx_path": None,
            "extension_metadata": None,
            "manifest_data": None,
            "analysis_results": None,
            "executive_summary": None,
            "extracted_files": None,
            # Governance fields
            "governance_bundle": None,
            "governance_verdict": None,
            "governance_report": None,
            "governance_error": None,
            # Status fields
            "status": WorkflowStatus.PENDING,
            "start_time": datetime.now().isoformat(),
            "end_time": None,
            "error": None,
        }

        # Run workflow
        logger.info("[TIMELINE] executing_workflow → extension_id=%s", extension_id)
        final_state = await graph.ainvoke(initial_state)
        logger.info("[TIMELINE] workflow_completed → extension_id=%s, status=%s", extension_id, final_state.get("status"))

        # Store results
        if (
            final_state["status"] == WorkflowStatus.COMPLETED
            or final_state["status"] == "completed"
        ):
            analysis_results = final_state.get("analysis_results", {}) or {}

            # Extract extension name from metadata or manifest
            metadata = final_state.get("extension_metadata") or {}
            manifest = final_state.get("manifest_data") or {}
            extension_name = (
                metadata.get("title")
                or metadata.get("name")
                or manifest.get("name")
                or extension_id
            )

            # Ensure all values are not None
            extracted_files = final_state.get("extracted_files")
            if extracted_files is None:
                extracted_files = []

            # Extract icon path from manifest
            extracted_path = final_state.get("extension_dir")
            icon_path = extract_icon_path(manifest, extracted_path)
            if not icon_path and extracted_path:
                icon_path = _find_icon_path_on_disk(extracted_path, manifest)
            icon_base64, icon_media_type = _extract_icon_blob_for_storage(
                icon_path=icon_path,
                extracted_path=extracted_path,
            )

            # =================================================================
            # V2 SCORING: Build SignalPack and compute scores via ScoringEngine
            # =================================================================
            signal_pack_builder = SignalPackBuilder()
            signal_pack = signal_pack_builder.build(
                scan_id=extension_id,
                analysis_results=analysis_results,
                metadata=metadata,
                manifest=manifest,
                extension_id=extension_id,
            )
            
            # Determine user count for context-aware scoring
            user_count = signal_pack.webstore_stats.installs
            if user_count is None:
                # Fallback to metadata if available
                user_count = metadata.get("users") or metadata.get("user_count")
            
            # Compute v2 scores
            logger.info("[TIMELINE] computing_scores → extension_id=%s", extension_id)
            scoring_engine = ScoringEngine(weights_version="v1")
            scoring_result = scoring_engine.calculate_scores(
                signal_pack=signal_pack,
                manifest=manifest,
                user_count=user_count,
            )
            logger.info("[TIMELINE] scores_computed → extension_id=%s, overall_score=%s", extension_id, scoring_result.overall_score)
            
            # Build scoring_v2 payload for API response
            scoring_v2_payload = {
                "scoring_version": "v2",
                "weights_version": "v1",
                "security_score": scoring_result.security_score,
                "privacy_score": scoring_result.privacy_score,
                "governance_score": scoring_result.governance_score,
                "overall_score": scoring_result.overall_score,
                "overall_confidence": scoring_result.overall_confidence,
                "decision": scoring_result.decision.value,
                "decision_reasons": scoring_result.reasons,
                "hard_gates_triggered": scoring_result.hard_gates_triggered,
                "risk_level": scoring_result.risk_level.value,
                "explanation": scoring_result.explanation,
            }

            # Build scan results - sanitize complex objects to prevent circular references
            raw_results = {
                "extension_id": extension_id,
                "extension_name": extension_name,
                "url": url,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "status": "completed",
                "metadata": metadata,
                "manifest": manifest,
                "permissions_analysis": analysis_results.get("permissions_analysis") or {},
                "sast_results": analysis_results.get("javascript_analysis") or {},
                "webstore_analysis": analysis_results.get("webstore_analysis") or {},
                "virustotal_analysis": analysis_results.get("virustotal_analysis") or {},
                "entropy_analysis": analysis_results.get("entropy_analysis") or {},
                "summary": final_state.get("executive_summary") or {},
                "impact_analysis": analysis_results.get("impact_analysis") or {},
                "privacy_compliance": analysis_results.get("privacy_compliance") or {},
                "extracted_path": _storage_relative_extracted_path(final_state.get("extension_dir")),
                "extracted_files": extracted_files,
                "icon_path": icon_path,  # Relative path to icon (e.g., "icons/128.png")
                "icon_base64": icon_base64,  # Persisted icon bytes for environments with ephemeral storage
                "icon_media_type": icon_media_type,
                # UI-first payload (production) - handle LLM failures gracefully
                "report_view_model": _build_report_view_model_safe(
                    manifest=manifest,
                    analysis_results={**analysis_results, "executive_summary": final_state.get("executive_summary") or {}},
                    metadata=metadata,
                    extension_id=extension_id,
                    scan_id=extension_id,
                ),
                # V2 scoring - overall_security_score for backward compatibility
                "overall_security_score": scoring_result.overall_score,
                # Explicit v2 keys for new consumers
                "security_score": scoring_result.security_score,
                "privacy_score": scoring_result.privacy_score,
                "governance_score": scoring_result.governance_score,
                "overall_confidence": scoring_result.overall_confidence,
                "decision_v2": scoring_result.decision.value,
                "decision_reasons_v2": scoring_result.reasons,
                # Full v2 scoring payload
                "scoring_v2": scoring_v2_payload,
                # Legacy helper outputs (kept for backward compatibility)
                "total_findings": count_total_findings(final_state),
                "risk_distribution": calculate_risk_distribution(final_state),
                "overall_risk": scoring_result.risk_level.value,  # Use v2 risk level
                "total_risk_score": calculate_total_risk_score(final_state),
                # Governance data (Pipeline B: Stages 2-8) - sanitize to prevent circular refs
                "governance_verdict": final_state.get("governance_verdict"),
                "governance_bundle": sanitize_for_json(final_state.get("governance_bundle")),
                "governance_report": sanitize_for_json(final_state.get("governance_report")),
                "governance_error": final_state.get("governance_error"),
            }
            
            # Final sanitization pass to ensure JSON-serializability
            scan_results[extension_id] = sanitize_for_json(raw_results)
            scan_status[extension_id] = "completed"
            logger.info("[TIMELINE] report_view_model_built → extension_id=%s, has_rvm=%s", extension_id, bool(scan_results[extension_id].get("report_view_model")))

            # Save to database
            logger.info("[TIMELINE] saving_to_database → extension_id=%s", extension_id)
            save_success = db.save_scan_result(scan_results[extension_id])
            if not save_success:
                logger.error("[TIMELINE] FAILED to save to database → extension_id=%s", extension_id)
            else:
                logger.info("[TIMELINE] saved_to_database → extension_id=%s, success=%s", extension_id, save_success)

            # Save to user history (best-effort; anonymous scans are not saved)
            user_id = scan_user_ids.pop(extension_id, None)
            if user_id:
                try:
                    db.add_user_scan_history(user_id=user_id, extension_id=extension_id)
                except Exception:
                    pass

            # Save to file (backup) - use safe JSON encoder to handle circular references
            logger.info("[TIMELINE] saving_to_file → extension_id=%s", extension_id)
            result_file = RESULTS_DIR / f"{extension_id}_results.json"
            try:
                with open(result_file, "w", encoding="utf-8") as f:
                    success = safe_json_dump(scan_results[extension_id], f, indent=2)
                if success:
                    logger.info("[TIMELINE] saved_to_file → extension_id=%s, file=%s", extension_id, result_file)
                else:
                    logger.warning("[TIMELINE] file_save_partial → extension_id=%s, file=%s", extension_id, result_file)
            except Exception as file_error:
                logger.error("[TIMELINE] file_save_failed → extension_id=%s, error=%s", extension_id, str(file_error))
                # Don't fail the scan if file save fails - database is the primary storage
            
            workflow_duration = (datetime.now() - workflow_start).total_seconds()
            logger.info("[TIMELINE] scan_complete → extension_id=%s, duration=%.2fs", extension_id, workflow_duration)
        else:
            scan_status[extension_id] = "failed"
            logger.error("[TIMELINE] scan_failed → extension_id=%s, status=%s, error=%s", extension_id, final_state.get("status"), final_state.get("error"))
            scan_results[extension_id] = {
                "extension_id": extension_id,
                "url": url,
                "status": "failed",
                "error": final_state.get("error", "Unknown error"),
            }

    except Exception as e:
        scan_status[extension_id] = "failed"
        import traceback
        logger.error("[TIMELINE] workflow_exception → extension_id=%s, error=%s", extension_id, str(e))
        logger.error("[TIMELINE] workflow_exception_traceback → extension_id=%s\n%s", extension_id, traceback.format_exc())
        
        # Check if this is an OpenAI API key error
        error_str = str(e)
        error_message = str(e)
        error_code = None
        
        # Check for OpenAI API key errors - detect specific patterns
        # Note: Both 'sk-' and 'sk-proj-' are valid OpenAI API key formats
        # 'sk-proj-' is OpenAI's project-based key format (introduced 2024)
        if "sk-proj-" in error_str and "invalid" in error_str.lower():
            # This might be an actual API error from OpenAI, not a format issue
            error_code = 401
            error_message = (
                "OpenAI API key error detected. Please verify your API key is valid and has not been revoked. "
                "Check your key at https://platform.openai.com/api-keys"
            )
        elif "invalid_api_key" in error_str or "Incorrect API key" in error_str:
            error_code = 401
            error_message = (
                "Invalid API key provided. The OpenAI API key is incorrect or has been revoked. "
                "Please check your OPENAI_API_KEY environment variable and ensure it's a valid key from "
                "https://platform.openai.com/api-keys"
            )
        elif "401" in error_str and ("api" in error_str.lower() or "key" in error_str.lower()):
            error_code = 401
            error_message = (
                "API authentication failed. Please verify your OpenAI API key configuration. "
                "Check your OPENAI_API_KEY environment variable."
            )
        elif "AuthenticationError" in error_str or "authentication" in error_str.lower():
            error_code = 401
            error_message = "Authentication failed. Please check your API key configuration."
        elif "connection refused" in error_str.lower() or "errno 61" in error_str.lower():
            # Connection refused errors (e.g., Ollama not running, wrong LLM provider in chain)
            error_code = 503
            error_message = (
                "LLM service connection failed. This usually means: "
                "1) An LLM provider in your fallback chain is not available (e.g., Ollama not running), "
                "2) Network connectivity issues, or "
                "3) The LLM service endpoint is incorrect. "
                "Please check your LLM_FALLBACK_CHAIN configuration and ensure only available providers are included. "
                "Default: watsonx,openai"
            )
        elif "connection" in error_str.lower() and ("refused" in error_str.lower() or "timeout" in error_str.lower()):
            error_code = 503
            error_message = (
                "LLM service connection error. Please verify your LLM provider configuration. "
                "Check LLM_FALLBACK_CHAIN in your environment variables."
            )
        elif "token_quota_reached" in error_str.lower() or ("403" in error_str and "quota" in error_str.lower()):
            # WatsonX quota exceeded
            error_code = 403
            error_message = (
                "WatsonX token quota has been reached. Your monthly token limit has been exceeded. "
                "Options: 1) Wait for quota reset, 2) Upgrade your WatsonX plan, or "
                "3) Add OpenAI as fallback by setting LLM_FALLBACK_CHAIN=watsonx,openai in your .env file."
            )
        elif "403" in error_str and ("forbidden" in error_str.lower() or "quota" in error_str.lower()):
            # Generic 403/quota error
            error_code = 403
            error_message = (
                "LLM service quota exceeded. Your API quota has been reached. "
                "Please check your LLM provider account limits or add a fallback provider."
            )
        
        scan_results[extension_id] = {
            "extension_id": extension_id,
            "url": url,
            "status": "failed",
            "error": error_message,
            "error_code": error_code,
        }


def get_extracted_files(extracted_path: Optional[str]) -> list[str]:
    """Get list of extracted files from the extension."""
    if not extracted_path or not os.path.exists(extracted_path):
        return []

    files = []
    for root, _, filenames in os.walk(extracted_path):
        for filename in filenames:
            file_path = os.path.join(root, filename)
            # Store relative path from extracted_path
            rel_path = os.path.relpath(file_path, extracted_path)
            files.append(rel_path)

    return files


def _calculate_permission_alignment_penalty(
    manifest: Dict,
    permissions_details: Dict,
    permissions_analysis: Dict,
    analysis_results: Dict
) -> int:
    """
    Calculate penalty based on permission-purpose alignment.
    
    This is the CONTEXT-AWARE mathematical model that differentiates:
    - Vimium: Needs <all_urls> for keyboard navigation → LEGITIMATE (low penalty)
    - Honey: Had permissions but used them covertly → ABUSIVE (high penalty)
    - Visa extension: Screenshot without consent → ABUSIVE (high penalty)
    
    The model evaluates:
    1. TRANSPARENCY: Is sensitive behavior disclosed in name/description?
    2. JUSTIFICATION: Do permissions match stated purpose?
    3. CONSENT: Are there popup/notification patterns in code?
    4. COVERT BEHAVIOR: Silent data collection without user awareness?
    
    Formula:
        penalty = base_risk × (1 - transparency_score) × covert_multiplier
    
    Returns:
        int: Penalty points (0-20)
    """
    penalty = 0
    
    # Extract extension metadata
    name = manifest.get("name", "").lower()
    description = manifest.get("description", "").lower()
    permissions = list(permissions_details.keys()) if permissions_details else []
    
    # === STEP 1: Identify Sensitive Permission Combinations ===
    
    # High-risk permission groups that require justification
    has_all_urls = any(
        p in permissions or p in str(permissions_analysis.get("host_permissions_analysis", ""))
        for p in ["<all_urls>", "*://*/*"]
    )
    has_cookies = "cookies" in permissions
    has_web_request = any(p in permissions for p in ["webRequest", "webRequestBlocking"])
    has_history = "history" in permissions
    has_clipboard = any(p in permissions for p in ["clipboardRead", "clipboardWrite"])
    has_tabs = "tabs" in permissions
    has_screenshot = any(p in permissions for p in ["desktopCapture", "tabCapture"])
    
    # Check for screenshot libraries (from screenshot_capture_analysis)
    screenshot_analysis = permissions_analysis.get("screenshot_capture_analysis", {})
    has_screenshot_lib = screenshot_analysis.get("detected", False) if isinstance(screenshot_analysis, dict) else False
    
    # === STEP 2: Check Transparency (Is behavior disclosed?) ===
    
    # Keywords that indicate transparent disclosure of sensitive features
    transparency_keywords = {
        "all_urls": ["browser", "navigation", "keyboard", "shortcut", "accessibility", "reader", "dark mode", "style"],
        "cookies": ["login", "session", "authentication", "sync", "password", "manager"],
        "webRequest": ["block", "filter", "ad", "privacy", "tracker", "vpn", "proxy"],
        "history": ["history", "bookmark", "search", "session", "backup"],
        "clipboard": ["clipboard", "copy", "paste", "text", "snippet"],
        "screenshot": ["screenshot", "capture", "image", "pdf", "print", "screen"],
    }
    
    transparency_score = 1.0  # 1.0 = fully transparent, 0.0 = opaque
    
    # Check if high-risk permissions are justified by description
    if has_all_urls:
        all_urls_justified = any(kw in name or kw in description for kw in transparency_keywords["all_urls"])
        if not all_urls_justified:
            transparency_score *= 0.5  # 50% reduction if not disclosed
    
    if has_cookies:
        cookies_justified = any(kw in name or kw in description for kw in transparency_keywords["cookies"])
        if not cookies_justified:
            transparency_score *= 0.7
    
    if has_web_request:
        web_request_justified = any(kw in name or kw in description for kw in transparency_keywords["webRequest"])
        if not web_request_justified:
            transparency_score *= 0.6
    
    if has_screenshot or has_screenshot_lib:
        screenshot_justified = any(kw in name or kw in description for kw in transparency_keywords["screenshot"])
        if not screenshot_justified:
            transparency_score *= 0.3  # Screenshot without disclosure = very suspicious
    
    # === STEP 3: Check for Covert Behavior Patterns ===
    
    covert_multiplier = 1.0
    
    # Pattern 1: Data Collection + Network (can exfiltrate)
    # This is the Honey pattern: collect data silently and send to server
    js_analysis = analysis_results.get("javascript_analysis", {})
    has_third_party_api = False
    if js_analysis and isinstance(js_analysis, dict):
        sast_findings = js_analysis.get("sast_findings", {})
        for findings_list in sast_findings.values():
            for finding in findings_list:
                check_id = finding.get("check_id", "")
                if "third_party" in check_id.lower() or "external_api" in check_id.lower():
                    has_third_party_api = True
                    break
    
    # Covert data collection pattern: sensitive permission + network + no disclosure
    if has_third_party_api:
        if has_cookies or has_history or has_clipboard:
            covert_multiplier = 2.0  # Double penalty for data exfiltration capability
        if has_screenshot or has_screenshot_lib:
            covert_multiplier = 2.5  # Higher penalty for screenshot exfiltration
    
    # Pattern 2: Silent operation (no popup/notification keywords)
    # Legitimate extensions often mention "popup", "toolbar", "notification"
    ui_keywords = ["popup", "toolbar", "icon", "badge", "notification", "alert", "confirm", "dialog"]
    has_ui_indication = any(kw in description for kw in ui_keywords)
    
    if not has_ui_indication and (has_screenshot or has_screenshot_lib):
        # Screenshot capability with no UI indication = likely covert
        covert_multiplier *= 1.5
    
    # === STEP 4: Check Extension Category Alignment ===
    
    # Some categories naturally need broad permissions
    legitimate_broad_permission_categories = [
        # Productivity tools that legitimately need all-site access
        ("vimium", "keyboard"),
        ("surfingkeys", "keyboard"),
        ("dark reader", "dark mode"),
        ("stylus", "style"),
        ("ublock", "ad blocker"),
        ("adblock", "ad blocker"),
        ("privacy badger", "privacy"),
        ("https everywhere", "https"),
        ("grammarly", "grammar"),
        ("lastpass", "password"),
        ("bitwarden", "password"),
        ("1password", "password"),
    ]
    
    is_legitimate_broad_tool = any(
        cat_name in name or cat_keyword in name
        for cat_name, cat_keyword in legitimate_broad_permission_categories
    )
    
    if is_legitimate_broad_tool:
        # Reduce penalty for known legitimate tool patterns
        covert_multiplier *= 0.3
    
    # === STEP 5: Calculate Final Penalty ===
    
    # Base risk from sensitive permission combinations
    base_risk = 0
    
    if has_all_urls and has_cookies:
        base_risk += 8  # Can track across all sites
    elif has_all_urls:
        base_risk += 4  # Broad access but no cookie tracking
    
    if has_web_request and has_cookies:
        base_risk += 6  # Can intercept and modify requests with tracking
    
    if (has_screenshot or has_screenshot_lib) and has_third_party_api:
        base_risk += 10  # Screenshot + network = exfiltration
    
    if has_history and has_third_party_api:
        base_risk += 5  # Browsing history exfiltration
    
    if has_clipboard and has_third_party_api:
        base_risk += 7  # Clipboard data exfiltration
    
    # Apply transparency and covert modifiers
    # Formula: penalty = base_risk × (2 - transparency_score) × covert_multiplier
    # When transparency = 1.0 (fully transparent): multiplier = 1.0
    # When transparency = 0.0 (opaque): multiplier = 2.0
    transparency_multiplier = 2.0 - transparency_score
    
    penalty = int(base_risk * transparency_multiplier * covert_multiplier)
    
    # Cap at 20 points
    return min(20, penalty)


def calculate_security_score(state: WorkflowState) -> int:
    """
    Calculate overall security score using weighted multi-factor analysis.

    Scoring Components (risk points deducted from 100):
    - SAST Findings (40 pts max): Critical code vulnerabilities
    - Permissions Risk (30 pts max): Unreasonable/excessive permissions
    - Webstore Trust (20 pts max): User ratings, install count, developer reputation
    - Manifest Quality (10 pts max): Proper metadata, CSP, update URL

    Returns:
        int: Security score from 0 (dangerous) to 100 (secure)
    """
    analysis_results = state.get("analysis_results", {}) or {}
    manifest = state.get("manifest_data", {}) or {}

    # Component 1: SAST Analysis (40 points max risk)
    sast_score = 0  # Start at 0 risk
    javascript_analysis = analysis_results.get("javascript_analysis", {})
    if javascript_analysis and isinstance(javascript_analysis, dict):
        sast_findings = javascript_analysis.get("sast_findings", {})
        for findings_list in sast_findings.values():
            for finding in findings_list:
                check_id = finding.get("check_id", "")
                # Exclude third-party API findings from SAST risk (counted separately)
                if "third_party" in check_id.lower() or "external_api" in check_id.lower():
                    continue
                severity = finding.get("extra", {}).get("severity", "INFO").upper()
                if severity in ("CRITICAL", "HIGH"):
                    sast_score += 8  # Add risk points
                elif severity in ("ERROR", "MEDIUM"):
                    sast_score += 4
                elif severity == "WARNING":
                    sast_score += 1
    sast_score = min(40, sast_score)  # Cap at 40

    # Component 2: Permissions Analysis (30 points max risk)
    permissions_score = 0  # Start at 0 risk
    permissions_analysis = analysis_results.get("permissions_analysis", {}) or {}
    permissions_details = (
        permissions_analysis.get("permissions_details")
        if isinstance(permissions_analysis, dict)
        else None
    )
    # Ensure permissions_details is a dict, not None
    if not isinstance(permissions_details, dict):
        permissions_details = {}

    _ = len(permissions_details)  # total_permissions - kept for potential future use
    unreasonable_count = 0
    high_risk_perms = 0

    for _, perm_analysis in permissions_details.items():
        is_reasonable = perm_analysis.get("is_reasonable", True)
        risk = perm_analysis.get("risk_level", "").lower()

        if not is_reasonable:
            unreasonable_count += 1
            if risk == "high":
                high_risk_perms += 1
                permissions_score += 5  # Add risk points
            elif risk == "medium":
                permissions_score += 2
            else:
                permissions_score += 1

    permissions_score = min(30, permissions_score)  # Cap at 30

    # Component 3: Webstore Trust Score (20 points max risk)
    webstore_score = 0  # Start at 0 risk
    _ = analysis_results.get("webstore_analysis", {})  # webstore_analysis - for future use
    metadata = state.get("extension_metadata", {}) or {}

    # Check user ratings (low rating = higher risk)
    rating = metadata.get("rating")
    if rating:
        try:
            rating_val = float(rating)
            if rating_val >= 4.5:
                webstore_score += 0  # Excellent - no risk
            elif rating_val >= 4.0:
                webstore_score += 2  # Good - slight risk
            elif rating_val >= 3.0:
                webstore_score += 5  # Average - moderate risk
            else:
                webstore_score += 10  # Poor - high risk
        except (ValueError, TypeError):
            webstore_score += 3  # No valid rating - some risk
    else:
        webstore_score += 3  # No rating data

    # Check install count (low adoption = higher risk)
    users = metadata.get("users", "0")
    try:
        user_count = int(users.replace(",", "").replace("+", ""))
        if user_count >= 1000000:
            webstore_score += 0  # Very popular - trusted
        elif user_count >= 100000:
            webstore_score += 2  # Popular - low risk
        elif user_count >= 10000:
            webstore_score += 5  # Moderate - some risk
        else:
            webstore_score += 8  # Low adoption - higher risk
    except (ValueError, TypeError):
        webstore_score += 5  # Unknown user count

    webstore_score = min(20, webstore_score)  # Cap at 20

    # Component 4: Manifest Quality (10 points max risk)
    manifest_score = 0  # Start at 0 risk

    # Check for proper metadata (missing = risk)
    if not manifest.get("name") or manifest.get("name", "").startswith("__MSG_"):
        manifest_score += 3  # Missing/placeholder name = risk
    if not manifest.get("description") or manifest.get("description", "").startswith("__MSG_"):
        manifest_score += 2  # Missing/placeholder description = risk

    # Check for Content Security Policy (missing = risk)
    if not manifest.get("content_security_policy"):
        manifest_score += 2

    # Check for update URL (missing = risk)
    if not manifest.get("update_url"):
        manifest_score += 1

    manifest_score = min(10, manifest_score)  # Cap at 10

    # Component 5: Third-Party API Calls Detection (+1 point if detected, only once)
    third_party_api_score = 0
    if javascript_analysis and isinstance(javascript_analysis, dict):
        sast_findings = javascript_analysis.get("sast_findings", {})
        # Check for third-party API rule in SAST findings
        # Rule ID: banking.third_party.external_api_calls
        third_party_detected = False
        for findings_list in sast_findings.values():
            for finding in findings_list:
                check_id = finding.get("check_id", "")
                if check_id and (
                    "banking.third_party.external_api_calls" in check_id
                    or "third_party" in check_id.lower()
                    or "external_api" in check_id.lower()
                ):
                    third_party_detected = True
                    break
            if third_party_detected:
                break
        if third_party_detected:
            third_party_api_score = 1  # Add only once, not per finding

    # Component 6: Screenshot Capture Detection (context-aware: 0-15 pts)
    # Different from binary +1: considers consent, transparency, and purpose alignment
    screenshot_score = 0
    if permissions_analysis and isinstance(permissions_analysis, dict):
        screenshot_analysis = permissions_analysis.get("screenshot_capture_analysis", {})
        if isinstance(screenshot_analysis, dict) and screenshot_analysis.get("detected", False):
            # Base detection score
            screenshot_score = 3
            
            # Context modifiers: Check if screenshot is justified by purpose
            extension_name = manifest.get("name", "").lower()
            extension_desc = manifest.get("description", "").lower()
            
            # Legitimate screenshot tools get reduced penalty
            screenshot_keywords = ["screenshot", "capture", "snap", "screen", "image", "pdf", "print"]
            is_screenshot_tool = any(kw in extension_name or kw in extension_desc for kw in screenshot_keywords)
            
            if is_screenshot_tool:
                screenshot_score = 1  # Expected behavior for screenshot tools
            else:
                # Check for covert behavior indicators (no consent patterns)
                # If extension has screenshot + network + no popup indication = higher risk
                has_network = any(
                    perm in permissions_details
                    for perm in ["webRequest", "webRequestBlocking", "<all_urls>"]
                )
                if has_network:
                    screenshot_score = 10  # Can capture and exfiltrate
                
                # Check for clipboard/download (can save screenshots)
                has_storage = any(
                    perm in permissions_details
                    for perm in ["clipboardWrite", "downloads"]
                )
                if has_storage and has_network:
                    screenshot_score = 15  # Full exfiltration capability

    # Component 7: VirusTotal Analysis (0-50 pts)
    # Critical: This was MISSING from scoring!
    virustotal_score = 0
    virustotal_analysis = analysis_results.get("virustotal_analysis", {})
    if virustotal_analysis and isinstance(virustotal_analysis, dict):
        if virustotal_analysis.get("enabled"):
            total_malicious = virustotal_analysis.get("total_malicious", 0)
            total_suspicious = virustotal_analysis.get("total_suspicious", 0)
            
            if total_malicious > 0:
                # Consensus-based scoring (not binary)
                if total_malicious >= 10:
                    virustotal_score = 50  # Strong malware consensus
                elif total_malicious >= 5:
                    virustotal_score = 40  # Multiple detections
                elif total_malicious >= 2:
                    virustotal_score = 30  # Some detections
                else:
                    virustotal_score = 15  # Single detection (could be false positive)
            elif total_suspicious > 0:
                virustotal_score = min(20, total_suspicious * 5)

    # Component 8: Entropy/Obfuscation Analysis (0-30 pts)
    # Critical: This was MISSING from scoring!
    entropy_score = 0
    entropy_analysis = analysis_results.get("entropy_analysis", {})
    if entropy_analysis and isinstance(entropy_analysis, dict):
        obfuscated_files = entropy_analysis.get("obfuscated_files", 0)
        suspicious_files = entropy_analysis.get("suspicious_files", 0)
        
        # Context-aware: Check if obfuscation is legitimate minification
        # Large popular extensions often use minified code
        user_count = 0
        try:
            users = state.get("extension_metadata", {}).get("users", "0")
            user_count = int(str(users).replace(",", "").replace("+", ""))
        except (ValueError, TypeError):
            pass
        
        # Popular extensions (>100K users) get reduced obfuscation penalty
        # (likely using legitimate minification/bundlers)
        popularity_modifier = 0.5 if user_count >= 100000 else 1.0
        
        if obfuscated_files > 0:
            base_obfuscation_risk = min(20, obfuscated_files * 8)
            entropy_score += int(base_obfuscation_risk * popularity_modifier)
        
        if suspicious_files > 0:
            entropy_score += min(10, suspicious_files * 4)
        
        entropy_score = min(30, entropy_score)

    # Component 9: ChromeStats Behavioral Analysis (0-28 pts)
    # Critical: This was MISSING from scoring!
    chromestats_score = 0
    chromestats_analysis = analysis_results.get("chromestats_analysis", {})
    if chromestats_analysis and isinstance(chromestats_analysis, dict):
        if chromestats_analysis.get("enabled") and not chromestats_analysis.get("error"):
            chromestats_score = min(28, chromestats_analysis.get("total_risk_score", 0))

    # Component 10: Permission-Purpose Alignment (Context-Aware Model)
    # This addresses the Vimium vs Honey problem:
    # - Vimium needs <all_urls> for keyboard navigation = LEGITIMATE
    # - Honey had permissions but used them covertly = ABUSIVE
    alignment_penalty = 0
    alignment_penalty = _calculate_permission_alignment_penalty(
        manifest=manifest,
        permissions_details=permissions_details,
        permissions_analysis=permissions_analysis,
        analysis_results=analysis_results
    )

    # Calculate final weighted score (risk points)
    # NEW TOTAL MAX: 40 + 30 + 20 + 10 + 1 + 15 + 50 + 30 + 28 + 20 = 244 pts
    final_score = (
        sast_score              # 40 max
        + permissions_score     # 30 max
        + webstore_score        # 20 max
        + manifest_score        # 10 max
        + third_party_api_score # 1 max
        + screenshot_score      # 15 max (was 1)
        + virustotal_score      # 50 max (NEW)
        + entropy_score         # 30 max (NEW)
        + chromestats_score     # 28 max (NEW)
        + alignment_penalty     # 20 max (NEW - context-aware)
    )

    # Invert to security score: 100 = secure, 0 = risky
    return max(0, min(100, 100 - final_score))


def count_total_findings(state: WorkflowState) -> int:
    """Count total security findings including unreasonable permissions."""
    analysis_results = state.get("analysis_results", {}) or {}

    # Count SAST findings
    javascript_analysis = analysis_results.get("javascript_analysis", {})
    total = 0
    if javascript_analysis:
        sast_findings = javascript_analysis.get("sast_findings", {})
        for findings_list in sast_findings.values():
            if findings_list is not None:
                total += len(findings_list)

    # Count unreasonable permissions as findings
    permissions_analysis = analysis_results.get("permissions_analysis", {}) or {}
    permissions_details = (
        permissions_analysis.get("permissions_details")
        if isinstance(permissions_analysis, dict)
        else None
    )
    # Ensure permissions_details is a dict, not None
    if not isinstance(permissions_details, dict):
        permissions_details = {}

    for _, perm_analysis in permissions_details.items():
        is_reasonable = perm_analysis.get("is_reasonable", True)
        if not is_reasonable:
            total += 1

    return total


def _coerce_int(value: Any) -> Optional[int]:
    """Best-effort int coercion."""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _build_scoring_v2_for_payload(payload: Dict[str, Any], extension_id: str) -> Dict[str, Any]:
    """
    Build scoring_v2 from available scan payload fields (no LLM/report generation).
    Used by /api/recent when legacy rows are missing scoring_v2.
    """
    try:
        manifest = payload.get("manifest") or {}
        metadata = payload.get("metadata") or {}
        analysis_results = {
            "permissions_analysis": payload.get("permissions_analysis") or {},
            "javascript_analysis": payload.get("sast_results") or {},
            "webstore_analysis": payload.get("webstore_analysis") or {},
            "virustotal_analysis": payload.get("virustotal_analysis") or {},
            "entropy_analysis": payload.get("entropy_analysis") or {},
            "impact_analysis": payload.get("impact_analysis") or {},
            "privacy_compliance": payload.get("privacy_compliance") or {},
            "executive_summary": payload.get("summary") or {},
        }

        signal_pack_builder = SignalPackBuilder()
        signal_pack = signal_pack_builder.build(
            scan_id=extension_id,
            analysis_results=analysis_results,
            metadata=metadata,
            manifest=manifest,
            extension_id=extension_id,
        )

        user_count = metadata.get("user_count") or metadata.get("users") or signal_pack.webstore_stats.installs
        scoring_engine = ScoringEngine(weights_version="v1")
        scoring_result = scoring_engine.calculate_scores(
            signal_pack=signal_pack,
            manifest=manifest,
            user_count=user_count if isinstance(user_count, int) else None,
            permissions_analysis=analysis_results.get("permissions_analysis"),
        )

        scoring_v2_payload = scoring_result.model_dump_for_api()
        scoring_v2_payload["weights_version"] = "v1"
        gate_results = scoring_engine.get_gate_results() or []
        scoring_v2_payload["gate_results"] = [
            {
                "gate_id": g.gate_id,
                "decision": g.decision,
                "triggered": g.triggered,
                "confidence": g.confidence,
                "reasons": g.reasons,
            }
            for g in gate_results
        ]
        return scoring_v2_payload
    except Exception as exc:
        logger.warning(
            "[RISK_SIGNALS] Could not rebuild scoring_v2 for extension_id=%s: %s",
            extension_id,
            exc,
        )
        return {}


def _extract_risk_and_signals(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract risk and signals mapping from scan results payload.
    
    Returns mapping:
    {
        "risk": overall_safety_score,
        "signals": {
            "security": security_score,
            "privacy": privacy_score,
            "gov": governance_score
        },
        "total_findings": deduplicated_count
    }
    """
    # Prefer top-level scoring_v2, then summary.scoring_v2, then governance_bundle.scoring_v2
    scoring_v2 = payload.get("scoring_v2")
    if not isinstance(scoring_v2, dict) or not scoring_v2:
        summary = payload.get("summary")
        if isinstance(summary, str):
            try:
                summary = json.loads(summary)
            except Exception:
                summary = {}
        if isinstance(summary, dict):
            candidate = summary.get("scoring_v2")
            if isinstance(candidate, dict) and candidate:
                scoring_v2 = candidate
    if (not isinstance(scoring_v2, dict) or not scoring_v2) and isinstance(payload.get("governance_bundle"), dict):
        candidate = payload.get("governance_bundle", {}).get("scoring_v2")
        if isinstance(candidate, dict) and candidate:
            scoring_v2 = candidate

    # If still missing, dynamically rebuild scoring_v2 from available analysis data.
    if not isinstance(scoring_v2, dict) or not scoring_v2:
        extension_id = str(payload.get("extension_id") or "unknown")
        scoring_v2 = _build_scoring_v2_for_payload(payload, extension_id=extension_id)
        if scoring_v2:
            payload["scoring_v2"] = scoring_v2

    # Overall safety score
    overall_score = (
        _coerce_int((scoring_v2 or {}).get("overall_score"))
        or _coerce_int(payload.get("overall_security_score"))
        or _coerce_int(payload.get("security_score"))
        or 0
    )

    # Layer signal scores
    security_score = _coerce_int((scoring_v2 or {}).get("security_score"))
    if security_score is None and isinstance((scoring_v2 or {}).get("security_layer"), dict):
        security_score = _coerce_int((scoring_v2 or {}).get("security_layer", {}).get("score"))
    if security_score is None:
        security_score = _coerce_int(payload.get("security_score")) or _coerce_int(payload.get("overall_security_score"))

    privacy_score = _coerce_int((scoring_v2 or {}).get("privacy_score"))
    if privacy_score is None and isinstance((scoring_v2 or {}).get("privacy_layer"), dict):
        privacy_score = _coerce_int((scoring_v2 or {}).get("privacy_layer", {}).get("score"))
    if privacy_score is None:
        privacy_score = _coerce_int(payload.get("privacy_score"))

    governance_score = _coerce_int((scoring_v2 or {}).get("governance_score"))
    if governance_score is None and isinstance((scoring_v2 or {}).get("governance_layer"), dict):
        governance_score = _coerce_int((scoring_v2 or {}).get("governance_layer", {}).get("score"))
    if governance_score is None:
        governance_score = _coerce_int(payload.get("governance_score"))

    # Combined, deduplicated findings count across layers (prefer scoring_v2 factors + triggered gates)
    total_findings = 0
    if isinstance(scoring_v2, dict) and scoring_v2:
        combined_keys = set()
        for layer_key in ("security_layer", "privacy_layer", "governance_layer"):
            layer_obj = scoring_v2.get(layer_key)
            if not isinstance(layer_obj, dict):
                continue
            factors = layer_obj.get("factors", [])
            if not isinstance(factors, list):
                continue
            for factor in factors:
                if not isinstance(factor, dict):
                    continue
                sev = factor.get("severity")
                contrib = factor.get("contribution")
                try:
                    sev_num = float(sev) if sev is not None else 0.0
                except (TypeError, ValueError):
                    sev_num = 0.0
                try:
                    contrib_num = float(contrib) if contrib is not None else 0.0
                except (TypeError, ValueError):
                    contrib_num = 0.0
                if sev_num <= 0 and contrib_num <= 0:
                    continue
                factor_name = str(factor.get("name") or factor.get("id") or factor.get("key") or "unknown")
                combined_keys.add(f"{layer_key}:{factor_name}")

        gate_results = scoring_v2.get("gate_results", [])
        if isinstance(gate_results, list):
            for gate in gate_results:
                if isinstance(gate, dict) and bool(gate.get("triggered")):
                    gate_id = str(gate.get("gate_id") or "gate")
                    combined_keys.add(f"gate:{gate_id}")

        if combined_keys:
            total_findings = len(combined_keys)

    # Fallbacks for findings count
    if total_findings == 0:
        facts = payload.get("governance_bundle", {}).get("facts", {})
        if isinstance(facts, dict):
            security_findings = facts.get("security_findings", {})
            if isinstance(security_findings, dict):
                deduped_findings = security_findings.get("deduped_findings", [])
                if isinstance(deduped_findings, list) and deduped_findings:
                    total_findings = len(deduped_findings)
                else:
                    total_findings = _coerce_int(security_findings.get("total_findings")) or 0

    if total_findings == 0:
        signal_pack = payload.get("signal_pack", {})
        if isinstance(signal_pack, dict):
            sast_signal = signal_pack.get("sast", {})
            if isinstance(sast_signal, dict):
                deduped = sast_signal.get("deduped_findings", [])
                if isinstance(deduped, list) and deduped:
                    total_findings = len(deduped)

    if total_findings == 0:
        total_findings = _coerce_int(payload.get("total_findings")) or 0

    # Last resort manual SAST dedupe
    if total_findings == 0:
        sast_results = payload.get("sast_results", {})
        if isinstance(sast_results, dict):
            sast_findings = sast_results.get("sast_findings", {})
            if isinstance(sast_findings, dict):
                seen = set()
                for file_path, findings_list in sast_findings.items():
                    if not isinstance(findings_list, list):
                        continue
                    for finding in findings_list:
                        if not isinstance(finding, dict):
                            continue
                        check_id = finding.get("check_id") or finding.get("rule_id", "")
                        line = (
                            finding.get("start", {}).get("line")
                            if isinstance(finding.get("start"), dict)
                            else finding.get("line")
                        )
                        key = f"{check_id}:{file_path}:{line}"
                        seen.add(key)
                total_findings = len(seen)

    signals: Dict[str, int] = {}
    if security_score is not None:
        signals["security"] = max(0, min(100, security_score))
    if privacy_score is not None:
        signals["privacy"] = max(0, min(100, privacy_score))
    if governance_score is not None:
        signals["gov"] = max(0, min(100, governance_score))

    return {
        "risk": max(0, min(100, int(overall_score))),
        "signals": signals,
        "total_findings": max(0, int(total_findings)),
    }


def calculate_risk_distribution(state: WorkflowState) -> Dict[str, int]:
    """Calculate distribution of risk levels."""
    distribution = {"high": 0, "medium": 0, "low": 0}

    analysis_results = state.get("analysis_results", {}) or {}

    # Count SAST findings
    javascript_analysis = analysis_results.get("javascript_analysis", {})
    js_analysis = []
    if javascript_analysis and isinstance(javascript_analysis, dict):
        sast_findings = javascript_analysis.get("sast_findings", {})
        for findings_list in sast_findings.values():
            if findings_list is not None:
                js_analysis.extend(findings_list)
    elif isinstance(javascript_analysis, list):
        js_analysis = javascript_analysis

    for finding in js_analysis:
        risk_level = finding.get("extra", {}).get("severity", "INFO").lower()
        if risk_level in ("critical", "high"):
            distribution["high"] += 1
        elif risk_level in ("error", "medium"):
            distribution["medium"] += 1
        else:
            distribution["low"] += 1

    # Count unreasonable permissions as findings
    permissions_analysis = analysis_results.get("permissions_analysis", {}) or {}
    permissions_details = (
        permissions_analysis.get("permissions_details")
        if isinstance(permissions_analysis, dict)
        else None
    )
    # Ensure permissions_details is a dict, not None
    if not isinstance(permissions_details, dict):
        permissions_details = {}

    for _, perm_analysis in permissions_details.items():
        is_reasonable = perm_analysis.get("is_reasonable", True)
        risk = perm_analysis.get("risk_level", "").lower()

        if not is_reasonable:
            # Classify unreasonable permissions by explicit risk_level or default to medium
            if risk == "high":
                distribution["high"] += 1
            elif risk == "low":
                distribution["low"] += 1
            else:
                # Default unreasonable permissions to medium risk
                distribution["medium"] += 1

    return distribution


def determine_overall_risk(state: WorkflowState) -> str:
    """Determine overall risk level."""
    score = calculate_security_score(state)

    if score < 30:
        return "high"
    if score < 70:
        return "medium"
    return "low"


def calculate_total_risk_score(state: WorkflowState) -> int:
    """Calculate total risk score."""
    analysis_results = state.get("analysis_results", {}) or {}
    javascript_analysis = analysis_results.get("javascript_analysis", {})

    js_analysis = []
    if javascript_analysis and isinstance(javascript_analysis, dict):
        sast_findings = javascript_analysis.get("sast_findings", {})
        for findings_list in sast_findings.values():
            js_analysis.extend(findings_list)
    elif isinstance(javascript_analysis, list):
        js_analysis = javascript_analysis

    total_score = 0
    # map severity to score if risk_score not present
    severity_scores = {"CRITICAL": 10, "HIGH": 8, "ERROR": 5, "MEDIUM": 5, "WARNING": 1, "INFO": 0}

    for finding in js_analysis:
        severity = finding.get("extra", {}).get("severity", "INFO")
        total_score += severity_scores.get(severity, 0)

    return total_score


# API Endpoints


def _no_frontend_html() -> str:
    """HTML shown when frontend is not built (e.g. only API running on 8007)."""
    return """<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>ExtensionShield API</title></head>
<body style="font-family: system-ui, sans-serif; max-width: 520px; margin: 60px auto; padding: 20px;">
  <h1>ExtensionShield API is running</h1>
  <p>You're on the <strong>API server</strong> (port 8007). The web app is not built here.</p>
  <ul>
    <li><strong>To use the app with latest changes:</strong> Run <code>make frontend</code> in another terminal, then open <a href="http://localhost:5173">http://localhost:5173</a>.</li>
    <li><strong>To serve the app from this port:</strong> Run <code>make build-and-serve</code> once (builds frontend and copies to static), then restart the API.</li>
  </ul>
  <p><a href="/docs">API docs</a> &middot; <a href="/health">Health</a></p>
</body>
</html>"""


@app.get("/")
async def root():
    """Root endpoint - serves frontend or API info."""
    # Serve frontend if available
    index_file = STATIC_DIR / "index.html"
    if STATIC_DIR.exists() and index_file.exists():
        return FileResponse(index_file)
    # Otherwise return helpful HTML (development mode)
    return HTMLResponse(_no_frontend_html())


@app.get("/robots.txt")
async def robots_txt(request: Request):
    """
    Dynamic robots.txt that varies by domain.
    
    - extensionshield.com: Allow all, point to sitemap
    - extensionscanner.com: Disallow all (redirect domain)
    - Note: extensionaudit.com will be added in the future
    """
    host = request.headers.get("host", "").lower()
    canonical_domain = "extensionshield.com"
    # Note: extensionaudit.com will be added in the future
    non_canonical_domains = ["extensionscanner.com"]
    
    # Check if this is a non-canonical domain
    if any(host.startswith(domain) for domain in non_canonical_domains):
        # Disallow all for non-canonical domains
        robots_content = """User-agent: *
Disallow: /
"""
    else:
        # Allow all for canonical domain
        robots_content = """User-agent: *
Allow: /

# Sitemap
Sitemap: https://extensionshield.com/sitemap.xml

# Disallow admin/internal routes
Disallow: /settings
Disallow: /reports
"""
    
    return Response(content=robots_content, media_type="text/plain")


@app.get("/api/limits/deep-scan")
async def get_deep_scan_limit(http_request: Request):
    """Return daily deep-scan usage status for the current user (placeholder)."""
    user_id = _get_user_id(http_request)
    return _deep_scan_limit_status(user_id)


@app.post("/api/enterprise/pilot-request")
async def create_enterprise_pilot_request(request: EnterprisePilotRequest, http_request: Request):
    """Capture an Enterprise pilot request (placeholder, no outbound email)."""
    user_id = _get_user_id(http_request)
    now = datetime.now(timezone.utc).isoformat()
    item = {
        "received_at": now,
        "user_id": user_id,
        "name": request.name.strip(),
        "email": request.email.strip(),
        "company": request.company.strip(),
        "notes": (request.notes or "").strip() or None,
    }
    enterprise_pilot_requests.append(item)
    return {"ok": True, "received_at": now}


@app.post("/api/scan/trigger")
@_rate_limit("5/minute")
async def trigger_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks, request: Request):
    """
    Trigger a new extension scan.

    Args:
        request: Scan request containing the extension URL
        background_tasks: FastAPI background tasks

    Returns:
        Scan trigger confirmation with extension ID
    """
    url = scan_request.url
    extension_id = extract_extension_id(url)

    if not extension_id:
        raise HTTPException(status_code=400, detail="Invalid Chrome Web Store URL")

    # If we already have results, treat this as a cached lookup (no deep-scan consumption)
    if _has_cached_results(extension_id):
        # Record user history even for cached lookups (if authenticated)
        user_id = getattr(getattr(request, "state", None), "user_id", None)
        if user_id:
            try:
                db.add_user_scan_history(user_id=user_id, extension_id=extension_id)
            except Exception:
                pass
        scan_status[extension_id] = "completed"
        return {
            "message": "Cached results available",
            "extension_id": extension_id,
            "status": "completed",
            "already_scanned": True,
            "scan_type": "lookup",
        }

    # Check if already scanning
    if extension_id in scan_status and scan_status[extension_id] == "running":
        return {
            "message": "Scan already in progress",
            "extension_id": extension_id,
            "status": "running",
        }

    # Get user ID for rate limiting and consumption tracking
    user_id = _get_user_id(request)
    
    # Enforce authentication for deep scans in production
    # This prevents abuse of VirusTotal API quota by anonymous users
    settings = get_settings()
    authenticated_user_id = getattr(getattr(request, "state", None), "user_id", None)
    if settings.is_prod() and not authenticated_user_id:
        raise HTTPException(
            status_code=401,
            detail={
                "error_code": "AUTH_REQUIRED",
                "message": "Authentication required to scan new extensions. Sign in to continue. You can view existing reports on the /scan page without signing in.",
            },
        )
    
    # Enforce daily deep-scan limit - skip in development
    if settings.is_prod():
        limit_status = _deep_scan_limit_status(user_id)
        if limit_status["remaining"] <= 0:
            raise HTTPException(
                status_code=429,
                detail={
                    "error_code": "DAILY_DEEP_SCAN_LIMIT",
                    "message": "Daily deep-scan limit reached. Cached lookups are still unlimited.",
                    **limit_status,
                },
            )

    # Consume one deep scan since we are starting a new analysis run
    after_consume = _consume_deep_scan(user_id)

    # Start background analysis
    scan_user_ids[extension_id] = getattr(getattr(request, "state", None), "user_id", None)
    background_tasks.add_task(run_analysis_workflow, url, extension_id)

    return {
        "message": "Scan triggered successfully",
        "extension_id": extension_id,
        "status": "running",
        "already_scanned": False,
        "scan_type": "deep_scan",
        "deep_scan_limit": after_consume,
    }


@app.post("/api/scan/upload")
@_rate_limit("10/minute")
async def upload_and_scan(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...)
):
    """
    Upload a CRX/ZIP file and trigger analysis.

    Args:
        file: Uploaded CRX or ZIP file
        background_tasks: FastAPI background tasks

    Returns:
        Scan trigger confirmation with extension ID
    """
    # Validate file extension
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")
    
    # Sanitize filename to prevent path traversal attacks
    import os
    safe_filename = os.path.basename(file.filename)  # Remove any path components
    # Remove any remaining dangerous characters
    safe_filename = "".join(c for c in safe_filename if c.isalnum() or c in "._-")
    if not safe_filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    
    filename_lower = safe_filename.lower()
    if not (filename_lower.endswith('.crx') or filename_lower.endswith('.zip')):
        raise HTTPException(
            status_code=400,
            detail="Invalid file type. Only .crx and .zip files are supported"
        )

    # Validate file size (max 100MB)
    max_size = 100 * 1024 * 1024  # 100MB
    file_content = await file.read()
    if len(file_content) > max_size:
        raise HTTPException(
            status_code=400,
            detail=f"File too large. Maximum size is {max_size / (1024*1024):.0f}MB"
        )

    # Validate MIME type (additional security check)
    import mimetypes
    detected_mime, _ = mimetypes.guess_type(safe_filename)
    # Check content magic bytes for CRX (Chrome Extension) or ZIP
    is_crx = file_content[:4] == b'Cr24'  # CRX v3 magic bytes
    is_zip = file_content[:2] == b'PK'  # ZIP magic bytes
    
    if not (is_crx or is_zip):
        raise HTTPException(
            status_code=400,
            detail="Invalid file content. File does not appear to be a valid CRX or ZIP file"
        )

    # Generate unique ID for uploaded file
    import uuid
    extension_id = str(uuid.uuid4())

    # Enforce authentication for file uploads in production
    # File uploads are always deep scans and consume VirusTotal API quota
    settings = get_settings()
    authenticated_user_id = getattr(getattr(request, "state", None), "user_id", None)
    if settings.is_prod() and not authenticated_user_id:
        raise HTTPException(
            status_code=401,
            detail={
                "error_code": "AUTH_REQUIRED",
                "message": "Authentication required to scan extensions. Sign in to continue. You can view existing reports on the /scan page without signing in.",
            },
        )

    # Enforce daily deep-scan limit (uploads are always deep scans) - skip in development
    user_id = _get_user_id(request)
    if settings.is_prod():
        limit_status = _deep_scan_limit_status(user_id)
        if limit_status["remaining"] <= 0:
            raise HTTPException(
                status_code=429,
                detail={
                    "error_code": "DAILY_DEEP_SCAN_LIMIT",
                    "message": "Daily deep-scan limit reached. Cached lookups are still unlimited.",
                    **limit_status,
                },
            )
    after_consume = _consume_deep_scan(user_id)

    # Save uploaded file to extensions_storage (use sanitized filename)
    file_path = RESULTS_DIR / f"{extension_id}_{safe_filename}"

    try:
        with open(file_path, "wb") as buffer:
            buffer.write(file_content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save file: {str(e)}")

    # Start background analysis with local file path
    scan_user_ids[extension_id] = getattr(getattr(request, "state", None), "user_id", None)
    background_tasks.add_task(run_analysis_workflow, str(file_path), extension_id)

    return {
        "message": "File uploaded and scan triggered successfully",
        "extension_id": extension_id,
        "filename": file.filename,
        "status": "running",
        "already_scanned": False,
        "scan_type": "deep_scan",
        "deep_scan_limit": after_consume,
    }


@app.get("/api/scan/status/{extension_id}")
async def get_scan_status(extension_id: str) -> ScanStatusResponse:
    """
    Get the status of a scan.

    Args:
        extension_id: Chrome extension ID

    Returns:
        Scan status information
    """
    status = scan_status.get(extension_id)

    if not status:
        return ScanStatusResponse(scanned=False)

    # Safely extract error and error_code to avoid circular reference issues
    # Only extract simple types (str, int, None) to prevent serialization problems
    error = None
    error_code = None
    
    try:
        result = scan_results.get(extension_id, {})
    except Exception as e:
        logger.warning(f"[get_scan_status] Failed to access scan_results for {extension_id}: {e}")
        result = {}
    
    try:
        error_val = result.get("error")
        # Ensure error is a string or None, not a complex object
        if error_val is not None:
            if isinstance(error_val, str):
                error = error_val
            else:
                # Convert to string if it's not already
                error = str(error_val)
    except Exception as e:
        # If there's any issue accessing error (e.g., circular reference), set to None
        logger.warning(f"[get_scan_status] Failed to extract error for {extension_id}: {e}")
        error = None
    
    try:
        error_code_val = result.get("error_code")
        # Ensure error_code is an int or None
        if error_code_val is not None:
            if isinstance(error_code_val, int):
                error_code = error_code_val
            elif isinstance(error_code_val, (str, float)):
                # Try to convert to int if possible
                try:
                    error_code = int(error_code_val)
                except (ValueError, TypeError):
                    error_code = None
    except Exception as e:
        # If there's any issue accessing error_code, set to None
        logger.warning(f"[get_scan_status] Failed to extract error_code for {extension_id}: {e}")
        error_code = None

    return ScanStatusResponse(
        scanned=status == "completed",
        status=status,
        extension_id=extension_id,
        error=error,
        error_code=error_code,
    )


@app.get("/api/scan/results/{extension_id}")
async def get_scan_results(extension_id: str, http_request: Request):
    """
    Get the results of a completed scan.

    Args:
        extension_id: Chrome extension ID

    Returns:
        Complete scan results
    """
    logger.info("[DEBUG get_scan_results] extension_id=%s", extension_id)
    
    # Authorization: logged-in users may view any completed scan.
    # Only block if an *in-progress* scan belongs to a *different* user.
    user_id = getattr(getattr(http_request, "state", None), "user_id", None)
    if user_id:
        scan_owner = scan_user_ids.get(extension_id)
        if scan_owner and scan_owner != user_id:
            raise HTTPException(status_code=403, detail="Access denied")
    
    # Try memory first
    if extension_id in scan_results:
        logger.info("[DEBUG get_scan_results] Using memory cache path")
        payload = scan_results[extension_id]
        # Upgrade legacy payload and ensure consumer_insights
        payload = _upgrade_legacy_payload(payload, extension_id)
        payload = _ensure_consumer_insights(payload)
        # Add risk and signals mapping
        payload["risk_and_signals"] = _extract_risk_and_signals(payload)
        scan_results[extension_id] = payload
        _log_get_scan_results_return_shape("memory", payload)
        return payload

    # Try loading from database
    logger.info("[DEBUG get_scan_results] Trying database path")
    results = db.get_scan_result(extension_id)
    if results:
        logger.info("[DEBUG get_scan_results] Database row exists: %s", bool(results))
        # Ensure consistent field naming for frontend
        formatted_results: Dict[str, Any] = {
            "extension_id": results.get("extension_id"),
            "extension_name": results.get("extension_name"),
            "url": results.get("url"),
            "timestamp": results.get("timestamp"),
            "status": results.get("status"),
            "metadata": results.get("metadata", {}),
            "manifest": results.get("manifest", {}),
            "permissions_analysis": results.get("permissions_analysis", {}),
            "sast_results": results.get("sast_results", {}),
            "webstore_analysis": results.get("webstore_analysis", {}),
            "summary": results.get("summary", {}),
            "impact_analysis": results.get("impact_analysis", {}),
            "privacy_compliance": results.get("privacy_compliance", {}),
            "extracted_path": results.get("extracted_path"),
            "icon_path": results.get("icon_path"),
            "icon_base64": results.get("icon_base64"),
            "icon_media_type": results.get("icon_media_type"),
            "extracted_files": results.get("extracted_files", []),
            "overall_security_score": results.get("security_score", 0),
            "total_findings": results.get("total_findings", 0),
            "risk_distribution": {
                "high": results.get("high_risk_count", 0),
                "medium": results.get("medium_risk_count", 0),
                "low": results.get("low_risk_count", 0),
            },
            "overall_risk": results.get("risk_level", "unknown"),
            "total_risk_score": results.get("total_findings", 0),
        }
        # Extract signal/risk fields: DB stores scoring_v2, report_view_model, governance_bundle in summary JSON
        summary = results.get("summary") or {}
        summary = summary if isinstance(summary, dict) else {}
        formatted_results["report_view_model"] = results.get("report_view_model") or summary.get("report_view_model")
        formatted_results["scoring_v2"] = results.get("scoring_v2") or summary.get("scoring_v2")
        formatted_results["governance_bundle"] = results.get("governance_bundle") or summary.get("governance_bundle")

        # Upgrade legacy payload and ensure consumer_insights
        payload = _upgrade_legacy_payload(formatted_results, extension_id)
        payload = _ensure_consumer_insights(payload)
        # Add risk and signals mapping
        payload["risk_and_signals"] = _extract_risk_and_signals(payload)
        scan_results[extension_id] = payload  # Cache in memory
        _log_get_scan_results_return_shape("db", payload)
        return payload
    else:
        logger.warning("[DEBUG get_scan_results] Database row does NOT exist for extension_id=%s", extension_id)

    # Try loading from file (fallback)
    logger.info("[DEBUG get_scan_results] Trying file path")
    result_file = RESULTS_DIR / f"{extension_id}_results.json"
    if result_file.exists():
        logger.info("[DEBUG get_scan_results] File exists: %s", result_file)
        try:
            with open(result_file, "r", encoding="utf-8") as f:
                payload = json.load(f)
            # Upgrade legacy payload and ensure consumer_insights
            payload = _upgrade_legacy_payload(payload, extension_id)
            payload = _ensure_consumer_insights(payload)
            # Add risk and signals mapping
            payload["risk_and_signals"] = _extract_risk_and_signals(payload)
            scan_results[extension_id] = payload  # Cache in memory
            _log_get_scan_results_return_shape("file", payload)
            return payload
        except json.JSONDecodeError as e:
            logger.error("[DEBUG get_scan_results] JSON file is corrupted for %s: %s", extension_id, str(e))
            # Delete the corrupted file
            try:
                result_file.unlink()
                logger.info("[DEBUG get_scan_results] Deleted corrupted JSON file: %s", result_file)
            except Exception as delete_err:
                logger.warning("[DEBUG get_scan_results] Failed to delete corrupted file: %s", str(delete_err))
    else:
        logger.warning("[DEBUG get_scan_results] File does NOT exist: %s", result_file)

    logger.error("[DEBUG get_scan_results] No results found in memory, DB, or file for extension_id=%s", extension_id)
    raise HTTPException(status_code=404, detail="Scan results not found")


@app.get("/api/scan/enforcement_bundle/{extension_id}")
async def get_enforcement_bundle(extension_id: str):
    """
    Get the governance enforcement bundle for an analyzed extension.
    
    This endpoint returns the complete governance decisioning data including:
    - facts: Normalized security analysis data
    - evidence_index: Chain-of-custody evidence items
    - signals: Extracted governance signals
    - store_listing: Chrome Web Store listing data
    - context: Policy evaluation context
    - rule_results: Individual rule evaluation outcomes
    - report: Final governance decision and report
    
    Args:
        extension_id: Chrome extension ID
        
    Returns:
        Complete governance enforcement bundle
    """
    # Try memory first
    results = scan_results.get(extension_id)
    
    # Try loading from database if not in memory
    if not results:
        results = db.get_scan_result(extension_id)
        if results:
            scan_results[extension_id] = results
    
    # Try loading from file (fallback)
    if not results:
        result_file = RESULTS_DIR / f"{extension_id}_results.json"
        if result_file.exists():
            with open(result_file, "r", encoding="utf-8") as f:
                results = json.load(f)
                scan_results[extension_id] = results
    
    if not results:
        raise HTTPException(status_code=404, detail="Scan results not found")
    
    # Check if governance analysis was run
    governance_bundle = results.get("governance_bundle")
    
    if governance_bundle is None:
        # Governance analysis was not run or failed
        governance_error = results.get("governance_error")
        if governance_error:
            raise HTTPException(
                status_code=500,
                detail=f"Governance analysis failed: {governance_error}"
            )
        raise HTTPException(
            status_code=404,
            detail="Governance enforcement bundle not available. Analysis may be in progress."
        )
    
    # Return the enforcement bundle with additional metadata
    return {
        "extension_id": extension_id,
        "extension_name": results.get("extension_name"),
        "verdict": results.get("governance_verdict"),
        "timestamp": results.get("timestamp"),
        "bundle": governance_bundle,
    }


@app.get("/api/scan/report/{extension_id}")
async def generate_pdf_report(extension_id: str) -> Response:
    """
    Generate a PDF security report for an analyzed extension.

    Args:
        extension_id: Chrome extension ID

    Returns:
        PDF file as downloadable response
    """
    # Get scan results
    results = scan_results.get(extension_id)

    # Try database if not in memory
    if not results:
        results = db.get_scan_result(extension_id)
        if results:
            scan_results[extension_id] = results

    # Try filesystem if not in database
    if not results:
        results_file = RESULTS_DIR / f"{extension_id}_results.json"
        if results_file.exists():
            with open(results_file, "r", encoding="utf-8") as f:
                results = json.load(f)
                scan_results[extension_id] = results

    if not results:
        raise HTTPException(status_code=404, detail="Scan results not found")

    # Generate PDF report
    try:
        report_generator = ReportGenerator()
        if not report_generator.enabled:
            raise HTTPException(
                status_code=503,
                detail="PDF generation is disabled. Install weasyprint to enable."
            )

        pdf_bytes = report_generator.generate_pdf(results)

        # Get extension name for filename
        extension_name = results.get("extension_name", results.get("metadata", {}).get("title", extension_id))
        safe_name = "".join(c for c in extension_name if c.isalnum() or c in " -_")[:50]
        filename = f"Project_Atlas_Report_{safe_name}.pdf"

        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"'
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate PDF: {str(e)}")


@app.get("/api/scan/files/{extension_id}")
async def get_file_list(extension_id: str, http_request: Request) -> FileListResponse:
    """
    Get list of files in the extracted extension.

    Args:
        extension_id: Chrome extension ID

    Returns:
        List of file paths
    """
    # Authorization: block only if in-progress scan belongs to a different user
    user_id = getattr(getattr(http_request, "state", None), "user_id", None)
    if user_id:
        scan_owner = scan_user_ids.get(extension_id)
        if scan_owner and scan_owner != user_id:
            raise HTTPException(status_code=403, detail="Access denied")
    
    results = scan_results.get(extension_id)
    if not results:
        raise HTTPException(status_code=404, detail="Extension not found")

    extracted_path = results.get("extracted_path")
    if not extracted_path or not os.path.exists(extracted_path):
        raise HTTPException(status_code=404, detail="Extracted files not found")

    files = get_extracted_files(extracted_path)
    return FileListResponse(files=files)


@app.get("/api/scan/file/{extension_id}/{file_path:path}")
async def get_file_content(extension_id: str, file_path: str, http_request: Request) -> FileContentResponse:
    """
    Get content of a specific file from the extracted extension.

    Args:
        extension_id: Chrome extension ID
        file_path: Relative path to the file

    Returns:
        File content
    """
    # Authorization: block only if in-progress scan belongs to a different user
    user_id = getattr(getattr(http_request, "state", None), "user_id", None)
    if user_id:
        scan_owner = scan_user_ids.get(extension_id)
        if scan_owner and scan_owner != user_id:
            raise HTTPException(status_code=403, detail="Access denied")
    
    results = scan_results.get(extension_id)
    if not results:
        raise HTTPException(status_code=404, detail="Extension not found")

    extracted_path = results.get("extracted_path")
    if not extracted_path:
        raise HTTPException(status_code=404, detail="Extracted files not found")

    # Construct full file path
    full_path = os.path.join(extracted_path, file_path)

    # Security check: ensure path is within extracted directory
    if not os.path.abspath(full_path).startswith(os.path.abspath(extracted_path)):
        raise HTTPException(status_code=403, detail="Access denied")

    if not os.path.exists(full_path):
        raise HTTPException(status_code=404, detail="File not found")

    try:
        with open(full_path, "r", encoding="utf-8") as f:
            content = f.read()
        return FileContentResponse(content=content, file_path=file_path)
    except UnicodeDecodeError as exc:
        # Binary file
        raise HTTPException(status_code=400, detail="Cannot read binary file") from exc
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading file: {str(e)}") from e


@app.get("/api/statistics")
async def get_statistics():
    """
    Get aggregated statistics.

    Returns:
        Statistics including total scans, high risk count, etc.
    """
    stats = db.get_statistics()
    risk_dist = db.get_risk_distribution()

    return {
        "total_scans": stats.get("total_scans", 0),
        "high_risk_extensions": stats.get("high_risk_extensions", 0),
        "total_files_analyzed": stats.get("total_files_analyzed", 0),
        "total_vulnerabilities": stats.get("total_vulnerabilities", 0),
        "avg_security_score": stats.get("avg_security_score", 0),
        "risk_distribution": risk_dist,
    }

@app.post("/api/telemetry/pageview")
async def track_pageview(event: PageViewEvent):
    """
    Privacy-first pageview counter.

    - No IP storage
    - No user identifier
    - Server computes day in UTC
    - Supports Postgres (Supabase) and SQLite dev fallback
    """
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    path = (event.path or "/").strip()
    try:
        count = db.increment_page_view(day=day, path=path)
    except AttributeError:
        # If backend doesn't support telemetry methods, fail open (do not break the UI).
        count = 0
    return {"day": day, "path": path if path.startswith("/") else f"/{path}", "count": count}


@app.get("/api/telemetry/summary")
async def telemetry_summary(days: int = 14):
    """
    Aggregate telemetry summary (open endpoint for now; intended for admin later).
    """
    try:
        return db.get_page_view_summary(days=days)
    except AttributeError:
        return {"days": days, "start_day": None, "end_day": None, "by_day": {}, "by_path": {}, "rows": []}


@app.get("/api/history")
async def get_history(http_request: Request, limit: int = 50):
    """
    Get scan history.

    Args:
        limit: Maximum number of results to return

    Returns:
        List of scan history items
    """
    user_id = getattr(getattr(http_request, "state", None), "user_id", None)
    if not user_id:
        # When using Supabase (staging or prod), require auth. SQLite fallback allows global history for dev testing.
        if isinstance(db, SupabaseDatabase):
            raise HTTPException(status_code=401, detail="Sign in to view history")
        history = db.get_scan_history(limit=limit)
        return {"history": history, "total": len(history)}

    history = db.get_user_scan_history(user_id=user_id, limit=limit)
    return {"history": history, "total": len(history)}


@app.get("/api/user/karma")
async def get_user_karma(http_request: Request):
    """
    Get user's karma points and scan statistics.
    
    Returns:
        User karma points, total scans, and timestamps
    """
    user_id = getattr(getattr(http_request, "state", None), "user_id", None)
    if not user_id:
        raise HTTPException(status_code=401, detail="Sign in to view karma")
    
    if not isinstance(db, SupabaseDatabase):
        # SQLite fallback doesn't have karma tracking (Postgres only)
        return {"karma_points": 0, "total_scans": 0, "created_at": None, "updated_at": None}
    
    karma = db.get_user_karma(user_id=user_id)
    return karma


@app.get("/api/recent")
async def get_recent_scans(limit: int = 10, search: str = None):
    """
    Get recent scans with summary info including risk and signals mapping.

    Args:
        limit: Maximum number of results to return
        search: Optional filter by extension name or ID (case-insensitive, Postgres/SQLite)

    Returns:
        List of recent scans with risk_and_signals mapping; db_backend for verification (supabase|sqlite).
    """
    db_backend = "supabase" if isinstance(db, SupabaseDatabase) else "sqlite"
    try:
        logger.info(f"[get_recent_scans] Fetching {limit} recent scans, search={search}")
        recent = db.get_recent_scans(limit=limit, search=search)
        logger.info(f"[get_recent_scans] Retrieved {len(recent)} scans from database")

        if len(recent) == 0:
            logger.warning("[get_recent_scans] No scans found in database - checking if any scans exist with different status")
            # Diagnostic: Check if scans exist but with wrong status
            try:
                if hasattr(db, 'get_connection'):
                    # SQLite path
                    with db.get_connection() as conn:
                        cursor = conn.cursor()
                        cursor.execute("SELECT COUNT(*) as total, status, COUNT(*) as count FROM scan_results GROUP BY status")
                        status_counts = cursor.fetchall()
                        logger.info(f"[get_recent_scans] Diagnostic - Status counts: {status_counts}")
            except Exception as diag_error:
                logger.warning(f"[get_recent_scans] Diagnostic check failed: {diag_error}")

        # Add risk_and_signals mapping to each scan.
        # If legacy recent rows are missing layer scores, backfill from full scan result dynamically.
        for scan in recent:
            try:
                mapping = _extract_risk_and_signals(scan)
                signals = mapping.get("signals", {})
                missing_layers = any(k not in signals for k in ("security", "privacy", "gov"))

                if missing_layers:
                    extension_id = scan.get("extension_id")
                    if extension_id:
                        try:
                            full_scan = db.get_scan_result(extension_id)
                        except Exception as e:
                            logger.warning(f"[get_recent_scans] Failed to fetch full scan for {extension_id}: {e}")
                            full_scan = None
                        if isinstance(full_scan, dict):
                            backfilled = _extract_risk_and_signals(full_scan)
                            if len(backfilled.get("signals", {})) > len(signals):
                                mapping = backfilled
                            # Expose scoring_v2 on recent rows when available to keep frontend consistent.
                            if isinstance(full_scan.get("scoring_v2"), dict):
                                scan["scoring_v2"] = full_scan.get("scoring_v2")

                scan["risk_and_signals"] = mapping
            except Exception as e:
                logger.error(f"[get_recent_scans] Error processing scan {scan.get('extension_id')}: {e}")
                # Continue processing other scans even if one fails
                scan["risk_and_signals"] = {"risk": 0, "signals": {}}

        logger.info(f"[get_recent_scans] Returning {len(recent)} enriched scans")
        return {"recent": recent, "db_backend": db_backend}
    except Exception as e:
        logger.error(f"[get_recent_scans] Error fetching recent scans: {e}", exc_info=True)
        return {"recent": [], "db_backend": db_backend}


@app.get("/api/diagnostic/scans")
async def diagnostic_scans():
    """
    Diagnostic endpoint to check scan data flow.
    Returns information about scans in memory, database, and their status.
    Useful for debugging why scans aren't appearing in the UI.
    """
    try:
        diagnostic_info = {
            "memory_scans": {
                "count": len(scan_results),
                "extension_ids": list(scan_results.keys())[:10],  # First 10
                "statuses": {}
            },
            "database_scans": {
                "total_count": 0,
                "completed_count": 0,
                "failed_count": 0,
                "other_statuses": {},
                "sample_extension_ids": []
            },
            "recent_endpoint_test": {
                "limit_10": 0,
                "limit_25": 0
            },
            "errors": []
        }
        
        # Check memory scans
        for ext_id, status in scan_status.items():
            diagnostic_info["memory_scans"]["statuses"][ext_id] = status
        
        # Check database scans
        try:
            # Get total count and status breakdown
            if hasattr(db, 'get_connection'):
                # SQLite path
                with db.get_connection() as conn:
                    cursor = conn.cursor()
                    # Total count
                    cursor.execute("SELECT COUNT(*) FROM scan_results")
                    diagnostic_info["database_scans"]["total_count"] = cursor.fetchone()[0]
                    
                    # Status breakdown
                    cursor.execute("SELECT status, COUNT(*) as count FROM scan_results GROUP BY status")
                    for row in cursor.fetchall():
                        status_val = row[0] if row[0] else "NULL"
                        count = row[1]
                        if status_val == "completed":
                            diagnostic_info["database_scans"]["completed_count"] = count
                        elif status_val == "failed":
                            diagnostic_info["database_scans"]["failed_count"] = count
                        else:
                            diagnostic_info["database_scans"]["other_statuses"][status_val] = count
                    
                    # Sample extension IDs
                    cursor.execute("SELECT extension_id FROM scan_results WHERE status = 'completed' ORDER BY timestamp DESC LIMIT 5")
                    diagnostic_info["database_scans"]["sample_extension_ids"] = [row[0] for row in cursor.fetchall()]
            else:
                # Supabase path
                try:
                    resp = db.client.table(db.table_scan_results).select("extension_id, status", count="exact").limit(1000).execute()
                    total = getattr(resp, "count", len(resp.data or []))
                    diagnostic_info["database_scans"]["total_count"] = total
                    
                    # Count by status
                    status_counts = {}
                    for row in (resp.data or []):
                        status = row.get("status", "NULL")
                        status_counts[status] = status_counts.get(status, 0) + 1
                    
                    diagnostic_info["database_scans"]["completed_count"] = status_counts.get("completed", 0)
                    diagnostic_info["database_scans"]["failed_count"] = status_counts.get("failed", 0)
                    for status, count in status_counts.items():
                        if status not in ["completed", "failed"]:
                            diagnostic_info["database_scans"]["other_statuses"][status] = count
                    
                    # Sample extension IDs
                    completed_resp = db.client.table(db.table_scan_results).select("extension_id").eq("status", "completed").order("scanned_at", desc=True).limit(5).execute()
                    diagnostic_info["database_scans"]["sample_extension_ids"] = [row.get("extension_id") for row in (completed_resp.data or [])]
                except Exception as supabase_error:
                    diagnostic_info["errors"].append(f"Supabase query error: {str(supabase_error)}")
        except Exception as db_error:
            diagnostic_info["errors"].append(f"Database query error: {str(db_error)}")
        
        # Test recent endpoint
        try:
            recent_10 = db.get_recent_scans(limit=10)
            diagnostic_info["recent_endpoint_test"]["limit_10"] = len(recent_10)
            
            recent_25 = db.get_recent_scans(limit=25)
            diagnostic_info["recent_endpoint_test"]["limit_25"] = len(recent_25)
        except Exception as recent_error:
            diagnostic_info["errors"].append(f"Recent scans query error: {str(recent_error)}")
        
        return diagnostic_info
    except Exception as e:
        logger.error(f"[diagnostic_scans] Error: {e}", exc_info=True)
        return {"error": str(e)}


@app.delete("/api/scan/{extension_id}")
async def delete_scan(extension_id: str):
    """
    Delete a scan result.

    Args:
        extension_id: Chrome extension ID

    Returns:
        Deletion confirmation
    """
    success = db.delete_scan_result(extension_id)

    if success:
        # Remove from memory cache
        scan_results.pop(extension_id, None)
        scan_status.pop(extension_id, None)

        return {"message": "Scan deleted successfully", "extension_id": extension_id}

    raise HTTPException(status_code=404, detail="Scan not found")


@app.post("/api/clear")
async def clear_all_scans():
    """
    Clear all scan results.

    Returns:
        Confirmation message
    """
    success = db.clear_all_results()

    if success:
        scan_results.clear()
        scan_status.clear()
        return {"message": "All scans cleared successfully"}

    raise HTTPException(status_code=500, detail="Failed to clear scans")


@app.get("/health")
async def health_check():
    """Health check endpoint for container orchestration."""
    return {
        "status": "healthy", 
        "service": "project-atlas", 
        "version": "1.0.0",
        "storage_path": str(RESULTS_DIR),
        "storage_exists": RESULTS_DIR.exists()
    }


@app.get("/api/health/db")
async def database_health_check(request: Request):
    """
    Production-safe database health check endpoint (admin-protected).
    
    Returns backend type, table status, write capability, table counts, function verification,
    and migration completeness checks.
    Useful for verifying Supabase is properly configured in production.
    
    Requires: X-Admin-Key header matching ADMIN_API_KEY
    
    Verifies:
    - Backend type (supabase/sqlite)
    - Required tables exist (scan_results, user_scan_history, page_views_daily)
    - increment_page_view function exists (Supabase only)
    - Table row counts
    - Write capability (tested via safe operations)
    - Migration completeness:
      * statistics table existence + row count
      * scan_results column structure (scanned_at for Supabase, timestamp for SQLite)
      * increment_page_view RPC exists and callable (Supabase only)
    
    Example response:
    {
        "backend": "supabase",
        "tables_ok": true,
        "can_write": true,
        "status": "healthy",
        "tables": {
            "scan_results": {"exists": true, "count": 42},
            "user_scan_history": {"exists": true, "count": 15},
            "page_views_daily": {"exists": true, "count": 128}
        },
        "functions": {
            "increment_page_view": {"exists": true}
        },
        "migrations": {
            "statistics": {"exists": true, "count": 4},
            "scan_results_columns_ok": true,
            "page_views_rpc_ok": true
        },
        "missing_tables": []
    }
    
    Note: Does NOT expose secrets, env values, or sensitive configuration.
    """
    # Require admin key
    _require_admin_key(request)
    
    from extension_shield.api.database import Database, SupabaseDatabase
    
    backend_type = "unknown"
    tables_ok = False
    can_write = False
    missing_tables = []
    tables_info = {}
    functions_info = {}
    error_message = None
    
    try:
        # Determine backend type
        if isinstance(db, SupabaseDatabase):
            backend_type = "supabase"
            
            # Check tables via information_schema query (preferred) or safe probe
            required_tables = ["scan_results", "user_scan_history", "page_views_daily"]
            existing_tables = []
            
            # Try to use information_schema query via RPC if available, otherwise use safe probes
            try:
                # Attempt to query information_schema via raw SQL (if Supabase supports it)
                # Fallback to safe table probes if not available
                for table_name in required_tables:
                    try:
                        # Safe probe: select count limit 1 (doesn't expose data)
                        resp = db.client.table(table_name).select("*", count="exact").limit(1).execute()
                        existing_tables.append(table_name)
                        
                        # Get row count (Supabase returns count in response)
                        count = getattr(resp, "count", None)
                        if count is None:
                            # Fallback: query with count="exact" and limit
                            count_resp = db.client.table(table_name).select("*", count="exact").limit(10000).execute()
                            count = getattr(count_resp, "count", 0)
                        
                        tables_info[table_name] = {
                            "exists": True,
                            "count": count if count is not None else 0
                        }
                    except Exception as e:
                        # Table doesn't exist or can't be accessed
                        missing_tables.append(table_name)
                        tables_info[table_name] = {
                            "exists": False,
                            "count": None
                        }
                        if not error_message:
                            error_message = str(e)[:200]  # Truncate to avoid exposing sensitive info
            except Exception as e:
                # If all table checks fail, set error
                if not error_message:
                    error_message = str(e)[:200]
            
            # Check for increment_page_view function via pg_proc query or safe RPC test
            try:
                # Try to call the function with a harmless test path and today's date
                # This will create a test row that we can optionally clean up
                today = datetime.now(timezone.utc).date().strftime("%Y-%m-%d")
                test_path = "/__healthcheck"
                
                # Call RPC to test function existence and write capability
                test_resp = db.client.rpc("increment_page_view", {
                    "p_day": today,
                    "p_path": test_path
                }).execute()
                
                # If RPC succeeds, function exists and we can write
                functions_info["increment_page_view"] = {"exists": True}
                can_write = True
                
                # Optional: Clean up test row (delete the healthcheck entry)
                try:
                    db.client.table("page_views_daily").delete().eq("day", today).eq("path", test_path).execute()
                except Exception:
                    # If cleanup fails, that's okay - the test row is harmless
                    pass
                    
            except Exception as e:
                # Function doesn't exist or can't be called
                functions_info["increment_page_view"] = {"exists": False}
                can_write = False
                if not error_message:
                    error_message = f"increment_page_view check failed: {str(e)[:100]}"
            
            # Tables are OK if at least scan_results exists (required)
            # user_scan_history is required for auth features
            # page_views_daily is optional but recommended
            if "scan_results" in existing_tables:
                tables_ok = True
                # can_write is set by function test above
            else:
                tables_ok = False
                if not error_message:
                    error_message = "Required table scan_results is missing"
                
        elif isinstance(db, Database):
            backend_type = "sqlite"
            
            # For SQLite, check if tables exist via sqlite_master
            try:
                with db.get_connection() as conn:
                    cursor = conn.cursor()
                    
                    # Check required tables
                    required_tables = ["scan_results", "user_scan_history", "page_views_daily"]
                    for table_name in required_tables:
                        cursor.execute(
                            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                            (table_name,)
                        )
                        exists = cursor.fetchone() is not None
                        
                        # Get count if table exists
                        count = None
                        if exists:
                            try:
                                cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
                                count = cursor.fetchone()[0]
                            except Exception:
                                count = None
                        
                        tables_info[table_name] = {
                            "exists": exists,
                            "count": count
                        }
                        if not exists:
                            missing_tables.append(table_name)
                    
                    tables_ok = "scan_results" in [t for t, info in tables_info.items() if info["exists"]]
                    
                    # Test write capability by incrementing page view for healthcheck
                    if tables_ok:
                        try:
                            today = datetime.now(timezone.utc).date().strftime("%Y-%m-%d")
                            test_path = "/__healthcheck"
                            # This will create or increment a test row
                            db.increment_page_view(today, test_path)
                            can_write = True
                            # Optional: Clean up test row
                            try:
                                with db.get_connection() as cleanup_conn:
                                    cleanup_cursor = cleanup_conn.cursor()
                                    cleanup_cursor.execute(
                                        "DELETE FROM page_views_daily WHERE day = ? AND path = ?",
                                        (today, test_path)
                                    )
                            except Exception:
                                pass  # Cleanup failure is okay
                        except Exception as e:
                            can_write = False
                            if not error_message:
                                error_message = f"Write test failed: {str(e)[:100]}"
                    else:
                        can_write = False
            except Exception as e:
                tables_ok = False
                can_write = False
                error_message = str(e)[:200]
        else:
            backend_type = "unknown"
                
    except Exception as e:
        # If we can't determine backend, return defaults
        backend_type = "error"
        error_message = str(e)[:200]  # Truncate to avoid exposing sensitive info
    
    # Migration verification
    migrations_info = {}
    
    try:
        if isinstance(db, SupabaseDatabase):
            # Check statistics table (migration 004)
            statistics_exists = False
            statistics_count = None
            try:
                stats_resp = db.client.table("statistics").select("*", count="exact").limit(1).execute()
                statistics_exists = True
                statistics_count = getattr(stats_resp, "count", None)
            except Exception:
                statistics_exists = False
            
            migrations_info["statistics"] = {
                "exists": statistics_exists,
                "count": statistics_count if statistics_count is not None else None
            }
            
            # Verify scan_results columns (especially scanned_at)
            scan_results_columns_ok = False
            # Check if scan_results table exists (from tables_info)
            if tables_info.get("scan_results", {}).get("exists", False):
                try:
                    # Try to query scanned_at column (should exist after migration 001b)
                    test_resp = db.client.table(db.table_scan_results).select("scanned_at").limit(1).execute()
                    scan_results_columns_ok = True
                except Exception:
                    # Column might not exist or table structure is wrong
                    scan_results_columns_ok = False
            else:
                scan_results_columns_ok = False
            
            migrations_info["scan_results_columns_ok"] = scan_results_columns_ok
            
            # Verify RPC increment_page_view exists AND callable
            page_views_rpc_ok = functions_info.get("increment_page_view", {}).get("exists", False)
            migrations_info["page_views_rpc_ok"] = page_views_rpc_ok
            
        elif isinstance(db, Database):
            # For SQLite, check statistics table
            statistics_exists = False
            statistics_count = None
            try:
                with db.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name='statistics'"
                    )
                    statistics_exists = cursor.fetchone() is not None
                    
                    if statistics_exists:
                        cursor.execute("SELECT COUNT(*) FROM statistics")
                        statistics_count = cursor.fetchone()[0]
            except Exception:
                statistics_exists = False
            
            migrations_info["statistics"] = {
                "exists": statistics_exists,
                "count": statistics_count
            }
            
            # Verify scan_results columns (timestamp in SQLite, not scanned_at)
            scan_results_columns_ok = False
            if tables_info.get("scan_results", {}).get("exists", False):
                try:
                    with db.get_connection() as conn:
                        cursor = conn.cursor()
                        # Check if timestamp column exists (SQLite uses timestamp, not scanned_at)
                        cursor.execute("PRAGMA table_info(scan_results)")
                        columns = [row[1] for row in cursor.fetchall()]
                        scan_results_columns_ok = "timestamp" in columns
                except Exception:
                    scan_results_columns_ok = False
            else:
                scan_results_columns_ok = False
            
            migrations_info["scan_results_columns_ok"] = scan_results_columns_ok
            
            # SQLite doesn't use RPC functions
            migrations_info["page_views_rpc_ok"] = None
    except Exception as e:
        # If migration checks fail, mark as unknown
        if not error_message:
            error_message = f"Migration check failed: {str(e)[:100]}"
    
    response = {
        "backend": backend_type,
        "tables_ok": tables_ok,
        "can_write": can_write,
        "status": "healthy" if (tables_ok and can_write) else "degraded",
        "tables": tables_info,
        "migrations": migrations_info,
    }
    
    # Add functions info for Supabase
    if backend_type == "supabase" and functions_info:
        response["functions"] = functions_info
    
    # Add diagnostic info if degraded
    if not tables_ok or missing_tables:
        response["missing_tables"] = missing_tables
        if error_message:
            # Only include first line of error to avoid exposing sensitive info
            response["error"] = error_message.split("\n")[0][:200]
    
    return response


@app.get("/api/scan/icon/{extension_id}")
async def get_extension_icon(extension_id: str):
    """
    Get extension icon from the extracted extension folder.
    Uses icon_path from storage when available, and falls back to persisted icon bytes.
    
    Args:
        extension_id: Chrome extension ID
        
    Returns:
        Icon image response (PNG/JPEG/WEBP/SVG)
    """
    logger.debug(f"[ICON] Request for extension_id={extension_id}")
    # Check if scan is completed first
    results = scan_results.get(extension_id)
    extracted_path = None
    icon_path = None
    icon_base64 = None
    icon_media_type = None
    
    if results:
        extracted_path = results.get("extracted_path")
        icon_path = results.get("icon_path")  # Use stored icon_path from database
        icon_base64 = results.get("icon_base64")
        icon_media_type = results.get("icon_media_type")
    else:
        db_icon_record = _load_icon_record_from_db(extension_id)
        extracted_path = db_icon_record.get("extracted_path")
        icon_path = db_icon_record.get("icon_path")
        icon_base64 = db_icon_record.get("icon_base64")
        icon_media_type = db_icon_record.get("icon_media_type")
        if icon_path:
            logger.debug("Loaded icon_path from database: %s", icon_path)
        
        # Scan might still be running - try to find extracted extension in storage
        # Check if extension is being scanned
        status = scan_status.get(extension_id)
        if status in ("running", "pending"):
            # Try to find the extracted extension in the storage directory
            # Extensions are stored as extracted_{filename}_{pid}, so we need to search
            settings = get_settings()
            storage_path = Path(settings.extension_storage_path)
            
            # Search for extracted directories that might contain this extension
            if storage_path.exists():
                try:
                    # Look for directories starting with "extracted_"
                    for item in storage_path.iterdir():
                        if item.is_dir() and item.name.startswith("extracted_"):
                            manifest_path = item / "manifest.json"
                            if manifest_path.exists():
                                # Check if manifest has matching extension_id
                                try:
                                    with open(manifest_path, "r", encoding="utf-8") as f:
                                        manifest = json.load(f)
                                        # Check manifest key (MV2) or extension_id from metadata
                                        manifest_id = manifest.get("key") or manifest.get("extension_id")
                                        # Also check if extension_id matches (for MV3)
                                        if manifest_id == extension_id or extension_id in str(manifest):
                                            extracted_path = str(item)
                                            logger.debug(f"Found extracted extension during scan at: {extracted_path}")
                                            break
                                except Exception:
                                    # Skip if we can't read manifest
                                    continue
                except Exception as e:
                    logger.debug(f"Error searching for extracted extension: {e}")

    # Best practice: if we have a persisted icon blob, serve it immediately.
    # This avoids relying on filesystem state (ephemeral/persistent) and prevents slow fallbacks.
    persisted = _extension_icon_response_from_base64(icon_base64, icon_media_type)
    if persisted:
        return persisted
    
    if not extracted_path:
        # Search for extracted extension directory by extension_id in storage
        settings = get_settings()
        storage_path = Path(settings.extension_storage_path)
        
        if storage_path.exists():
            # Look for directories containing the extension_id
            for item in storage_path.iterdir():
                if item.is_dir() and extension_id in item.name and item.name.startswith("extracted_"):
                    extracted_path = str(item)
                    logger.debug(f"[ICON] Found extracted extension by ID: {extracted_path}")
                    break
    
    db_icon_checked = bool(icon_base64)

    def _persisted_icon_response() -> Optional[Response]:
        nonlocal icon_base64, icon_media_type, db_icon_checked
        response = _extension_icon_response_from_base64(icon_base64, icon_media_type)
        if response:
            return response
        if not db_icon_checked:
            db_icon_checked = True
            db_icon_record = _load_icon_record_from_db(extension_id)
            icon_base64 = db_icon_record.get("icon_base64")
            icon_media_type = db_icon_record.get("icon_media_type")
            return _extension_icon_response_from_base64(icon_base64, icon_media_type)
        return None

    if not extracted_path:
        persisted_response = _persisted_icon_response()
        if persisted_response:
            logger.debug("[ICON] Served persisted icon blob for %s", extension_id)
            return persisted_response
        # Return placeholder - expected during early scan stages or when storage is ephemeral (Railway)
        logger.debug(f"[ICON] No extracted_path for {extension_id}, returning placeholder")
        return _extension_icon_placeholder_response()
    
    # Convert to absolute path if it's relative
    # extracted_path is relative to extension_storage_path, not RESULTS_DIR
    if not os.path.isabs(extracted_path):
        settings = get_settings()
        storage_path = Path(settings.extension_storage_path)
        # If extracted_path is just a directory name, join with storage_path
        if os.path.basename(extracted_path) == extracted_path:
            extracted_path = os.path.join(str(storage_path), extracted_path)
        else:
            # Already has path components, resolve relative to storage_path
            extracted_path = os.path.join(str(storage_path), extracted_path)
    
    # Verify the path exists
    if not os.path.exists(extracted_path):
        logger.warning(f"Extracted path does not exist: {extracted_path}")
        # Try alternative: search in storage_path for matching directory
        settings = get_settings()
        storage_path = Path(settings.extension_storage_path)
        if storage_path.exists():
            # Look for directory matching the basename
            basename = os.path.basename(extracted_path)
            for item in storage_path.iterdir():
                if item.is_dir() and (item.name == basename or item.name.startswith(basename)):
                    extracted_path = str(item)
                    logger.debug(f"Found extracted extension at: {extracted_path}")
                    break
            else:
                persisted_response = _persisted_icon_response()
                if persisted_response:
                    logger.debug("[ICON] Served persisted icon blob for %s", extension_id)
                    return persisted_response
                logger.debug(f"[ICON] Extracted path not found for {extension_id}, returning placeholder")
                return _extension_icon_placeholder_response()
        else:
            persisted_response = _persisted_icon_response()
            if persisted_response:
                logger.debug("[ICON] Served persisted icon blob for %s", extension_id)
                return persisted_response
            logger.debug(f"[ICON] Storage path missing for {extension_id}, returning placeholder")
            return _extension_icon_placeholder_response()
    
    logger.debug(f"[ICON] extracted_path={extracted_path}, icon_path={icon_path}")
    
    # First, try using icon_path from database if available
    if icon_path:
        full_icon_path = os.path.join(extracted_path, icon_path)
        # Security check: ensure icon_path is within extracted_path
        abs_icon_path = os.path.abspath(full_icon_path)
        abs_extracted_path = os.path.abspath(extracted_path)
        
        logger.debug(f"[ICON] Trying stored icon_path: {full_icon_path}")
        if abs_icon_path.startswith(abs_extracted_path) and os.path.exists(full_icon_path):
            logger.info(f"[ICON] Found icon using stored icon_path: {full_icon_path}")
            return _extension_icon_file_response(full_icon_path)
        else:
            logger.warning(f"[ICON] Stored icon_path {icon_path} not found at {full_icon_path}, falling back to search")
    
    # Fallback: Try common icon sizes in order of preference
    icon_sizes = ["128", "64", "48", "32", "16", "96", "256"]
    icons_dir = os.path.join(extracted_path, "icons")
    
    # First try icons directory
    if os.path.exists(icons_dir):
        for size in icon_sizes:
            icon_path = os.path.join(icons_dir, f"{size}.png")
            if os.path.exists(icon_path):
                logger.debug(f"Found icon at: {icon_path}")
                return _extension_icon_file_response(icon_path)
    
    # Try root directory
    for size in icon_sizes:
        test_icon_path = os.path.join(extracted_path, f"icon{size}.png")
        if os.path.exists(test_icon_path):
            logger.debug(f"Found icon at: {test_icon_path}")
            return _extension_icon_file_response(test_icon_path)
        
        test_icon_path = os.path.join(extracted_path, f"{size}.png")
        if os.path.exists(test_icon_path):
            logger.debug(f"Found icon at: {test_icon_path}")
            return _extension_icon_file_response(test_icon_path)
    
    # Try images directory (common for many extensions)
    images_dir = os.path.join(extracted_path, "images")
    if os.path.exists(images_dir):
        # Look for icon files in images directory
        for icon_name in ["icon128.png", "icon.png", "icon64.png", "icon48.png", "icon32.png", "icon16.png", "logo.png"]:
            icon_path = os.path.join(images_dir, icon_name)
            if os.path.exists(icon_path):
                logger.debug(f"Found icon in images dir: {icon_path}")
                return _extension_icon_file_response(icon_path)
    
    # Try checking manifest for icon paths
    manifest_path = os.path.join(extracted_path, "manifest.json")
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest = json.load(f)
                
            # Check icons object in manifest
            manifest_icons = manifest.get("icons", {})
            if manifest_icons:
                # Get the largest icon
                largest_size = max(manifest_icons.keys(), key=lambda x: int(x))
                icon_rel_path = manifest_icons[largest_size]
                manifest_icon_path = os.path.join(extracted_path, icon_rel_path)
                
                # Security check
                abs_icon_path = os.path.abspath(manifest_icon_path)
                abs_extracted_path = os.path.abspath(extracted_path)
                
                if abs_icon_path.startswith(abs_extracted_path):
                    if os.path.exists(manifest_icon_path):
                        logger.debug(f"Found icon from manifest at: {manifest_icon_path}")
                        return _extension_icon_file_response(manifest_icon_path)
        except Exception as e:
            logger.warning(f"Failed to read manifest for icons: {e}")
    
    persisted_response = _persisted_icon_response()
    if persisted_response:
        logger.debug("[ICON] Served persisted icon blob for %s", extension_id)
        return persisted_response

    # No icon file found (path exists but no icon, or path from DB is gone - ephemeral storage)
    logger.debug(f"[ICON] No icon file for {extension_id}, returning placeholder")
    return _extension_icon_placeholder_response()


# Mount static files for React frontend assets (if static directory exists)
if STATIC_DIR.exists() and (STATIC_DIR / "assets").exists():
    app.mount("/assets", StaticFiles(directory=STATIC_DIR / "assets"), name="assets")
    # Mount root static files (vite.svg, etc.)
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Mount data files - check production first, then fallback to development
# This allows data files to be served both in production (from static/) and local dev (from frontend/public/)
data_dir = None
if STATIC_DIR.exists():
    prod_data_dir = STATIC_DIR / "data"
    if prod_data_dir.exists():
        data_dir = prod_data_dir

# Fallback to development directory if production static dir doesn't exist
if not data_dir and FRONTEND_PUBLIC_DIR.exists():
    dev_data_dir = FRONTEND_PUBLIC_DIR / "data"
    if dev_data_dir.exists():
        data_dir = dev_data_dir

if data_dir:
    app.mount("/data", StaticFiles(directory=data_dir), name="data")


# Catch-all route for SPA - must be defined last
@app.get("/{full_path:path}")
async def serve_spa(full_path: str):
    """
    Serve React SPA for all non-API routes.
    This enables client-side routing in the React app.
    """
    # Don't intercept API routes
    if full_path.startswith("api/"):
        raise HTTPException(status_code=404, detail="API endpoint not found")
    
    # Don't intercept data files (should be handled by static mount above)
    if full_path.startswith("data/"):
        raise HTTPException(status_code=404, detail="Data file not found")
    
    # Don't intercept assets (should be handled by static mount above)
    if full_path.startswith("assets/"):
        raise HTTPException(status_code=404, detail="Asset not found")
    
    # Don't intercept static files (should be handled by static mount above)
    if full_path.startswith("static/"):
        raise HTTPException(status_code=404, detail="Static file not found")

    # Check if this is a static file request (favicon, logo, manifest, etc.)
    # These files are in the root of STATIC_DIR (copied from public/ during build)
    if STATIC_DIR.exists():
        static_file = STATIC_DIR / full_path
        # Only serve actual files, not directories, and only common static file types
        if static_file.is_file() and full_path not in ("", "/"):
            # Check if it's a known static file type
            static_extensions = (".png", ".jpg", ".jpeg", ".svg", ".ico", ".json", ".txt", ".xml", ".webmanifest")
            if static_file.suffix.lower() in static_extensions or full_path in ("manifest.json", "robots.txt", "sitemap.xml"):
                return FileResponse(static_file)

    # Serve index.html for all other routes (SPA routing)
    index_file = STATIC_DIR / "index.html"
    if STATIC_DIR.exists() and index_file.exists():
        return FileResponse(index_file)

    # If no static files, return helpful HTML (development mode)
    return HTMLResponse(_no_frontend_html())


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8007)
