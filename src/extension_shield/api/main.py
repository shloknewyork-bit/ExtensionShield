"""
FastAPI Backend for Project Atlas

Provides REST API endpoints for the frontend to trigger extension analysis
and retrieve results.
"""

import os
import json
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime, timezone, timedelta

from fastapi import FastAPI, HTTPException, BackgroundTasks, Response, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import shutil

from extension_shield.core.report_generator import ReportGenerator

from extension_shield.workflow.graph import build_graph
from extension_shield.workflow.state import WorkflowState, WorkflowStatus
from extension_shield.api.database import db
from extension_shield.scoring.engine import ScoringEngine
from extension_shield.governance.tool_adapters import SignalPackBuilder
from extension_shield.core.config import get_settings


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


class FileContentResponse(BaseModel):
    """Response model for file content."""

    content: str
    file_path: str


class FileListResponse(BaseModel):
    """Response model for file list."""

    files: list[str]


# Initialize FastAPI app
app = FastAPI(
    title="Project Atlas API",
    description="REST API for Chrome extension security analysis",
    version="1.0.0",
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",  # Vite dev server (default)
        "http://localhost:5174",  # Vite fallback port
        "http://localhost:5175",  # Vite fallback port
        "http://localhost:5176",  # Vite fallback port
        "http://localhost:5177",  # Vite fallback port
        "http://localhost:3000",  # Alternative dev port
        "http://localhost:8007",  # Same-origin in container
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files directory for React frontend (in container)
STATIC_DIR = Path(__file__).parent.parent.parent.parent / "static"
# Frontend public directory for development (serves data files)
FRONTEND_PUBLIC_DIR = Path(__file__).parent.parent.parent.parent / "frontend" / "public"

# Storage for scan results (in-memory cache + database persistence)
scan_results: Dict[str, Dict[str, Any]] = {}
scan_status: Dict[str, str] = {}

# -----------------------------------------------------------------------------
# Daily deep-scan limit (placeholder, in-memory)
# -----------------------------------------------------------------------------
DAILY_DEEP_SCAN_LIMIT = 2
# deep_scan_usage[user_id][YYYY-MM-DD] = used_count
deep_scan_usage: Dict[str, Dict[str, int]] = {}


def _get_user_id(request: Request) -> str:
    """
    Best-effort user identifier.

    Frontend should send `X-User-Id` (stable per account/device). If absent,
    we fallback to IP-based identifier to keep the placeholder limit functional.
    """
    header_user = request.headers.get("x-user-id") or request.headers.get("X-User-Id")
    if header_user:
        return header_user.strip()

    host = getattr(getattr(request, "client", None), "host", None)
    if host:
        return f"anon-ip:{host}"
    return "anon"


def _deep_scan_limit_status(user_id: str) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    day_key = now.strftime("%Y-%m-%d")
    used = deep_scan_usage.get(user_id, {}).get(day_key, 0)
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


def extract_extension_id(url: str) -> Optional[str]:
    """Extract extension ID from Chrome Web Store URL."""
    import re

    match = re.search(r"/detail/(?:[^/]+/)?([a-z]{32})", url)
    return match.group(1) if match else None


async def run_analysis_workflow(url: str, extension_id: str):
    """Run the analysis workflow in the background."""
    try:
        # Update status
        scan_status[extension_id] = "running"

        # Build and run workflow
        graph = build_graph()

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
        final_state = await graph.ainvoke(initial_state)

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
            scoring_engine = ScoringEngine(weights_version="v1")
            scoring_result = scoring_engine.calculate_scores(
                signal_pack=signal_pack,
                manifest=manifest,
                user_count=user_count,
            )
            
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

            scan_results[extension_id] = {
                "extension_id": extension_id,
                "extension_name": extension_name,
                "url": url,
                "timestamp": datetime.now().isoformat(),
                "status": "completed",
                "metadata": metadata,
                "manifest": manifest,
                "permissions_analysis": analysis_results.get("permissions_analysis") or {},
                "sast_results": analysis_results.get("javascript_analysis") or {},
                "webstore_analysis": analysis_results.get("webstore_analysis") or {},
                "virustotal_analysis": analysis_results.get("virustotal_analysis") or {},
                "entropy_analysis": analysis_results.get("entropy_analysis") or {},
                "summary": final_state.get("executive_summary") or {},
                "extracted_path": final_state.get("extension_dir"),
                "extracted_files": extracted_files,
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
                # Governance data (Pipeline B: Stages 2-8)
                "governance_verdict": final_state.get("governance_verdict"),
                "governance_bundle": final_state.get("governance_bundle"),
                "governance_report": final_state.get("governance_report"),
                "governance_error": final_state.get("governance_error"),
            }
            scan_status[extension_id] = "completed"

            # Save to database
            db.save_scan_result(scan_results[extension_id])

            # Save to file (backup)
            result_file = RESULTS_DIR / f"{extension_id}_results.json"
            with open(result_file, "w", encoding="utf-8") as f:
                json.dump(scan_results[extension_id], f, indent=2)
        else:
            scan_status[extension_id] = "failed"
            scan_results[extension_id] = {
                "extension_id": extension_id,
                "url": url,
                "status": "failed",
                "error": final_state.get("error", "Unknown error"),
            }

    except Exception as e:
        scan_status[extension_id] = "failed"
        scan_results[extension_id] = {
            "extension_id": extension_id,
            "url": url,
            "status": "failed",
            "error": str(e),
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


@app.get("/")
async def root():
    """Root endpoint - serves frontend or API info."""
    # Serve frontend if available
    index_file = STATIC_DIR / "index.html"
    if STATIC_DIR.exists() and index_file.exists():
        return FileResponse(index_file)
    # Otherwise return API info (development mode)
    return {"name": "Project Atlas API", "version": "1.0.0", "status": "running"}


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
async def trigger_scan(request: ScanRequest, background_tasks: BackgroundTasks, http_request: Request):
    """
    Trigger a new extension scan.

    Args:
        request: Scan request containing the extension URL
        background_tasks: FastAPI background tasks

    Returns:
        Scan trigger confirmation with extension ID
    """
    url = request.url
    extension_id = extract_extension_id(url)

    if not extension_id:
        raise HTTPException(status_code=400, detail="Invalid Chrome Web Store URL")

    # If we already have results, treat this as a cached lookup (no deep-scan consumption)
    if _has_cached_results(extension_id):
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

    # Enforce daily deep-scan limit (placeholder)
    user_id = _get_user_id(http_request)
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
async def upload_and_scan(
    http_request: Request,
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
    
    filename_lower = file.filename.lower()
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

    # Generate unique ID for uploaded file
    import uuid
    extension_id = str(uuid.uuid4())

    # Enforce daily deep-scan limit (uploads are always deep scans)
    user_id = _get_user_id(http_request)
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

    # Save uploaded file to extensions_storage
    file_path = RESULTS_DIR / f"{extension_id}_{file.filename}"

    try:
        with open(file_path, "wb") as buffer:
            buffer.write(file_content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save file: {str(e)}")

    # Start background analysis with local file path
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

    result = scan_results.get(extension_id, {})

    return ScanStatusResponse(
        scanned=status == "completed",
        status=status,
        extension_id=extension_id,
        error=result.get("error"),
    )


@app.get("/api/scan/results/{extension_id}")
async def get_scan_results(extension_id: str):
    """
    Get the results of a completed scan.

    Args:
        extension_id: Chrome extension ID

    Returns:
        Complete scan results
    """
    # Try memory first
    if extension_id in scan_results:
        return scan_results[extension_id]

    # Try loading from database
    results = db.get_scan_result(extension_id)
    if results:
        # Ensure consistent field naming for frontend
        formatted_results = {
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
            "extracted_path": results.get("extracted_path"),
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
        scan_results[extension_id] = formatted_results  # Cache in memory
        return formatted_results

    # Try loading from file (fallback)
    result_file = RESULTS_DIR / f"{extension_id}_results.json"
    if result_file.exists():
        with open(result_file, "r", encoding="utf-8") as f:
            results = json.load(f)
            scan_results[extension_id] = results  # Cache in memory
            return results

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
async def get_file_list(extension_id: str) -> FileListResponse:
    """
    Get list of files in the extracted extension.

    Args:
        extension_id: Chrome extension ID

    Returns:
        List of file paths
    """
    results = scan_results.get(extension_id)
    if not results:
        raise HTTPException(status_code=404, detail="Extension not found")

    extracted_path = results.get("extracted_path")
    if not extracted_path or not os.path.exists(extracted_path):
        raise HTTPException(status_code=404, detail="Extracted files not found")

    files = get_extracted_files(extracted_path)
    return FileListResponse(files=files)


@app.get("/api/scan/file/{extension_id}/{file_path:path}")
async def get_file_content(extension_id: str, file_path: str) -> FileContentResponse:
    """
    Get content of a specific file from the extracted extension.

    Args:
        extension_id: Chrome extension ID
        file_path: Relative path to the file

    Returns:
        File content
    """
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


@app.get("/api/history")
async def get_history(limit: int = 50):
    """
    Get scan history.

    Args:
        limit: Maximum number of results to return

    Returns:
        List of scan history items
    """
    history = db.get_scan_history(limit=limit)
    return {"history": history, "total": len(history)}


@app.get("/api/recent")
async def get_recent_scans(limit: int = 10):
    """
    Get recent scans with summary info.

    Args:
        limit: Maximum number of results to return

    Returns:
        List of recent scans
    """
    recent = db.get_recent_scans(limit=limit)
    return {"recent": recent}


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


@app.get("/api/scan/icon/{extension_id}")
async def get_extension_icon(extension_id: str):
    """
    Get extension icon from the extracted extension folder.
    Tries common icon sizes (128, 64, 48, 32, 16) and returns the first found.
    
    Args:
        extension_id: Chrome extension ID
        
    Returns:
        PNG icon file
    """
    results = scan_results.get(extension_id)
    if not results:
        raise HTTPException(status_code=404, detail="Extension not found")
    
    extracted_path = results.get("extracted_path")
    if not extracted_path:
        raise HTTPException(status_code=404, detail="Extracted path not available")
    
    # Convert to absolute path if it's relative (for Railway deployment)
    if not os.path.isabs(extracted_path):
        extracted_path = os.path.join(str(RESULTS_DIR), os.path.basename(extracted_path))
    
    # Verify the path exists
    if not os.path.exists(extracted_path):
        logger.warning(f"Extracted path does not exist: {extracted_path}")
        raise HTTPException(status_code=404, detail="Extracted files not found")
    
    # Try common icon sizes in order of preference
    icon_sizes = ["128", "64", "48", "32", "16", "96", "256"]
    icons_dir = os.path.join(extracted_path, "icons")
    
    # First try icons directory
    if os.path.exists(icons_dir):
        for size in icon_sizes:
            icon_path = os.path.join(icons_dir, f"{size}.png")
            if os.path.exists(icon_path):
                logger.debug(f"Found icon at: {icon_path}")
                return FileResponse(
                    icon_path, 
                    media_type="image/png",
                    headers={
                        "Cache-Control": "public, max-age=86400",  # Cache for 24 hours
                        "Access-Control-Allow-Origin": "*"
                    }
                )
    
    # Try root directory
    for size in icon_sizes:
        icon_path = os.path.join(extracted_path, f"icon{size}.png")
        if os.path.exists(icon_path):
            logger.debug(f"Found icon at: {icon_path}")
            return FileResponse(
                icon_path, 
                media_type="image/png",
                headers={
                    "Cache-Control": "public, max-age=86400",
                    "Access-Control-Allow-Origin": "*"
                }
            )
        
        icon_path = os.path.join(extracted_path, f"{size}.png")
        if os.path.exists(icon_path):
            logger.debug(f"Found icon at: {icon_path}")
            return FileResponse(
                icon_path, 
                media_type="image/png",
                headers={
                    "Cache-Control": "public, max-age=86400",
                    "Access-Control-Allow-Origin": "*"
                }
            )
    
    # Try checking manifest for icon paths
    manifest_path = os.path.join(extracted_path, "manifest.json")
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest = json.load(f)
                
            # Check icons object in manifest
            icons = manifest.get("icons", {})
            if icons:
                # Get the largest icon
                largest_size = max(icons.keys(), key=lambda x: int(x))
                icon_rel_path = icons[largest_size]
                icon_path = os.path.join(extracted_path, icon_rel_path)
                
                # Security check
                abs_icon_path = os.path.abspath(icon_path)
                abs_extracted_path = os.path.abspath(extracted_path)
                
                if abs_icon_path.startswith(abs_extracted_path):
                    if os.path.exists(icon_path):
                        logger.debug(f"Found icon from manifest at: {icon_path}")
                        return FileResponse(
                            icon_path, 
                            media_type="image/png",
                            headers={
                                "Cache-Control": "public, max-age=86400",
                                "Access-Control-Allow-Origin": "*"
                            }
                        )
        except Exception as e:
            logger.warning(f"Failed to read manifest for icons: {e}")
    
    logger.warning(f"No icon found for extension {extension_id} at path: {extracted_path}")
    raise HTTPException(status_code=404, detail="No icon found for this extension")


@app.get("/api/scan/icon/{extension_id}")
async def get_extension_icon(extension_id: str):
    """
    Get extension icon from the extracted extension folder.
    Tries common icon sizes (128, 64, 48, 32, 16) and returns the first found.
    
    Args:
        extension_id: Chrome extension ID
        
    Returns:
        PNG icon file
    """
    results = scan_results.get(extension_id)
    if not results:
        raise HTTPException(status_code=404, detail="Extension not found")
    
    extracted_path = results.get("extracted_path")
    if not extracted_path or not os.path.exists(extracted_path):
        raise HTTPException(status_code=404, detail="Extracted files not found")
    
    # Try common icon sizes in order of preference
    icon_sizes = ["128", "64", "48", "32", "16", "96", "256"]
    icons_dir = os.path.join(extracted_path, "icons")
    
    # First try icons directory
    if os.path.exists(icons_dir):
        for size in icon_sizes:
            icon_path = os.path.join(icons_dir, f"{size}.png")
            if os.path.exists(icon_path):
                return FileResponse(icon_path, media_type="image/png")
    
    # Try root directory
    for size in icon_sizes:
        icon_path = os.path.join(extracted_path, f"icon{size}.png")
        if os.path.exists(icon_path):
            return FileResponse(icon_path, media_type="image/png")
        
        icon_path = os.path.join(extracted_path, f"{size}.png")
        if os.path.exists(icon_path):
            return FileResponse(icon_path, media_type="image/png")
    
    # Try checking manifest for icon paths
    manifest_path = os.path.join(extracted_path, "manifest.json")
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest = json.load(f)
                
            # Check icons object in manifest
            icons = manifest.get("icons", {})
            if icons:
                # Get the largest icon
                largest_size = max(icons.keys(), key=lambda x: int(x))
                icon_rel_path = icons[largest_size]
                icon_path = os.path.join(extracted_path, icon_rel_path)
                
                # Security check
                if os.path.abspath(icon_path).startswith(os.path.abspath(extracted_path)):
                    if os.path.exists(icon_path):
                        return FileResponse(icon_path, media_type="image/png")
        except Exception as e:
            logger.warning(f"Failed to read manifest for icons: {e}")
    
    raise HTTPException(status_code=404, detail="No icon found for this extension")


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

    # Serve index.html for all other routes (SPA routing)
    index_file = STATIC_DIR / "index.html"
    if STATIC_DIR.exists() and index_file.exists():
        return FileResponse(index_file)

    # If no static files, return API info (development mode)
    return {
        "name": "Project Atlas API",
        "version": "1.0.0",
        "docs": "/docs",
        "note": "Frontend not built. Run 'npm run build' in frontend/ directory.",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8007)
