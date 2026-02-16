"""
Helper utilities that keep FastAPI endpoints lean by handling legacy payload upgrades,
report view model construction, and logging the shape of scan results.
"""

import logging
from typing import Any, Dict, Optional

from extension_shield.core.report_view_model import (
    build_consumer_insights,
    build_report_view_model,
)
from extension_shield.governance.tool_adapters import SignalPackBuilder
from extension_shield.scoring.engine import ScoringEngine

logger = logging.getLogger(__name__)


def build_report_view_model_safe(
    manifest: Dict[str, Any],
    analysis_results: Dict[str, Any],
    metadata: Optional[Dict[str, Any]],
    extension_id: str,
    scan_id: str,
) -> Dict[str, Any]:
    """Safely build the report view model, returning an empty dict on failure."""
    try:
        return build_report_view_model(
            manifest=manifest,
            analysis_results=analysis_results,
            metadata=metadata,
            extension_id=extension_id,
            scan_id=scan_id,
        )
    except Exception as exc:
        logger.warning("Failed to build report_view_model, using empty dict: %s", exc)
        return {}


def upgrade_legacy_payload(payload: Dict[str, Any], extension_id: str) -> Dict[str, Any]:
    """
    Upgrade or recompute legacy scan payloads to include scoring_v2 and report view models.

    Args:
        payload: The legacy payload (may be missing scoring_v2 and report_view_model)
        extension_id: Extension ID used to build SignalPacks and scoring.

    Returns:
        The payload that now includes scoring_v2, report_view_model, and consumer insights.
    """
    has_scoring_v2_before = bool(
        payload.get("scoring_v2")
        or payload.get("governance_bundle", {}).get("scoring_v2")
    )
    has_report_view_model_before = bool(payload.get("report_view_model"))
    has_consumer_insights_before = bool(
        payload.get("report_view_model", {}).get("consumer_insights")
    )
    upgraded = False

    force_recompute = False
    try:
        existing_scoring = (
            payload.get("scoring_v2")
            or payload.get("governance_bundle", {}).get("scoring_v2")
            or {}
        )
        existing_version = (existing_scoring or {}).get("scoring_version")
        if isinstance(existing_version, str) and existing_version and existing_version != ScoringEngine.VERSION:
            force_recompute = True
    except Exception:
        force_recompute = False

    if (
        has_scoring_v2_before
        and has_report_view_model_before
        and has_consumer_insights_before
        and not force_recompute
    ):
        logger.info(
            "[UPGRADE] extension_id=%s, results_payload_upgraded=false, has_scoring_v2=%s→%s, has_report_view_model=%s→%s, has_consumer_insights=%s→%s",
            extension_id,
            has_scoring_v2_before,
            has_scoring_v2_before,
            has_report_view_model_before,
            has_report_view_model_before,
            has_consumer_insights_before,
            has_consumer_insights_before,
        )
        return payload

    logger.info(
        "[UPGRADE] Upgrading legacy payload for extension_id=%s (has_scoring_v2=%s, has_report_view_model=%s)",
        extension_id,
        has_scoring_v2_before,
        has_report_view_model_before,
    )

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

        if (not has_scoring_v2_before) or force_recompute:
            user_count = (
                metadata.get("user_count")
                or metadata.get("users")
                or signal_pack.webstore_stats.installs
            )
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

            payload["scoring_v2"] = scoring_v2_payload
            logger.info(
                "[UPGRADE] Built scoring_v2 for extension_id=%s (force=%s)",
                extension_id,
                force_recompute,
            )
            upgraded = True

        if (not has_report_view_model_before) or force_recompute:
            report_view_model = build_report_view_model(
                manifest=manifest,
                analysis_results=analysis_results,
                metadata=metadata,
                extension_id=extension_id,
                scan_id=extension_id,
            )
            payload["report_view_model"] = report_view_model
            logger.info(
                "[UPGRADE] Built report_view_model for extension_id=%s (force=%s)",
                extension_id,
                force_recompute,
            )
            upgraded = True

        ensure_consumer_insights(payload)

        final_has_scoring_v2 = bool(payload.get("scoring_v2"))
        final_has_report_view_model = bool(payload.get("report_view_model"))
        final_has_consumer_insights = bool(
            payload.get("report_view_model", {}).get("consumer_insights")
        )
        logger.info(
            "[UPGRADE] extension_id=%s, results_payload_upgraded=%s, has_scoring_v2=%s→%s, has_report_view_model=%s→%s, has_consumer_insights=%s→%s",
            extension_id,
            upgraded,
            has_scoring_v2_before,
            final_has_scoring_v2,
            has_report_view_model_before,
            final_has_report_view_model,
            has_consumer_insights_before,
            final_has_consumer_insights,
        )
        return payload

    except Exception as exc:
        logger.error(
            "[UPGRADE] Failed to upgrade legacy payload for extension_id=%s: %s",
            extension_id,
            exc,
        )
        try:
            ensure_consumer_insights(payload)
        except Exception:
            pass
        final_has_scoring_v2 = bool(
            payload.get("scoring_v2")
            or payload.get("governance_bundle", {}).get("scoring_v2")
        )
        final_has_report_view_model = bool(payload.get("report_view_model"))
        final_has_consumer_insights = bool(
            payload.get("report_view_model", {}).get("consumer_insights")
        )
        logger.info(
            "[UPGRADE] extension_id=%s, results_payload_upgraded=false (error), has_scoring_v2=%s→%s, has_report_view_model=%s→%s, has_consumer_insights=%s→%s",
            extension_id,
            has_scoring_v2_before,
            final_has_scoring_v2,
            has_report_view_model_before,
            final_has_report_view_model,
            has_consumer_insights_before,
            final_has_consumer_insights,
        )
        return payload


def ensure_consumer_insights(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Ensure that the payload contains consumer insights and summary in the report view model.
    """
    if "report_view_model" not in payload:
        payload["report_view_model"] = {}

    rvm = payload["report_view_model"]
    if rvm.get("consumer_insights") is not None:
        logger.info("consumer_insights_attached=true (already present)")
        return payload

    scoring_v2 = payload.get("scoring_v2")
    if not scoring_v2:
        governance_bundle = payload.get("governance_bundle", {})
        if isinstance(governance_bundle, dict):
            scoring_v2 = governance_bundle.get("scoring_v2")

    capability_flags = None
    if isinstance(rvm.get("evidence"), dict):
        capability_flags = rvm["evidence"].get("capability_flags")
    if not capability_flags:
        capability_flags = payload.get("capability_flags")

    host_access_summary = None
    if isinstance(rvm.get("evidence"), dict):
        host_access_summary = rvm["evidence"].get("host_access_summary")
    if not host_access_summary:
        host_access_summary = payload.get("host_access_summary")

    permissions_analysis = payload.get("permissions_analysis")
    if not permissions_analysis and isinstance(rvm.get("evidence"), dict):
        permissions_analysis = rvm["evidence"].get("permissions_summary")

    webstore_metadata = payload.get("metadata")
    if not webstore_metadata and isinstance(rvm.get("evidence"), dict):
        webstore_metadata = rvm["evidence"].get("webstore_metadata")

    network_evidence = payload.get("network_evidence")
    if not network_evidence and isinstance(rvm.get("evidence"), dict):
        network_evidence = rvm["evidence"].get("network_evidence")

    external_domains = payload.get("external_domains")
    if not external_domains and isinstance(rvm.get("evidence"), dict):
        external_domains = rvm["evidence"].get("external_domains")

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


def log_scan_results_return_shape(path: str, payload: Dict[str, Any]) -> None:
    """Log a consistent shape for traceability when returning scan results."""
    if not isinstance(payload, dict):
        logger.info(
            "[DEBUG get_scan_results return_shape] path=%s payload_type=%s (non-dict)",
            path,
            type(payload).__name__,
        )
        return

    payload_keys = sorted(list(payload.keys()))
    report_view_model = payload.get("report_view_model")
    has_report_view_model = "report_view_model" in payload
    has_consumer_insights = bool(
        isinstance(report_view_model, dict) and report_view_model.get("consumer_insights") is not None
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
