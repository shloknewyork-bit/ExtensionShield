"""
Abstract storage interface for ExtensionShield scan data.

All storage backends must implement this protocol so that
the API layer is backend-agnostic.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class ScanStore(ABC):
    """Interface that every storage backend must implement."""

    # ── Scan results ──────────────────────────────────────────────────

    @abstractmethod
    def save_scan_result(self, result: Dict[str, Any]) -> bool: ...

    @abstractmethod
    def get_scan_result(self, identifier: str) -> Optional[Dict[str, Any]]: ...

    @abstractmethod
    def get_scan_history(self, limit: int = 50) -> List[Dict[str, Any]]: ...

    @abstractmethod
    def get_recent_scans(self, limit: int = 10, search: Optional[str] = None) -> List[Dict[str, Any]]: ...

    @abstractmethod
    def touch_scan_result(self, extension_id: str) -> bool: ...

    @abstractmethod
    def update_scan_summary(self, extension_id: str, scoring_v2: dict, report_view_model: dict) -> bool: ...

    @abstractmethod
    def delete_scan_result(self, extension_id: str) -> bool: ...

    @abstractmethod
    def clear_all_results(self) -> bool: ...

    @abstractmethod
    def delete_scans_before(self, cutoff_iso: str) -> int: ...

    # ── Statistics ────────────────────────────────────────────────────

    @abstractmethod
    def get_statistics(self) -> Dict[str, int]: ...

    @abstractmethod
    def get_risk_distribution(self) -> Dict[str, int]: ...

    # ── Telemetry (page views) ────────────────────────────────────────

    @abstractmethod
    def increment_page_view(self, day: str, path: str) -> int: ...

    @abstractmethod
    def get_page_view_summary(self, days: int = 14) -> Dict[str, Any]: ...

    # ── Feedback ──────────────────────────────────────────────────────

    @abstractmethod
    def save_feedback(
        self,
        scan_id: str,
        helpful: bool,
        reason: Optional[str] = None,
        suggested_score: Optional[int] = None,
        comment: Optional[str] = None,
        user_id: Optional[str] = None,
        model_version: Optional[str] = None,
        ruleset_version: Optional[str] = None,
    ) -> Dict[str, Any]: ...

    # ── User history / karma (cloud-only, optional) ───────────────────

    def add_user_scan_history(self, user_id: str, extension_id: str) -> bool:
        return False

    def get_user_scan_history(self, user_id: str, limit: int = 50, private_only: bool = False) -> List[Dict[str, Any]]:
        return []

    def get_user_karma(self, user_id: str) -> Dict[str, Any]:
        return {"karma_points": 0, "total_scans": 0, "created_at": None, "updated_at": None}

    # ── Community review queue (cloud-only, optional) ─────────────────

    def get_review_queue(self) -> List[Dict[str, Any]]:
        return []

    def claim_review_queue_item(self, queue_item_id: str, user_id: Optional[str] = None) -> bool:
        return False

    def upsert_review_vote(self, queue_item_id: str, user_id: str, vote: str, note: Optional[str] = None) -> bool:
        return False
