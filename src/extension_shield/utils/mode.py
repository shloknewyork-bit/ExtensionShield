"""
Runtime mode and feature flags for ExtensionShield open-core.

EXTSHIELD_MODE controls which features are available:
  - "oss"   (default): Core scanner, CLI, local SQLite. Cloud features disabled.
  - "cloud": All features enabled (auth, history, telemetry admin, etc.).

Individual feature flags can override the mode defaults via env vars.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Literal

from fastapi import HTTPException

Mode = Literal["oss", "cloud"]


def _parse_mode() -> Mode:
    raw = os.environ.get("EXTSHIELD_MODE", "oss").strip().lower()
    if raw in ("cloud", "enterprise"):
        return "cloud"
    return "oss"


def _flag(env_name: str, default: bool) -> bool:
    val = os.environ.get(env_name, "").strip().lower()
    if val in ("1", "true", "yes"):
        return True
    if val in ("0", "false", "no"):
        return False
    return default


@dataclass(frozen=True)
class FeatureFlags:
    mode: Mode
    auth_enabled: bool
    history_enabled: bool
    telemetry_enabled: bool
    community_queue_enabled: bool
    enterprise_forms_enabled: bool


@lru_cache(maxsize=1)
def get_feature_flags() -> FeatureFlags:
    mode = _parse_mode()
    cloud = mode == "cloud"

    return FeatureFlags(
        mode=mode,
        auth_enabled=_flag("AUTH_ENABLED", cloud),
        history_enabled=_flag("HISTORY_ENABLED", cloud),
        telemetry_enabled=_flag("TELEMETRY_ENABLED", cloud),
        community_queue_enabled=_flag("COMMUNITY_QUEUE_ENABLED", cloud),
        enterprise_forms_enabled=_flag("ENTERPRISE_FORMS_ENABLED", cloud),
    )


def is_cloud() -> bool:
    return get_feature_flags().mode == "cloud"


def is_oss() -> bool:
    return get_feature_flags().mode == "oss"


def require_cloud(feature_name: str) -> None:
    """
    Guard for cloud-only API routes.

    Raises HTTP 501 with a structured JSON body when the feature
    is not enabled in the current mode. Safe to call at the top of
    any FastAPI route handler.
    """
    flags = get_feature_flags()

    flag_map = {
        "auth": flags.auth_enabled,
        "history": flags.history_enabled,
        "telemetry": flags.telemetry_enabled,
        "community_queue": flags.community_queue_enabled,
        "enterprise_forms": flags.enterprise_forms_enabled,
    }

    enabled = flag_map.get(feature_name)
    if enabled is None:
        enabled = is_cloud()

    if not enabled:
        raise HTTPException(
            status_code=501,
            detail={
                "error": "cloud_feature_disabled",
                "feature": feature_name,
                "message": f"Available in ExtensionShield Cloud. "
                f"Set EXTSHIELD_MODE=cloud or {feature_name.upper()}_ENABLED=true to enable.",
            },
        )
