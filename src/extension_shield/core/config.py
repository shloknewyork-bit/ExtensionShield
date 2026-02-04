"""
Central configuration for ExtensionShield.

Goals:
- Single place for env var parsing + defaults
- Centralize storage/db backend selection (maps current behavior)
- Provide local filesystem paths
- Validate required env in production

This module intentionally avoids importing app/business logic to prevent cycles.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Literal, Optional

EnvName = Literal["local", "dev", "prod"]
StorageBackend = Literal["local", "supabase"]
DbBackend = Literal["sqlite", "postgres", "supabase"]


def _normalize_env(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    v = value.strip().lower()
    return v or None


def _parse_env_name(value: Optional[str]) -> EnvName:
    v = _normalize_env(value) or "local"
    if v in ("local", "development", "dev"):
        return "dev" if v in ("development", "dev") else "local"
    if v in ("prod", "production"):
        return "prod"
    # Unknown values fall back to local to preserve current behavior.
    return "local"


def _parse_storage_backend(value: Optional[str]) -> StorageBackend:
    v = _normalize_env(value) or "local"
    if v == "supabase":
        return "supabase"
    return "local"


def _parse_db_backend(value: Optional[str]) -> Optional[DbBackend]:
    v = _normalize_env(value)
    if not v:
        return None
    if v in ("sqlite", "supabase", "postgres"):
        return v  # type: ignore[return-value]
    return None


@dataclass(frozen=True)
class LocalPaths:
    """
    Filesystem paths used by the current implementation.

    Note: `storage_root` preserves the raw value of EXTENSION_STORAGE_PATH (may be relative).
    `results_dir` matches existing API behavior (absolute path via resolve()).
    """

    storage_root: Path
    results_dir: Path

    def ensure_dirs(self) -> None:
        self.results_dir.mkdir(parents=True, exist_ok=True)


@dataclass(frozen=True)
class Settings:
    # Environment
    env: EnvName

    # Backends (present for future-proofing; current code uses local FS + sqlite/supabase)
    storage_backend: StorageBackend
    db_backend: DbBackend

    # Local filesystem paths
    extension_storage_path: str
    database_path: str

    # Supabase (optional)
    supabase_url: Optional[str]
    supabase_key: Optional[str]
    supabase_scan_results_table: str

    @property
    def paths(self) -> LocalPaths:
        storage_root = Path(self.extension_storage_path)
        results_dir = storage_root.resolve()
        return LocalPaths(storage_root=storage_root, results_dir=results_dir)

    def is_prod(self) -> bool:
        return self.env == "prod"

    def validate(self) -> None:
        """
        Validate required configuration for production.

        In non-prod environments we preserve the current "best-effort defaults" behavior.
        """

        if not self.is_prod():
            return

        # Require explicit storage path to avoid accidentally writing into CWD in prod.
        if os.environ.get("EXTENSION_STORAGE_PATH") is None:
            raise ValueError("Missing required env var EXTENSION_STORAGE_PATH for prod")

        if self.db_backend == "sqlite":
            if os.environ.get("DATABASE_PATH") is None:
                raise ValueError("Missing required env var DATABASE_PATH for prod (sqlite backend)")

        if self.db_backend == "supabase":
            if not self.supabase_url:
                raise ValueError("Missing required env var SUPABASE_URL for prod (supabase backend)")
            if not self.supabase_key:
                raise ValueError(
                    "Missing required env var SUPABASE_SERVICE_ROLE_KEY or SUPABASE_ANON_KEY for prod (supabase backend)"
                )

        if self.db_backend == "postgres":
            # Not wired into the app yet; keep this explicit so prod can't silently misconfigure.
            raise ValueError("DB_BACKEND=postgres is not supported by the current codebase")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Load settings from env vars.

    Env vars recognized (current + forward-looking):
    - ENV / APP_ENV / EXTENSION_SHIELD_ENV: local|dev|prod
    - EXTENSION_STORAGE_PATH: local filesystem root for artifacts/backups
    - DATABASE_PATH: sqlite file path
    - SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, SUPABASE_ANON_KEY, SUPABASE_SCAN_RESULTS_TABLE
    - STORAGE_BACKEND: local|supabase (currently only local FS is used)
    - DB_BACKEND: sqlite|supabase|postgres (postgres not supported yet)
    """

    env = _parse_env_name(
        os.environ.get("EXTENSION_SHIELD_ENV")
        or os.environ.get("APP_ENV")
        or os.environ.get("ENV")
    )

    extension_storage_path = os.environ.get("EXTENSION_STORAGE_PATH", "extensions_storage")
    database_path = os.environ.get("DATABASE_PATH", "project-atlas.db")

    supabase_url = os.environ.get("SUPABASE_URL")
    supabase_key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY") or os.environ.get("SUPABASE_ANON_KEY")
    supabase_scan_results_table = os.environ.get("SUPABASE_SCAN_RESULTS_TABLE", "scan_results")

    storage_backend = _parse_storage_backend(os.environ.get("STORAGE_BACKEND"))

    explicit_db_backend = _parse_db_backend(os.environ.get("DB_BACKEND"))
    if explicit_db_backend:
        db_backend: DbBackend = explicit_db_backend
    else:
        # Current behavior: enable Supabase when URL + key exist, else use SQLite.
        db_backend = "supabase" if (supabase_url and supabase_key) else "sqlite"

    settings = Settings(
        env=env,
        storage_backend=storage_backend,
        db_backend=db_backend,
        extension_storage_path=extension_storage_path,
        database_path=database_path,
        supabase_url=supabase_url,
        supabase_key=supabase_key,
        supabase_scan_results_table=supabase_scan_results_table,
    )
    settings.validate()
    return settings


