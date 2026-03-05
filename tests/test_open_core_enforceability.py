"""
Mechanical enforceability of the open-core boundary.

- Router/route-level dependencies ensure 501 without per-handler discipline.
- OSS mode must not initialize Supabase or any cloud client at import time.
- Feature flag cache can be reset for tests.
"""

import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from extension_shield.utils.mode import (
    get_feature_flags,
    reset_feature_flags_cache,
    require_cloud_dep,
)
from extension_shield.api.database import Database, _create_db


def _oss_flags():
    f = MagicMock()
    f.mode = "oss"
    f.auth_enabled = False
    f.history_enabled = False
    f.telemetry_enabled = False
    f.community_queue_enabled = False
    f.enterprise_forms_enabled = False
    f.oss_telemetry_enabled = False
    return f


def _cloud_flags():
    f = MagicMock()
    f.mode = "cloud"
    f.auth_enabled = True
    f.history_enabled = True
    f.telemetry_enabled = True
    f.community_queue_enabled = True
    f.enterprise_forms_enabled = True
    f.oss_telemetry_enabled = True
    return f


class TestRequireCloudDep:
    """require_cloud_dep() returns a FastAPI Depends that enforces 501."""

    def test_require_cloud_dep_returns_depends(self):
        dep = require_cloud_dep("telemetry")
        assert dep is not None
        assert hasattr(dep, "dependency")


class TestOSSCreateDbNeverInitializesSupabase:
    """In OSS mode _create_db() must return SQLite and never call Supabase create_client."""

    def test_oss_mode_returns_sqlite_even_when_db_backend_supabase(self):
        """With mode=oss, _create_db returns Database and never instantiates Supabase."""
        mock_settings = MagicMock()
        mock_settings.db_backend = "supabase"
        with patch("extension_shield.utils.mode.get_feature_flags", return_value=_oss_flags()):
            with patch("extension_shield.core.config.get_settings", return_value=mock_settings):
                with patch("supabase.create_client") as mock_create:
                    result = _create_db()
                    assert isinstance(result, Database)
                    assert type(result).__name__ == "Database"
                    mock_create.assert_not_called()


class TestOSSImportDoesNotInitSupabase:
    """Importing the app and hitting an OSS endpoint must not initialize Supabase."""

    def test_oss_health_does_not_require_supabase(self):
        """GET /health with OSS flags returns 200 and mode=oss. No Supabase at import is proven by test_oss_mode_returns_sqlite_even_when_db_backend_supabase."""
        with patch("extension_shield.api.main.get_feature_flags", return_value=_oss_flags()):
            from extension_shield.api.main import app
            client = TestClient(app)
            r = client.get("/health")
        assert r.status_code == 200
        assert r.json().get("mode") == "oss"


class TestCloudRoutesReturn501WithCorrectDetail:
    """Cloud routes return 501 and detail shape when feature disabled (dependency runs first)."""

    @pytest.mark.parametrize(
        "method,url,kwargs,expected_feature",
        [
            ("get", "/api/history", {}, "history"),
            ("get", "/api/telemetry/summary", {}, "telemetry"),
            ("get", "/api/user/karma", {}, "auth"),
            ("get", "/api/community/review-queue", {}, "community_queue"),
            ("post", "/api/enterprise/pilot-request", {"json": {"name": "a", "email": "a@b.c"}}, "enterprise_forms"),
        ],
    )
    def test_cloud_route_returns_501_and_detail_shape(self, method, url, kwargs, expected_feature):
        with patch("extension_shield.utils.mode.get_feature_flags", return_value=_oss_flags()):
            with patch("extension_shield.api.main.get_feature_flags", return_value=_oss_flags()):
                from extension_shield.api.main import app
                client = TestClient(app)
                r = getattr(client, method)(url, **kwargs)
        assert r.status_code == 501
        data = r.json()
        detail = data.get("detail") or data
        assert detail.get("error") == "not_implemented"
        assert detail.get("feature") == expected_feature
        assert detail.get("mode") == "oss"


class TestCloudModeRoutesNot501:
    """When feature is enabled, cloud routes do not return 501 (may 200/403/404)."""

    def test_telemetry_summary_with_cloud_flags_accepts_admin_key(self):
        """With telemetry enabled, GET /api/telemetry/summary with admin key is not 501."""
        with patch("extension_shield.utils.mode.get_feature_flags", return_value=_cloud_flags()):
            with patch("extension_shield.api.main.get_settings") as mock_settings:
                s = MagicMock()
                s.admin_api_key = "test-key"
                s.telemetry_admin_key = "test-telemetry-key"
                mock_settings.return_value = s
                with patch("extension_shield.api.main.db") as mock_db:
                    mock_db.get_page_view_summary.return_value = {
                        "days": 14, "by_day": {}, "by_path": {}, "rows": [],
                    }
                    from extension_shield.api.main import app
                    client = TestClient(app)
                    r = client.get(
                        "/api/telemetry/summary",
                        headers={"X-Admin-Key": "test-telemetry-key"},
                    )
        assert r.status_code != 501
        if r.status_code == 200:
            assert "days" in r.json() or "by_day" in r.json()


class TestResetFeatureFlagsCache:
    """reset_feature_flags_cache() makes get_feature_flags() read env again."""

    def test_cache_clear_allows_fresh_read(self):
        reset_feature_flags_cache()
        flags = get_feature_flags()
        assert flags.mode in ("oss", "cloud")
