"""
Tests for CORS: prod allowlist, allowed vs disallowed origin behavior.
"""

import os
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

from extension_shield.api.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_cors_allowed_origin_receives_acao(client):
    """Allowed origin (e.g. dev localhost) gets Access-Control-Allow-Origin echoed."""
    # Dev default allowlist includes http://localhost:5173
    response = client.get(
        "/health",
        headers={"Origin": "http://localhost:5173"},
    )
    assert response.status_code == 200
    assert response.headers.get("Access-Control-Allow-Origin") == "http://localhost:5173"


def test_cors_disallowed_origin_no_acao(client):
    """Disallowed origin (e.g. evil.com) does not get Access-Control-Allow-Origin."""
    response = client.get(
        "/health",
        headers={"Origin": "https://evil.com"},
    )
    assert response.status_code == 200
    # CORS middleware must not echo back a disallowed origin
    acao = response.headers.get("Access-Control-Allow-Origin")
    assert acao is None or acao != "https://evil.com"


def test_cors_prod_requires_explicit_origins():
    """In prod, empty CORS_ORIGINS causes startup to fail."""
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import os
import sys
# Set prod + empty CORS before any extension_shield import
os.environ["ENV"] = "prod"
os.environ.pop("CORS_ORIGINS", None)
os.environ.setdefault("EXTENSION_STORAGE_PATH", "/tmp")
os.environ.setdefault("DATABASE_PATH", "/tmp/test-cors.db")
try:
    from extension_shield.api import main
    sys.exit(0)
except ValueError as e:
    if "CORS_ORIGINS" in str(e) and "production" in str(e).lower():
        sys.exit(42)
    raise
""",
        ],
        capture_output=True,
        text=True,
        timeout=10,
        env={**os.environ, "ENV": "prod", "CORS_ORIGINS": ""},
    )
    assert result.returncode == 42, f"Expected ValueError for prod + empty CORS; got {result.returncode}. stderr: {result.stderr}"
