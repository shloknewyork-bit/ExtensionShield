"""
Tests for GET /api/scan/enforcement_bundle/{extension_id} Endpoint

Verifies that the enforcement bundle endpoint correctly returns
governance decisioning data for analyzed extensions.
"""

import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from extension_shield.api.main import app, scan_results, scan_status


@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app)


@pytest.fixture
def sample_governance_bundle():
    """Create sample governance bundle."""
    return {
        "facts": {
            "scan_id": "test_ext_001",
            "manifest": {"name": "Test Extension"},
            "permissions": [],
            "host_access_patterns": [],
            "security_findings": [],
            "file_inventory": [],
        },
        "evidence_index": {
            "items": [],
            "total_items": 0,
        },
        "signals": {
            "scan_id": "test_ext_001",
            "signals": [
                {
                    "type": "HOST_PERMS_BROAD",
                    "confidence": "HIGH",
                    "source": "manifest",
                }
            ],
        },
        "store_listing": {
            "extraction": {"status": "ok"},
            "declared_data_categories": [],
        },
        "context": {
            "rulepacks": ["ENTERPRISE_GOV_BASELINE"],
            "regions_in_scope": ["GLOBAL"],
        },
        "rule_results": {
            "scan_id": "test_ext_001",
            "results": [],
        },
        "report": {
            "scan_id": "test_ext_001",
            "decision": {
                "verdict": "ALLOW",
                "rationale": "No rules triggered",
            },
        },
        "decision": {
            "verdict": "ALLOW",
            "rationale": "No rules triggered",
            "action_required": None,
        },
    }


@pytest.fixture
def sample_scan_result(sample_governance_bundle):
    """Create sample scan result with governance data."""
    return {
        "extension_id": "abcdefghijklmnopqrstuvwxyzabcdef",
        "extension_name": "Test Extension",
        "url": "https://chromewebstore.google.com/detail/test/abcdefghijklmnopqrstuvwxyzabcdef",
        "timestamp": "2026-01-26T10:00:00",
        "status": "completed",
        "governance_verdict": "ALLOW",
        "governance_bundle": sample_governance_bundle,
        "governance_report": sample_governance_bundle["report"],
        "governance_error": None,
    }


class TestEnforcementBundleEndpoint:
    """Tests for the enforcement bundle API endpoint."""
    
    def test_get_enforcement_bundle_success(self, client, sample_scan_result, sample_governance_bundle):
        """Test successful retrieval of enforcement bundle."""
        ext_id = "abcdefghijklmnopqrstuvwxyzabcdef"
        
        # Populate cache
        scan_results[ext_id] = sample_scan_result
        
        try:
            response = client.get(f"/api/scan/enforcement_bundle/{ext_id}")
            
            assert response.status_code == 200
            data = response.json()
            
            assert data["extension_id"] == ext_id
            assert data["extension_name"] == "Test Extension"
            assert data["verdict"] == "ALLOW"
            assert "bundle" in data
            assert data["bundle"] == sample_governance_bundle
        finally:
            # Cleanup
            scan_results.pop(ext_id, None)
    
    def test_get_enforcement_bundle_not_found(self, client):
        """Test 404 when extension not found."""
        response = client.get("/api/scan/enforcement_bundle/nonexistent123456789012345678901")
        
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()
    
    def test_get_enforcement_bundle_no_governance_data(self, client):
        """Test 404 when governance bundle not available."""
        ext_id = "nogovdata12345678901234567890123"
        
        # Scan result without governance data
        scan_results[ext_id] = {
            "extension_id": ext_id,
            "status": "completed",
            "governance_bundle": None,
            "governance_error": None,
        }
        
        try:
            response = client.get(f"/api/scan/enforcement_bundle/{ext_id}")
            
            assert response.status_code == 404
            assert "not available" in response.json()["detail"].lower()
        finally:
            scan_results.pop(ext_id, None)
    
    def test_get_enforcement_bundle_governance_error(self, client):
        """Test 500 when governance analysis failed without leaking internal details."""
        ext_id = "goverror12345678901234567890123456"
        
        # Scan result with governance error
        scan_results[ext_id] = {
            "extension_id": ext_id,
            "status": "completed",
            "governance_bundle": None,
            "governance_error": "Rules engine failed: invalid rulepack",
        }
        
        try:
            response = client.get(f"/api/scan/enforcement_bundle/{ext_id}")
            
            assert response.status_code == 500
            assert response.json()["detail"] == "Governance analysis failed. Please try again."
            assert "invalid rulepack" not in response.json()["detail"]
        finally:
            scan_results.pop(ext_id, None)
    
    def test_enforcement_bundle_contains_all_fields(self, client, sample_scan_result):
        """Test that bundle contains all required fields."""
        ext_id = sample_scan_result["extension_id"]
        scan_results[ext_id] = sample_scan_result
        
        try:
            response = client.get(f"/api/scan/enforcement_bundle/{ext_id}")
            
            assert response.status_code == 200
            data = response.json()
            
            # Top-level fields
            assert "extension_id" in data
            assert "extension_name" in data
            assert "verdict" in data
            assert "timestamp" in data
            assert "bundle" in data
            
            # Bundle contents
            bundle = data["bundle"]
            assert "facts" in bundle
            assert "evidence_index" in bundle
            assert "signals" in bundle
            assert "store_listing" in bundle
            assert "context" in bundle
            assert "rule_results" in bundle
            assert "report" in bundle
            assert "decision" in bundle
        finally:
            scan_results.pop(ext_id, None)
    
    def test_enforcement_bundle_decision_structure(self, client, sample_scan_result):
        """Test that decision has correct structure."""
        ext_id = sample_scan_result["extension_id"]
        scan_results[ext_id] = sample_scan_result
        
        try:
            response = client.get(f"/api/scan/enforcement_bundle/{ext_id}")
            
            assert response.status_code == 200
            decision = response.json()["bundle"]["decision"]
            
            assert "verdict" in decision
            assert "rationale" in decision
            assert "action_required" in decision
        finally:
            scan_results.pop(ext_id, None)


class TestEnforcementBundleVerdicts:
    """Tests for different verdict types in enforcement bundle."""
    
    @pytest.fixture
    def make_result_with_verdict(self, sample_governance_bundle):
        """Factory to create results with specific verdicts."""
        def _make(ext_id: str, verdict: str, rationale: str = "Test rationale"):
            bundle = sample_governance_bundle.copy()
            bundle["decision"] = {
                "verdict": verdict,
                "rationale": rationale,
                "action_required": "Block installation" if verdict == "BLOCK" else None,
            }
            bundle["report"]["decision"]["verdict"] = verdict
            
            return {
                "extension_id": ext_id,
                "extension_name": f"Test Extension ({verdict})",
                "status": "completed",
                "governance_verdict": verdict,
                "governance_bundle": bundle,
                "governance_report": bundle["report"],
            }
        return _make
    
    def test_allow_verdict(self, client, make_result_with_verdict):
        """Test ALLOW verdict response."""
        ext_id = "allowext12345678901234567890123456"
        scan_results[ext_id] = make_result_with_verdict(ext_id, "ALLOW")
        
        try:
            response = client.get(f"/api/scan/enforcement_bundle/{ext_id}")
            
            assert response.status_code == 200
            assert response.json()["verdict"] == "ALLOW"
        finally:
            scan_results.pop(ext_id, None)
    
    def test_block_verdict(self, client, make_result_with_verdict):
        """Test BLOCK verdict response."""
        ext_id = "blockext12345678901234567890123456"
        scan_results[ext_id] = make_result_with_verdict(
            ext_id, "BLOCK", "Extension exhibits malicious behavior"
        )
        
        try:
            response = client.get(f"/api/scan/enforcement_bundle/{ext_id}")
            
            assert response.status_code == 200
            data = response.json()
            assert data["verdict"] == "BLOCK"
            assert data["bundle"]["decision"]["action_required"] == "Block installation"
        finally:
            scan_results.pop(ext_id, None)
    
    def test_needs_review_verdict(self, client, make_result_with_verdict):
        """Test NEEDS_REVIEW verdict response."""
        ext_id = "reviewxt12345678901234567890123456"
        scan_results[ext_id] = make_result_with_verdict(
            ext_id, "NEEDS_REVIEW", "Manual review required for sensitive permissions"
        )
        
        try:
            response = client.get(f"/api/scan/enforcement_bundle/{ext_id}")
            
            assert response.status_code == 200
            assert response.json()["verdict"] == "NEEDS_REVIEW"
        finally:
            scan_results.pop(ext_id, None)


class TestEnforcementBundleFromDatabase:
    """Tests for loading enforcement bundle from database."""
    
    def test_load_from_database_fallback(self, client, sample_scan_result):
        """Test that database is used when memory cache misses."""
        ext_id = "dbfallback1234567890123456789012"
        
        # Mock database call
        with patch("extension_shield.api.main.db") as mock_db:
            mock_db.get_scan_result.return_value = sample_scan_result
            
            response = client.get(f"/api/scan/enforcement_bundle/{ext_id}")
            
            # Should have called database
            mock_db.get_scan_result.assert_called_once_with(ext_id)
            
            assert response.status_code == 200
    
    def test_load_from_file_fallback(self, client, sample_scan_result, tmp_path):
        """Test that file is used when database misses."""
        ext_id = "filefallbk1234567890123456789012"
        
        # Create temp file with results
        import json
        from pathlib import Path
        
        with patch("extension_shield.api.main.db") as mock_db, \
             patch("extension_shield.api.main.RESULTS_DIR", tmp_path):
            
            mock_db.get_scan_result.return_value = None
            
            # Write result file
            result_file = tmp_path / f"{ext_id}_results.json"
            result_file.write_text(json.dumps(sample_scan_result))
            
            response = client.get(f"/api/scan/enforcement_bundle/{ext_id}")
            
            assert response.status_code == 200
            assert response.json()["verdict"] == "ALLOW"
