"""
Tests for LLM Output Validators

Tests that validators correctly detect violations and that generators
use fallbacks when validation fails.
"""

import pytest
from unittest.mock import patch, MagicMock

from extension_shield.llm.validators import (
    ValidationResult,
    validate_summary,
    validate_summary_not_generic,
    validate_impact,
    validate_privacy,
    validate_layer_details_not_generic,
    validate_layer_details_lengths,
    validate_layer_details_references,
)
from extension_shield.core.summary_generator import SummaryGenerator
from extension_shield.core.impact_analyzer import ImpactAnalyzer
from extension_shield.core.privacy_compliance_analyzer import PrivacyComplianceAnalyzer


class TestValidateSummary:
    """Tests for validate_summary validator."""

    def test_low_risk_contains_high_risk_violation(self):
        """Test that LOW RISK score_label with 'high risk' text is rejected."""
        output = {
            "one_liner": "This extension has high risk security issues.",
            "score_label": "LOW RISK",
        }
        result = validate_summary(
            output=output,
            score_label="LOW RISK",
            host_scope_label="NONE",
            capability_flags={},
        )
        assert not result.ok
        assert any("high risk" in reason.lower() for reason in result.reasons)

    def test_all_websites_missing_broad_mention(self):
        """Test that ALL_WEBSITES host_scope_label without broad mention in what_to_watch is rejected."""
        output = {
            "one_liner": "Extension summary",
            "what_to_watch": ["Watch for updates"],
        }
        result = validate_summary(
            output=output,
            score_label="MEDIUM RISK",
            host_scope_label="ALL_WEBSITES",
            capability_flags={},
        )
        assert not result.ok
        assert any("broad" in reason.lower() or "all websites" in reason.lower() for reason in result.reasons)

    def test_all_websites_with_broad_mention_passes(self):
        """Test that ALL_WEBSITES with proper mention passes."""
        output = {
            "one_liner": "Extension summary",
            "what_to_watch": ["Runs on all websites (broad host access)."],
        }
        result = validate_summary(
            output=output,
            score_label="MEDIUM RISK",
            host_scope_label="ALL_WEBSITES",
            capability_flags={},
        )
        assert result.ok

    def test_cookies_false_but_mentioned_violation(self):
        """Test that can_read_cookies=false with cookies mention is rejected."""
        output = {
            "one_liner": "This extension can access cookies.",
            "why_this_score": ["Extension requests cookie permissions"],
        }
        result = validate_summary(
            output=output,
            score_label="MEDIUM RISK",
            host_scope_label="NONE",
            capability_flags={"can_read_cookies": False},
        )
        assert not result.ok
        assert any("cookie" in reason.lower() for reason in result.reasons)

    def test_history_false_but_mentioned_violation(self):
        """Test that can_read_history=false with history mention is rejected."""
        output = {
            "one_liner": "Extension can read browsing history.",
        }
        result = validate_summary(
            output=output,
            score_label="MEDIUM RISK",
            host_scope_label="NONE",
            capability_flags={"can_read_history": False},
        )
        assert not result.ok
        assert any("history" in reason.lower() for reason in result.reasons)

    def test_inject_scripts_false_but_mentioned_violation(self):
        """Test that can_inject_scripts=false and can_modify_page_content=false with inject mention is rejected."""
        output = {
            "one_liner": "Extension can inject scripts into pages.",
        }
        result = validate_summary(
            output=output,
            score_label="MEDIUM RISK",
            host_scope_label="NONE",
            capability_flags={
                "can_inject_scripts": False,
                "can_modify_page_content": False,
            },
        )
        assert not result.ok
        assert any("inject" in reason.lower() or "modify" in reason.lower() for reason in result.reasons)

    def test_valid_summary_passes(self):
        """Test that a valid summary passes all checks."""
        output = {
            "one_liner": "Extension appears safe.",
            "what_to_watch": ["Runs on all websites (broad host access)."],
            "why_this_score": ["Low risk signals detected."],
        }
        result = validate_summary(
            output=output,
            score_label="LOW RISK",
            host_scope_label="ALL_WEBSITES",
            capability_flags={"can_read_cookies": True, "can_read_history": True},
        )
        assert result.ok

    def test_low_risk_forbids_alarm_words(self):
        """Test that LOW RISK score_label forbids alarm words like 'severe' or 'avoid'."""
        output = {
            "one_liner": "Avoid this extension as it has severe issues.",
            "why_this_score": ["Severe security flaws"],
        }
        result = validate_summary(
            output=output,
            score_label="LOW RISK",
            host_scope_label="NONE",
            capability_flags={},
        )
        assert not result.ok
        assert any(word in str(result.reasons).lower() for word in ["avoid", "severe"])


class TestValidateSummaryNotGeneric:
    """Tests for validate_summary_not_generic validator."""

    def test_generic_filler_rejected(self):
        """Test that generic filler phrases are rejected."""
        output = {
            "one_liner": "Score is based on permissions and code signals.",
            "why_this_score": ["This analysis checked metadata", "Review the notes below"],
        }
        result = validate_summary_not_generic(output)
        assert not result.ok
        assert len(result.reasons) >= 3

    def test_non_generic_passes(self):
        """Test that non-generic summary passes."""
        output = {
            "one_liner": "This extension manages your tabs efficiently.",
            "why_this_score": ["Requests 'tabs' permission for functionality", "No data sent to external servers"],
        }
        result = validate_summary_not_generic(output)
        assert result.ok


class TestValidateImpact:
    """Tests for validate_impact validator."""

    def test_cookies_false_but_data_access_mentions_cookies(self):
        """Test that can_read_cookies=false with data_access cookies mention is rejected."""
        output = {
            "data_access": {
                "risk_level": "HIGH",
                "bullets": ["Extension can access cookies on all sites."],
            },
        }
        result = validate_impact(
            output=output,
            capability_flags={"can_read_cookies": False},
            external_domains=[],
            network_evidence=[],
        )
        assert not result.ok
        assert any("cookie" in reason.lower() for reason in result.reasons)

    def test_history_false_but_data_access_mentions_history(self):
        """Test that can_read_history=false with data_access history mention is rejected."""
        output = {
            "data_access": {
                "risk_level": "MEDIUM",
                "bullets": ["Can read browsing history."],
            },
        }
        result = validate_impact(
            output=output,
            capability_flags={"can_read_history": False},
            external_domains=[],
            network_evidence=[],
        )
        assert not result.ok
        assert any("history" in reason.lower() for reason in result.reasons)

    def test_inject_scripts_false_but_browser_control_mentions_injection(self):
        """Test that can_inject_scripts=false with browser_control injection mention is rejected."""
        output = {
            "browser_control": {
                "risk_level": "MEDIUM",
                "bullets": ["Can inject scripts into pages."],
            },
        }
        result = validate_impact(
            output=output,
            capability_flags={"can_inject_scripts": False},
            external_domains=[],
            network_evidence=[],
        )
        assert not result.ok
        assert any("inject" in reason.lower() for reason in result.reasons)

    def test_external_sharing_not_unknown_when_no_evidence(self):
        """Test that external_sharing must be UNKNOWN when no evidence exists."""
        output = {
            "external_sharing": {
                "risk_level": "MEDIUM",
                "bullets": ["Contacts external domains."],
                "mitigations": ["Review endpoints."],
            },
        }
        result = validate_impact(
            output=output,
            capability_flags={},
            external_domains=[],
            network_evidence=[],
        )
        assert not result.ok
        assert any("unknown" in reason.lower() for reason in result.reasons)

    def test_external_sharing_unknown_when_no_evidence_passes(self):
        """Test that external_sharing UNKNOWN with empty bullets/mitigations passes when no evidence."""
        output = {
            "external_sharing": {
                "risk_level": "UNKNOWN",
                "bullets": [],
                "mitigations": [],
            },
        }
        result = validate_impact(
            output=output,
            capability_flags={},
            external_domains=[],
            network_evidence=[],
        )
        assert result.ok

    def test_valid_impact_passes(self):
        """Test that a valid impact analysis passes all checks."""
        output = {
            "data_access": {
                "risk_level": "MEDIUM",
                "bullets": ["Can read page content."],
            },
            "external_sharing": {
                "risk_level": "UNKNOWN",
                "bullets": [],
                "mitigations": [],
            },
        }
        result = validate_impact(
            output=output,
            capability_flags={"can_read_cookies": False, "can_read_history": False},
            external_domains=[],
            network_evidence=[],
        )
        assert result.ok


class TestValidatePrivacy:
    """Tests for validate_privacy validator."""

    def test_no_external_evidence_but_claims_sharing(self):
        """Test that privacy_snapshot claiming sharing when no evidence is rejected."""
        output = {
            "privacy_snapshot": "Extension shares data with third-party services.",
            "compliance_notes": [],
        }
        result = validate_privacy(
            output=output,
            capability_flags={},
            external_domains=[],
            network_evidence=[],
            host_scope_label="NONE",
        )
        assert not result.ok
        assert any("sharing" in reason.lower() or "sending" in reason.lower() for reason in result.reasons)

    def test_no_external_evidence_but_compliance_notes_claim_sharing(self):
        """Test that compliance_notes claiming sharing when no evidence is rejected."""
        output = {
            "privacy_snapshot": "Extension privacy practices.",
            "compliance_notes": ["Extension sends data to external servers."],
        }
        result = validate_privacy(
            output=output,
            capability_flags={},
            external_domains=[],
            network_evidence=[],
            host_scope_label="NONE",
        )
        assert not result.ok
        assert any("sharing" in reason.lower() or "sending" in reason.lower() for reason in result.reasons)

    def test_all_websites_missing_broad_warning(self):
        """Test that ALL_WEBSITES host_scope_label without broad warning in governance_checks is rejected."""
        output = {
            "privacy_snapshot": "Extension privacy practices.",
            "governance_checks": [
                {"check": "Privacy policy", "status": "PASS", "note": "Policy present"},
            ],
        }
        result = validate_privacy(
            output=output,
            capability_flags={},
            external_domains=[],
            network_evidence=[],
            host_scope_label="ALL_WEBSITES",
        )
        assert not result.ok
        assert any("broad" in reason.lower() or "all websites" in reason.lower() for reason in result.reasons)

    def test_all_websites_with_broad_warning_passes(self):
        """Test that ALL_WEBSITES with proper broad warning passes."""
        output = {
            "privacy_snapshot": "Extension privacy practices.",
            "governance_checks": [
                {
                    "check": "Host access scope",
                    "status": "WARN",
                    "note": "Runs on all websites (broad site access).",
                },
            ],
        }
        result = validate_privacy(
            output=output,
            capability_flags={},
            external_domains=[],
            network_evidence=[],
            host_scope_label="ALL_WEBSITES",
        )
        assert result.ok

    def test_valid_privacy_passes(self):
        """Test that a valid privacy compliance output passes all checks."""
        output = {
            "privacy_snapshot": "Extension privacy practices.",
            "governance_checks": [
                {
                    "check": "Host access scope",
                    "status": "WARN",
                    "note": "Runs on all websites (broad site access).",
                },
            ],
            "compliance_notes": [],
        }
        result = validate_privacy(
            output=output,
            capability_flags={},
            external_domains=[],
            network_evidence=[],
            host_scope_label="ALL_WEBSITES",
        )
        assert result.ok


class TestGeneratorIntegration:
    """Integration tests showing generators use fallbacks when validation fails."""

    @patch("extension_shield.core.summary_generator.invoke_with_fallback")
    def test_summary_generator_uses_fallback_on_validation_failure(self, mock_invoke):
        """Test that SummaryGenerator uses fallback when validation fails."""
        # Mock LLM response with violation
        mock_response = MagicMock()
        mock_response.content = '{"one_liner": "Extension has high risk issues", "score_label": "LOW RISK", "what_to_watch": []}'
        mock_invoke.return_value = mock_response

        generator = SummaryGenerator()
        result = generator.generate(
            analysis_results={"permissions_analysis": {}},
            manifest={"name": "Test", "version": "1.0.0", "manifest_version": 3, "permissions": []},
            metadata={},
        )

        # Should return fallback (not the LLM output)
        assert result is not None
        assert "one_liner" in result
        # Fallback should not contain the violation
        assert "high risk" not in result.get("one_liner", "").lower() or result.get("score_label") != "LOW RISK"

    @patch("extension_shield.core.impact_analyzer.invoke_with_fallback")
    def test_impact_analyzer_uses_fallback_on_validation_failure(self, mock_invoke):
        """Test that ImpactAnalyzer uses fallback when validation fails."""
        # Mock LLM response with violation (cookies mentioned but can_read_cookies=false)
        mock_response = MagicMock()
        mock_response.content = '{"data_access": {"risk_level": "HIGH", "bullets": ["Extension can access cookies"]}}'
        mock_invoke.return_value = mock_response

        analyzer = ImpactAnalyzer()
        manifest = {
            "name": "Test",
            "version": "1.0.0",
            "manifest_version": 3,
            "permissions": [],  # No cookies permission
        }
        result = analyzer.generate(
            analysis_results={"permissions_analysis": {}},
            manifest=manifest,
        )

        # Should return fallback (not the LLM output)
        assert result is not None
        assert "data_access" in result
        # Fallback should not mention cookies if capability flag is false
        data_access = result.get("data_access", {})
        bullets = data_access.get("bullets", [])
        bullets_text = " ".join(bullets).lower()
        # If cookies permission is not present, fallback should not claim cookies access
        assert "cookie" not in bullets_text or "cookies" not in manifest.get("permissions", [])

    @patch("extension_shield.llm.clients.fallback.invoke_with_fallback")
    def test_privacy_analyzer_uses_fallback_on_validation_failure(self, mock_invoke):
        """Test that PrivacyComplianceAnalyzer uses fallback when validation fails."""
        # Mock LLM response with violation (claims sharing but no evidence)
        mock_response = MagicMock()
        mock_response.content = '{"privacy_snapshot": "Extension shares data with third parties", "governance_checks": []}'
        mock_invoke.return_value = mock_response

        analyzer = PrivacyComplianceAnalyzer()
        result = analyzer.generate(
            analysis_results={},
            manifest={
                "name": "Test",
                "version": "1.0.0",
                "manifest_version": 3,
                "permissions": [],
                "host_permissions": ["<all_urls>"],
            },
        )

        # Should return fallback (not the LLM output)
        assert result is not None
        assert "privacy_snapshot" in result
        # Fallback should not claim sharing when no evidence
        snapshot = result.get("privacy_snapshot", "").lower()
        # Fallback should be more conservative and not claim sharing without evidence
        assert "shares data" not in snapshot or "third parties" not in snapshot
