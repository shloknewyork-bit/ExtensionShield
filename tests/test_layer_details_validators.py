"""
Tests for Layer Details Validators

Tests the validators specific to layer details output.
"""

import pytest

from extension_shield.llm.validators import (
    validate_layer_details_not_generic,
    validate_layer_details_lengths,
    validate_layer_details_references,
)


class TestValidateLayerDetailsNotGeneric:
    """Tests for validate_layer_details_not_generic validator."""

    def test_rejects_generic_filler(self):
        """Test that generic filler phrases are rejected."""
        output = {
            "security": {
                "one_liner": "Score is based on analysis results",
                "key_points": ["This analysis shows some issues"],
                "what_to_watch": ["Review the notes below"]
            },
            "privacy": {
                "one_liner": "Privacy analysis complete",
                "key_points": [],
                "what_to_watch": []
            },
            "governance": {
                "one_liner": "Governance check complete",
                "key_points": [],
                "what_to_watch": []
            }
        }
        
        result = validate_layer_details_not_generic(output)
        
        assert not result.ok
        assert any("generic filler phrase" in reason for reason in result.reasons)

    def test_accepts_specific_content(self):
        """Test that specific, non-generic content is accepted."""
        output = {
            "security": {
                "one_liner": "High security risk due to eval() usage in content.js",
                "key_points": ["CRITICAL_SAST: eval() detected in content script"],
                "what_to_watch": ["Monitor for code injection attempts"]
            },
            "privacy": {
                "one_liner": "Moderate privacy risk from broad website access",
                "key_points": ["cookies permission can read site data"],
                "what_to_watch": ["Extension runs on all websites"]
            },
            "governance": {
                "one_liner": "Low governance risk with good compliance",
                "key_points": ["No policy violations detected"],
                "what_to_watch": ["Monitor for security updates"]
            }
        }
        
        result = validate_layer_details_not_generic(output)
        
        assert result.ok


class TestValidateLayerDetailsLengths:
    """Tests for validate_layer_details_lengths validator."""

    def test_rejects_long_one_liner(self):
        """Test that one-liners exceeding 150 characters are rejected."""
        output = {
            "security": {
                "one_liner": "A" * 151,  # Exceeds 150 char limit
                "key_points": ["Short point"],
                "what_to_watch": ["Short watch"]
            },
            "privacy": {
                "one_liner": "Short",
                "key_points": [],
                "what_to_watch": []
            },
            "governance": {
                "one_liner": "Short",
                "key_points": [],
                "what_to_watch": []
            }
        }
        
        result = validate_layer_details_lengths(output)
        
        assert not result.ok
        assert any("exceeds 150 characters" in reason for reason in result.reasons)

    def test_rejects_long_bullets(self):
        """Test that bullet points exceeding 120 characters are rejected."""
        output = {
            "security": {
                "one_liner": "Short summary",
                "key_points": ["B" * 121],  # Exceeds 120 char limit
                "what_to_watch": []
            },
            "privacy": {
                "one_liner": "Short",
                "key_points": [],
                "what_to_watch": ["C" * 121]  # Exceeds 120 char limit
            },
            "governance": {
                "one_liner": "Short",
                "key_points": [],
                "what_to_watch": []
            }
        }
        
        result = validate_layer_details_lengths(output)
        
        assert not result.ok
        assert sum(1 for reason in result.reasons if "exceeds 120 characters" in reason) == 2

    def test_accepts_valid_lengths(self):
        """Test that content within length limits is accepted."""
        output = {
            "security": {
                "one_liner": "High security risk due to dangerous code patterns that could execute arbitrary code",  # Under 150 chars
                "key_points": ["CRITICAL_SAST: code can run injected scripts which is dangerous"],  # Under 120 chars
                "what_to_watch": ["Monitor for code injection attempts that could compromise security"]  # Under 120 chars
            },
            "privacy": {
                "one_liner": "Moderate privacy risk from data access permissions",
                "key_points": ["cookies permission can read your site data"],
                "what_to_watch": ["Extension runs on all websites which may pose privacy risks"]
            },
            "governance": {
                "one_liner": "Low governance risk with good policy compliance",
                "key_points": ["Good policy compliance and disclosure practices"],
                "what_to_watch": ["Monitor for security updates and policy changes"]
            }
        }
        
        result = validate_layer_details_lengths(output)
        
        assert result.ok

    def test_handles_missing_layers(self):
        """Test handling of missing layers."""
        output = {
            "security": {
                "one_liner": "Short",
                "key_points": [],
                "what_to_watch": []
            }
            # Missing privacy and governance layers
        }
        
        result = validate_layer_details_lengths(output)
        
        assert not result.ok
        assert any("Missing privacy layer" in reason for reason in result.reasons)
        assert any("Missing governance layer" in reason for reason in result.reasons)


class TestValidateLayerDetailsReferences:
    """Tests for validate_layer_details_references validator."""

    def test_rejects_bullets_without_concrete_references(self):
        """Test that bullets without concrete signal references are rejected."""
        concrete_signals = ["CRITICAL_SAST", "cookies", "webRequest", "https://*/*", "eval"]
        
        output = {
            "security": {
                "one_liner": "Security issues found",
                "key_points": [
                    "Some security problems detected",  # No concrete reference
                    "CRITICAL_SAST: eval() usage found"  # Has concrete reference
                ],
                "what_to_watch": ["Monitor the extension"]  # No concrete reference
            },
            "privacy": {
                "one_liner": "Privacy concerns",
                "key_points": [],
                "what_to_watch": []
            },
            "governance": {
                "one_liner": "Governance issues", 
                "key_points": [],
                "what_to_watch": []
            }
        }
        
        result = validate_layer_details_references(output, concrete_signals)
        
        assert not result.ok
        assert sum(1 for reason in result.reasons if "lacks concrete signal reference" in reason) == 2

    def test_accepts_bullets_with_concrete_references(self):
        """Test that bullets with concrete signal references are accepted."""
        concrete_signals = ["CRITICAL_SAST", "cookies", "webRequest", "https://*/*", "eval"]
        
        output = {
            "security": {
                "one_liner": "Security issues with eval usage",
                "key_points": [
                    "CRITICAL_SAST: code can run injected scripts which is dangerous",
                    "webRequest permission can intercept and modify network traffic"
                ],
                "what_to_watch": ["Monitor eval() usage patterns for security risks"]
            },
            "privacy": {
                "one_liner": "Privacy risk from cookies permission",
                "key_points": ["cookies permission can read your site data"],
                "what_to_watch": ["Extension runs on https://*/* which means all HTTPS websites"]
            },
            "governance": {
                "one_liner": "Good compliance",
                "key_points": [],
                "what_to_watch": []
            }
        }
        
        result = validate_layer_details_references(output, concrete_signals)
        
        assert result.ok
    
    def test_rejects_bullets_with_only_gate_name(self):
        """Test that bullets containing only a gate name without explanation are rejected."""
        concrete_signals = ["CRITICAL_SAST", "SENSITIVE_EXFIL", "cookies"]
        
        output = {
            "security": {
                "one_liner": "Security issues found",
                "key_points": [
                    "CRITICAL_SAST detected",  # Only gate name, no explanation
                    "CRITICAL_SAST: code can run injected scripts (dangerous)"  # Has explanation, should pass
                ],
                "what_to_watch": []
            },
            "privacy": {
                "one_liner": "Privacy concerns",
                "key_points": ["SENSITIVE_EXFIL"],  # Only gate name, no explanation
                "what_to_watch": []
            },
            "governance": {
                "one_liner": "Governance review",
                "key_points": [],
                "what_to_watch": []
            }
        }
        
        result = validate_layer_details_references(output, concrete_signals)
        
        assert not result.ok
        assert sum(1 for reason in result.reasons if "lacks human explanation" in reason or "without explanation" in reason) >= 2
    
    def test_accepts_bullets_with_gate_and_explanation(self):
        """Test that bullets with gate names plus human explanation are accepted."""
        concrete_signals = ["CRITICAL_SAST", "SENSITIVE_EXFIL", "PURPOSE_MISMATCH"]
        
        output = {
            "security": {
                "one_liner": "Security issues found",
                "key_points": [
                    "CRITICAL_SAST: code can run injected scripts which is dangerous",
                    "CRITICAL_SAST: dangerous code patterns found that could execute arbitrary code"
                ],
                "what_to_watch": []
            },
            "privacy": {
                "one_liner": "Privacy concerns",
                "key_points": ["SENSITIVE_EXFIL: extension may send your data to other websites"],
                "what_to_watch": []
            },
            "governance": {
                "one_liner": "Governance review",
                "key_points": ["PURPOSE_MISMATCH: extension says it's for looks but can access webpages"],
                "what_to_watch": []
            }
        }
        
        result = validate_layer_details_references(output, concrete_signals)
        
        assert result.ok

    def test_handles_empty_signals_list(self):
        """Test handling when no concrete signals are provided."""
        output = {
            "security": {
                "one_liner": "Some issues",
                "key_points": ["Generic security issue"],
                "what_to_watch": []
            },
            "privacy": {
                "one_liner": "Privacy concerns",
                "key_points": [],
                "what_to_watch": []
            },
            "governance": {
                "one_liner": "Governance review",
                "key_points": [],
                "what_to_watch": []
            }
        }
        
        result = validate_layer_details_references(output, [])
        
        # Should accept when no signals available for validation
        assert result.ok

    def test_ignores_empty_bullets(self):
        """Test that empty bullet strings are ignored."""
        concrete_signals = ["CRITICAL_SAST", "cookies"]
        
        output = {
            "security": {
                "one_liner": "Security issues",
                "key_points": ["", "CRITICAL_SAST: eval() usage can run injected code.", ""],  # Empty strings ignored
                "what_to_watch": ["cookies permission risk"]
            },
            "privacy": {
                "one_liner": "Privacy issues",
                "key_points": [],
                "what_to_watch": []
            },
            "governance": {
                "one_liner": "Governance review",
                "key_points": [],
                "what_to_watch": []
            }
        }
        
        result = validate_layer_details_references(output, concrete_signals)
        
        # Should accept since non-empty bullets have concrete references
        assert result.ok
