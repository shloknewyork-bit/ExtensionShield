"""
Tests for Layer Details Generator

Tests the LLM-powered layer details generation and deterministic fallback.
"""

import pytest
from unittest.mock import Mock, patch
from extension_shield.core.layer_details_generator import LayerDetailsGenerator
from extension_shield.scoring.humanize import LayerHumanizer
from extension_shield.scoring.models import ScoringResult, LayerScore, FactorScore, RiskLevel, Decision
from extension_shield.scoring.gates import GateResult
from extension_shield.llm.validators import ValidationResult


@pytest.fixture
def sample_scoring_result():
    """Create a sample scoring result for testing."""
    security_factors = [
        FactorScore(
            name="SAST",
            severity=0.7,
            confidence=0.9,
            weight=0.4,
            evidence_ids=["sast_1"],
            details={"critical_count": 2},
            flags=["code_injection"]
        ),
        FactorScore(
            name="VirusTotal",
            severity=0.3,
            confidence=0.8,
            weight=0.2,
            evidence_ids=["vt_1"],
            details={"detections": 1},
            flags=[]
        )
    ]
    
    privacy_factors = [
        FactorScore(
            name="PermissionsBaseline",
            severity=0.6,
            confidence=0.95,
            weight=0.5,
            evidence_ids=["perm_1"],
            details={"sensitive_permissions": ["cookies", "history"]},
            flags=["broad_permissions"]
        )
    ]
    
    governance_factors = [
        FactorScore(
            name="WebStoreTrust",
            severity=0.2,
            confidence=0.7,
            weight=0.3,
            evidence_ids=["ws_1"],
            details={"user_count": 50000},
            flags=[]
        )
    ]
    
    return ScoringResult(
        scan_id="test_scan",
        extension_id="test_ext",
        security_score=75,
        privacy_score=65,
        governance_score=80,
        overall_score=72,
        decision=Decision.ALLOW,
        security_layer=LayerScore(
            layer_name="security",
            score=75,
            risk=0.25,
            factors=security_factors
        ),
        privacy_layer=LayerScore(
            layer_name="privacy",
            score=65,
            risk=0.35,
            factors=privacy_factors
        ),
        governance_layer=LayerScore(
            layer_name="governance", 
            score=80,
            risk=0.20,
            factors=governance_factors
        )
    )


@pytest.fixture
def sample_analysis_results():
    """Create sample analysis results."""
    return {
        "permissions_analysis": {
            "permissions": ["cookies", "activeTab", "webRequest"],
            "host_permissions": ["https://*/*"],
            "sensitive_permissions": ["cookies"]
        },
        "javascript_analysis": {
            "findings": [
                {
                    "severity": "high",
                    "category": "injection",
                    "description": "eval() usage detected",
                    "file": "content.js",
                    "line": 42
                }
            ],
            "sast_analysis": "Code contains eval() usage which could execute arbitrary code."
        }
    }


@pytest.fixture
def sample_manifest():
    """Create sample manifest data."""
    return {
        "name": "Test Extension",
        "version": "1.0.0",
        "permissions": ["cookies", "activeTab", "webRequest"],
        "host_permissions": ["https://*/*"]
    }


@pytest.fixture
def sample_gate_results():
    """Create sample gate results."""
    return [
        GateResult(
            gate_id="CRITICAL_SAST",
            decision="WARN",
            triggered=True,
            confidence=0.8,
            reasons=["eval() usage detected in content script"],
            evidence_ids=["sast_finding_1"],
            details={"file": "content.js", "line": 42}
        ),
        GateResult(
            gate_id="SENSITIVE_EXFIL",
            decision="WARN", 
            triggered=True,
            confidence=0.7,
            reasons=["Extension has network permissions and cookie access"],
            evidence_ids=["perm_1", "host_1"],
            details={}
        )
    ]


class TestLayerDetailsGenerator:
    """Test the LayerDetailsGenerator class."""

    def test_generate_success(self, sample_scoring_result, sample_analysis_results, 
                             sample_manifest, sample_gate_results):
        """Test successful layer details generation."""
        generator = LayerDetailsGenerator()
        
        # Mock LLM response
        mock_response = {
            "security": {
                "one_liner": "High security risk due to dangerous code patterns including eval() usage.",
                "key_points": [
                    "CRITICAL_SAST: eval() usage in content.js can run injected code.",
                    "webRequest permission can intercept network traffic",
                    "Code injection vulnerabilities found in SAST analysis"
                ],
                "what_to_watch": [
                    "Monitor CRITICAL_SAST-related arbitrary code execution risks.",
                    "Review webRequest usage in content scripts."
                ]
            },
            "privacy": {
                "one_liner": "Moderate privacy risk due to broad website access and cookie permissions.",
                "key_points": [
                    "cookies permission can read site cookies",
                    "https://*/* runs on all HTTPS websites",
                    "SENSITIVE_EXFIL: network and cookie access could expose browsing data."
                ],
                "what_to_watch": [
                    "Monitor cookies permission use on high-sensitivity sites.",
                    "Review https://*/* access for unnecessary broad coverage."
                ]
            },
            "governance": {
                "one_liner": "Low governance risk with good policy compliance.",
                "key_points": [
                    "WebStoreTrust: 50,000 users indicates established extension",
                    "WebStoreTrust reports no Chrome Web Store policy violations for this listing."
                ],
                "what_to_watch": [
                    "Monitor WebStoreTrust changes and store policy updates."
                ]
            }
        }
        
        with patch('extension_shield.core.layer_details_generator.invoke_with_fallback') as mock_llm:
            mock_llm.return_value = Mock(content=str(mock_response).replace("'", '"'))
            
            result = generator.generate(
                scoring_result=sample_scoring_result,
                analysis_results=sample_analysis_results,
                manifest=sample_manifest,
                gate_results=sample_gate_results
            )
            
            assert result is not None
            assert "security" in result
            assert "privacy" in result
            assert "governance" in result
            
            # Check security layer
            security = result["security"]
            assert "one_liner" in security
            assert "key_points" in security
            assert "what_to_watch" in security
            assert isinstance(security["key_points"], list)
            assert isinstance(security["what_to_watch"], list)

    def test_generate_llm_failure_returns_none(self, sample_scoring_result, sample_analysis_results, 
                                              sample_manifest, sample_gate_results):
        """Test that LLM failure returns None for fallback handling."""
        generator = LayerDetailsGenerator()
        
        with patch('extension_shield.core.layer_details_generator.invoke_with_fallback') as mock_llm:
            mock_llm.side_effect = Exception("LLM API error")
            
            result = generator.generate(
                scoring_result=sample_scoring_result,
                analysis_results=sample_analysis_results,
                manifest=sample_manifest,
                gate_results=sample_gate_results
            )
            
            assert result is None

    def test_validate_layer_details_generic_filler(self, sample_scoring_result, sample_analysis_results,
                                                   sample_manifest, sample_gate_results):
        """Test validation rejects generic filler phrases."""
        generator = LayerDetailsGenerator()
        
        invalid_output = {
            "security": {
                "one_liner": "Score is based on analysis results.",
                "key_points": ["This analysis shows some issues"],
                "what_to_watch": ["Review the notes below"]
            },
            "privacy": {
                "one_liner": "Privacy analysis complete.",
                "key_points": [],
                "what_to_watch": []
            },
            "governance": {
                "one_liner": "Governance check complete.",
                "key_points": [],
                "what_to_watch": []
            }
        }
        
        validation = generator._validate_layer_details(
            invalid_output, sample_scoring_result, sample_analysis_results, 
            sample_manifest, sample_gate_results
        )
        
        assert not validation.ok
        assert any("generic filler phrase" in reason for reason in validation.reasons)

    def test_validate_layer_details_length_limits(self, sample_scoring_result, sample_analysis_results,
                                                  sample_manifest, sample_gate_results):
        """Test validation enforces length limits (150/120/120)."""
        generator = LayerDetailsGenerator()
        
        invalid_output = {
            "security": {
                "one_liner": "A" * 151,  # Exceeds 150 char limit
                "key_points": ["B" * 121],  # Exceeds 120 char limit
                "what_to_watch": []
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
        
        validation = generator._validate_layer_details(
            invalid_output, sample_scoring_result, sample_analysis_results,
            sample_manifest, sample_gate_results
        )
        
        assert not validation.ok
        assert any("exceeds 150 characters" in reason for reason in validation.reasons)
        assert any("exceeds 120 characters" in reason for reason in validation.reasons)

    def test_extract_concrete_signals(self, sample_scoring_result, sample_analysis_results,
                                     sample_manifest, sample_gate_results):
        """Test concrete signal extraction."""
        generator = LayerDetailsGenerator()
        
        signals = generator._extract_concrete_signals(
            sample_scoring_result, sample_analysis_results, sample_manifest, sample_gate_results
        )
        
        # Should include gate IDs
        assert "CRITICAL_SAST" in signals
        assert "SENSITIVE_EXFIL" in signals
        
        # Should include permissions
        assert "cookies" in signals
        assert "activeTab" in signals
        assert "webRequest" in signals
        
        # Should include host patterns
        assert "https://*/*" in signals
        
        # Should include factor names
        assert "SAST" in signals
        assert "PermissionsBaseline" in signals


class TestLayerHumanizer:
    """Test the LayerHumanizer deterministic fallback."""

    def test_generate_fallback_complete(self, sample_scoring_result, sample_analysis_results,
                                       sample_manifest, sample_gate_results):
        """Test complete fallback generation."""
        result = LayerHumanizer.generate_layer_details_fallback(
            sample_scoring_result, sample_analysis_results, sample_manifest, sample_gate_results
        )
        
        assert result is not None
        assert "security" in result
        assert "privacy" in result  
        assert "governance" in result
        
        # Check structure of each layer
        for layer_name in ["security", "privacy", "governance"]:
            layer = result[layer_name]
            assert "one_liner" in layer
            assert "key_points" in layer
            assert "what_to_watch" in layer
            assert isinstance(layer["key_points"], list)
            assert isinstance(layer["what_to_watch"], list)
            
            # Should respect length limits (150/120/120)
            assert len(layer["one_liner"]) <= 150
            for point in layer["key_points"]:
                assert len(point) <= 120
            for watch in layer["what_to_watch"]:
                assert len(watch) <= 120

    def test_security_layer_with_gates(self, sample_scoring_result, sample_analysis_results,
                                      sample_manifest, sample_gate_results):
        """Test security layer generation with gate results."""
        result = LayerHumanizer._generate_security_layer(
            sample_scoring_result, sample_analysis_results, sample_manifest, sample_gate_results
        )
        
        # Should explain the triggered security gate in plain English
        key_points_text = " ".join(result["key_points"])
        assert "dangerous code pattern" in key_points_text.lower()

    def test_privacy_layer_with_permissions(self, sample_scoring_result, sample_analysis_results,
                                           sample_manifest, sample_gate_results):
        """Test privacy layer generation mentions permissions."""
        result = LayerHumanizer._generate_privacy_layer(
            sample_scoring_result, sample_analysis_results, sample_manifest, sample_gate_results
        )
        
        # Should mention sensitive permissions or broad host access
        all_text = result["one_liner"] + " ".join(result["key_points"]) + " ".join(result["what_to_watch"])
        assert ("cookies" in all_text.lower() or 
                "websites" in all_text.lower() or 
                "https://*/*" in all_text)

    def test_risk_level_mapping(self):
        """Test risk level mapping from scores."""
        assert LayerHumanizer._get_risk_level_from_score(90) == "LOW"
        assert LayerHumanizer._get_risk_level_from_score(70) == "MEDIUM" 
        assert LayerHumanizer._get_risk_level_from_score(50) == "MEDIUM"

    def test_permission_helpers(self, sample_manifest):
        """Test permission helper methods."""
        powerful = LayerHumanizer._get_powerful_permissions(sample_manifest)
        data_perms = LayerHumanizer._get_data_permissions(sample_manifest)
        sensitive = LayerHumanizer._get_sensitive_permissions(sample_manifest)
        
        # webRequest is powerful but not sensitive data permission
        assert "webRequest" not in data_perms
        
        # cookies is both data and sensitive
        assert "cookies" in data_perms
        assert "cookies" in sensitive
        
        # Should detect broad host access
        assert LayerHumanizer._has_broad_host_access(sample_manifest) == True

    def test_layer_details_generator_uses_gpt4o_default(self, sample_scoring_result, sample_analysis_results,
                                                         sample_manifest, sample_gate_results):
        """Test that LayerDetailsGenerator uses gpt-4o as default model if LLM_MODEL env not set."""
        import os
        from unittest.mock import patch
        
        generator = LayerDetailsGenerator()
        
        # Save original env value
        original_model = os.environ.get("LLM_MODEL")
        if "LLM_MODEL" in os.environ:
            del os.environ["LLM_MODEL"]
        
        try:
            with patch('extension_shield.core.layer_details_generator.invoke_with_fallback') as mock_llm:
                mock_llm.return_value = Mock(content='{"security": {"one_liner": "test", "key_points": [], "what_to_watch": []}, "privacy": {"one_liner": "test", "key_points": [], "what_to_watch": []}, "governance": {"one_liner": "test", "key_points": [], "what_to_watch": []}}')
                
                generator.generate(
                    scoring_result=sample_scoring_result,
                    analysis_results=sample_analysis_results,
                    manifest=sample_manifest,
                    gate_results=sample_gate_results
                )
                
                # Check that invoke_with_fallback was called with gpt-4o
                assert mock_llm.called
                call_kwargs = mock_llm.call_args[1]
                assert call_kwargs.get("model_name") == "gpt-4o"
        finally:
            # Restore original env value
            if original_model:
                os.environ["LLM_MODEL"] = original_model

    def test_layer_details_generator_uses_temperature_0_3(self, sample_scoring_result, sample_analysis_results,
                                                          sample_manifest, sample_gate_results):
        """Test that LayerDetailsGenerator uses temperature 0.3 by default."""
        from unittest.mock import patch, call
        
        generator = LayerDetailsGenerator()
        
        with patch('extension_shield.core.layer_details_generator.invoke_with_fallback') as mock_llm:
            mock_llm.return_value = Mock(content='{"security": {"one_liner": "test", "key_points": [], "what_to_watch": []}, "privacy": {"one_liner": "test", "key_points": [], "what_to_watch": []}, "governance": {"one_liner": "test", "key_points": [], "what_to_watch": []}}')
            
            generator.generate(
                scoring_result=sample_scoring_result,
                analysis_results=sample_analysis_results,
                manifest=sample_manifest,
                gate_results=sample_gate_results
            )
            
            # Check that invoke_with_fallback was called with temperature 0.3
            assert mock_llm.called
            call_kwargs = mock_llm.call_args[1]  # Get keyword arguments
            model_parameters = call_kwargs.get("model_parameters", {})
            assert model_parameters.get("temperature") == 0.3
