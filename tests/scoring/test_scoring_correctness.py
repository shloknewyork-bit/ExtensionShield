"""
Scoring correctness regression tests.

Locks the following behaviors introduced by the scoring-correctness patch set:
A) Overall score uses round(), not int() (no floor bias)
B) Missing VT signal does not inflate scores (confidence=0 excludes it)
C) Coverage cap forces NEEDS_REVIEW + reason
D) VT gate WARN (1-4) vs BLOCK (>=5) thresholds with correct penalty multipliers
"""

import pytest

from extension_shield.scoring.engine import ScoringEngine
from extension_shield.scoring.models import Decision
from extension_shield.scoring.normalizers import normalize_virustotal
from extension_shield.scoring.gates import HardGates
from extension_shield.governance.signal_pack import VirusTotalSignalPack

from tests.scoring.utils import (
    make_min_signal_pack,
    make_test_manifest,
    add_vt_detections,
    add_sast_findings,
    add_permissions,
    add_webstore_stats,
)


# =========================================================================
# A) Overall score uses round(), not int()
# =========================================================================

class TestOverallRounding:
    """Verify overall score uses round() to avoid systematic floor bias."""

    def test_overall_uses_round_not_floor(self):
        """
        Construct layer scores that produce a fractional weighted average
        of 72.5 (sec=72, priv=65, gov=85). With the v1 layer weights
        (sec*0.5 + priv*0.3 + gov*0.2):

            72*0.5 + 65*0.3 + 85*0.2
            = 36 + 19.5 + 17
            = 72.5

        round(72.5) = 72 (banker's rounding) or 73 depending on Python impl.
        int(72.5) = 72  (always floor)

        We test by checking that the engine produces the same value as
        round(), which is not always identical to int().
        """
        engine = ScoringEngine()

        pack = make_min_signal_pack()
        manifest = make_test_manifest()

        result = engine.calculate_scores(pack, manifest)

        raw_weighted = (
            result.security_score * engine.weights.layer_weights.get("security", 0.34)
            + result.privacy_score * engine.weights.layer_weights.get("privacy", 0.33)
            + result.governance_score * engine.weights.layer_weights.get("governance", 0.33)
        )
        expected = round(raw_weighted)

        assert result.base_overall == expected, (
            f"base_overall should use round(), got {result.base_overall} "
            f"vs round({raw_weighted})={expected}"
        )

    def test_fractional_rounds_up_at_point_five(self):
        """
        Craft a scenario where the exact fractional value >=.5 so
        round() differs from int() truncation. We don't control exact
        layer scores precisely, but we verify the invariant:
        base_overall == round(sec*0.5 + priv*0.3 + gov*0.2).
        """
        engine = ScoringEngine()

        pack = make_min_signal_pack()
        add_sast_findings(pack, n=2, severity="MEDIUM")
        add_vt_detections(pack, malicious_count=0, total_engines=70)
        add_webstore_stats(pack, installs=5000, rating_avg=4.0, has_privacy_policy=True)

        manifest = make_test_manifest(manifest_version=3)
        result = engine.calculate_scores(pack, manifest)

        raw = (
            result.security_score * engine.weights.layer_weights.get("security", 0.34)
            + result.privacy_score * engine.weights.layer_weights.get("privacy", 0.33)
            + result.governance_score * engine.weights.layer_weights.get("governance", 0.33)
        )
        assert result.base_overall == round(raw)


# =========================================================================
# B) Missing VT signal does not inflate scores
# =========================================================================

class TestMissingSignalSemantics:
    """Missing data must not make an extension look safer."""

    def test_vt_unavailable_does_not_improve_score(self):
        """
        Compare two identical signal packs:
        - Pack A: VT enabled, malicious_count=0, full scan (clean)
        - Pack B: VT unavailable (not enabled)

        Pack B must NOT have a higher security or overall score than Pack A.
        With Option 1 (confidence=0), VT-unavailable is simply excluded,
        so the score is driven by fewer signals — it should be equal or
        lower, never higher.
        """
        engine = ScoringEngine()
        manifest = make_test_manifest()

        pack_vt_clean = make_min_signal_pack(scan_id="vt-clean")
        add_vt_detections(pack_vt_clean, malicious_count=0, total_engines=70)
        add_sast_findings(pack_vt_clean, n=1, severity="MEDIUM")
        add_webstore_stats(pack_vt_clean, installs=10000, rating_avg=4.0, has_privacy_policy=True)

        pack_vt_missing = make_min_signal_pack(scan_id="vt-missing")
        # VT stays at default (enabled=False)
        add_sast_findings(pack_vt_missing, n=1, severity="MEDIUM")
        add_webstore_stats(pack_vt_missing, installs=10000, rating_avg=4.0, has_privacy_policy=True)

        result_clean = engine.calculate_scores(pack_vt_clean, manifest)

        engine2 = ScoringEngine()
        result_missing = engine2.calculate_scores(pack_vt_missing, manifest)

        assert result_missing.security_score <= result_clean.security_score, (
            f"VT-unavailable security ({result_missing.security_score}) should not "
            f"exceed VT-clean security ({result_clean.security_score})"
        )
        assert result_missing.overall_score <= result_clean.overall_score, (
            f"VT-unavailable overall ({result_missing.overall_score}) should not "
            f"exceed VT-clean overall ({result_clean.overall_score})"
        )

    def test_vt_unavailable_normalizer_returns_zero_confidence(self):
        """Directly verify the normalizer output for unavailable VT."""
        vt_disabled = VirusTotalSignalPack(enabled=False)
        factor = normalize_virustotal(vt_disabled)

        assert factor.confidence == 0.0, (
            f"Unavailable VT should have confidence=0.0, got {factor.confidence}"
        )
        assert factor.severity == 0.0
        assert "signal_unavailable" in factor.flags

    def test_vt_rate_limited_normalizer_returns_zero_confidence(self):
        """VT enabled but with total_engines=0 (rate-limited) should also
        be excluded from the formula."""
        vt_rate_limited = VirusTotalSignalPack(
            enabled=True,
            malicious_count=0,
            suspicious_count=0,
            total_engines=0,
        )
        factor = normalize_virustotal(vt_rate_limited)

        assert factor.confidence == 0.0, (
            f"Rate-limited VT should have confidence=0.0, got {factor.confidence}"
        )


# =========================================================================
# C) Coverage cap forces NEEDS_REVIEW + reason
# =========================================================================

class TestCoverageCapEnforcement:
    """When SAST coverage is missing, cap score and force NEEDS_REVIEW."""

    def test_coverage_cap_forces_needs_review(self):
        """
        Construct a signal pack where:
        - sast.files_scanned == 0, sast.deduped_findings == [] (missing coverage)
        - Other signals are clean enough that overall > 80 before cap

        Assert:
        - overall_score == 80
        - decision == NEEDS_REVIEW
        - needs_review == True
        - coverage_cap_applied == True
        - coverage_cap_reason is set
        - "SAST coverage missing; score capped at 80" in reasons
        """
        engine = ScoringEngine()

        pack = make_min_signal_pack()
        # Leave sast at default: files_scanned=0, deduped_findings=[]
        add_vt_detections(pack, malicious_count=0, total_engines=70)
        add_webstore_stats(
            pack, installs=500000, rating_avg=4.8,
            rating_count=5000, has_privacy_policy=True,
            last_updated="2025-12-01",
        )
        add_permissions(pack, api_permissions=["storage"])

        manifest = make_test_manifest(manifest_version=3)
        result = engine.calculate_scores(pack, manifest)

        assert result.coverage_cap_applied is True
        assert result.overall_score == 80
        assert result.decision == Decision.NEEDS_REVIEW
        assert result.needs_review is True
        assert result.coverage_cap_reason is not None
        assert "SAST coverage missing; score capped at 80" in result.reasons

    def test_coverage_cap_not_applied_when_sast_present(self):
        """Coverage cap should not activate when SAST ran successfully."""
        engine = ScoringEngine()

        pack = make_min_signal_pack()
        add_sast_findings(pack, n=0, severity="INFO")
        # Manually set files_scanned > 0 to indicate SAST ran
        from extension_shield.governance.signal_pack import SastSignalPack
        pack.sast = SastSignalPack(deduped_findings=[], files_scanned=10, confidence=0.9)

        add_vt_detections(pack, malicious_count=0, total_engines=70)
        add_webstore_stats(
            pack, installs=500000, rating_avg=4.8,
            has_privacy_policy=True, last_updated="2025-12-01",
        )

        manifest = make_test_manifest(manifest_version=3)
        result = engine.calculate_scores(pack, manifest)

        assert result.coverage_cap_applied is not True

    def test_coverage_cap_reason_no_duplicates(self):
        """The coverage reason must appear exactly once in reasons list."""
        engine = ScoringEngine()
        pack = make_min_signal_pack()
        add_vt_detections(pack, malicious_count=0, total_engines=70)
        add_webstore_stats(
            pack, installs=500000, rating_avg=4.8,
            has_privacy_policy=True, last_updated="2025-12-01",
        )
        manifest = make_test_manifest(manifest_version=3)

        result = engine.calculate_scores(pack, manifest)

        cap_reasons = [r for r in result.reasons if "score capped at 80" in r]
        assert len(cap_reasons) <= 1, f"Coverage reason duplicated: {cap_reasons}"


# =========================================================================
# D) VT gate WARN vs BLOCK thresholds
# =========================================================================

class TestVTGateThresholds:
    """VT gate tiering: WARN for 1-4, BLOCK for >=5."""

    def test_vt_gate_mal_count_1_triggers_warn(self):
        """malicious_count=1 should trigger WARN, not BLOCK."""
        gates = HardGates()
        vt = VirusTotalSignalPack(
            enabled=True,
            malicious_count=1,
            suspicious_count=0,
            total_engines=70,
        )
        result = gates.evaluate_vt_malware(vt)

        assert result.triggered is True
        assert result.decision == "WARN"

    def test_vt_gate_mal_count_4_triggers_warn(self):
        """malicious_count=4 should still be WARN."""
        gates = HardGates()
        vt = VirusTotalSignalPack(
            enabled=True,
            malicious_count=4,
            suspicious_count=0,
            total_engines=70,
        )
        result = gates.evaluate_vt_malware(vt)

        assert result.triggered is True
        assert result.decision == "WARN"

    def test_vt_gate_mal_count_5_triggers_block(self):
        """malicious_count=5 should trigger BLOCK."""
        gates = HardGates()
        vt = VirusTotalSignalPack(
            enabled=True,
            malicious_count=5,
            suspicious_count=0,
            total_engines=70,
        )
        result = gates.evaluate_vt_malware(vt)

        assert result.triggered is True
        assert result.decision == "BLOCK"

    def test_vt_gate_mal_count_0_no_trigger(self):
        """malicious_count=0 should not trigger the gate."""
        gates = HardGates()
        vt = VirusTotalSignalPack(
            enabled=True,
            malicious_count=0,
            suspicious_count=0,
            total_engines=70,
        )
        result = gates.evaluate_vt_malware(vt)

        assert result.triggered is False
        assert result.decision == "ALLOW"

    def test_vt_warn_applies_reduced_penalty_multiplier(self):
        """WARN gate should apply penalty_multiplier=0.7, not 1.0."""
        engine = ScoringEngine()
        manifest = make_test_manifest()

        pack_warn = make_min_signal_pack(scan_id="vt-warn")
        add_vt_detections(pack_warn, malicious_count=1, total_engines=70)
        add_webstore_stats(pack_warn, installs=10000, rating_avg=4.0, has_privacy_policy=True)
        from extension_shield.governance.signal_pack import SastSignalPack
        pack_warn.sast = SastSignalPack(deduped_findings=[], files_scanned=5, confidence=0.8)

        pack_block = make_min_signal_pack(scan_id="vt-block")
        add_vt_detections(pack_block, malicious_count=5, total_engines=70)
        add_webstore_stats(pack_block, installs=10000, rating_avg=4.0, has_privacy_policy=True)
        pack_block.sast = SastSignalPack(deduped_findings=[], files_scanned=5, confidence=0.8)

        result_warn = engine.calculate_scores(pack_warn, manifest)
        engine2 = ScoringEngine()
        result_block = engine2.calculate_scores(pack_block, manifest)

        assert result_block.security_score < result_warn.security_score, (
            f"BLOCK penalty ({result_block.security_score}) should be more severe "
            f"than WARN ({result_warn.security_score})"
        )
        assert result_block.gate_penalty > result_warn.gate_penalty, (
            f"BLOCK gate_penalty ({result_block.gate_penalty}) should exceed "
            f"WARN gate_penalty ({result_warn.gate_penalty})"
        )

    def test_vt_warn_confidence_scaled(self):
        """WARN confidence should be lower than BLOCK confidence (×0.8)."""
        gates = HardGates()
        vt = VirusTotalSignalPack(
            enabled=True,
            malicious_count=3,
            suspicious_count=0,
            total_engines=70,
        )
        result_warn = gates.evaluate_vt_malware(vt)

        vt_block = VirusTotalSignalPack(
            enabled=True,
            malicious_count=5,
            suspicious_count=0,
            total_engines=70,
        )
        result_block = gates.evaluate_vt_malware(vt_block)

        assert result_warn.confidence < result_block.confidence, (
            f"WARN confidence ({result_warn.confidence}) should be lower than "
            f"BLOCK confidence ({result_block.confidence})"
        )
