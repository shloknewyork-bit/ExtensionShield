"""
Analyzer Interface Contract
============================

This file defines the interface that all analyzers must implement.
Freelancers receive this file and must implement the BaseAnalyzer class.

DO NOT MODIFY THIS FILE - It is the contract between your analyzer and the system.
"""
from typing import Dict, Any, Optional, List
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict


@dataclass
class Finding:
    """Represents a single security finding."""

    type: str  # e.g., "credential_theft", "data_exfiltration"
    severity: str  # "critical", "high", "medium", "low", "info"
    description: str
    file: Optional[str] = None
    line: Optional[int] = None
    evidence: Optional[str] = None
    cwe: Optional[str] = None  # e.g., "CWE-312"
    mitre_attack: Optional[str] = None  # e.g., "T1555"
    recommendation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class AnalyzerResult:
    """
    Standard result format all analyzers must return.

    Attributes:
        analyzer_name: Unique identifier for your analyzer (e.g., "sast", "permissions")
        risk_score: Float between 0.0 (safe) and 1.0 (critical risk)
        findings: List of Finding objects
        summary: Human-readable summary of the analysis
        metadata: Optional additional data specific to your analyzer
    """

    analyzer_name: str
    risk_score: float  # 0.0 to 1.0
    findings: List[Finding] = field(default_factory=list)
    summary: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not 0.0 <= self.risk_score <= 1.0:
            raise ValueError(f"risk_score must be between 0.0 and 1.0, got {self.risk_score}")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "analyzer_name": self.analyzer_name,
            "risk_score": self.risk_score,
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary,
            "metadata": self.metadata,
        }


class BaseAnalyzer(ABC):
    """
    Base class all analyzers must inherit from.

    Your implementation should:
    1. Inherit from this class
    2. Implement the `name` property
    3. Implement the `analyze` method

    Example:
        class MyAnalyzer(BaseAnalyzer):
            @property
            def name(self) -> str:
                return "my_analyzer"

            def analyze(self, extension_dir: str, manifest: Dict[str, Any]) -> AnalyzerResult:
                findings = []
                # Your analysis logic here
                return AnalyzerResult(
                    analyzer_name=self.name,
                    risk_score=0.3,
                    findings=findings,
                    summary="Found X issues"
                )
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """
        Return the unique name of this analyzer.

        This name is used to identify results in the workflow.
        Examples: "sast", "permissions", "entropy", "network_traffic"
        """
        pass

    @abstractmethod
    def analyze(self, extension_dir: str, manifest: Dict[str, Any]) -> AnalyzerResult:
        """
        Analyze a Chrome extension.

        Args:
            extension_dir: Absolute path to the extracted extension directory.
                          Contains: manifest.json, JS files, HTML, CSS, etc.
            manifest: Pre-parsed manifest.json as a Python dictionary.
                     Contains: name, version, permissions, content_scripts, etc.

        Returns:
            AnalyzerResult containing:
                - analyzer_name: Your analyzer's name
                - risk_score: 0.0 (safe) to 1.0 (critical)
                - findings: List of Finding objects
                - summary: Human-readable summary
                - metadata: Optional additional data

        Raises:
            Should NOT raise exceptions. Catch errors internally and return
            an AnalyzerResult with appropriate error information in metadata.
        """
        pass

    def validate(self) -> bool:
        """
        Validate that this analyzer is properly configured.
        Override this method if you have configuration to validate.

        Returns:
            True if valid, raises ValueError if invalid
        """
        return True


# === SEVERITY LEVELS (use these constants) ===
SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"
SEVERITY_INFO = "info"


# === EXAMPLE IMPLEMENTATION (for reference only) ===
class ExampleAnalyzer(BaseAnalyzer):
    """
    Example implementation - DO NOT COPY DIRECTLY.
    Use as reference for your own implementation.
    """

    @property
    def name(self) -> str:
        return "example"

    def analyze(self, extension_dir: str, manifest: Dict[str, Any]) -> AnalyzerResult:
        findings = []

        # Example: Check for suspicious permissions
        permissions = manifest.get("permissions", [])
        if "tabs" in permissions and "webRequest" in permissions:
            findings.append(
                Finding(
                    type="suspicious_permission_combo",
                    severity=SEVERITY_MEDIUM,
                    description="Extension requests both tabs and webRequest permissions",
                    recommendation="Review if both permissions are necessary",
                )
            )

        # Calculate risk score based on findings
        risk_score = min(len(findings) * 0.2, 1.0)

        return AnalyzerResult(
            analyzer_name=self.name,
            risk_score=risk_score,
            findings=findings,
            summary=f"Found {len(findings)} potential issues",
        )

