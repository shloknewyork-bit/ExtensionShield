"""
Privacy + Compliance Analyzer

Generates a privacy/compliance snapshot using deterministic truth anchors:
- host_access_summary_json (authoritative scope)
- capability_flags_json (authoritative booleans)
Plus optional evidence blocks (may be empty).
"""

import os
import json
import logging
import re
from pathlib import Path
from typing import Dict, Optional, Any, List, Tuple

from dotenv import load_dotenv
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import JsonOutputParser

from extension_shield.llm.prompts import get_prompts
from extension_shield.llm.clients.fallback import invoke_with_fallback
from extension_shield.llm.validators import validate_privacy

load_dotenv()
logger = logging.getLogger(__name__)


class PrivacyComplianceAnalyzer:
    """Generates privacy + compliance snapshot from scope, capabilities, and evidence."""

    NETWORK_KEYS = [
        "network_analysis",
        "network_behavior",
        "third_party_api_analysis",
        "urls_analysis",
    ]

    @staticmethod
    def _json_block(value: Any) -> str:
        """Serialize a value to a stable JSON block for prompt injection."""
        try:
            return json.dumps(value or {}, indent=2, sort_keys=True, ensure_ascii=True)
        except (TypeError, ValueError):
            return json.dumps(str(value), ensure_ascii=True)

    @staticmethod
    def _is_url_pattern(permission: str) -> bool:
        if not isinstance(permission, str):
            return False
        url_indicators = ["://", "*://", "http://", "https://", "file://", "ftp://", "<all_urls>"]
        return any(indicator in permission for indicator in url_indicators)

    @staticmethod
    def _extract_host_permissions(manifest: Dict[str, Any]) -> List[str]:
        host_permissions = manifest.get("host_permissions", []) or []
        if not host_permissions:
            permissions = manifest.get("permissions", []) or []
            host_permissions = [p for p in permissions if PrivacyComplianceAnalyzer._is_url_pattern(p)]
        return [p for p in host_permissions if isinstance(p, str)]

    @staticmethod
    def _classify_host_access_scope(manifest: Dict[str, Any]) -> Dict[str, Any]:
        broad_patterns = [
            "<all_urls>",
            "*://*/*",
            "http://*/*",
            "https://*/*",
            "file:///*",
        ]

        host_permissions = PrivacyComplianceAnalyzer._extract_host_permissions(manifest)
        if not host_permissions:
            return {
                "host_scope_label": "NONE",
                "patterns_count": 0,
                "domains": [],
                "has_all_urls": False,
            }

        has_all_urls = "<all_urls>" in host_permissions
        has_broad = any(pattern in host_permissions for pattern in broad_patterns)
        if has_broad:
            return {
                "host_scope_label": "ALL_WEBSITES",
                "patterns_count": len(host_permissions),
                "domains": [],
                "has_all_urls": has_all_urls,
            }

        domains = set()
        for pattern in host_permissions:
            match = re.search(
                r"(?:https?://)?(?:\*\.)?([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)",
                pattern,
            )
            if match:
                domains.add(match.group(1).lower())

        top_domains = sorted(domains)[:10]
        if len(domains) == 1:
            return {
                "host_scope_label": "SINGLE_DOMAIN",
                "patterns_count": len(host_permissions),
                "domains": top_domains,
                "has_all_urls": has_all_urls,
            }
        return {
            "host_scope_label": "MULTI_DOMAIN",
            "patterns_count": len(host_permissions),
            "domains": top_domains,
            "has_all_urls": has_all_urls,
        }

    def _extract_external_domains_from_network_payloads(self, analysis_results: Dict[str, Any]) -> List[str]:
        """Extract external domains from any available network analysis payload."""
        payload = None
        for key in self.NETWORK_KEYS:
            if analysis_results.get(key):
                payload = analysis_results.get(key)
                break

        if payload is None:
            return []

        if isinstance(payload, list):
            raw_domains = payload
        elif isinstance(payload, dict):
            raw_domains = payload.get("domains", [])
        else:
            return []

        if not isinstance(raw_domains, list):
            return []

        domains: List[str] = []
        for domain in raw_domains:
            if not isinstance(domain, str) or not domain.strip():
                continue
            # Normalize: strip scheme/path if needed
            m = re.search(r"([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)", domain)
            if m:
                domains.append(m.group(1).lower())

        return list(dict.fromkeys(domains))[:100]

    @staticmethod
    def _extract_network_evidence_from_sast(javascript_analysis: Any) -> Tuple[List[str], List[Dict[str, Any]]]:
        """
        Extract external domains + small evidence objects from SAST findings.

        Returns:
            (domains, evidence)
        """
        if not isinstance(javascript_analysis, dict):
            return [], []

        sast_findings = javascript_analysis.get("sast_findings") or {}
        if not isinstance(sast_findings, dict):
            return [], []

        url_re = re.compile(r"https?://[^\s\"')`]+", re.IGNORECASE)
        domains: List[str] = []
        evidence: List[Dict[str, Any]] = []

        for file_path, findings in sast_findings.items():
            if not isinstance(findings, list):
                continue
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                check_id = str(finding.get("check_id", "")).lower()
                extra = finding.get("extra") or {}
                message = str(extra.get("message", ""))
                category = str((extra.get("metadata") or {}).get("category", "")).lower()

                is_networkish = (
                    "third_party" in check_id
                    or "external_api" in check_id
                    or "third-party" in category
                    or "third-party api" in message.lower()
                    or "external domains" in message.lower()
                )
                if not is_networkish:
                    continue

                url_match = url_re.search(message) or url_re.search(str(extra.get("lines", "")))
                url = url_match.group(0) if url_match else None
                domain_match = re.search(
                    r"https?://([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)",
                    url or "",
                    re.IGNORECASE,
                )
                domain = domain_match.group(1).lower() if domain_match else None
                if domain:
                    domains.append(domain)

                evidence.append(
                    {
                        "source": "sast",
                        "check_id": finding.get("check_id"),
                        "file": file_path,
                        "line": (finding.get("start") or {}).get("line"),
                        "message": message[:200],
                        "url": (url[:200] if isinstance(url, str) else None),
                        "domain": domain,
                    }
                )

        domains = list(dict.fromkeys([d for d in domains if isinstance(d, str)]))[:100]
        evidence = evidence[:20]
        return domains, evidence

    def _compute_capability_flags(
        self,
        manifest: Dict[str, Any],
        analysis_results: Dict[str, Any],
        host_access_summary: Dict[str, Any],
        external_domains: List[str],
    ) -> Dict[str, bool]:
        """Compute deterministic capability flags (authoritative booleans)."""
        permissions = manifest.get("permissions", []) or []
        api_permissions = [
            p for p in permissions if isinstance(p, str) and not self._is_url_pattern(p)
        ]
        host_permissions = self._extract_host_permissions(manifest)
        host_scope_label = host_access_summary.get("host_scope_label", "NONE")

        content_scripts = manifest.get("content_scripts", []) or []
        web_accessible_resources = manifest.get("web_accessible_resources", []) or []

        screenshot_analysis = (
            (analysis_results.get("permissions_analysis", {}) or {}).get("screenshot_capture_analysis", {}) or {}
        )
        screenshot_detected = bool(screenshot_analysis.get("detected", False))

        has_content_scripts = bool(content_scripts)
        has_web_accessible_resources = bool(web_accessible_resources)
        can_read_sites = host_scope_label in ("ALL_WEBSITES", "MULTI_DOMAIN", "SINGLE_DOMAIN")

        return {
            # Data access
            "can_read_all_sites": host_scope_label == "ALL_WEBSITES",
            "can_read_specific_sites": host_scope_label in ("SINGLE_DOMAIN", "MULTI_DOMAIN"),
            "can_read_page_content": can_read_sites or has_content_scripts,
            "can_read_cookies": "cookies" in api_permissions,
            "can_read_history": "history" in api_permissions,
            "can_read_clipboard": "clipboardRead" in api_permissions,
            "can_read_downloads": "downloads" in api_permissions,
            "can_read_tabs": "tabs" in api_permissions or "activeTab" in api_permissions,
            "can_capture_screenshots": screenshot_detected
            or any(p in api_permissions for p in ["desktopCapture", "tabCapture"]),
            # Browser control
            "can_modify_page_content": has_content_scripts
            or any(p in api_permissions for p in ["scripting", "activeTab"]),
            "can_inject_scripts": has_content_scripts or "scripting" in api_permissions,
            "can_block_or_modify_network": any(
                p in api_permissions
                for p in [
                    "webRequest",
                    "webRequestBlocking",
                    "declarativeNetRequest",
                    "declarativeNetRequestWithHostAccess",
                ]
            ),
            "can_manage_extensions": "management" in api_permissions,
            "can_control_proxy": "proxy" in api_permissions,
            "can_debugger": "debugger" in api_permissions,
            # External sharing
            "can_connect_external_domains": can_read_sites,
            "has_external_domains": bool(external_domains),
            "has_externally_connectable": bool(manifest.get("externally_connectable")),
            "has_web_accessible_resources": has_web_accessible_resources,
        }

    @staticmethod
    def _scan_code_usage(
        extension_dir: Optional[str],
        needles: List[str],
        file_globs: Tuple[str, ...] = ("**/*.js", "**/*.ts", "**/*.jsx", "**/*.tsx"),
        max_files: int = 200,
        max_file_bytes: int = 750_000,
        max_evidence: int = 5,
    ) -> Dict[str, Any]:
        """Best-effort string scan for explicit API usage in source files."""
        if not extension_dir:
            return {}

        root = Path(extension_dir)
        if not root.exists() or not root.is_dir():
            return {}

        files: List[Path] = []
        for glob_pat in file_globs:
            files.extend(root.glob(glob_pat))

        # Deterministic order + cap
        files = sorted(set(files))[:max_files]

        evidence: List[Dict[str, Any]] = []
        total_hits = 0

        for fp in files:
            try:
                if fp.is_dir():
                    continue
                if fp.stat().st_size > max_file_bytes:
                    continue
                text = fp.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            for needle in needles:
                if needle in text:
                    total_hits += text.count(needle)
                    if len(evidence) < max_evidence:
                        # Capture a small snippet around the first hit
                        idx = text.find(needle)
                        start = max(0, idx - 40)
                        end = min(len(text), idx + len(needle) + 40)
                        snippet = text[start:end].replace("\n", " ")[:120]
                        evidence.append(
                            {
                                "file": str(fp.relative_to(root)).replace("\\", "/"),
                                "match": needle,
                                "snippet": snippet,
                            }
                        )

        return {
            "hits": total_hits,
            "evidence": evidence,
        }

    def _get_prompt_template(
        self,
        analysis_results: Dict[str, Any],
        manifest: Dict[str, Any],
        extension_dir: Optional[str],
        webstore_metadata: Optional[Dict[str, Any]],
    ) -> PromptTemplate:
        """Create prompt template for privacy + compliance snapshot."""
        template_str = get_prompts("privacy_compliance")
        template_str = template_str.get("privacy_compliance")
        if not template_str:
            raise ValueError("Privacy compliance prompt template not found")

        host_access_summary = self._classify_host_access_scope(manifest)

        # Evidence: external domains + network evidence (best-effort from SAST)
        external_domains = self._extract_external_domains_from_network_payloads(analysis_results)
        sast_domains, network_evidence = self._extract_network_evidence_from_sast(
            analysis_results.get("javascript_analysis")
        )

        # Merge domains (prefer explicit evidence; dedupe)
        merged_domains = list(dict.fromkeys((external_domains or []) + (sast_domains or [])))[:100]

        capability_flags = self._compute_capability_flags(
            manifest=manifest,
            analysis_results=analysis_results,
            host_access_summary=host_access_summary,
            external_domains=merged_domains,
        )

        # Optional evidence blocks (best defaults)
        storage_scan = self._scan_code_usage(
            extension_dir=extension_dir,
            needles=["chrome.storage", "browser.storage"],
        )
        cookies_scan = self._scan_code_usage(
            extension_dir=extension_dir,
            needles=["chrome.cookies", "browser.cookies"],
        )

        storage_usage_json: Any = (
            {"uses_storage": bool(storage_scan.get("hits")), **storage_scan} if storage_scan else {}
        )
        cookies_usage_json: Any = (
            {"uses_cookies_api": bool(cookies_scan.get("hits")), **cookies_scan} if cookies_scan else {}
        )

        # If we have no network evidence and no domains, keep network evidence empty as requested
        network_evidence_json: Any = network_evidence or []

        template = PromptTemplate(
            input_variables=[
                "host_access_summary_json",
                "capability_flags_json",
                "external_domains_json",
                "network_evidence_json",
                "storage_usage_json",
                "cookies_usage_json",
                "webstore_metadata_json",
            ],
            template=template_str,
            template_format="jinja2",
        ).partial(
            host_access_summary_json=self._json_block(host_access_summary),
            capability_flags_json=self._json_block(capability_flags),
            external_domains_json=self._json_block(merged_domains),
            network_evidence_json=self._json_block(network_evidence_json),
            storage_usage_json=self._json_block(storage_usage_json),
            cookies_usage_json=self._json_block(cookies_usage_json),
            webstore_metadata_json=self._json_block(webstore_metadata or {}),
        )

        return template

    def _fallback_result(
        self,
        analysis_results: Dict[str, Any],
        manifest: Dict[str, Any],
        extension_dir: Optional[str],
        webstore_metadata: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Deterministic fallback when LLM is unavailable.

        Produces a minimal, capability-based snapshot that does not claim actual collection/sharing.
        """
        host_access_summary = self._classify_host_access_scope(manifest)

        external_domains_net = self._extract_external_domains_from_network_payloads(analysis_results)
        sast_domains, network_evidence = self._extract_network_evidence_from_sast(
            analysis_results.get("javascript_analysis")
        )
        merged_domains = list(dict.fromkeys((external_domains_net or []) + (sast_domains or [])))[:100]

        capability_flags = self._compute_capability_flags(
            manifest=manifest,
            analysis_results=analysis_results,
            host_access_summary=host_access_summary,
            external_domains=merged_domains,
        )

        # Data categories (capability-based, max 6)
        categories: List[str] = []
        if capability_flags.get("can_read_page_content"):
            categories.append("Web page content")
        if capability_flags.get("can_read_tabs"):
            categories.append("Open tab URLs")
        if capability_flags.get("can_read_cookies"):
            categories.append("Cookies")
        if capability_flags.get("can_read_history"):
            categories.append("Browsing history")
        if capability_flags.get("can_read_clipboard"):
            categories.append("Clipboard")
        if capability_flags.get("can_capture_screenshots"):
            categories.append("Screenshots / screen capture")
        categories = categories[:6]

        # Governance checks (4-6)
        host_scope_label = host_access_summary.get("host_scope_label", "NONE")
        checks: List[Dict[str, str]] = []

        if host_scope_label == "ALL_WEBSITES":
            checks.append(
                {
                    "check": "Host access scope",
                    "status": "WARN",
                    "note": "Runs on all websites (broad site access).",
                }
            )
        elif host_scope_label in ("SINGLE_DOMAIN", "MULTI_DOMAIN"):
            checks.append(
                {
                    "check": "Host access scope",
                    "status": "PASS",
                    "note": "Host access appears limited to specific domains.",
                }
            )
        else:
            checks.append(
                {
                    "check": "Host access scope",
                    "status": "PASS",
                    "note": "No website host access requested.",
                }
            )

        if merged_domains or network_evidence:
            checks.append(
                {
                    "check": "External endpoints (evidence)",
                    "status": "WARN",
                    "note": "External endpoints referenced in available evidence.",
                }
            )
        else:
            checks.append(
                {
                    "check": "External endpoints (evidence)",
                    "status": "PASS",
                    "note": "No external endpoints detected in provided evidence.",
                }
            )

        sensitive_read = any(
            capability_flags.get(k)
            for k in (
                "can_read_cookies",
                "can_read_history",
                "can_read_clipboard",
                "can_capture_screenshots",
            )
        )
        checks.append(
            {
                "check": "Sensitive data access capabilities",
                "status": "WARN" if sensitive_read else "PASS",
                "note": "Some sensitive read capabilities are present." if sensitive_read else "No sensitive read capabilities detected from flags.",
            }
        )

        strong_control = any(
            capability_flags.get(k)
            for k in (
                "can_block_or_modify_network",
                "can_control_proxy",
                "can_manage_extensions",
                "can_debugger",
            )
        )
        checks.append(
            {
                "check": "High-control capabilities",
                "status": "WARN" if strong_control else "PASS",
                "note": "Some high-control browser capabilities are present." if strong_control else "No high-control capabilities detected from flags.",
            }
        )

        # Store metadata: privacy policy presence
        md = webstore_metadata or {}
        privacy_policy_url = md.get("privacy_policy") or md.get("privacyPolicy") or md.get("privacy_policy_url")
        if privacy_policy_url:
            checks.append(
                {
                    "check": "Store privacy policy",
                    "status": "PASS",
                    "note": "Privacy policy URL is present in metadata.",
                }
            )
        else:
            checks.append(
                {
                    "check": "Store privacy policy",
                    "status": "UNKNOWN" if not md else "WARN",
                    "note": "Privacy policy URL not found in provided metadata.",
                }
            )

        checks = checks[:6]

        # ---------------------------------------------------------------------
        # Compliance check: protected travel-docs / visa portal Terms of Use risk
        # ---------------------------------------------------------------------
        try:
            from extension_shield.scoring.gates import TRAVEL_DOCS_PROTECTED_DOMAINS, VISA_SLOT_ECOSYSTEM_DOMAINS

            host_perms = self._extract_host_permissions(manifest)
            host_text = " ".join([p.lower() for p in host_perms if isinstance(p, str)])
            protected_hit = any(d in host_text for d in TRAVEL_DOCS_PROTECTED_DOMAINS)

            # Ecosystem endpoints: best-effort via merged domains
            ecosystem_hit = any(
                any(d == dom or dom.endswith("." + d) for d in VISA_SLOT_ECOSYSTEM_DOMAINS)
                for dom in (merged_domains or [])
                if isinstance(dom, str)
            )

            can_automate = bool(capability_flags.get("can_inject_scripts") or capability_flags.get("can_modify_page_content"))
            can_capture = bool(capability_flags.get("can_capture_screenshots"))

            if protected_hit and (can_automate or can_capture or ecosystem_hit):
                checks.insert(
                    0,
                    {
                        "check": "US visa portal Terms of Use (no automation)",
                        "status": "FAIL",
                        "note": "Runs on usvisascheduling/ustraveldocs-style portals with automation/capture patterns; may violate site ToS and lead to account bans.",
                    },
                )
        except Exception:
            pass

        # Re-cap after insertion
        checks = checks[:6]

        # Compliance notes (capability-based, avoid PASS/FAIL claims)
        compliance: List[Dict[str, str]] = []
        # If protected ToS risk is present, explicitly surface as FAIL for site terms.
        try:
            # Mirror logic above (keep simple, deterministic)
            from extension_shield.scoring.gates import TRAVEL_DOCS_PROTECTED_DOMAINS

            host_perms = self._extract_host_permissions(manifest)
            host_text = " ".join([p.lower() for p in host_perms if isinstance(p, str)])
            protected_hit = any(d in host_text for d in TRAVEL_DOCS_PROTECTED_DOMAINS)
            if protected_hit and (capability_flags.get("can_inject_scripts") or capability_flags.get("can_capture_screenshots")):
                compliance.insert(
                    0,
                    {
                        "framework": "Site Terms (US visa portals)",
                        "status": "FAIL",
                        "note": "Automated access/scraping or document capture on visa portals can violate Terms of Use and trigger bans.",
                    },
                )
        except Exception:
            pass

        if host_scope_label == "ALL_WEBSITES" or sensitive_read or (merged_domains or network_evidence):
            compliance.append(
                {
                    "framework": "GDPR",
                    "status": "WARN",
                    "note": "Broad access may require clear disclosure and controls.",
                }
            )
            compliance.append(
                {
                    "framework": "CCPA",
                    "status": "WARN",
                    "note": "Review disclosures if personal data could be accessed.",
                }
            )
        else:
            compliance.append(
                {
                    "framework": "GDPR",
                    "status": "UNKNOWN",
                    "note": "Not assessed from available evidence.",
                }
            )
            compliance.append(
                {
                    "framework": "CCPA",
                    "status": "UNKNOWN",
                    "note": "Not assessed from available evidence.",
                }
            )
        compliance.append(
            {
                "framework": "SOC2",
                "status": "UNKNOWN",
                "note": "Not assessed from available evidence.",
            }
        )
        compliance = compliance[:4]

        # Snapshot sentence (non-alarmist, capability-based)
        parts: List[str] = []
        if host_scope_label == "ALL_WEBSITES":
            parts.append("May access content on all visited websites.")
        elif host_scope_label in ("SINGLE_DOMAIN", "MULTI_DOMAIN"):
            parts.append("Site access appears limited to specific domains.")
        else:
            parts.append("No website access requested in manifest.")

        if merged_domains or network_evidence:
            parts.append("Code may contact external endpoints.")

        privacy_snapshot = " ".join(parts)[:240]

        return {
            "privacy_snapshot": privacy_snapshot,
            "data_categories": categories,
            "governance_checks": checks,
            "compliance_notes": compliance,
        }

    def generate(
        self,
        analysis_results: Dict[str, Any],
        manifest: Dict[str, Any],
        extension_dir: Optional[str] = None,
        webstore_metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Generate privacy + compliance snapshot."""
        if not manifest:
            logger.warning("No manifest data provided for privacy compliance analysis")
            return None

        prompt = self._get_prompt_template(
            analysis_results=analysis_results or {},
            manifest=manifest or {},
            extension_dir=extension_dir,
            webstore_metadata=webstore_metadata,
        )

        model_name = os.getenv("LLM_MODEL", "rits/openai/gpt-oss-20b")
        model_parameters = {
            "temperature": 0.05,
            "max_tokens": 1024,
        }

        try:
            formatted_prompt = prompt.format_prompt()
            messages = formatted_prompt.to_messages()

            response = invoke_with_fallback(
                messages=messages,
                model_name=model_name,
                model_parameters=model_parameters,
            )

            parser = JsonOutputParser()
            result = parser.parse(
                response.content if hasattr(response, "content") else str(response)
            )
            
            if isinstance(result, dict):
                # Validate against authoritative signals
                host_access_summary = self._classify_host_access_scope(manifest)
                host_scope_label = host_access_summary.get("host_scope_label", "UNKNOWN")
                
                external_domains_net = self._extract_external_domains_from_network_payloads(analysis_results)
                sast_domains, network_evidence = self._extract_network_evidence_from_sast(
                    analysis_results.get("javascript_analysis")
                )
                merged_domains = list(dict.fromkeys((external_domains_net or []) + (sast_domains or [])))[:100]
                
                capability_flags = self._compute_capability_flags(
                    manifest=manifest,
                    analysis_results=analysis_results,
                    host_access_summary=host_access_summary,
                    external_domains=merged_domains,
                )
                
                validation = validate_privacy(
                    output=result,
                    capability_flags=capability_flags,
                    external_domains=merged_domains,
                    network_evidence=network_evidence,
                    host_scope_label=host_scope_label,
                )
                
                if not validation.ok:
                    logger.warning(
                        "LLM privacy compliance validation failed, using fallback. Reasons: %s",
                        "; ".join(validation.reasons),
                    )
                    return self._fallback_result(
                        analysis_results=analysis_results or {},
                        manifest=manifest or {},
                        extension_dir=extension_dir,
                        webstore_metadata=webstore_metadata,
                    )
                
                logger.info("Privacy compliance snapshot generated successfully")
                # Deterministic post-processing: always inject travel-docs ToS checks
                return self._inject_travel_docs_site_terms_checks(
                    result=result,
                    manifest=manifest or {},
                    analysis_results=analysis_results or {},
                )
            
            logger.warning("Privacy compliance LLM returned non-dict result; using fallback")
            fallback = self._fallback_result(
                analysis_results=analysis_results or {},
                manifest=manifest or {},
                extension_dir=extension_dir,
                webstore_metadata=webstore_metadata,
            )
            return self._inject_travel_docs_site_terms_checks(
                result=fallback,
                manifest=manifest or {},
                analysis_results=analysis_results or {},
            )
        except Exception as exc:
            # Avoid noisy stack traces in normal operation; we always have a deterministic fallback.
            logger.warning("Failed to generate privacy compliance snapshot: %s", exc)
            fallback = self._fallback_result(
                analysis_results=analysis_results or {},
                manifest=manifest or {},
                extension_dir=extension_dir,
                webstore_metadata=webstore_metadata,
            )
            return self._inject_travel_docs_site_terms_checks(
                result=fallback,
                manifest=manifest or {},
                analysis_results=analysis_results or {},
            )

    @staticmethod
    def _inject_travel_docs_site_terms_checks(
        result: Optional[Dict[str, Any]],
        manifest: Dict[str, Any],
        analysis_results: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """
        Deterministically inject US visa portal Terms-of-Use compliance checks
        into an existing privacy_compliance dict (LLM or fallback).
        """
        if not isinstance(result, dict):
            return result

        try:
            from extension_shield.scoring.gates import TRAVEL_DOCS_PROTECTED_DOMAINS, VISA_SLOT_ECOSYSTEM_DOMAINS

            host_perms = PrivacyComplianceAnalyzer._extract_host_permissions(manifest or {})
            host_text = " ".join([p.lower() for p in host_perms if isinstance(p, str)])
            protected_hit = any(d in host_text for d in TRAVEL_DOCS_PROTECTED_DOMAINS)

            # Best-effort: external domains from network payloads (if present)
            external_domains_net: List[str] = []
            try:
                external_domains_net = PrivacyComplianceAnalyzer()._extract_external_domains_from_network_payloads(analysis_results or {})
            except Exception:
                external_domains_net = []

            ecosystem_hit = any(
                any(d == dom or dom.endswith("." + d) for d in VISA_SLOT_ECOSYSTEM_DOMAINS)
                for dom in (external_domains_net or [])
                if isinstance(dom, str)
            )

            # Capabilities derived from permissions_analysis if available
            host_access_summary = PrivacyComplianceAnalyzer._classify_host_access_scope(manifest or {})
            capability_flags = PrivacyComplianceAnalyzer()._compute_capability_flags(
                manifest=manifest or {},
                analysis_results=analysis_results or {},
                host_access_summary=host_access_summary,
                external_domains=external_domains_net,
            )

            can_automate = bool(capability_flags.get("can_inject_scripts") or capability_flags.get("can_modify_page_content"))
            can_capture = bool(capability_flags.get("can_capture_screenshots"))

            if not (protected_hit and (can_automate or can_capture or ecosystem_hit)):
                return result

            checks = result.get("governance_checks")
            if not isinstance(checks, list):
                checks = []

            tos_row = {
                "check": "US visa portal Terms of Use (no automation)",
                "status": "FAIL",
                "note": "Runs on usvisascheduling/ustraveldocs-style portals with automation/capture patterns; may violate site ToS and lead to account bans.",
            }
            # Prepend if not already present
            if not any(isinstance(r, dict) and r.get("check") == tos_row["check"] for r in checks):
                checks = [tos_row] + checks
            result["governance_checks"] = checks[:6]

            notes = result.get("compliance_notes")
            if not isinstance(notes, list):
                notes = []
            note_row = {
                "framework": "Site Terms (US visa portals)",
                "status": "FAIL",
                "note": "Automated access/scraping or document capture on visa portals can violate Terms of Use and trigger bans.",
            }
            if not any(isinstance(r, dict) and r.get("framework") == note_row["framework"] for r in notes):
                notes = [note_row] + notes
            result["compliance_notes"] = notes[:4]

            return result
        except Exception:
            return result


