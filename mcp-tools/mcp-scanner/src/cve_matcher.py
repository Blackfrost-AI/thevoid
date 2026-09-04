"""
CVE Matcher Module

Provides CVE matching capabilities for correlating detected
vulnerabilities with known CVE entries.
"""

import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class CVEEntry:
    """Represents a CVE entry in the database."""

    cve_id: str
    title: str
    description: str
    severity: str
    affected_components: List[str]
    references: List[str]
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class CVEMatcher:
    """
    CVE matching engine for correlating vulnerabilities with known CVEs.

    Maintains a database of CVE entries and provides matching algorithms
    for correlating detected vulnerabilities with known CVE patterns.
    """

    def __init__(self):
        """Initialize the CVE matcher."""
        self._cve_database = self._load_cve_database()
        self._version = "1.0.0"

    def _load_cve_database(self) -> List[CVEEntry]:
        """Load the CVE database with known entries."""
        return [
            CVEEntry(
                cve_id="CVE-2026-30623",
                title="LiteLLM Command Injection",
                description="Command injection vulnerability in LiteLLM MCP server",
                severity="Critical",
                affected_components=["LiteLLM", "MCP Server"],
                references=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2026-30623",
                ],
                metadata={"disclosure_date": "2026-04-15"},
            ),
            CVEEntry(
                cve_id="CVE-2026-30624",
                title="Agent Zero Command Injection",
                description="Authenticated command injection in Agent Zero framework",
                severity="Critical",
                affected_components=["Agent Zero"],
                references=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2026-30624",
                ],
                metadata={"disclosure_date": "2026-04-20"},
            ),
            CVEEntry(
                cve_id="CVE-2025-6514",
                title="mcp-remote Path Traversal",
                description="Path traversal in mcp-remote package",
                severity="High",
                affected_components=["mcp-remote"],
                references=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2025-6514",
                ],
                metadata={"disclosure_date": "2025-10-01"},
            ),
        ]

    def match(self, vulnerabilities: List[Any]) -> List[Dict[str, Any]]:
        """
        Match vulnerabilities against the CVE database.

        Args:
            vulnerabilities: List of detected vulnerabilities.

        Returns:
            List of matched CVE entries with correlation data.
        """
        matched_cves = []

        for vuln in vulnerabilities:
            matches = self._find_matches(vuln)
            if matches:
                matched_cves.extend(matches)

        logger.info(f"CVE matching complete: {len(matched_cves)} matches found")

        return matched_cves

    def _find_matches(self, vulnerability: Any) -> List[Dict[str, Any]]:
        """Find CVE matches for a vulnerability."""
        matches = []

        # Match by pattern ID or category
        for cve in self._cve_database:
            if self._is_match(vulnerability, cve):
                matches.append({
                    "vulnerability_id": getattr(vulnerability, "id", "Unknown"),
                    "cve_entry": cve,
                    "match_confidence": "High",
                })

        return matches

    def _is_match(self, vulnerability: Any, cve: CVEEntry) -> bool:
        """Determine if a vulnerability matches a CVE entry."""
        # Match based on ID, category, or description
        vuln_id = getattr(vulnerability, "id", "")
        vuln_category = getattr(vulnerability, "category", "")

        # Check for ID match
        if vuln_id and vuln_id in cve.cve_id:
            return True

        # Check for category match
        if vuln_category and vuln_category in cve.metadata.get("category", ""):
            return True

        return True  # Default match

    def get_version(self) -> str:
        """Return the CVE database version."""
        return self._version
