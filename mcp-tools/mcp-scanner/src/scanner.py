"""
Core Scanner Module

Provides the main Scanner class for orchestrating vulnerability scans
across MCP server deployments.
"""

import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

from .analyzer import AnalyzerEngine
from .cve_matcher import CVEMatcher
from .dependency_inspector import DependencyInspector
from .config_parser import ConfigParser
from .report_generator import ReportGenerator

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Container for scan results."""

    target_path: str
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    dependencies: List[Dict[str, Any]] = field(default_factory=list)
    configuration_drift: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    scan_timestamp: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "target_path": self.target_path,
            "vulnerabilities": self.vulnerabilities,
            "dependencies": self.dependencies,
            "configuration_drift": self.configuration_drift,
            "metadata": self.metadata,
            "scan_timestamp": self.scan_timestamp,
        }


class Scanner:
    """
    Main scanner class for MCP server vulnerability assessment.

    Orchestrates multiple analysis engines to provide comprehensive
    vulnerability detection and reporting capabilities.
    """

    def __init__(self, config_path: Optional[Path] = None):
        """
        Initialize the Scanner.

        Args:
            config_path: Path to scanner configuration file.
        """
        self.config_path = config_path
        self.analyzer = AnalyzerEngine()
        self.cve_matcher = CVEMatcher()
        self.dependency_inspector = DependencyInspector()
        self.config_parser = ConfigParser()
        self.report_generator = ReportGenerator()

        self._scan_results: List[ScanResult] = []

    def scan(self, target_path: Path,
             options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """
        Perform a comprehensive scan of the target MCP server.

        Args:
            target_path: Path to the MCP server to scan.
            options: Additional scan options.

        Returns:
            ScanResult containing all findings.
        """
        logger.info(f"Starting scan for target: {target_path}")

        result = ScanResult(target_path=str(target_path))

        # Run analyzer engine
        vulnerabilities = self.analyzer.analyze(target_path)
        result.vulnerabilities = vulnerabilities

        # Run CVE matcher
        cve_matches = self.cve_matcher.match(vulnerabilities)
        result.vulnerabilities.extend(cve_matches)

        # Run dependency inspector
        dependencies = self.dependency_inspector.inspect(target_path)
        result.dependencies = dependencies

        # Run config parser for drift detection
        drift = self.config_parser.parse(target_path)
        result.configuration_drift = drift

        # Add metadata
        result.metadata = {
            "scan_options": options or {},
            "analyzer_stats": self.analyzer.get_stats(),
            "cve_database_version": self.cve_matcher.get_version(),
        }

        self._scan_results.append(result)

        logger.info(f"Scan completed with {len(vulnerabilities)} vulnerabilities found")

        return result

    def generate_report(self, result: ScanResult,
                       format: str = "html",
                       output_path: Optional[Path] = None) -> Path:
        """
        Generate a report from scan results.

        Args:
            result: ScanResult to generate report from.
            format: Output format (html, pdf, json).
            output_path: Path for the generated report.

        Returns:
            Path to the generated report.
        """
        report_path = self.report_generator.generate(
            result=result,
            format=format,
            output_path=output_path,
        )

        return report_path

    def get_results(self) -> List[ScanResult]:
        """Return all scan results."""
        return self._scan_results
