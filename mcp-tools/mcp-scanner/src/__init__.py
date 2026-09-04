"""
MCP Scanner Package

A comprehensive vulnerability scanner for MCP server deployments
with pattern-based analysis, CVE matching, and reporting capabilities.
"""

from .scanner import Scanner, ScanResult
from .analyzer import AnalyzerEngine, Vulnerability
from .cve_matcher import CVEMatcher, CVEEntry
from .dependency_inspector import DependencyInspector, Dependency
from .config_parser import ConfigParser
from .report_generator import ReportGenerator

__version__ = "1.0.0"
__all__ = [
    "Scanner",
    "ScanResult",
    "AnalyzerEngine",
    "Vulnerability",
    "CVEMatcher",
    "CVEEntry",
    "DependencyInspector",
    "Dependency",
    "ConfigParser",
    "ReportGenerator",
]
