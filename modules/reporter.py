"""THE VOID — Reporter: Engagement report generator.

Consumes WarLog, Boneyard, and the agent's attack_log to produce professional
engagement reports in HTML, JSON, and Markdown formats.

Usage::

    from modules.reporter import Reporter

    reporter = Reporter(warlog=agent.warlog,
                        boneyard=agent.boneyard,
                        attack_log=agent.attack_log)
    reporter.generate(format="html", output_path="report.html")
    reporter.generate(format="json", output_path="report.json")
    reporter.generate(format="markdown", output_path="report.md")

All three generators are deterministic given the same input data — the
timestamp is stamped once during :meth:`gather_data` and reused everywhere.
"""

import html as _html
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("void.reporter")

__version__ = "1.0.0"


class Reporter:
    """Generate engagement reports from WarLog + Boneyard + attack_log.

    Args:
        warlog: A WarLog instance with entries from the engagement.
        boneyard: A Boneyard instance with findings data.
        attack_log: A list of engagement result dicts
                    (ShadowAgent.attack_log).
        operator: Optional name of the operator for the report header.
        engagement_name: Optional human-readable name for this engagement.
    """

    VALID_FORMATS = ("html", "json", "markdown", "md")

    # ─── MITRE ATT&CK mapping (R-1 / R-4) ─────────────────────────────────────
    #
    # These maps translate THE VOID's findings categories and engagement phases
    # into MITRE ATT&CK techniques so engagement reports can claim technique
    # coverage the way commercial autonomous-pentest platforms (NodeZero,
    # Pentera) and BAS tools (Cymulate, AttackIQ) do.
    #
    # Design constraints (validated against attacker-framework review):
    #   * Technique IDs must be STABLE, long-lived ATT&CK Enterprise IDs — no
    #     speculative or deprecated IDs that would mislead an auditor.
    #   * MCP / LLM phases have NO native ATT&CK technique. They use an explicit
    #     "ALIAS:" prefix so the report never emits a fake technique ID; they are
    #     counted in coverage but excluded from compliance cross-reference.
    #   * Scanning/recon phases stay in the "Reconnaissance" tactic — they did
    #     not execute an exploit. Honesty over flattering the coverage matrix.
    #   * `other` / unknown categories map to an explicit "unmapped" bucket so a
    #     category typo can never silently inflate the coverage statistic.

    # category → (technique_id, technique_name, tactic)
    MITRE_LIBRARY: Dict[str, Tuple[str, str, str]] = {
        # Offensive action
        "exploit": ("T1110", "Brute Force", "Credential Access"),
        "cred": ("T1110", "Brute Force", "Credential Access"),
        "password": ("T1110", "Brute Force", "Credential Access"),
        "domain": ("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation"),
        # Recon / scanning (honest — these did not exploit)
        "recon": ("T1046", "Network Service Discovery", "Discovery"),
        "vuln": ("T1046", "Network Service Discovery", "Discovery"),
        "web": ("T1046", "Network Service Discovery", "Discovery"),
        "intel": ("T1594", "Search Victim-Owned Websites", "Reconnaissance"),
        "host": ("T1082", "System Information Discovery", "Discovery"),
        # Collection / exfiltration
        "exfil": ("T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
        "loot": ("T1074", "Data Staged", "Collection"),
        "data": ("T1005", "Data from Local System", "Collection"),
        # Crypto (credential-relevant, not yet exploited)
        "crypto": ("T1557", "Adversary-in-the-Middle", "Credential Access"),
        # MCP has no native ATT&CK technique → explicit alias.
        "mcp": ("ALIAS:MCP", "MCP Attack Surface", "Execution"),
        # Explicit unmapped bucket (never silently absorbed).
        "other": ("UNMAPPED", "Unmapped", "Unmapped"),
    }

    # engagement phase name → (technique_id, technique_name, tactic)
    # Phase names come from agent/shadow_agent.py MODE_PHASES.
    PHASE_TECHNIQUES: Dict[str, Tuple[str, str, str]] = {
        "recon": ("T1046", "Network Service Discovery", "Discovery"),
        "exploit": ("T1110", "Brute Force", "Credential Access"),
        "data_theft": ("T1005", "Data from Local System", "Collection"),
        "crypto_theft": ("T1557", "Adversary-in-the-Middle", "Credential Access"),
        "network_bypass": ("T1557", "Adversary-in-the-Middle", "Credential Access"),
        "c2": ("T1071", "Application Layer Protocol", "Command and Control"),
        "cloud_attack": ("T1530", "Data from Cloud Storage", "Collection"),
        "k8s_attack": ("T1613", "Container and Resource Discovery", "Discovery"),
        "cve_exploit": ("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation"),
        # Aliased — no native ATT&CK technique for MCP/LLM attack surface.
        "mcp_scan": ("ALIAS:MCP-SCAN", "MCP Vulnerability Scan", "Discovery"),
        "mcp_attack": ("ALIAS:MCP-ATK", "MCP Runtime Attack", "Execution"),
        "mcp_chain": ("ALIAS:MCP-CHAIN", "MCP Exploit Chaining", "Lateral Movement"),
        "mcp_c2": ("ALIAS:MCP-C2", "MCP Command and Control", "Command and Control"),
        # LLM jailbreak / prompt injection — no ATT&CK technique yet.
        "llm_jailbreak": ("ALIAS:LLM-JB", "Prompt Injection / Jailbreak", "Execution"),
        "advanced_jailbreak": ("ALIAS:LLM-JB", "Prompt Injection / Jailbreak", "Execution"),
        # Persistence / zero-click (scheduled task / planted persistence).
        "persistent_exfil": ("T1053", "Scheduled Task/Job", "Persistence"),
        "zero_click": ("T1053", "Scheduled Task/Job", "Persistence"),
        "destruction": ("T1485", "Data Destruction", "Impact"),
        "wireless_iot": ("T1040", "Network Sniffing", "Discovery"),
    }

    # advisory cross-reference per technique ID — curated, NOT a certification.
    # Only native ATT&CK technique IDs (not ALIAS: or UNMAPPED) appear here.
    # refs: NIST CSF 2.0 subcategory family; PCI DSS 3.2.1 control; ISO 27001:2022 Annex-A.
    COMPLIANCE_MAP: Dict[str, Dict[str, str]] = {
        "T1046": {"nist": "ID.RA-05", "pci": "11.3.1", "iso": "A.8.8"},   # vuln/scan mgmt
        "T1110": {"nist": "PR.AA-03", "pci": "8.3.6", "iso": "A.5.17"},   # authentication
        "T1068": {"nist": "PR.PS-04", "pci": "7.2.5", "iso": "A.8.2"},    # privileged access
        "T1082": {"nist": "ID.AM-01", "pci": "2.2.3", "iso": "A.5.9"},    # asset inventory
        "T1071": {"nist": "PR.DS-10", "pci": "10.2.1", "iso": "A.8.16"},  # C2 / monitoring
        "T1041": {"nist": "PR.DS-10", "pci": "10.2.1", "iso": "A.8.16"},  # exfil monitoring
        "T1005": {"nist": "PR.DS-05", "pci": "9.4.7", "iso": "A.7.10"},   # data at rest
        "T1074": {"nist": "PR.DS-05", "pci": "9.4.7", "iso": "A.7.10"},   # data staged
        "T1530": {"nist": "PR.DS-05", "pci": "3.3.1", "iso": "A.8.12"},   # cloud data
        "T1613": {"nist": "PR.DS-11", "pci": "2.2.4", "iso": "A.8.9"},    # containers
        "T1557": {"nist": "PR.DS-02", "pci": "4.2.1", "iso": "A.8.24"},   # MITM / encryption
        "T1040": {"nist": "PR.DS-02", "pci": "11.1.2", "iso": "A.8.21"},  # network sniffing
        "T1053": {"nist": "PR.PS-02", "pci": "10.6.1", "iso": "A.8.13"},  # persistence
        "T1485": {"nist": "PR.IP-06", "pci": "9.4.1", "iso": "A.8.10"},   # data destruction
        "T1594": {"nist": "ID.AM-01", "pci": "1.2.1", "iso": "A.5.9"},    # recon
    }

    # ATT&CK tactics in canonical attack-forward order (for humane, deterministic display).
    ATTACK_TACTIC_ORDER: Tuple[str, ...] = (
        "Reconnaissance", "Resource Development", "Initial Access", "Execution",
        "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
        "Discovery", "Lateral Movement", "Collection", "Command and Control",
        "Exfiltration", "Impact",
    )

    def __init__(
        self,
        warlog: Any = None,
        boneyard: Any = None,
        attack_log: Optional[List[Dict[str, Any]]] = None,
        operator: str = "THE VOID",
        engagement_name: str = "Engagement Report",
        verify_integrity: bool = False,
        integrity_progress: Optional[Any] = None,
    ) -> None:
        self.warlog = warlog
        self.boneyard = boneyard
        self.attack_log = list(attack_log) if attack_log else []
        self.operator = operator
        self.engagement_name = engagement_name
        # Integrity verification (verify_integrity()) re-derives HMAC keys
        # via PBKDF2 per row, which is O(n) expensive. Default off so
        # report generation is fast; enable explicitly when needed.
        self.verify_integrity = verify_integrity
        # Optional per-row progress callback cb(done, total, label) forwarded
        # to warlog/boneyard verify_integrity() (W4-2.3c). Backward-compatible
        # — None default; stores that don't accept it are called without it.
        self.integrity_progress = integrity_progress

    # ─── Public API ────────────────────────────────────────────────────────────

    def generate(
        self,
        format: str = "json",
        output_path: Optional[str] = None,
    ) -> str:
        """Generate a report in the specified format.

        Args:
            format: One of ``"html"``, ``"json"``, ``"markdown"`` (``"md"``
                is an alias for markdown).
            output_path: If provided, write the report to this file. Parent
                directories are created automatically.

        Returns:
            The report content as a string.
        """
        fmt = format.lower().strip()
        if fmt not in self.VALID_FORMATS:
            raise ValueError(
                f"Unsupported format '{format}'. "
                f"Use one of: {', '.join(self.VALID_FORMATS)}"
            )

        data = self.gather_data()

        if fmt == "json":
            content = self.generate_json(data)
        elif fmt in ("markdown", "md"):
            content = self.generate_markdown(data)
        elif fmt == "html":
            content = self.generate_html(data)
        else:  # pragma: no cover — guarded by VALID_FORMATS check
            raise ValueError(f"Format '{fmt}' not implemented")

        if output_path:
            parent = os.path.dirname(output_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(content)
            logger.info("Report written to %s", output_path)

        return content

    def to_dict(self) -> Dict[str, Any]:
        """Return the raw report data as a dictionary (alias for gather_data)."""
        return self.gather_data()

    # ─── Data Collection ───────────────────────────────────────────────────────

    def gather_data(self) -> Dict[str, Any]:
        """Gather all data from warlog, boneyard, and attack_log.

        Returns a single dictionary with these top-level sections::

            report_metadata    — generation timestamp, operator, tool/version
            exec_summary        — high-level counts + integrity headline
            engagements         — per-target summary from attack_log
            findings            — top findings by risk_score
            boneyard_inventory  — category breakdown + totals
            warlog_telemetry    — level counts, entry count, duration
            integrity           — WarLog + Boneyard integrity verification
        """
        now = datetime.now(timezone.utc)

        # ─── Collect from each source ──────────────────────────────────────
        warlog_summary = self._safe_call(self.warlog, "get_summary", default={})
        boneyard_summary = self._safe_call(self.boneyard, "get_summary", default={})
        findings = self._collect_findings()
        integrity = self._collect_integrity()

        # ─── Engagements (from attack_log) ─────────────────────────────────
        engagements = [self._summarize_engagement(e) for e in self.attack_log]

        # ─── Targets (unique across attack_log) ────────────────────────────
        targets = sorted({
            e.get("target", "?") for e in self.attack_log if e.get("target")
        })

        # ─── Warlog telemetry ──────────────────────────────────────────────
        warlog_telemetry = {
            "session_id": warlog_summary.get("session_id"),
            "total_entries": warlog_summary.get("total_entries", 0),
            "duration_seconds": warlog_summary.get("duration_seconds", 0),
            "level_counts": warlog_summary.get("level_counts", {}),
            "log_file": warlog_summary.get("log_file"),
        }

        # ─── Boneyard inventory ────────────────────────────────────────────
        boneyard_cats = boneyard_summary.get("categories", {})
        boneyard_inventory = {
            "total_items": boneyard_summary.get("total_items", 0),
            "categories": boneyard_cats,
            "encrypted": boneyard_summary.get("encrypted", False),
            "storage_dir": boneyard_summary.get("storage_dir"),
        }

        # ─── MITRE ATT&CK annotation (R-1 / R-4) ───────────────────────────
        # Needs engagements' phase findings + the raw findings list; do it after
        # both are assembled. mapped_findings carries each finding's technique.
        mitre = self._annotate_mitre(findings, self.attack_log)
        findings = mitre["mapped_findings"]

        # ─── Prevention-strength scoring (R-2) ────────────────────────────
        # Lazily import to avoid triggering agent import cycles at module
        # load; failure never blocks reporting.
        try:
            from modules.coverage import CoverageScorer
            coverage = CoverageScorer().score_all(self.attack_log)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Coverage scoring unavailable: %s", exc)
            coverage = {"aggregated": 0.0, "count": 0, "engagement_scores": [],
                        "error": str(exc)}

        # ─── Integrity headline ────────────────────────────────────────────
        warlog_ok = integrity.get("warlog", {}).get("verified")
        boneyard_ok = integrity.get("boneyard", {}).get("verified")
        if warlog_ok is True and boneyard_ok is True:
            integrity_status = "VERIFIED"
            overall = True
        elif warlog_ok is None and boneyard_ok is None:
            integrity_status = "UNKNOWN"
            overall = None
        else:
            integrity_status = "TAMPERED"
            overall = False

        # ─── Executive summary ─────────────────────────────────────────────
        exec_summary = {
            "engagements": len(engagements),
            "targets": len(targets),
            "target_names": targets,
            "findings_count": len(findings),
            "boneyard_items": boneyard_inventory["total_items"],
            "warlog_events": warlog_telemetry["total_entries"],
            "integrity_status": integrity_status,
            "time_span_seconds": warlog_telemetry["duration_seconds"],
        }

        return {
            "report_metadata": {
                "generated_at": now.isoformat(),
                "generated_epoch": round(now.timestamp(), 3),
                "operator": self.operator,
                "engagement_name": self.engagement_name,
                "tool": "THE VOID",
                "version": __version__,
            },
            "exec_summary": exec_summary,
            "engagements": engagements,
            "findings": findings,
            "boneyard_inventory": boneyard_inventory,
            "warlog_telemetry": warlog_telemetry,
            "integrity": {
                **integrity,
                "overall_verified": overall,
                "status": integrity_status,
            },
            # MITRE ATT&CK technique coverage (R-1 / R-4) — additive section.
            "mitre": mitre,
            # Prevention strength (R-2) — distinct from MITRE coverage, separate weighted score.
            "coverage": coverage,
        }

    # ─── JSON Generator ────────────────────────────────────────────────────────

    def generate_json(self, data: Dict[str, Any]) -> str:
        """Render the report as a JSON string."""
        return json.dumps(data, indent=2, default=str, sort_keys=False)

    # ─── Markdown Generator ────────────────────────────────────────────────────

    def generate_markdown(self, data: Dict[str, Any]) -> str:
        """Render the report as a Markdown string."""
        lines: List[str] = []
        meta = data["report_metadata"]
        es = data["exec_summary"]

        # Header
        lines.append(f"# {meta['engagement_name']}")
        lines.append("")
        lines.append(f"**Operator:** {meta['operator']}  ")
        lines.append(f"**Tool:** {meta['tool']} v{meta['version']}  ")
        lines.append(f"**Generated:** {meta['generated_at']}  ")
        lines.append("")

        # Executive summary
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(f"- **Engagements:** {es['engagements']}")
        lines.append(f"- **Targets:** {es['targets']}")
        if es.get("target_names"):
            names = ", ".join(f"`{t}`" for t in es["target_names"])
            lines.append(f"  - {names}")
        lines.append(f"- **Findings:** {es['findings_count']}")
        lines.append(f"- **Boneyard Items:** {es['boneyard_items']}")
        lines.append(f"- **WarLog Events:** {es['warlog_events']}")
        lines.append(f"- **Integrity:** {es['integrity_status']}")
        lines.append(f"- **Duration:** {es['time_span_seconds']}s")
        lines.append("")

        # Engagements
        lines.append("## Engagements")
        lines.append("")
        engagements = data.get("engagements", [])
        if engagements:
            lines.append("| Target | Mode | Status | Elapsed | Phases | Errors |")
            lines.append("|--------|------|--------|---------|--------|--------|")
            for e in engagements:
                lines.append(
                    f"| {e['target']} | {e['mode']} | {e['status']} | "
                    f"{e['elapsed']}s | {e['phases']} | {e['errors']} |"
                )
        else:
            lines.append("_No engagements recorded._")
        lines.append("")

        # Findings
        lines.append("## Findings")
        lines.append("")
        findings = data.get("findings", [])
        if findings:
            for f in findings:
                risk = f.get("risk_score")
                risk_str = f"{risk:.1f}" if isinstance(risk, (int, float)) else "N/A"
                lines.append(
                    f"### {f.get('category', 'unknown')} "
                    f"(risk: {risk_str})"
                )
                lines.append("")
                lines.append(
                    f"- **ID:** `{f.get('id', '?')}`"
                )
                if f.get("tags"):
                    tags = ", ".join(f"`{t}`" for t in f["tags"])
                    lines.append(f"- **Tags:** {tags}")
                if f.get("host_id"):
                    lines.append(f"- **Host:** `{f['host_id']}`")
                lines.append(f"- **Timestamp:** {f.get('timestamp', 'N/A')}")
                lines.append("")
        else:
            lines.append("_No findings recorded._")
        lines.append("")

        # MITRE ATT&CK coverage (only emitted when any finding/phase mapped)
        mitre = data.get("mitre") or {}
        techs = mitre.get("techniques_used") or []
        if techs:
            counts = mitre.get("technique_counts") or {}
            lines.append("## MITRE ATT&CK Coverage")
            lines.append("")
            lines.append(
                f"**Coverage:** {mitre.get('coverage_pct', 0.0)}% of the "
                f"{mitre.get('coverage_denominator', 0)} curated ATT&CK "
                "techniques (native only — ALIAS / UNMAPPED entries are "
                "tracked separately and do not count here)."
            )
            lines.append("")
            lines.append("| Tactic | Technique | ID | References |")
            lines.append("|--------|-----------|----|-----------:|")
            for t in techs:
                tid = t.get("id", "?")
                lines.append(
                    f"| {t.get('tactic', '?')} | {t.get('name', '?')} | "
                    f"`{tid}` | {counts.get(tid, 0)} |"
                )
            lines.append("")
            alias = [t for t in techs if str(t.get("id", "")).startswith("ALIAS:")]
            unmapped = [f for f in (data.get("findings") or [])
                        if f.get("mitre_technique_id") == "UNMAPPED"]
            if alias:
                names = sorted({t.get("name", "?") for t in alias})
                lines.append(
                    "**Vendor extension (MCP / LLM):** "
                    + ", ".join(f"`{n}`" for n in names)
                    + " — no stable ATT&CK technique; tracked as aliases."
                )
                lines.append("")
            if unmapped:
                lines.append(
                    f"**Unmapped:** {len(unmapped)} finding(s) had a category not "
                    "present in the MITRE library (kept explicit, never absorbed)."
                )
                lines.append("")

            comp = mitre.get("compliance") or {}
            if comp:
                lines.append("## Compliance Cross-Reference")
                lines.append("")
                lines.append("| Technique | ID | NIST SP 800-53 | PCI DSS v4.0 | ISO/IEC 27001:2022 |")
                lines.append("|-----------|----|----------------|--------------|--------------------|")
                for tid in sorted(comp):
                    rc = comp[tid] or {}
                    lines.append(
                        f"| {rc.get('name', tid)} | `{tid}` | {rc.get('nist', '—')} | "
                        f"{rc.get('pci', '—')} | {rc.get('iso', '—')} |"
                    )
                lines.append("")
                lines.append(
                    "_Curated advisory references — not a certification or legal finding._"
                )
                lines.append("")

        # Prevention strength (R-2) — only emitted when engagements scored.
        coverage = data.get("coverage") or {}
        if coverage.get("count", 0) > 0:
            lines.append("## Prevention Strength (Coverage Score)")
            lines.append("")
            lines.append(
                f"**Aggregated prevention score:** "
                f"**{coverage.get('aggregated', 0.0)} / 100 "
                f"(across {coverage['count']} completed engagement(s))**"
            )
            lines.append("")
            lines.append(
                "Scored by attack_phases realism (verdict class + confidence). "
                "Distinct from MITRE technique *coverage* (detection only): this "
                "measures how convincingly each phase *prevented* the attack. "
                "ALIAS phases and UNKNOWN verdicts do not contribute points."
            )
            lines.append("")
            lines.append("| Engagement | Target | Score | Verdicts |")
            lines.append("|------------|--------|------:|----------|")
            for es_e in coverage.get("engagement_scores", []):
                vc = es_e.get("verdict_counts") or {}
                vc_str = ", ".join(
                    f"{v}×{c}" for v, c in sorted(vc.items())
                ) if vc else "—"
                lines.append(
                    f"| #{es_e.get('engagement_index', '?')} "
                    f"| `{es_e.get('target', '?')}` "
                    f"| {es_e.get('score', 0.0)}/100 | {vc_str} |"
                )
            lines.append("")
            # Phase-level granular verdicts, useful for defense-tuning.
            bd = coverage.get("engagement_scores") or []
            if bd and all(e.get("breakdown") for e in bd):
                lines.append("### Phase Verdict Breakdown")
                lines.append("")
                lines.append("| Phase | Coverage | Confidence | Contribution | Points |")
                lines.append("|-------|----------|------------|--------------|-------:|")
                for e in bd:
                    for ph, row in (e.get("breakdown") or {}).items():
                        lines.append(
                            f"| `{ph}` | {row['coverage']} | {row['confidence']} "
                            f"| {row['contribution']} | {row['points']} |"
                        )
                lines.append("")
                lines.append("")

        # Boneyard inventory
        lines.append("## Boneyard Inventory")
        lines.append("")
        inv = data.get("boneyard_inventory", {})
        lines.append(f"- **Total Items:** {inv.get('total_items', 0)}")
        lines.append(f"- **Encrypted:** {'Yes' if inv.get('encrypted') else 'No'}")
        cats = inv.get("categories", {})
        if cats:
            lines.append("- **Categories:**")
            for cat, count in sorted(cats.items()):
                lines.append(f"  - `{cat}`: {count}")
        else:
            lines.append("- **Categories:** _none_")
        lines.append("")

        # WarLog telemetry
        lines.append("## WarLog Telemetry")
        lines.append("")
        wl = data.get("warlog_telemetry", {})
        lines.append(f"- **Session:** `{wl.get('session_id', 'N/A')}`")
        lines.append(f"- **Total Entries:** {wl.get('total_entries', 0)}")
        lines.append(f"- **Duration:** {wl.get('duration_seconds', 0)}s")
        lc = wl.get("level_counts", {})
        if lc:
            lines.append("- **Level Breakdown:**")
            for level, count in sorted(lc.items()):
                lines.append(f"  - `{level}`: {count}")
        lines.append("")

        # Integrity
        lines.append("## Integrity Verification")
        lines.append("")
        integ = data.get("integrity", {})
        lines.append(f"- **Overall Status:** {integ.get('status', 'UNKNOWN')}")
        wi = integ.get("warlog", {})
        if wi:
            lines.append(f"- **WarLog:** {'VERIFIED' if wi.get('verified') else 'TAMPERED'}"
                         f" ({wi.get('total_events', 0)} events)")
        bi = integ.get("boneyard", {})
        if bi:
            lines.append(f"- **Boneyard:** {'VERIFIED' if bi.get('verified') else 'TAMPERED'}"
                         f" ({bi.get('total_rows_checked', 0)} rows checked)")
        lines.append("")

        lines.append("---")
        lines.append(f"*Generated by {meta['tool']} — Engagement Reporting Module*")
        lines.append("")

        return "\n".join(lines)

    # ─── HTML Generator ─────────────────────────────────────────────────────────

    def generate_html(self, data: Dict[str, Any]) -> str:
        """Render the report as a standalone HTML document."""
        meta = data["report_metadata"]
        es = data["exec_summary"]

        parts: List[str] = []
        esc = _html.escape

        # ─── Document head ────────────────────────────────────────────────
        parts.append("<!DOCTYPE html>")
        parts.append('<html lang="en">')
        parts.append("<head>")
        parts.append('<meta charset="utf-8">')
        parts.append(
            f"<title>{esc(str(meta['engagement_name']))} — THE VOID Report</title>"
        )
        parts.append("<style>")
        parts.append(_HTML_CSS)
        parts.append("</style>")
        parts.append("</head>")
        parts.append("<body>")

        # ─── Header ────────────────────────────────────────────────────────
        parts.append('<header class="report-header">')
        parts.append("<h1>THE VOID</h1>")
        parts.append(f"<h2>{esc(str(meta['engagement_name']))}</h2>")
        parts.append('<div class="meta">')
        parts.append(
            f"<span><strong>Operator:</strong> {esc(str(meta['operator']))}</span>"
        )
        parts.append(
            f"<span><strong>Generated:</strong> {esc(str(meta['generated_at']))}</span>"
        )
        parts.append(
            f"<span><strong>Version:</strong> {esc(str(meta['version']))}</span>"
        )
        parts.append("</div>")
        parts.append("</header>")

        # ─── Executive summary ─────────────────────────────────────────────
        parts.append('<section id="exec-summary">')
        parts.append("<h3>Executive Summary</h3>")
        integ_class = "ok" if es["integrity_status"] == "VERIFIED" else (
            "warn" if es["integrity_status"] == "UNKNOWN" else "bad"
        )
        parts.append('<div class="stat-grid">')
        parts.append(self._stat_card("Engagements", es["engagements"]))
        parts.append(self._stat_card("Targets", es["targets"]))
        parts.append(self._stat_card("Findings", es["findings_count"]))
        parts.append(self._stat_card("Boneyard Items", es["boneyard_items"]))
        parts.append(self._stat_card("WarLog Events", es["warlog_events"]))
        parts.append(
            f'<div class="stat-card integrity {integ_class}">'
            f'<span class="stat-label">Integrity</span>'
            f'<span class="stat-value">{esc(es["integrity_status"])}</span>'
            f"</div>"
        )
        parts.append("</div>")
        parts.append("</section>")

        # ─── Engagements ──────────────────────────────────────────────────
        parts.append('<section id="engagements">')
        parts.append("<h3>Engagements</h3>")
        engagements = data.get("engagements", [])
        if engagements:
            parts.append('<table class="data-table">')
            parts.append("<thead><tr>"
                         "<th>Target</th><th>Mode</th><th>Status</th>"
                         "<th>Elapsed</th><th>Phases</th><th>Errors</th>"
                         "</tr></thead><tbody>")
            for e in engagements:
                parts.append(
                    f"<tr><td>{esc(str(e['target']))}</td>"
                    f"<td>{esc(str(e['mode']))}</td>"
                    f"<td>{esc(str(e['status']))}</td>"
                    f"<td>{esc(str(e['elapsed']))}s</td>"
                    f"<td>{e['phases']}</td>"
                    f"<td>{e['errors']}</td></tr>"
                )
            parts.append("</tbody></table>")
        else:
            parts.append('<p class="muted">No engagements recorded.</p>')
        parts.append("</section>")

        # ─── Findings ─────────────────────────────────────────────────────
        parts.append('<section id="findings">')
        parts.append("<h3>Findings</h3>")
        findings = data.get("findings", [])
        if findings:
            parts.append('<table class="data-table">')
            parts.append("<thead><tr>"
                         "<th>Category</th><th>Risk</th><th>ID</th>"
                         "<th>Tags</th><th>Timestamp</th>"
                         "</tr></thead><tbody>")
            for f in findings:
                risk = f.get("risk_score")
                risk_str = f"{risk:.1f}" if isinstance(risk, (int, float)) else "N/A"
                risk_cls = "risk-high" if isinstance(risk, (int, float)) and risk >= 7 else (
                    "risk-med" if isinstance(risk, (int, float)) and risk >= 4 else "risk-low"
                )
                tags = ", ".join(esc(str(t)) for t in f.get("tags", []))
                parts.append(
                    f"<tr><td>{esc(str(f.get('category', 'unknown')))}</td>"
                    f'<td class="{risk_cls}">{risk_str}</td>'
                    f"<td><code>{esc(str(f.get('id', '?')))[:12]}</code></td>"
                    f"<td>{tags}</td>"
                    f"<td>{esc(str(f.get('timestamp', 'N/A')))}</td></tr>"
                )
            parts.append("</tbody></table>")
        else:
            parts.append('<p class="muted">No findings recorded.</p>')
        parts.append('</section>')

        # ─── MITRE ATT&CK coverage ────────────────────────────────────────
        mitre = data.get("mitre") or {}
        techs = mitre.get("techniques_used") or []
        if techs:
            counts = mitre.get("technique_counts") or {}
            parts.append('<section id="mitre">')
            parts.append("<h3>MITRE ATT&CK Coverage</h3>")
            parts.append(
                f'<p class="muted">Coverage: '
                f"{mitre.get('coverage_pct', 0.0)}% of the "
                f"{mitre.get('coverage_denominator', 0)} curated ATT&CK techniques "
                "(native only — ALIAS / UNMAPPED entries are tracked separately "
                "and do not count here).</p>"
            )
            parts.append('<table class="data-table">')
            parts.append(
                "<thead><tr><th>Tactic</th><th>Technique</th>"
                "<th>ID</th><th>References</th></tr></thead><tbody>"
            )
            for t in techs:
                tid = t.get("id", "?")
                parts.append(
                    f"<tr>"
                    f"<td>{esc(str(t.get('tactic', '?')))}</td>"
                    f"<td>{esc(str(t.get('name', '?')))}</td>"
                    f"<td><code>{esc(str(tid))}</code></td>"
                    f"<td>{counts.get(tid, 0)}</td>"
                    f"</tr>"
                )
            parts.append("</tbody></table>")
            alias = sorted({t.get("name", "?") for t in techs
                            if str(t.get("id", "")).startswith("ALIAS:")})
            unmapped_count = sum(1 for f in (data.get("findings") or [])
                                 if f.get("mitre_technique_id") == "UNMAPPED")
            if alias:
                names = ", ".join(f"<code>{esc(n)}</code>" for n in alias)
                parts.append(
                    f'<p class="muted">Vendor extension (MCP / LLM): '
                    f"{names} — no stable ATT&CK technique; tracked as aliases.</p>"
                )
            if unmapped_count:
                parts.append(
                    f'<p class="muted">Unmapped: {unmapped_count} finding(s) had a '
                    'category not present in the MITRE library '
                    '(kept explicit, never absorbed).</p>'
                )

            comp = mitre.get("compliance") or {}
            if comp:
                parts.append("<h3>Compliance Cross-Reference</h3>")
                parts.append(
                    f'<table class="data-table"><thead><tr>'
                    f"<th>Technique</th><th>ID</th><th>NIST SP 800-53</th>"
                    f"<th>PCI DSS v4.0</th><th>ISO/IEC 27001:2022</th>"
                    f"</tr></thead><tbody>"
                )
                for tid in sorted(comp):
                    rc = comp[tid] or {}
                    parts.append(
                        f"<tr>"
                        f"<td>{esc(str(rc.get('name', tid)))}</td>"
                        f"<td><code>{esc(str(tid))}</code></td>"
                        f"<td>{esc(str(rc.get('nist', '—')))}</td>"
                        f"<td>{esc(str(rc.get('pci', '—')))}</td>"
                        f"<td>{esc(str(rc.get('iso', '—')))}</td>"
                        f"</tr>"
                    )
                parts.append("</tbody></table>")
                parts.append(
                    '<p class="muted">Curated advisory references — '
                    'not a certification or legal finding.</p>'
                )
            parts.append('</section>')

        # ─── Boneyard inventory ───────────────────────────────────────────
        parts.append('<section id="boneyard">')
        parts.append("<h3>Boneyard Inventory</h3>")
        inv = data.get("boneyard_inventory", {})
        cats = inv.get("categories", {})
        parts.append('<div class="stat-grid">')
        parts.append(self._stat_card("Total Items", inv.get("total_items", 0)))
        parts.append(
            self._stat_card(
                "Encrypted",
                "Yes" if inv.get("encrypted") else "No",
            )
        )
        parts.append(self._stat_card("Categories", len(cats)))
        parts.append("</div>")
        if cats:
            parts.append('<table class="data-table">')
            parts.append("<thead><tr><th>Category</th><th>Count</th></tr></thead><tbody>")
            for cat, count in sorted(cats.items()):
                parts.append(
                    f"<tr><td>{esc(str(cat))}</td><td>{count}</td></tr>"
                )
            parts.append("</tbody></table>")
        parts.append("</section>")

        # ─── WarLog telemetry ─────────────────────────────────────────────
        parts.append('<section id="warlog">')
        parts.append("<h3>WarLog Telemetry</h3>")
        wl = data.get("warlog_telemetry", {})
        lc = wl.get("level_counts", {})
        parts.append('<div class="stat-grid">')
        parts.append(self._stat_card("Total Entries", wl.get("total_entries", 0)))
        parts.append(
            self._stat_card("Duration", f"{wl.get('duration_seconds', 0)}s")
        )
        parts.append(self._stat_card("Log Levels", len(lc)))
        parts.append("</div>")
        if lc:
            parts.append('<table class="data-table">')
            parts.append("<thead><tr><th>Level</th><th>Count</th></tr></thead><tbody>")
            for level, count in sorted(lc.items()):
                parts.append(
                    f"<tr><td><code>{esc(str(level))}</code></td><td>{count}</td></tr>"
                )
            parts.append("</tbody></table>")
        parts.append("</section>")

        # ─── Integrity ────────────────────────────────────────────────────
        parts.append('<section id="integrity">')
        parts.append("<h3>Integrity Verification</h3>")
        integ = data.get("integrity", {})
        overall = integ.get("status", "UNKNOWN")
        cls = "ok" if overall == "VERIFIED" else (
            "warn" if overall == "UNKNOWN" else "bad"
        )
        parts.append(
            f'<div class="integrity-banner {cls}">'
            f"<strong>Overall:</strong> {esc(overall)}</div>"
        )
        wi = integ.get("warlog", {})
        bi = integ.get("boneyard", {})
        if wi or bi:
            parts.append('<table class="data-table">')
            parts.append("<thead><tr><th>Component</th><th>Status</th>"
                         "<th>Checked</th></tr></thead><tbody>")
            if wi:
                wstat = "VERIFIED" if wi.get("verified") else "TAMPERED"
                wcls = "ok" if wi.get("verified") else "bad"
                parts.append(
                    f"<tr><td>WarLog</td>"
                    f'<td class="{wcls}">{wstat}</td>'
                    f"<td>{wi.get('total_events', 0)} events</td></tr>"
                )
            if bi:
                bstat = "VERIFIED" if bi.get("verified") else "TAMPERED"
                bcls = "ok" if bi.get("verified") else "bad"
                parts.append(
                    f"<tr><td>Boneyard</td>"
                    f'<td class="{bcls}">{bstat}</td>'
                    f"<td>{bi.get('total_rows_checked', 0)} rows</td></tr>"
                )
            parts.append("</tbody></table>")
        parts.append("</section>")

        # ─── Footer ────────────────────────────────────────────────────────
        parts.append("<footer>")
        parts.append(
            f"<p>Generated by <strong>{esc(str(meta['tool']))}</strong> "
            f"— Engagement Reporting Module v{esc(str(meta['version']))}</p>"
        )
        parts.append("</footer>")

        parts.append("</body>")
        parts.append("</html>")

        return "\n".join(parts)

    # ─── Internal Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _safe_call(obj: Any, method: str, default: Any = None) -> Any:
        """Call a method on an object if it exists, else return default."""
        if obj is None:
            return default
        fn = getattr(obj, method, None)
        if fn is None:
            return default
        try:
            return fn()
        except Exception as e:
            logger.debug("%s.%s() failed: %s", type(obj).__name__, method, e)
            return default

    def _verify_store(self, store: Any, label: str) -> Any:
        """Call ``store.verify_integrity()``, forwarding the per-row
        progress callback when the store's method supports it (W4-2.3c).

        Robust to any store shape: real stores declare a ``progress`` kwarg;
        older stores (and mocks) don't. We always *attempt* the progress
        call first and fall back to the no-arg call on TypeError, rather
        than relying on signature introspection (which can't see through
        MagicMock). Never raises; returns None on failure.
        """
        if store is None:
            return None
        fn = getattr(store, "verify_integrity", None)
        if fn is None or not callable(fn):
            return None
        cb = self.integrity_progress
        if callable(cb):
            try:
                return fn(progress=cb)
            except TypeError:
                pass
            except Exception as e:
                logger.debug("%s.verify_integrity(progress=) failed: %s",
                             label, e)
                return None
        try:
            return fn()
        except Exception as e:
            logger.debug("%s.verify_integrity() failed: %s", label, e)
            return None

    # ─── MITRE ATT&CK annotation (R-1 / R-4) ────────────────────────────────

    def _annotate_mitre(
        self,
        findings: List[Dict[str, Any]],
        engagements: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Annotate findings and phases with MITRE ATT&CK techniques.

        Args:
            findings: raw finding dicts from :meth:`_collect_findings`.
            engagements: attack_log engagement summaries (they carry the
                executed-phase-keyed ``findings`` dict).

        Returns:
            A deterministic ``mitre`` section dict for the report payload::

                techniques_used     — ordered (tactic, id, name, tactic) tuples of distinct techniques
                technique_counts    — technique_id → (count of findings + phases referencing it)
                tactic_coverage     — tactic → count of distinct techniques used within it
                tactics             — list of tactics exercised (attack-forward order)
                coverage_pct        — NATIVE techniques used / curated native technique universe.
                                      ALIAS: and UNMAPPED entries never inflate this metric
                                      (see roadmap R-1 vs R-2: technique *detection* only;
                                      prevention-strength scoring is out of scope here).
                coverage_denominator— the native technique-universe size used for coverage_pct
                compliance          — technique_id → {nist, pci, iso} for native techniques only
                mapped_findings     — findings annotated in-place with mitre_* fields
                mapped_phases       — phase_name → (id, name, tactic) for phases executed
        """
        # ─── Annotate findings by category ─────────────────────────────────
        mapped_findings: List[Dict[str, Any]] = []
        category_use: Dict[str, int] = {}  # technique_id -> count
        for f in findings:
            cat = (f.get("category") or "other").strip().lower()
            tech_id, tech_name, tech_tactic = self.MITRE_LIBRARY.get(
                cat, self.MITRE_LIBRARY["other"]
            )
            category_use[tech_id] = category_use.get(tech_id, 0) + 1
            annotated = dict(f)
            annotated["mitre_technique_id"] = tech_id
            annotated["mitre_technique_name"] = tech_name
            annotated["mitre_tactic"] = tech_tactic
            mapped_findings.append(annotated)

        # ─── Map phases executed (from engagement "findings" keys) ─────────
        # Deterministic phase ordering: execute-phases in MODE order, not the
        # per-engagement dict key order (which is set by phase-completion).
        # Collect phase-name set first, then emit mapped_phases deterministically.
        phases_seen: set = set()
        for eng in engagements:
            if not isinstance(eng.get("findings"), dict):
                continue
            phases_seen.update(eng["findings"].keys())
        mapped_phases: Dict[str, Tuple[str, str, str]] = {}
        for phase_name in sorted(phases_seen):
            if phase_name in self.PHASE_TECHNIQUES:
                mapped_phases[phase_name] = self.PHASE_TECHNIQUES[phase_name]

        # ─── Aggregate techniques used (stable ordering for determinism) ──
        tech_seen: Dict[str, Tuple[str, str, str]] = {}  # id -> (name, tactic)
        for f in mapped_findings:
            tech_seen[f["mitre_technique_id"]] = (
                f["mitre_technique_name"],
                f["mitre_tactic"],
            )
        for tid, name, tactic in mapped_phases.values():
            tech_seen.setdefault(tid, (name, tactic))
        tech_list = sorted(
            (tid, name, tactic) for tid, (name, tactic) in tech_seen.items()
        )

        # tactic → set of techniques exercised, in ATT&CK attack-forward order
        tactic_tech: Dict[str, set] = {}
        for tid, name, tactic in tech_list:
            tactic_tech.setdefault(tactic, set()).add(tid)
        tactics = [t for t in self.ATTACK_TACTIC_ORDER if t in tactic_tech]
        for t in sorted(tactic_tech):               # any tactic we didn't rank
            if t not in tactics:
                tactics.append(t)

        # technique_id → total references across findings + phases
        technique_counts: Dict[str, int] = {}
        for f in mapped_findings:
            technique_counts[f["mitre_technique_id"]] = technique_counts.get(
                f["mitre_technique_id"], 0
            ) + 1
        for phase_name, (tid, _, _) in mapped_phases.items():
            technique_counts[tid] = technique_counts.get(tid, 0) + 1

        # compliance cross-reference (native techniques only — no ALIAS/UNMAPPED)
        compliance: Dict[str, Dict[str, str]] = {
            tid: self.COMPLIANCE_MAP[tid]
            for tid, _, _ in tech_list
            if tid in self.COMPLIANCE_MAP
        }

        # coverage denominator: the curated native ATT&CK technique universe THE
        # VOID maps to. Roadmap R-1 detects techniques; R-2 is the dedicated
        # coverage *scoring engine* (weighted, prevention-strength). Until R-2
        # exists we do not claim coverage of ALIAS or UNMAPPED techniques.
        curated = {tid for v in self.MITRE_LIBRARY.values() for tid in (v[0],)
                   if not tid.startswith(("ALIAS:", "UNMAPPED"))}
        curated |= {tid for v in self.PHASE_TECHNIQUES.values() for tid in (v[0],)
                    if not tid.startswith("ALIAS:")}
        denominator = max(len(curated), 1)
        used_native = len({tid for tid, _, _ in tech_list
                           if not tid.startswith(("ALIAS:", "UNMAPPED"))})
        alias_used = len({tid for tid, _, _ in tech_list
                          if tid.startswith("ALIAS:")})

        return {
            "techniques_used": [
                {"id": tid, "name": name, "tactic": tactic}
                for tid, name, tactic in tech_list
            ],
            "technique_counts": {
                tid: technique_counts.get(tid, 0) for tid, _, _ in tech_list
            },
            "tactic_coverage": {
                t: len(tactic_tech.get(t, set())) for t in tactics
            },
            "tactics": tactics,
            "coverage_pct": round(100.0 * used_native / denominator, 1),
            "coverage_denominator": denominator,
            "native_techniques_used": used_native,
            "alias_techniques_used": alias_used,
            "compliance": compliance,
            "mapped_findings": mapped_findings,
            "mapped_phases": {
                p: {"id": v[0], "name": v[1], "tactic": v[2]}
                for p, v in sorted(mapped_phases.items())
            },
        }

    # ─── Findings Collection ───────────────────────────────────────────────────

    def _collect_findings(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Collect top findings sorted by risk_score (descending)."""
        if self.boneyard is None:
            return []
        result = self._safe_call(
            self.boneyard, "query_findings", default=None
        )
        if result is None:
            return []
        try:
            rows = list(result)
        except TypeError:
            return []
        # Sort by risk_score descending, take top N (stable secondary sort on
        # the finding id for deterministic output across runs)
        def _risk(f: Dict[str, Any]) -> Tuple[float, str]:
            r = f.get("risk_score")
            risk = float(r) if isinstance(r, (int, float)) else 0.0
            return (risk, str(f.get("id") or ""))
        rows.sort(key=_risk, reverse=True)
        out: List[Dict[str, Any]] = []
        for f in rows[:limit]:
            entry = {
                "id": f.get("id"),
                "category": f.get("category"),
                "risk_score": f.get("risk_score"),
                "tags": f.get("tags", []),
                "host_id": f.get("host_id"),
                "timestamp": f.get("timestamp"),
            }
            out.append(entry)
        return out

    def _collect_integrity(self) -> Dict[str, Any]:
        """Collect integrity reports from warlog and boneyard.

        Integrity verification re-derives HMAC keys via PBKDF2 per row and is
        O(n) expensive. It is skipped unless ``self.verify_integrity`` is True;
        in that case the report records ``verified: None`` (UNKNOWN).
        """
        result: Dict[str, Any] = {}

        if not self.verify_integrity:
            result["warlog"] = {"verified": None, "total_events": 0}
            result["boneyard"] = {"verified": None, "total_rows_checked": 0}
            return result

        # WarLog integrity
        wi = self._verify_store(self.warlog, "WarLog")
        if wi is not None:
            wi_dict = wi.to_dict() if hasattr(wi, "to_dict") else {"verified": bool(wi)}
            result["warlog"] = {
                "verified": wi_dict.get("verified", False),
                "total_events": wi_dict.get("total_events", 0),
                "broken_hmacs": wi_dict.get("broken_hmacs", 0)
                if isinstance(wi_dict.get("broken_hmacs"), int)
                else len(wi_dict.get("broken_hmacs", [])),
                "broken_chain_links": wi_dict.get("broken_chain_links", 0)
                if isinstance(wi_dict.get("broken_chain_links"), int)
                else len(wi_dict.get("broken_chain_links", [])),
            }
        else:
            result["warlog"] = {"verified": None, "total_events": 0}

        # Boneyard integrity
        bi = self._verify_store(self.boneyard, "Boneyard")
        if bi is not None:
            bi_dict = bi.to_dict() if hasattr(bi, "to_dict") else {"verified": bool(bi)}
            result["boneyard"] = {
                "verified": bi_dict.get("verified", False),
                "total_rows_checked": bi_dict.get("total_rows_checked", 0),
                "broken_hmacs": len(bi_dict.get("broken_hmacs", []))
                if isinstance(bi_dict.get("broken_hmacs"), list)
                else bi_dict.get("broken_hmacs", 0),
                "broken_chain_links": len(bi_dict.get("broken_chain_links", []))
                if isinstance(bi_dict.get("broken_chain_links"), list)
                else bi_dict.get("broken_chain_links", 0),
            }
        else:
            result["boneyard"] = {"verified": None, "total_rows_checked": 0}

        return result

    @staticmethod
    def _summarize_engagement(entry: Dict[str, Any]) -> Dict[str, Any]:
        """Summarize a single attack_log entry into a compact report row."""
        findings = entry.get("findings", {})
        if not isinstance(findings, dict):
            findings = {}
        phases = len(findings)
        errors = sum(
            1 for v in findings.values()
            if isinstance(v, dict) and "error" in v
        )
        return {
            "target": entry.get("target", "unknown"),
            "mode": entry.get("mode", "unknown"),
            "status": entry.get("status", "unknown"),
            "elapsed": entry.get("elapsed", 0),
            "phases": phases,
            "errors": errors,
            "started_at": entry.get("started_at"),
        }

    @staticmethod
    def _stat_card(label: str, value: Any) -> str:
        """Render a single stat card for HTML."""
        return (
            f'<div class="stat-card">'
            f'<span class="stat-label">{_html.escape(str(label))}</span>'
            f'<span class="stat-value">{_html.escape(str(value))}</span>'
            f"</div>"
        )


# ─── HTML CSS ──────────────────────────────────────────────────────────────────

_HTML_CSS = """
:root {
    --bg: #0a0a0f;
    --card-bg: #15151f;
    --text: #e0e0e0;
    --muted: #888;
    --accent: #ff4444;
    --green: #44ff88;
    --yellow: #ffcc44;
    --red: #ff4444;
    --border: #2a2a3a;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
    line-height: 1.6;
    padding: 2rem;
    max-width: 1100px;
    margin: 0 auto;
}
.report-header {
    text-align: center;
    border-bottom: 2px solid var(--accent);
    padding-bottom: 1.5rem;
    margin-bottom: 2rem;
}
.report-header h1 {
    color: var(--accent);
    font-size: 2.5rem;
    letter-spacing: 0.3em;
}
.report-header h2 {
    color: var(--text);
    font-size: 1.4rem;
    font-weight: 300;
    margin-top: 0.5rem;
}
.report-header .meta {
    display: flex;
    justify-content: center;
    gap: 2rem;
    margin-top: 1rem;
    font-size: 0.85rem;
    color: var(--muted);
}
section {
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
}
section h3 {
    color: var(--accent);
    font-size: 1.1rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    margin-bottom: 1rem;
    padding-bottom: 0.5rem;
    border-bottom: 1px solid var(--border);
}
.stat-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
    gap: 1rem;
    margin-bottom: 1rem;
}
.stat-card {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 1rem;
    text-align: center;
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
}
.stat-label {
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--muted);
}
.stat-value {
    font-size: 1.8rem;
    font-weight: 700;
}
.stat-card.integrity.ok .stat-value { color: var(--green); }
.stat-card.integrity.bad .stat-value { color: var(--red); }
.stat-card.integrity.warn .stat-value { color: var(--yellow); }
table.data-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.9rem;
}
table.data-table th {
    text-align: left;
    padding: 0.6rem;
    background: var(--bg);
    color: var(--muted);
    text-transform: uppercase;
    font-size: 0.75rem;
    letter-spacing: 0.05em;
    border-bottom: 1px solid var(--border);
}
table.data-table td {
    padding: 0.6rem;
    border-bottom: 1px solid var(--border);
}
table.data-table td code {
    background: var(--bg);
    padding: 0.15rem 0.4rem;
    border-radius: 3px;
    font-size: 0.85rem;
}
td.risk-high { color: var(--red); font-weight: 700; }
td.risk-med { color: var(--yellow); }
td.risk-low { color: var(--green); }
td.ok { color: var(--green); }
td.bad { color: var(--red); }
.integrity-banner {
    padding: 1rem;
    border-radius: 6px;
    text-align: center;
    font-size: 1.1rem;
    margin-bottom: 1rem;
}
.integrity-banner.ok { background: rgba(68, 255, 136, 0.1); color: var(--green); }
.integrity-banner.bad { background: rgba(255, 68, 68, 0.1); color: var(--red); }
.integrity-banner.warn { background: rgba(255, 204, 68, 0.1); color: var(--yellow); }
.muted { color: var(--muted); font-style: italic; }
footer {
    text-align: center;
    padding: 2rem 0;
    color: var(--muted);
    font-size: 0.8rem;
}
"""
