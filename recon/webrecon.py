"""THE VOID — WebRecon: Web reconnaissance module.

nikto, nuclei, gobuster, wfuzz, dirb, dirsearch, uro — the agent finds every hidden path, every vulnerability.
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional, Set

from core.executor import Executor, CommandResult
from core.target import Target

logger = logging.getLogger("void.recon.webrecon")


class WebRecon:
    """Web reconnaissance module."""

    def __init__(self, executor: Optional[Executor] = None, boneyard=None):
        self.executor = executor or Executor()
        self.boneyard = boneyard
        self._url_queue: Set[str] = set()  # de-duped URL queue
        logger.info("WebRecon module initialized")

    def nikto_scan(self, target: Target, port: int = 443) -> Dict[str, Any]:
        """Run nikto scan against target.

        Args:
            target: The target to scan
            port: Port to scan

        Returns:
            Dict with nikto findings
        """
        url = target.value if target.is_url() else f"http://{target.get_domain()}"
        if port != 80 and port != 443:
            url = f"{url}:{port}"
        logger.info(f"Nikto scan on {url}")

        result = self.executor.run_tool("nikto", ["-h", url, "-nointeractive"], timeout=300)
        if result.success:
            findings = self._parse_nikto(result.stdout)
            target.add_discovery(f"nikto_{port}", findings)
            return findings
        return {"error": result.stderr, "raw": result.stdout[:2000]}

    def _parse_nikto(self, output: str) -> Dict[str, Any]:
        """Parse nikto output."""
        findings = {"vulnerabilities": [], "os": "", "server": ""}
        for line in output.split("\n"):
            line = line.strip()
            if line.startswith("+") and "OSVDB" in line:
                findings["vulnerabilities"].append(line)
            elif line.startswith("+") and "Server:" in line:
                findings["server"] = line.split("Server:")[-1].strip()
            elif line.startswith("+") and "OS:" in line:
                findings["os"] = line.split("OS:")[-1].strip()
        findings["total_vulns"] = len(findings["vulnerabilities"])
        return findings

    def nuclei_scan(self, target: Target, severity: str = "critical,high,medium",
                     templates: Optional[str] = None) -> Dict[str, Any]:
        """Run nuclei scan against target.

        Args:
            target: The target to scan
            severity: Severity filter
            templates: Custom templates directory

        Returns:
            Dict with nuclei findings
        """
        url = target.value if target.is_url() else f"http://{target.get_domain()}"
        logger.info(f"Nuclei scan on {url} (severity={severity})")

        args = ["-u", url, "-severity", severity, "-jsonl", "-silent"]
        if templates:
            args.extend(["-t", templates])

        result = self.executor.run_tool("nuclei", args, timeout=600)
        findings = {"url": url, "vulnerabilities": [], "count": 0}
        if result.stdout:
            for line in result.stdout.strip().split("\n"):
                try:
                    entry = json.loads(line)
                    findings["vulnerabilities"].append({
                        "template": entry.get("template-id", ""),
                        "severity": entry.get("info", {}).get("severity", ""),
                        "name": entry.get("info", {}).get("name", ""),
                        "matched": entry.get("matched-at", ""),
                        "host": entry.get("host", ""),
                    })
                except json.JSONDecodeError:
                    continue
            findings["count"] = len(findings["vulnerabilities"])
        target.add_discovery("nuclei", findings)
        return findings

    def gobuster_dir(self, target: Target, wordlist: Optional[str] = None,
                      extensions: str = "php,html,js,txt,xml") -> Dict[str, Any]:
        """Run gobuster directory enumeration.

        Args:
            target: The target to scan
            wordlist: Custom wordlist path
            extensions: File extensions to search

        Returns:
            Dict with discovered directories
        """
        url = target.value if target.is_url() else f"http://{target.get_domain()}"
        if not wordlist:
            wordlist = "/usr/share/wordlists/dirb/common.txt"
        logger.info(f"Gobuster dir scan on {url}")

        result = self.executor.run_tool(
            "gobuster", ["dir", "-u", url, "-w", wordlist, "-x", extensions, "-s", "200,301,302,403", "-q"],
            timeout=300
        )
        findings = {"url": url, "directories": [], "count": 0}
        if result.success:
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if line and "Status:" in line:
                    findings["directories"].append(line)
            findings["count"] = len(findings["directories"])
        target.add_discovery("gobuster", findings)
        return findings

    def wfuzz_fuzz(self, target: Target, wordlist: Optional[str] = None,
                   url_template: Optional[str] = None, filters: str = "") -> Dict[str, Any]:
        """Run wfuzz fuzzing.

        Args:
            target: The target to scan
            wordlist: Custom wordlist path
            url_template: Custom URL template with FUZZ marker
            filters: wfuzz filters

        Returns:
            Dict with fuzzing results
        """
        url = target.value if target.is_url() else f"http://{target.get_domain()}"
        if not url_template:
            url_template = f"{url}/FUZZ"
        if not wordlist:
            wordlist = "/usr/share/wordlists/dirb/common.txt"
        logger.info(f"Wfuzz fuzzing on {url_template}")

        args = ["-u", url_template, "-w", wordlist, "--hc", "404"]
        if filters:
            args.extend(["--efilter", filters])

        result = self.executor.run_tool("wfuzz", args, timeout=300)
        findings = {"url": url_template, "results": [], "count": 0}
        if result.stdout:
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if line and "200" in line or "301" in line or "302" in line or "403" in line:
                    findings["results"].append(line)
            findings["count"] = len(findings["results"])
        target.add_discovery("wfuzz", findings)
        return findings

    def dirb_scan(self, target: Target, wordlist: Optional[str] = None) -> Dict[str, Any]:
        """Run dirb directory scan.

        Args:
            target: The target to scan
            wordlist: Custom wordlist path

        Returns:
            Dict with discovered directories
        """
        url = target.value if target.is_url() else f"http://{target.get_domain()}"
        if not wordlist:
            wordlist = "/usr/share/wordlists/dirb/common.txt"
        logger.info(f"Dirb scan on {url}")

        result = self.executor.run_tool("dirb", [url, wordlist, "-S"], timeout=300)
        findings = {"url": url, "directories": [], "count": 0}
        if result.stdout:
            for line in result.stdout.strip().split("\n"):
                if line.startswith("+") and "CODE:" in line:
                    findings["directories"].append(line)
            findings["count"] = len(findings["directories"])
        target.add_discovery("dirb", findings)
        return findings

    def whatweb_scan(self, target: Target) -> Dict[str, Any]:
        """Run whatweb technology fingerprinting.

        Args:
            target: The target to scan

        Returns:
            Dict with technology findings
        """
        url = target.value if target.is_url() else f"http://{target.get_domain()}"
        logger.info(f"WhatWeb scan on {url}")

        result = self.executor.run_tool("whatweb", [url, "--color=never", "-q"], timeout=60)
        findings = {"url": url, "technologies": [], "raw": result.stdout[:2000]}
        if result.success:
            findings["technologies"] = self._parse_whatweb(result.stdout)
        target.add_discovery("whatweb", findings)
        return findings

    def _parse_whatweb(self, output: str) -> List[str]:
        """Parse whatweb output."""
        techs = []
        for line in output.split("\n"):
            line = line.strip()
            if line:
                parts = line.split(",")
                for part in parts:
                    part = part.strip()
                    if part and part != "HTTPServer" and "http" not in part.lower():
                        techs.append(part)
        return list(set(techs))

    def full_web_recon(self, target: Target) -> Dict[str, Any]:
        """Perform full web reconnaissance.

        Args:
            target: The target to scan

        Returns:
            Dict with all web recon findings
        """
        logger.info(f"Full web recon on {target.name}")
        findings = {}

        try:
            findings["nikto"] = self.nikto_scan(target)
        except Exception as e:
            findings["nikto"] = {"error": str(e)}

        try:
            findings["nuclei"] = self.nuclei_scan(target)
        except Exception as e:
            findings["nuclei"] = {"error": str(e)}

        try:
            findings["gobuster"] = self.gobuster_dir(target)
        except Exception as e:
            findings["gobuster"] = {"error": str(e)}

        try:
            findings["whatweb"] = self.whatweb_scan(target)
        except Exception as e:
            findings["whatweb"] = {"error": str(e)}

        return findings

    # ─── uro crawl de-duplication ────────────────────────────────────────────

    def uro_crawl(self, target, wordlist: Optional[str] = None,
                  extensions: str = "php,html,js,txt,xml", depth: int = 3,
                  extra_args: Optional[List[str]] = None) -> Dict[str, Any]:
        """Crawl target with uro for URL de-duplication.

        uro is a pre-nuclei crawl phase that de-duplicates discovered URLs,
        removing parameter noise and keeping unique paths for more efficient
        scanning.

        Args:
            target: The target to crawl (string or Target)
            wordlist: Custom wordlist path (for fallback)
            extensions: File extensions to search
            depth: Crawl depth (default 3)
            extra_args: Additional uro arguments

        Returns:
            Dict with de-duplicated URL findings
        """
        # Accept both string and Target
        if isinstance(target, str):
            url = target if target.startswith("http") else f"http://{target}"
        else:
            url = target.value if target.is_url() else f"http://{target.get_domain()}"
        logger.info(f"Uro crawl on {url} (depth={depth})")

        if not wordlist:
            wordlist = "/usr/share/wordlists/dirb/common.txt"

        # Build uro arguments
        args = ["-u", url, "-w", wordlist, "-d", str(depth), "-x", extensions]
        if extra_args:
            args.extend(extra_args)

        result = self.executor.run_tool("uro", args, timeout=300)
        findings: Dict[str, Any] = {
            "url": url,
            "urls": [],
            "total_before_dedup": 0,
            "count": 0,
            "raw": result.stdout[:5000],
        }

        if result.stdout:
            urls = self._parse_uro(result.stdout)
            # De-duplicate against the persistent URL queue
            new_urls = self._dedup_urls(urls)
            findings["urls"] = sorted(new_urls)
            findings["total_before_dedup"] = len(urls)
            findings["count"] = len(new_urls)
        else:
            findings["error"] = result.stderr

        # Persist in boneyard
        if self.boneyard and findings["urls"]:
            self.boneyard.store(
                "web",
                {"url": url, "urls": findings["urls"],
                 "count": findings["count"]},
                tags=["uro", "crawl", target.name if isinstance(target, Target) else url]
            )

        if isinstance(target, Target):
            target.add_discovery("uro_crawl", findings)
        return findings

    def _parse_uro(self, output: str) -> List[str]:
        """Parse uro output into a list of URLs."""
        urls = []
        for line in output.split("\n"):
            line = line.strip()
            if line and (line.startswith("http://") or line.startswith("https://")):
                urls.append(line)
        return urls

    def _dedup_urls(self, urls: List[str]) -> List[str]:
        """De-duplicate URLs against the persistent URL queue.

        Uses the full URL (including query params) for dedup.
        Returns only new URLs that haven't been seen before.
        """
        new_urls = []
        for url in urls:
            # Normalize: strip trailing slash for dedup
            normalized = url.rstrip("/")
            if normalized not in self._url_queue:
                self._url_queue.add(normalized)
                new_urls.append(url)
        return new_urls

    def get_url_queue(self) -> List[str]:
        """Return the current de-duplicated URL queue."""
        return sorted(self._url_queue)

    def get_url_queue_size(self) -> int:
        """Return the size of the URL queue."""
        return len(self._url_queue)

    def uro_deduplicate(self, urls: List[str]) -> List[str]:
        """De-duplicate a list of URLs using the persistent URL queue.

        This is a public wrapper around _dedup_urls that can be called
        independently of the uro_crawl method.

        Args:
            urls: List of URLs to de-duplicate

        Returns:
            List of de-duplicated URLs
        """
        return self._dedup_urls(urls)
