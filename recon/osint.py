"""THE VOID — OSINT: Open Source Intelligence gathering.

The agent doesn't just scan — it harvests intelligence.
amass, subfinder, whatweb, whois, tookie-osint, and more.
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional

from core.executor import Executor, CommandResult
from core.target import Target, TargetType

logger = logging.getLogger("void.recon.osint")


# ─── Social media platforms for tookie-osint ─────────────────────────────────
SOCIAL_PLATFORMS = ["twitter", "linkedin", "github", "mastodon"]


class OSINT:
    """Open Source Intelligence gathering module."""

    def __init__(self, executor: Optional[Executor] = None, boneyard=None):
        """Initialize the OSINT module.

        Args:
            executor: The command executor. If None, creates a new one.
            boneyard: The Boneyard instance for storing findings.
        """
        self.executor = executor or Executor()
        self.boneyard = boneyard
        self.tools = {
            "amass": "amass",
            "subfinder": "subfinder",
            "whatweb": "whatweb",
            "whois": "whois",
            "nslookup": "nslookup",
            "dig": "dig",
            "host": "host",
            "curl": "curl",
            "tookie": "tookie-osint",
        }
        logger.info("OSINT module initialized")

    def enumerate_subdomains(self, target: Target) -> Dict[str, Any]:
        """Enumerate subdomains using amass and subfinder.

        Args:
            target: The target to enumerate

        Returns:
            Dict with discovered subdomains
        """
        domain = target.get_domain()
        logger.info(f"Enumerating subdomains for {domain}")
        subdomains = set()

        # Use amass
        amass_result = self.executor.run_tool("amass", ["enum", "-passive", "-d", domain], timeout=120)
        if amass_result.success:
            for line in amass_result.stdout.split("\n"):
                line = line.strip()
                if line and not line.startswith("#") and "." in line:
                    subdomains.add(line)
            logger.info(f"Amass found {len(subdomains)} subdomains")

        # Use subfinder
        subfinder_result = self.executor.run_tool("subfinder", ["-d", domain, "-silent"], timeout=120)
        if subfinder_result.success:
            for line in subfinder_result.stdout.split("\n"):
                line = line.strip()
                if line and "." in line:
                    subdomains.add(line)
            logger.info(f"Subfinder found {len(subdomains)} subdomains")

        result = {
            "domain": domain,
            "subdomains": sorted(list(subdomains)),
            "count": len(subdomains),
        }
        target.add_discovery("subdomains", result)
        return result

    def whois_lookup(self, target: Target) -> Dict[str, Any]:
        """Perform WHOIS lookup on a target.

        Args:
            target: The target to look up

        Returns:
            Dict with WHOIS data
        """
        domain = target.get_domain()
        logger.info(f"WHOIS lookup for {domain}")
        result = self.executor.run_tool("whois", [domain], timeout=60)
        if result.success:
            whois_data = self._parse_whois(result.stdout)
            target.add_discovery("whois", whois_data)
            return whois_data
        return {"error": result.stderr, "raw": result.stdout}

    def _parse_whois(self, raw: str) -> Dict[str, Any]:
        """Parse WHOIS output into structured data."""
        data = {}
        for line in raw.split("\n"):
            line = line.strip()
            if ":" in line and not line.startswith("#"):
                key, _, value = line.partition(":")
                key = key.strip().lower()
                value = value.strip()
                if value and key:
                    data[key] = value
        return data

    def dns_lookup(self, target: Target) -> Dict[str, Any]:
        """Perform DNS lookup on a target.

        Args:
            target: The target to look up

        Returns:
            Dict with DNS data
        """
        domain = target.get_domain()
        logger.info(f"DNS lookup for {domain}")

        result = self.executor.run_tool("dig", [domain, "+short"], timeout=30)
        ips = result.stdout.strip().split("\n") if result.success else []

        ns_result = self.executor.run_tool("dig", [domain, "NS", "+short"], timeout=30)
        ns = ns_result.stdout.strip().split("\n") if ns_result.success else []

        mx_result = self.executor.run_tool("dig", [domain, "MX", "+short"], timeout=30)
        mx = mx_result.stdout.strip().split("\n") if mx_result.success else []

        dns_data = {
            "domain": domain,
            "a_records": [ip.strip() for ip in ips if ip.strip()],
            "ns_records": [ns.strip() for ns in ns if ns.strip()],
            "mx_records": [mx.strip() for mx in mx if mx.strip()],
        }
        target.add_discovery("dns", dns_data)
        return dns_data

    def whatweb_scan(self, target: Target) -> Dict[str, Any]:
        """Perform whatweb scan to identify technologies.

        Args:
            target: The target to scan

        Returns:
            Dict with technology fingerprinting data
        """
        url = target.value if target.is_url() else f"http://{target.get_domain()}"
        logger.info(f"WhatWeb scan for {url}")
        result = self.executor.run_tool("whatweb", [url, "--color=never", "-q"], timeout=60)
        if result.success:
            data = {"url": url, "technologies": self._parse_whatweb(result.stdout)}
            target.add_discovery("technologies", data)
            return data
        return {"error": result.stderr, "raw": result.stdout}

    def _parse_whatweb(self, raw: str) -> List[str]:
        """Parse whatweb output into a list of technologies."""
        techs = []
        for line in raw.split("\n"):
            line = line.strip()
            if line:
                # Extract technology names from whatweb output
                parts = line.split(",")
                for part in parts:
                    part = part.strip()
                    if part and part != "HTTPServer" and "http" not in part.lower():
                        techs.append(part)
        return list(set(techs))

    def full_recon(self, target: Target) -> Dict[str, Any]:
        """Perform full OSINT reconnaissance on a target.

        Args:
            target: The target to scan

        Returns:
            Dict with all OSINT findings
        """
        logger.info(f"Full OSINT recon on {target.name}")
        findings = {}

        try:
            findings["subdomains"] = self.enumerate_subdomains(target)
        except Exception as e:
            findings["subdomains"] = {"error": str(e)}

        try:
            findings["whois"] = self.whois_lookup(target)
        except Exception as e:
            findings["whois"] = {"error": str(e)}

        try:
            findings["dns"] = self.dns_lookup(target)
        except Exception as e:
            findings["dns"] = {"error": str(e)}

        try:
            findings["technologies"] = self.whatweb_scan(target)
        except Exception as e:
            findings["technologies"] = {"error": str(e)}

        return findings

    # ─── tookie-osint social media account discovery ─────────────────────────

    def social_media_accounts(self, target: Target, username: str = "",
                              platforms: Optional[List[str]] = None) -> Dict[str, Any]:
        """Discover social media accounts using tookie-osint.

        Uses tookie-osint to enumerate social media accounts (Twitter/X,
        LinkedIn, GitHub, Mastodon) for a given username.

        Args:
            target: The target (for context/logging)
            username: Username to search for across platforms
            platforms: List of platforms to search (default: all)

        Returns:
            Dict with discovered accounts per platform
        """
        if not username:
            username = target.name
        if platforms is None:
            platforms = SOCIAL_PLATFORMS.copy()

        logger.info(f"Tookie-osint social media accounts for '{username}' on {platforms}")
        results: Dict[str, Any] = {
            "username": username,
            "platforms": {},
            "total_accounts": 0,
        }

        for platform in platforms:
            platform_result = self._tookie_search(username, platform)
            results["platforms"][platform] = platform_result
            results["total_accounts"] += platform_result.get("count", 0)

        # Cross-reference with boneyard if available
        if self.boneyard:
            self._cross_reference_boneyard(results, username)

        # Store in boneyard
        if self.boneyard and results["total_accounts"] > 0:
            self.boneyard.store(
                "osint",
                {"username": username, "platforms": results["platforms"],
                 "total_accounts": results["total_accounts"]},
                tags=["tookie", "social_media", username]
            )

        target.add_discovery("social_media_accounts", results)
        return results

    def _tookie_search(self, username: str, platform: str) -> Dict[str, Any]:
        """Search for a username on a specific platform using tookie-osint.

        Args:
            username: Username to search
            platform: Platform to search on

        Returns:
            Dict with search results for this platform
        """
        logger.debug(f"Tookie search: {username} on {platform}")

        args = ["-u", username, "-p", platform, "--json"]
        result = self.executor.run_tool("tookie-osint", args, timeout=120)

        platform_result: Dict[str, Any] = {
            "platform": platform,
            "accounts": [],
            "count": 0,
            "error": None,
        }

        if result.success and result.stdout:
            try:
                data = json.loads(result.stdout)
                if isinstance(data, dict) and "accounts" in data:
                    platform_result["accounts"] = data["accounts"]
                elif isinstance(data, list):
                    platform_result["accounts"] = data
                else:
                    platform_result["accounts"] = [data]
            except json.JSONDecodeError:
                # Fallback: parse text output
                platform_result["accounts"] = self._parse_tookie_text(result.stdout)
            platform_result["count"] = len(platform_result["accounts"])
        elif result.stderr:
            platform_result["error"] = result.stderr[:200]

        return platform_result

    def _parse_tookie_text(self, output: str) -> List[Dict[str, str]]:
        """Parse tookie-osint text output into structured account data.

        Args:
            output: Raw text output from tookie-osint

        Returns:
            List of account dicts with url, username, platform
        """
        accounts = []
        for line in output.split("\n"):
            line = line.strip()
            if not line:
                continue
            # Try to extract URL and username from text lines
            url_match = re.search(r"(https?://\S+)", line)
            if url_match:
                accounts.append({
                    "url": url_match.group(1),
                    "username": line.split()[0] if line.split() else "",
                    "raw": line[:200],
                })
        return accounts

    def _cross_reference_boneyard(self, results: Dict[str, Any], username: str) -> None:
        """Cross-reference social media results with boneyard.

        Looks for previously discovered accounts for the same username
        and adds any new ones.

        Args:
            results: Results dict to update in-place
            username: Username to cross-reference
        """
        if not self.boneyard:
            return

        try:
            existing = self.boneyard.search("tookie", tags=["social_media", username])
            if existing:
                for entry in existing:
                    data = entry.get("data", {})
                    platform = data.get("platform", "")
                    if platform in results["platforms"]:
                        existing_urls = {a.get("url", "") for a in results["platforms"][platform].get("accounts", [])}
                        for acc in data.get("accounts", []):
                            if acc.get("url", "") not in existing_urls:
                                results["platforms"][platform]["accounts"].append(acc)
                                results["platforms"][platform]["count"] += 1
                                results["total_accounts"] += 1
        except Exception as e:
            logger.debug(f"Boneyard cross-reference failed: {e}")

    # ─── tookie-osint public wrappers ──────────────────────────────────────

    TOOKIE_PLATFORMS = SOCIAL_PLATFORMS.copy()

    def tookie_discover(self, username: str, platforms: Optional[List[str]] = None) -> Dict[str, Any]:
        """Discover social media accounts using tookie-osint.

        This is a public wrapper around social_media_accounts that
        takes a username string and optional platform list.

        Args:
            username: Username to search for
            platforms: List of platforms to search (default: all)

        Returns:
            Dict with discovered accounts at top level
        """
        target = Target(username)
        result = self.social_media_accounts(target, username=username, platforms=platforms)
        # Flatten to top-level "accounts" and "error" for test compatibility
        all_accounts = []
        for platform_data in result.get("platforms", {}).values():
            all_accounts.extend(platform_data.get("accounts", []))
        output = {"accounts": all_accounts, "username": username, "platforms": result.get("platforms", {}), "total_accounts": result.get("total_accounts", 0)}
        # Check if any platform had an error and no accounts
        if not all_accounts and any(
            p.get("error") for p in result.get("platforms", {}).values()
        ):
            first_error = next(
                (p.get("error") for p in result.get("platforms", {}).values() if p.get("error")),
                None
            )
            output["error"] = first_error
        return output

    def tookie_crossref(self, accounts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Cross-reference social media accounts.

        This is a public wrapper around _cross_reference_boneyard that
        takes a list of account dicts.

        Args:
            accounts: List of account dicts with platform, username, url

        Returns:
            Dict with cross-reference results
        """
        if not accounts:
            return {"crossref": []}

        crossref = []
        for account in accounts:
            platform = account.get("platform", "")
            username = account.get("username", "")
            if self.boneyard:
                self._cross_reference_boneyard({"platforms": {platform: {"accounts": [account]}}}, username)
            crossref.append(account)

        return {"crossref": crossref}
