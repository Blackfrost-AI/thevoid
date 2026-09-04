"""THE VOID — HostEnum: Host enumeration module.

smbclient, enum4linux, rpcclient, nbtscan — the agent finds every host, every user, every share.
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional

from core.executor import Executor, CommandResult
from core.target import Target

logger = logging.getLogger("void.recon.hostenum")


class HostEnum:
    """Host enumeration module."""

    def __init__(self, executor: Optional[Executor] = None):
        self.executor = executor or Executor()
        logger.info("HostEnum module initialized")

    def smb_enum(self, target: Target, username: str = "guest", password: str = "") -> Dict[str, Any]:
        """Enumerate SMB shares and users.

        Args:
            target: The target to scan
            username: Username for authentication
            password: Password for authentication

        Returns:
            Dict with SMB findings
        """
        host = target.get_ip() or target.get_domain()
        logger.info(f"SMB enumeration on {host}")

        findings = {"host": host, "shares": [], "users": [], "domains": []}

        # enum4linux
        enum_result = self.executor.run_tool(
            "enum4linux", ["-a", host], timeout=120
        )
        if enum_result.success:
            findings["enum4linux"] = self._parse_enum4linux(enum_result.stdout)

        # smbclient -L
        smb_result = self.executor.run_tool(
            "smbclient", ["-L", f"//{host}", "-U", f"{username}%{password}", "-N"],
            timeout=60
        )
        if smb_result.success:
            findings["shares"] = self._parse_smbclient_shares(smb_result.stdout)

        target.add_discovery("smb_enum", findings)
        return findings

    def _parse_enum4linux(self, output: str) -> Dict[str, Any]:
        """Parse enum4linux output."""
        data = {"users": [], "shares": [], "domains": [], "os": ""}
        current_section = ""
        for line in output.split("\n"):
            line = line.strip()
            if "Domain" in line and "=" in line:
                data["domains"].append(line.split("=")[-1].strip())
            elif "User" in line and "=" in line:
                data["users"].append(line.split("=")[-1].strip())
            elif line.startswith("Sharename"):
                current_section = "shares"
            elif current_section == "shares" and line:
                data["shares"].append(line)
        return data

    def _parse_smbclient_shares(self, output: str) -> List[str]:
        """Parse smbclient -L output."""
        shares = []
        for line in output.split("\n"):
            line = line.strip()
            if line and "Disk" in line or "IPC" in line or "Print" in line:
                shares.append(line)
        return shares

    def rpc_enum(self, target: Target) -> Dict[str, Any]:
        """Enumerate RPC services.

        Args:
            target: The target to scan

        Returns:
            Dict with RPC findings
        """
        host = target.get_ip() or target.get_domain()
        logger.info(f"RPC enumeration on {host}")

        findings = {"host": host, "users": [], "groups": [], "shares": []}

        # rpcclient
        result = self.executor.run_tool(
            "rpcclient", ["-U", "guest%", host, "-c", "enumdomusers"],
            timeout=60
        )
        if result.success:
            for line in result.stdout.split("\n"):
                if line.strip():
                    findings["users"].append(line.strip())

        result = self.executor.run_tool(
            "rpcclient", ["-U", "guest%", host, "-c", "enumdomgroups"],
            timeout=60
        )
        if result.success:
            for line in result.stdout.split("\n"):
                if line.strip():
                    findings["groups"].append(line.strip())

        target.add_discovery("rpc_enum", findings)
        return findings

    def nbtscan(self, target: Target) -> Dict[str, Any]:
        """Scan for NetBIOS names.

        Args:
            target: The target to scan

        Returns:
            Dict with NetBIOS findings
        """
        host = target.get_ip() or target.get_domain()
        logger.info(f"NetBIOS scan on {host}")

        result = self.executor.run_tool("nbtscan", [host], timeout=60)
        findings = {"host": host, "netbios": []}
        if result.success:
            for line in result.stdout.split("\n"):
                line = line.strip()
                if line and not line.startswith("Creating"):
                    findings["netbios"].append(line)
        target.add_discovery("nbtscan", findings)
        return findings

    def nmap_discovery(self, target: Target) -> Dict[str, Any]:
        """Discover hosts on the network using nmap.

        Args:
            target: The target to scan

        Returns:
            Dict with discovered hosts
        """
        host = target.get_ip() or target.get_domain()
        logger.info(f"Host discovery on {host}")

        result = self.executor.run_tool(
            "nmap", ["-sn", host, "-oG", "-"], timeout=120
        )
        findings = {"host": host, "hosts": []}
        if result.success:
            for line in result.stdout.split("\n"):
                if "Up" in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        findings["hosts"].append(parts[1])
        target.add_discovery("nmap_discovery", findings)
        return findings

    def full_enum(self, target: Target) -> Dict[str, Any]:
        """Perform full host enumeration.

        Args:
            target: The target to scan

        Returns:
            Dict with all host enumeration findings
        """
        logger.info(f"Full host enumeration on {target.name}")
        findings = {}

        try:
            findings["smb"] = self.smb_enum(target)
        except Exception as e:
            findings["smb"] = {"error": str(e)}

        try:
            findings["rpc"] = self.rpc_enum(target)
        except Exception as e:
            findings["rpc"] = {"error": str(e)}

        try:
            findings["nbtscan"] = self.nbtscan(target)
        except Exception as e:
            findings["nbtscan"] = {"error": str(e)}

        try:
            findings["nmap_discovery"] = self.nmap_discovery(target)
        except Exception as e:
            findings["nmap_discovery"] = {"error": str(e)}

        return findings
