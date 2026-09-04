"""THE VOID — PortScan: The network scanner that finds every open door.

nmap, masscan, aggressive scanning — the agent finds every port, every service, every version.
"""

import json
import logging
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from core.executor import Executor, CommandResult
from core.target import Target, TargetType

logger = logging.getLogger("void.recon.portscan")


class PortScan:
    """Port scanning module using nmap and masscan."""

    def __init__(self, executor: Optional[Executor] = None):
        self.executor = executor or Executor()
        logger.info("PortScan module initialized")

    def quick_scan(self, target: Target, ports: str = "1-1000") -> Dict[str, Any]:
        """Quick port scan using nmap.

        Args:
            target: The target to scan
            ports: Port range (default 1-1000)

        Returns:
            Dict with open ports and services
        """
        host = target.get_ip() or target.get_domain()
        logger.info(f"Quick port scan on {host} (ports={ports})")

        result = self.executor.run_tool(
            "nmap", ["-sV", "-T4", "-p", ports, host, "-oX", "-"],
            timeout=300
        )
        if result.success:
            parsed = self._parse_nmap_xml(result.stdout)
            target.add_discovery("portscan_quick", parsed)
            return parsed
        return {"error": result.stderr, "raw": result.stdout[:2000]}

    def full_scan(self, target: Target) -> Dict[str, Any]:
        """Full port scan using nmap (all 65535 ports).

        Args:
            target: The target to scan

        Returns:
            Dict with all open ports and services
        """
        host = target.get_ip() or target.get_domain()
        logger.info(f"Full port scan on {host} (all ports)")

        result = self.executor.run_tool(
            "nmap", ["-sV", "-T4", "-p", "1-65535", host, "-oX", "-"],
            timeout=1800
        )
        if result.success:
            parsed = self._parse_nmap_xml(result.stdout)
            target.add_discovery("portscan_full", parsed)
            return parsed
        return {"error": result.stderr, "raw": result.stdout[:2000]}

    def aggressive_scan(self, target: Target) -> Dict[str, Any]:
        """Aggressive scan using nmap with all scripts.

        Args:
            target: The target to scan

        Returns:
            Dict with detailed scan results
        """
        host = target.get_ip() or target.get_domain()
        logger.info(f"Aggressive scan on {host}")

        result = self.executor.run_tool(
            "nmap", ["-sV", "-sC", "-A", "-T4", "-p-", host, "-oX", "-"],
            timeout=1800
        )
        if result.success:
            parsed = self._parse_nmap_xml(result.stdout)
            target.add_discovery("portscan_aggressive", parsed)
            return parsed
        return {"error": result.stderr, "raw": result.stdout[:2000]}

    def masscan_scan(self, target: Target, ports: str = "0-65535",
                     rate: int = 10000) -> Dict[str, Any]:
        """Fast port scan using masscan.

        Args:
            target: The target to scan
            ports: Port range
            rate: Rate of packets per second

        Returns:
            Dict with discovered ports
        """
        host = target.get_ip() or target.get_domain()
        logger.info(f"Masscan scan on {host} (rate={rate} pps)")

        result = self.executor.run_tool(
            "masscan", [host, "-p", ports, "--rate", str(rate), "-oL", "-"],
            timeout=600
        )
        if result.success:
            ports_found = self._parse_masscan(result.stdout)
            data = {"host": host, "ports": ports_found, "count": len(ports_found)}
            target.add_discovery("masscan", data)
            return data
        return {"error": result.stderr, "raw": result.stdout[:2000]}

    def udp_scan(self, target: Target) -> Dict[str, Any]:
        """UDP port scan using nmap.

        Args:
            target: The target to scan

        Returns:
            Dict with UDP ports and services
        """
        host = target.get_ip() or target.get_domain()
        logger.info(f"UDP scan on {host}")

        result = self.executor.run_tool(
            "nmap", ["-sU", "-T4", "--top-ports", "100", host, "-oX", "-"],
            timeout=600
        )
        if result.success:
            parsed = self._parse_nmap_xml(result.stdout)
            target.add_discovery("portscan_udp", parsed)
            return parsed
        return {"error": result.stderr, "raw": result.stdout[:2000]}

    def _parse_nmap_xml(self, xml_str: str) -> Dict[str, Any]:
        """Parse nmap XML output.

        Args:
            xml_str: XML output from nmap

        Returns:
            Dict with parsed port information
        """
        try:
            root = ET.fromstring(xml_str)
            ports = []
            for host in root.findall(".//host"):
                for port in host.findall(".//port"):
                    port_data = {
                        "port": int(port.get("portid", 0)),
                        "protocol": port.get("protocol", "tcp"),
                        "state": port.get("state", "unknown"),
                    }
                    service = port.find("service")
                    if service is not None:
                        port_data["service"] = service.get("name", "unknown")
                        port_data["product"] = service.get("product", "")
                        port_data["version"] = service.get("version", "")
                    scripts = []
                    for script in port.findall(".//script"):
                        scripts.append({
                            "id": script.get("id", ""),
                            "output": script.get("output", "")[:500],
                        })
                    if scripts:
                        port_data["scripts"] = scripts
                    ports.append(port_data)
            return {"ports": ports, "count": len(ports)}
        except ET.ParseError as e:
            logger.error(f"Failed to parse nmap XML: {e}")
            return {"error": str(e), "raw": xml_str[:2000]}

    def _parse_masscan(self, output: str) -> List[Dict[str, Any]]:
        """Parse masscan output."""
        ports = []
        for line in output.strip().split("\n"):
            line = line.strip()
            if line.startswith("open"):
                parts = line.split()
                if len(parts) >= 3:
                    ports.append({
                        "port": int(parts[1]) if parts[1].isdigit() else parts[1],
                        "protocol": parts[2],
                        "ip": parts[3] if len(parts) > 3 else "",
                    })
        return ports

    def scan(self, target: Target, scan_type: str = "quick",
             ports: Optional[str] = None) -> Dict[str, Any]:
        """Perform a scan with the specified type.

        Args:
            target: The target to scan
            scan_type: Type of scan (quick, full, aggressive, masscan, udp)
            ports: Port range for quick scan

        Returns:
            Dict with scan results
        """
        if scan_type == "quick":
            return self.quick_scan(target, ports=ports or "1-1000")
        elif scan_type == "full":
            return self.full_scan(target)
        elif scan_type == "aggressive":
            return self.aggressive_scan(target)
        elif scan_type == "masscan":
            return self.masscan_scan(target, ports=ports or "0-65535")
        elif scan_type == "udp":
            return self.udp_scan(target)
        else:
            return {"error": f"Unknown scan type: {scan_type}"}
