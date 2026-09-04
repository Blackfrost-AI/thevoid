#!/usr/bin/env python3
"""
Stealth Module — Operational Security and Tor Integration

No noise. No traces. Just silence as the target burns.

This module handles all stealth operations: Tor routing, OPSEC (operational
security), traffic obfuscation, and silent engagement techniques.
"""

from __future__ import annotations

import json
import os
import random
import re
import socket
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


# ============================================================================
# CONFIGURATION
# ============================================================================

@dataclass
class StealthConfig:
    """Configuration for stealth operations."""

    # Tor configuration
    tor_socks_port: int = 9050
    tor_control_port: int = 9051
    tor_data_dir: Path = Path("/var/lib/tor")
    tor_binary: str = "tor"

    # OPSEC settings
    opsec_enabled: bool = True
    anonymize_logs: bool = True
    log_retention_days: int = 30
    cleanup_frequency: int = 3600  # seconds

    # Traffic obfuscation
    use_onion_services: bool = True
    use_stem_circuits: bool = True
    circuit_padding: bool = True

    # Evasion settings
    fingerprint_obfuscation: bool = True
    tls_fingerprint: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    user_agents: List[str] = field(default_factory=lambda: [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    ])

    # Proxy configuration
    socks_proxy: Optional[str] = None
    http_proxy: Optional[str] = None
    dns_proxy: Optional[str] = None

    # Communication security
    encryption: str = "nacl"  # libsodium/nacl
    key_rotation_days: int = 7

    @classmethod
    def from_file(cls, path: Path) -> StealthConfig:
        """Load configuration from JSON file."""
        if path.exists():
            data = json.loads(path.read_text())
            return cls(**data)
        return cls()

    def to_file(self, path: Path) -> None:
        """Save configuration to JSON file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "tor_socks_port": self.tor_socks_port,
            "tor_control_port": self.tor_control_port,
            "tor_data_dir": str(self.tor_data_dir),
            "opsec_enabled": self.opsec_enabled,
            "anonymize_logs": self.anonymize_logs,
            "log_retention_days": self.log_retention_days,
            "cleanup_frequency": self.cleanup_frequency,
            "use_onion_services": self.use_onion_services,
            "use_stem_circuits": self.use_stem_circuits,
            "circuit_padding": self.circuit_padding,
            "fingerprint_obfuscation": self.fingerprint_obfuscation,
            "tls_fingerprint": self.tls_fingerprint,
            "user_agents": self.user_agents,
            "socks_proxy": self.socks_proxy,
            "http_proxy": self.http_proxy,
            "dns_proxy": self.dns_proxy,
            "encryption": self.encryption,
            "key_rotation_days": self.key_rotation_days,
        }, indent=2))


# ============================================================================
# TOR CONTROL
# ============================================================================

class TorController:
    """Controls Tor for anonymous communications."""

    def __init__(self, config: StealthConfig):
        self.config = config
        self.socks_port = config.tor_socks_port
        self.control_port = config.tor_control_port
        self.control_socket: Optional[str] = None
        self.is_active = False
        self.onion_services: Dict[str, str] = {}

    def install(self) -> bool:
        """Install Tor if not present."""
        try:
            result = subprocess.run(
                ["apt-get", "install", "-y", "tor"],
                capture_output=True,
                text=True,
                check=True,
            )
            return result.returncode == 0
        except subprocess.CalledProcessError as e:
            print(f"[TOR] Installation failed: {e.stderr}")
            return False

    def start(self) -> bool:
        """Start Tor service."""
        try:
            result = subprocess.run(
                ["systemctl", "start", "tor"],
                capture_output=True,
                text=True,
                check=True,
            )
            self.is_active = True
            return True
        except subprocess.CalledProcessError as e:
            print(f"[TOR] Failed to start: {e.stderr}")
            return False

    def stop(self) -> bool:
        """Stop Tor service."""
        try:
            subprocess.run(
                ["systemctl", "stop", "tor"],
                capture_output=True,
                text=True,
                check=True,
            )
            self.is_active = False
            return True
        except subprocess.CalledProcessError as e:
            print(f"[TOR] Failed to stop: {e.stderr}")
            return False

    def restart(self) -> bool:
        """Restart Tor service."""
        try:
            subprocess.run(
                ["systemctl", "restart", "tor"],
                capture_output=True,
                text=True,
                check=True,
            )
            self.is_active = True
            return True
        except subprocess.CalledProcessError as e:
            print(f"[TOR] Failed to restart: {e.stderr}")
            return False

    def is_listening(self) -> bool:
        """Check if Tor is listening on SOCKS port."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect(("127.0.0.1", self.socks_port))
            return True
        except (socket.timeout, socket.error):
            return False

    def get_circuit(self) -> Dict[str, Any]:
        """Get current Tor circuit information."""
        try:
            result = subprocess.run(
                ["curl", "-s", f"http://127.0.0.1:{self.control_port}/api/versions"],
                capture_output=True,
                text=True,
                check=True,
            )
            return {"status": "active", "socks": self.socks_port}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def new_circuit(self) -> bool:
        """Request a new Tor circuit."""
        try:
            subprocess.run(
                ["systemctl", "reload", "tor"],
                capture_output=True,
                text=True,
                check=True,
            )
            time.sleep(1)  # Wait for new circuit
            return True
        except Exception as e:
            print(f"[TOR] New circuit request: {e}")
            return False

    def create_onion_service(self, port: int, target_port: Optional[int] = None) -> str:
        """Create a new onion service."""
        service_id = f"shadow_{port}_{int(time.time())}"
        onion_dir = Path("/var/lib/tor/services") / service_id

        try:
            onion_dir.mkdir(parents=True, exist_ok=True)

            # Create service configuration
            config = f"""HiddenServiceDir {onion_dir}
HiddenServicePort {port} 127.0.0.1:{target_port or port}
"""

            (onion_dir / "hostname").write_text(f"{service_id}.onion")
            (onion_dir / "config").write_text(config)

            self.onion_services[service_id] = f"{service_id}.onion"

            return f"{service_id}.onion"
        except Exception as e:
            print(f"[TOR] Failed to create onion service: {e}")
            return ""

    def destroy_onion_service(self, service_id: str) -> bool:
        """Destroy an onion service."""
        onion_dir = Path("/var/lib/tor/services") / service_id

        try:
            if onion_dir.exists():
                subprocess.run(
                    ["rm", "-rf", str(onion_dir)],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                del self.onion_services[service_id]
            return True
        except Exception as e:
            print(f"[TOR] Failed to destroy onion service: {e}")
            return False


# ============================================================================
# OPERATIONAL SECURITY (OPSEC)
# ============================================================================

class OPSEC:
    """Handles operational security tasks."""

    def __init__(self, config: StealthConfig):
        self.config = config
        self.log_dir = Path("/var/log/shadow_opsec")
        self.metadata_dir = Path("/var/lib/shadow_metadata")
        self.traffic_mask = self._init_traffic_mask()

    def _init_traffic_mask(self) -> Dict[str, Any]:
        """Initialize traffic masking state."""
        return {
            "total_bytes": 0,
            "total_packets": 0,
            "timestamps": [],
            "sources": [],
        }

    def log_operation(self, operation: str, details: Dict[str, Any]) -> None:
        """Log an operation for OPSEC review."""
        if not self.config.opsec_enabled:
            return

        self.log_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).isoformat()
        log_entry = {
            "timestamp": timestamp,
            "operation": operation,
            "details": details,
        }

        # Write to log file
        log_file = self.log_dir / f"opsec_{timestamp[:10]}.json"
        if log_file.exists():
            existing = json.loads(log_file.read_text())
            existing.append(log_entry)
        else:
            existing = [log_entry]

        log_file.write_text(json.dumps(existing, indent=2))

    def anonymize_log(self, log_path: Path) -> None:
        """Anonymize a log file."""
        if not self.config.anonymize_logs:
            return

        try:
            content = log_path.read_text()

            # Replace IP addresses with placeholders
            content = re.sub(
                r'\b(\d{1,3}\.){3}\d{1,3}\b',
                lambda m: f"IP_{hash(m.group()):08x}",
                content,
            )

            # Replace hostnames
            content = re.sub(
                r'\b[a-zA-Z0-9-]+\.shadow(?:local|org)\b',
                lambda m: f"HOST_{hash(m.group()):08x}",
                content,
            )

            log_path.write_text(content)
        except Exception as e:
            print(f"[OPSEC] Failed to anonymize log: {e}")

    def cleanup_old_logs(self, days: Optional[int] = None) -> None:
        """Clean up old logs beyond retention period."""
        days = days or self.config.log_retention_days
        cutoff = datetime.now() - timedelta(days=days)

        for log_file in self.log_dir.glob("*.json"):
            try:
                mtime = datetime.fromtimestamp(log_file.stat().st_mtime)
                if mtime < cutoff:
                    log_file.unlink()
            except Exception as e:
                print(f"[OPSEC] Failed to cleanup {log_file}: {e}")

    def mask_traffic(self, data: bytes) -> bytes:
        """Mask traffic for stealth transmission."""
        self.traffic_mask["total_bytes"] += len(data)
        self.traffic_mask["total_packets"] += 1
        self.traffic_mask["timestamps"].append(time.time())

        # Simple XOR masking with rotating key
        key = hash(f"{time.time()}:{len(data)}") & 0xFF
        return bytes(b ^ key for b in data)

    def unmask_traffic(self, data: bytes) -> bytes:
        """Unmask received traffic."""
        key = hash(f"{time.time()}:{len(data)}") & 0xFF
        return bytes(b ^ key for b in data)

    def generate_noise(self, size: int = 1024) -> bytes:
        """Generate noise traffic to mask real operations."""
        import random
        return bytes(random.getrandbits(8) for _ in range(size))

    def rotate_keys(self) -> Dict[str, str]:
        """Rotate encryption keys."""
        import base64
        import hashlib

        key_dir = self.metadata_dir / "keys"
        key_dir.mkdir(parents=True, exist_ok=True)

        # Generate new keys
        now = datetime.now(timezone.utc)
        key_data = {
            "encryption": "nacl",
            "created": now.isoformat(),
            "keys": {},
        }

        for algo in ["nacl", "curve25519"]:
            seed = os.urandom(32)
            key_data["keys"][algo] = base64.b64encode(seed).decode()

        # Save old keys for rotation
        if (key_dir / "current.json").exists():
            old_keys = json.loads((key_dir / "current.json").read_text())
            old_keys["rotated_at"] = now.isoformat()
            (key_dir / f"rotated_{now.strftime('%Y%m%d')}.json").write_text(
                json.dumps(old_keys, indent=2)
            )

        # Save new keys
        (key_dir / "current.json").write_text(json.dumps(key_data, indent=2))

        return key_data


# ============================================================================
# TRAFFIC OBUSFUCATION
# ============================================================================

class TrafficObfuscator:
    """Obfuscates network traffic to evade detection."""

    def __init__(self, config: StealthConfig):
        self.config = config
        self.fingerprint = config.tls_fingerprint
        self.user_agent = config.user_agents[0]
        self.stealth_headers = self._build_stealth_headers()

    def _build_stealth_headers(self) -> Dict[str, str]:
        """Build HTTP headers for stealth operations."""
        return {
            "User-Agent": self.fingerprint,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Cache-Control": "max-age=0",
            "Pragma": "no-cache",
        }

    def select_user_agent(self, target: Optional[str] = None) -> str:
        """Select an appropriate user agent."""
        if target and "safari" in target.lower():
            return "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15"
        elif target and "firefox" in target.lower():
            return "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0"
        return self.fingerprint

    def fingerprint_target(self, host: str, port: int = 443) -> Dict[str, Any]:
        """Fingerprint a target by sending probe requests."""
        results = {
            "host": host,
            "port": port,
            "tls_fingerprint": self.fingerprint,
            "headers": self.stealth_headers,
            "obfuscation": "standard",
        }

        try:
            # TLS fingerprint
            import ssl
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    results["tls_version"] = ssock.version()
                    results["cipher"] = ssock.cipher()[0]

        except Exception as e:
            results["tls_error"] = str(e)

        return results

    def obfuscate_request(self, method: str, path: str, body: Optional[bytes] = None) -> Dict[str, Any]:
        """Obfuscate an HTTP request."""
        request = {
            "method": method,
            "path": path,
            "headers": self.stealth_headers.copy(),
            "body_size": len(body) if body else 0,
            "body_hash": hash(body) if body else None,
        }

        # Apply obfuscation based on method
        if method == "GET":
            request["headers"]["If-Modified-Since"] = datetime.now(timezone.utc).isoformat()
        elif method == "POST":
            if body:
                request["body"] = self._encrypt_body(body)

        return request

    def _encrypt_body(self, body: bytes) -> bytes:
        """Encrypt request body for stealth."""
        import base64
        import hashlib

        # Simple XOR encryption with rotating key
        key = hashlib.sha256(body).digest()[:16]
        encrypted = bytes(b ^ key[i % len(key)] for i, b in enumerate(body))

        return base64.b64encode(encrypted).decode()

    def decode_response(self, response: str) -> Dict[str, Any]:
        """Decode an obfuscated response."""
        try:
            # Try to parse as JSON first
            if response.startswith(("{", "[")):
                return {"json": json.loads(response)}
        except json.JSONDecodeError:
            pass

        # Check for encrypted content
        if response.startswith("-----BEGIN"):
            import base64
            data = base64.b64decode(response)
            return {"encrypted": True, "data": data}

        return {"text": response}


# ============================================================================
# CIRCUIT MANAGEMENT
# ============================================================================

class CircuitManager:
    """Manages Tor circuits for stealth operations."""

    def __init__(self, config: StealthConfig):
        self.config = config
        self.circuits: List[Dict[str, Any]] = []
        self.current_circuit: Optional[Dict[str, Any]] = None

    def build_circuit(self, hops: List[str]) -> Dict[str, Any]:
        """Build a new Tor circuit."""
        circuit = {
            "id": len(self.circuits),
            "hops": hops,
            "created": datetime.now(timezone.utc).isoformat(),
            "status": "active",
        }
        self.circuits.append(circuit)
        self.current_circuit = circuit
        return circuit

    def rotate_circuit(self) -> Dict[str, Any]:
        """Rotate to a new circuit."""
        return self.build_circuit(["entry", "middle", "exit"])

    def get_circuit_path(self) -> List[str]:
        """Get the current circuit path."""
        if self.current_circuit:
            return self.current_circuit["hops"]
        return []

    def circuit_fingerprint(self) -> str:
        """Generate a fingerprint for the current circuit."""
        if not self.current_circuit:
            return ""
        return f"circ_{self.current_circuit['id']}_{len(self.current_circuit['hops'])}hops"


# ============================================================================
# NOISE GENERATION
# ============================================================================

class NoiseGenerator:
    """Generates noise traffic to mask real operations."""

    def __init__(self, config: StealthConfig):
        self.config = config
        self.noise_rate = 0.3  # 30% of traffic is noise
        self.noise_sources: List[str] = []

    def generate_noise_packet(self) -> Dict[str, Any]:
        """Generate a single noise packet."""
        import random
        import string

        packet = {
            "type": "noise",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload": {
                "data": ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(100, 1000))),
                "size": random.randint(100, 10000),
                "format": random.choice(["json", "xml", "text"]),
            },
            "destination": random.choice(self.noise_sources or ["google.com", "microsoft.com", "cloudflare.com"]),
        }
        return packet

    def generate_burst(self, count: int = 10) -> List[Dict[str, Any]]:
        """Generate a burst of noise packets."""
        return [self.generate_noise_packet() for _ in range(count)]

    def inject_noise(self, traffic: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Inject noise into real traffic."""
        result = []
        for item in traffic:
            result.append(item)
            if random.random() < self.noise_rate:
                result.append(self.generate_noise_packet())
        return result


# ============================================================================
# STEALTH MODULE MAIN CLASS
# ============================================================================

class StealthModule:
    """Main stealth module for Shadow Agent."""

    def __init__(self, config: Optional[StealthConfig] = None):
        self.config = config or StealthConfig()
        self.tor = TorController(self.config)
        self.opsec = OPSEC(self.config)
        self.obfuscator = TrafficObfuscator(self.config)
        self.circuit_manager = CircuitManager(self.config)
        self.noise = NoiseGenerator(self.config)
        self.is_initialized = False

    def initialize(self) -> None:
        """Initialize the stealth module."""
        print("[STEALTH] Initializing...")

        # Install Tor if needed
        if not self.tor.is_listening():
            print("[STEALTH] Tor not running, installing...")
            if not self.tor.install():
                print("[STEALTH] Warning: Tor installation failed")

        # Start Tor
        if not self.tor.start():
            print("[STEALTH] Warning: Tor start failed")

        # Initialize other components
        self.opsec.log_operation("stealth_init", {"config": "default"})

        self.is_initialized = True
        print("[STEALTH] Initialization complete")

    def enter_stealth(self) -> None:
        """Enter full stealth mode."""
        if not self.is_initialized:
            self.initialize()

        print("[STEALTH] Entering stealth mode...")

        # Build new circuit
        self.circuit_manager.build_circuit(["entry", "middle", "exit"])

        # Apply traffic obfuscation
        self.obfuscator.fingerprint = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

        # Start noise generation
        self.noise.noise_rate = 0.3

        # Log operation
        self.opsec.log_operation("enter_stealth", {
            "circuit_id": self.circuit_manager.current_circuit["id"] if self.circuit_manager.current_circuit else None,
            "fingerprint": self.obfuscator.fingerprint,
            "noise_rate": self.noise.noise_rate,
        })

    def exit_stealth(self) -> None:
        """Exit stealth mode."""
        print("[STEALTH] Exiting stealth mode...")

        if self.circuit_manager.current_circuit:
            self.opsec.log_operation("exit_stealth", {
                "circuit_id": self.circuit_manager.current_circuit["id"],
                "duration": datetime.now(timezone.utc).isoformat(),
            })

    def run_operation(self, operation: str, **kwargs) -> Dict[str, Any]:
        """Run an operation in stealth mode."""
        if not self.is_initialized:
            self.initialize()

        print(f"[STEALTH] Running operation: {operation}")

        # Apply circuit rotation
        if self.config.use_stem_circuits:
            self.circuit_manager.rotate_circuit()

        # Generate noise
        noise_packets = self.noise.generate_burst(5)

        # Run operation
        result = {"operation": operation, "timestamp": datetime.now(timezone.utc).isoformat()}

        # Log operation
        self.opsec.log_operation(operation, {"kwargs": kwargs, "noise_packets": len(noise_packets)})

        return result

    def get_status(self) -> Dict[str, Any]:
        """Get current stealth status."""
        return {
            "tor_active": self.tor.is_listening(),
            "opsec_enabled": self.config.opsec_enabled,
            "anonymize_logs": self.config.anonymize_logs,
            "current_circuit": self.circuit_manager.current_circuit["id"] if self.circuit_manager.current_circuit else None,
            "fingerprint": self.obfuscator.fingerprint,
            "noise_rate": self.noise.noise_rate,
            "onion_services": len(self.tor.onion_services),
        }

    def cleanup(self) -> None:
        """Clean up stealth module."""
        print("[STEALTH] Cleaning up...")

        # Rotate keys
        self.opsec.rotate_keys()

        # Clean old logs
        self.opsec.cleanup_old_logs(self.config.log_retention_days)

        # Stop Tor
        self.tor.stop()

        # Log cleanup
        self.opsec.log_operation("cleanup", {"status": "complete"})

        self.is_initialized = False


# ============================================================================
# MODULE EXPORTS
# ============================================================================

__all__ = [
    "StealthConfig",
    "TorController",
    "OPSEC",
    "TrafficObfuscator",
    "CircuitManager",
    "NoiseGenerator",
    "StealthModule",
]
