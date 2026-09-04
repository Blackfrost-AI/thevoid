"""THE VOID — Stealth: The invisible hand that keeps the agent unseen.

Tor, jitter, timing evasion, and traffic obfuscation.
The agent doesn't just attack — it attacks without being seen.
"""

import os
import time
import random
import subprocess
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("void.stealth")


class Stealth:
    """Stealth manager for the agent — Tor, jitter, timing evasion, and traffic obfuscation."""

    def __init__(self, tor_enabled: bool = True, jitter_min: float = 0.5,
                 jitter_max: float = 3.0, jitter_factor: float = 1.5):
        """Initialize the stealth manager.

        Args:
            tor_enabled: Whether to use Tor for anonymity
            jitter_min: Minimum jitter in seconds
            jitter_max: Maximum jitter in seconds
            jitter_factor: Jitter factor for randomization
        """
        self.tor_enabled = tor_enabled
        self.jitter_min = jitter_min
        self.jitter_max = jitter_max
        self.jitter_factor = jitter_factor
        self._tor_active = False
        self._tor_pid: Optional[int] = None
        logger.info(f"Stealth initialized (tor={tor_enabled}, jitter={jitter_min}-{jitter_max}s)")

    def activate_tor(self) -> bool:
        """Activate Tor for anonymity.

        Returns:
            True if Tor is active, False otherwise
        """
        if self._tor_active:
            logger.info("Tor is already active")
            return True

        try:
            # Start Tor service
            result = subprocess.run(
                ["systemctl", "start", "tor"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                self._tor_active = True
                logger.info("Tor activated successfully")
                return True

            # Try direct tor command if systemctl fails
            proc = subprocess.Popen(
                ["tor", "--runasdaemon", "1", "--SocksPort", "9050"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            self._tor_pid = proc.pid
            time.sleep(3)
            self._tor_active = True
            logger.info(f"Tor activated via direct command (PID={self._tor_pid})")
            return True
        except Exception as e:
            logger.error(f"Failed to activate Tor: {e}")
            return False

    def deactivate_tor(self) -> None:
        """Deactivate Tor."""
        if self._tor_pid:
            try:
                os.kill(self._tor_pid, 15)
                self._tor_pid = None
            except Exception:
                pass
        self._tor_active = False
        logger.info("Tor deactivated")

    def is_tor_active(self) -> bool:
        """Check if Tor is active."""
        return self._tor_active

    def get_tor_proxy(self) -> str:
        """Get the Tor SOCKS proxy address."""
        return "socks5h://127.0.0.1:9050"

    def add_jitter(self, base_time: float) -> float:
        """Add random jitter to a base time.

        Args:
            base_time: Base time in seconds

        Returns:
            Base time with jitter applied
        """
        jitter = random.uniform(self.jitter_min, self.jitter_max)
        return base_time * self.jitter_factor + jitter

    def sleep_jitter(self, base_time: Optional[float] = None) -> None:
        """Sleep for a randomized duration.

        Args:
            base_time: Base time in seconds (if None, uses random between jitter_min and jitter_max)
        """
        if base_time is None:
            base_time = random.uniform(self.jitter_min, self.jitter_max)
        sleep_time = self.add_jitter(base_time)
        logger.debug(f"Sleeping for {sleep_time:.2f}s (jitter)")
        time.sleep(sleep_time)

    def get_evasion_headers(self) -> Dict[str, str]:
        """Get HTTP headers for traffic evasion."""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
        ]
        return {
            "User-Agent": random.choice(user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": random.choice([
                "en-US,en;q=0.5",
                "en-GB,en;q=0.9",
                "en-US,en;q=0.9,fr;q=0.8",
            ]),
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }

    def randomize_mac(self, interface: str = "eth0") -> bool:
        """Randomize the MAC address of a network interface.

        Args:
            interface: Network interface to randomize

        Returns:
            True if successful, False otherwise
        """
        try:
            mac = ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))
            subprocess.run(
                ["macchanger", "-r", interface],
                capture_output=True, text=True, timeout=10
            )
            logger.info(f"MAC address randomized on {interface}")
            return True
        except Exception as e:
            logger.error(f"Failed to randomize MAC on {interface}: {e}")
            return False

    def get_status(self) -> Dict[str, Any]:
        """Get the current stealth status."""
        return {
            "tor_active": self._tor_active,
            "tor_pid": self._tor_pid,
            "tor_proxy": self.get_tor_proxy() if self._tor_active else None,
            "jitter_range": f"{self.jitter_min}-{self.jitter_max}s",
            "jitter_factor": self.jitter_factor,
        }

    def __repr__(self) -> str:
        return f"Stealth(tor={self._tor_active}, jitter={self.jitter_min}-{self.jitter_max}s)"
