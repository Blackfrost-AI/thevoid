"""THE VOID — Executor: The command runner that executes Kali tools with precision.

Every command runs through the executor. It handles timeouts, errors, and output capture.
It's the backbone of the agent — without it, nothing moves.
"""

import os
import subprocess
import time
import logging
import shlex
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass, field

logger = logging.getLogger("void.executor")


@dataclass
class CommandResult:
    """Result of a command execution."""
    command: str
    stdout: str
    stderr: str
    exit_code: int
    duration: float
    timed_out: bool = False
    error: Optional[str] = None

    @property
    def success(self) -> bool:
        return self.exit_code == 0 and not self.timed_out

    @property
    def output(self) -> str:
        return self.stdout

    @property
    def has_error(self) -> bool:
        return bool(self.stderr) or self.exit_code != 0 or self.timed_out

    def to_dict(self) -> Dict[str, Any]:
        return {
            "command": self.command,
            "stdout": self.stdout[:10000],  # Truncate large output
            "stderr": self.stderr[:5000],
            "exit_code": self.exit_code,
            "duration": round(self.duration, 3),
            "timed_out": self.timed_out,
            "error": self.error,
            "success": self.success,
        }


class Executor:
    """Executes commands on the system — the backbone of the agent."""

    def __init__(self, default_timeout: int = 300, default_shell: str = "/usr/bin/zsh"):
        """Initialize the executor.

        Args:
            default_timeout: Default timeout in seconds for commands
            default_shell: Shell to use for execution
        """
        self.default_timeout = default_timeout
        self.default_shell = default_shell
        self.history: List[CommandResult] = []
        logger.info(f"Executor initialized (timeout={default_timeout}s, shell={default_shell})")

    def run(self, command: Union[str, List[str]], timeout: Optional[int] = None,
            cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None,
            shell: Optional[bool] = None, capture_output: bool = True,
            stdin: Optional[str] = None) -> CommandResult:
        """Execute a command.

        Args:
            command: Command to execute (string or list of args). Prefer a list
                with shell=False for anything influenced by untrusted input.
            timeout: Timeout in seconds (overrides default)
            cwd: Working directory
            env: Environment variables (merged with current env)
            shell: Whether to use a shell. ``None`` (default) auto-selects:
                list commands → shell=False; string commands → shell=True for
                backward compatibility. Explicit True/False always wins.
            capture_output: Whether to capture stdout/stderr
            stdin: Optional stdin input

        Returns:
            CommandResult with stdout, stderr, exit code, and duration
        """
        if timeout is None:
            timeout = self.default_timeout

        # Auto shell policy: default to shell=False for all command types.
        # String commands are parsed with shlex.split() into argv form.
        # Callers that genuinely need shell features (pipes, redirection,
        # globbing) must explicitly pass shell=True.
        if shell is None:
            shell = False

        if isinstance(command, list):
            command_str = " ".join(str(c) for c in command)
            # For shell=False, pass the list directly to subprocess
            cmd_arg = command if not shell else command_str
        else:
            command_str = command.strip()
            if not shell:
                # Safer string execution: parse into argv instead of shell=True
                try:
                    cmd_arg = shlex.split(command_str)
                except ValueError:
                    cmd_arg = command_str
                    shell = True  # fall back if shlex cannot parse
            else:
                cmd_arg = command_str
        if not command_str:
            return CommandResult(command="", stdout="", stderr="Empty command", exit_code=1, duration=0.0)

        logger.debug(f"Executing: {command_str} (timeout={timeout}s, shell={shell})")
        start = time.time()
        timed_out = False
        try:
            # Merge environment
            merged_env = dict(os.environ)
            if env:
                merged_env.update(env)

            run_kwargs: Dict[str, Any] = dict(
                shell=shell,
                cwd=cwd,
                env=merged_env,
                capture_output=capture_output,
                text=True,
                timeout=timeout,
            )
            if stdin is not None:
                run_kwargs["input"] = stdin
            proc = subprocess.run(cmd_arg, **run_kwargs)
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            stdout = ""
            stderr = f"Command timed out after {timeout}s"
            exit_code = -1
        except Exception as e:
            stdout = ""
            stderr = str(e)
            exit_code = -1

        duration = time.time() - start
        result = CommandResult(
            command=command_str,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            duration=duration,
            timed_out=timed_out,
            error=stderr if not timed_out and exit_code != 0 else None,
        )
        self.history.append(result)

        if result.success:
            logger.debug(f"Command succeeded in {duration:.2f}s")
        else:
            logger.warning(f"Command failed (exit={exit_code}, timeout={timed_out}): {command_str[:80]}")

        return result

    def run_tool(self, tool: str, args: List[str], timeout: Optional[int] = None,
                 cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None) -> CommandResult:
        """Run a specific Kali tool with arguments.

        Args:
            tool: Tool name (e.g., 'nmap', 'hydra')
            args: Arguments list
            timeout: Timeout in seconds
            cwd: Working directory
            env: Environment variables

        Returns:
            CommandResult
        """
        cmd = [tool] + args
        return self.run(cmd, timeout=timeout, cwd=cwd, env=env, shell=False)

    def run_parallel(self, commands: List[Union[str, List[str]]], timeout: Optional[int] = None,
                     cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None,
                     max_workers: int = 10) -> List[CommandResult]:
        """Run multiple commands in parallel using threading.

        Args:
            commands: List of commands to run
            timeout: Timeout for each command
            cwd: Working directory
            env: Environment variables
            max_workers: Maximum number of parallel workers

        Returns:
            List of CommandResult objects
        """
        import concurrent.futures
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self.run, cmd, timeout=timeout, cwd=cwd, env=env): i
                for i, cmd in enumerate(commands)
            }
            for future in concurrent.futures.as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as e:
                    results.append(CommandResult(
                        command="parallel_error",
                        stdout="",
                        stderr=str(e),
                        exit_code=-1,
                        duration=0.0,
                    ))
        return results

    def is_tool_available(self, tool: str) -> bool:
        """Check if a tool is available on the system."""
        result = self.run(f"which {shlex.quote(tool)}", timeout=5)
        return result.success and bool(result.stdout.strip())

    def get_tool_version(self, tool: str) -> Optional[str]:
        """Get the version of a tool."""
        result = self.run(f"{shlex.quote(tool)} --version", timeout=5)
        if result.success:
            return result.stdout.strip().split("\n")[0]
        return None

    def clear_history(self) -> None:
        """Clear the command history."""
        self.history.clear()
        logger.info("Command history cleared")


# ─── Deb822 Sources Migration ────────────────────────────────────────────────

class Deb822Sources:
    """Migrate from /etc/apt/sources.list to /etc/apt/sources.list.d/kali.sources (deb822 format).

    Supports dual-format: both old-style sources.list and new-style deb822
    can coexist during migration. The agent reads old sources, converts to
    deb822, writes the new file, and optionally backs up the old one.
    """

    # Default paths
    LEGACY_PATH = "/etc/apt/sources.list"
    DEB822_PATH = "/etc/apt/sources.list.d/kali.sources"
    BACKUP_SUFFIX = ".bak"

    # Default deb822 template for Kali
    DEB822_TEMPLATE = (
        "Types: deb\n"
        "URIs: https://http.kali.org/kali\n"
        "Suites: {suite}\n"
        "Components: {components}\n"
        "Signed-By: /usr/share/keyrings/kali-archive-keyring.gpg\n"
        "Architectures: {architectures}\n"
    )

    def __init__(self, executor: Optional[Executor] = None):
        self.executor = executor or Executor()
        logger.info("Deb822Sources migration module initialized")

    def read_legacy_sources(self, path: Optional[str] = None) -> Dict[str, Any]:
        """Read and parse legacy sources.list file.

        Args:
            path: Path to sources.list (default: /etc/apt/sources.list)

        Returns:
            Dict with parsed sources entries
        """
        path = path or self.LEGACY_PATH
        result = self.executor.run(f"cat {shlex.quote(path)}", timeout=10)
        if not result.success:
            return {"error": result.stderr, "path": path, "entries": []}

        entries = []
        for line in result.stdout.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("deb ") or line.startswith("deb-src "):
                entry = self._parse_deb_line(line)
                if entry:
                    entries.append(entry)

        return {"path": path, "entries": entries, "count": len(entries)}

    def _parse_deb_line(self, line: str) -> Optional[Dict[str, str]]:
        """Parse a single deb/deb-src line.

        Returns:
            Dict with uri, suite, components, type
        """
        parts = line.split()
        if len(parts) < 4:
            return None
        return {
            "type": parts[0],  # deb or deb-src
            "uri": parts[1],
            "suite": parts[2],
            "components": " ".join(parts[3:]),
        }

    def convert_to_deb822(self, legacy_entries: List[Dict[str, str]],
                          architectures: str = "amd64 arm64") -> str:
        """Convert legacy sources to deb822 format.

        Args:
            legacy_entries: List of parsed deb/deb-src entries
            architectures: Architectures string for deb822

        Returns:
            String content in deb822 format
        """
        if not legacy_entries:
            return ""

        # Group by URI and suite for cleaner deb822 output
        groups: Dict[str, Dict[str, Any]] = {}
        for entry in legacy_entries:
            key = f"{entry['type']}|{entry['uri']}|{entry['suite']}"
            if key not in groups:
                groups[key] = {
                    "type": entry["type"],
                    "uri": entry["uri"],
                    "suite": entry["suite"],
                    "components": set(),
                }
            groups[key]["components"].update(entry["components"].split())

        lines = []
        for group in groups.values():
            lines.append(
                self.DEB822_TEMPLATE.format(
                    suite=group["suite"],
                    components=" ".join(sorted(group["components"])),
                    architectures=architectures,
                )
            )

        return "\n".join(lines)

    def migrate(self, legacy_path: Optional[str] = None,
                deb822_path: Optional[str] = None,
                backup: bool = True,
                architectures: str = "amd64 arm64") -> Dict[str, Any]:
        """Perform the full migration from legacy to deb822 format.

        Args:
            legacy_path: Path to legacy sources.list
            deb822_path: Path to new deb822 file
            backup: Whether to backup the legacy file
            architectures: Architectures string

        Returns:
            Dict with migration results
        """
        legacy_path = legacy_path or self.LEGACY_PATH
        deb822_path = deb822_path or self.DEB822_PATH

        logger.info(f"Migrating {legacy_path} to {deb822_path} (deb822)")

        # Read legacy sources
        legacy = self.read_legacy_sources(legacy_path)
        if "error" in legacy:
            return {"success": False, "error": legacy["error"], "status": "failed"}

        if not legacy["entries"]:
            return {"success": False, "error": "No entries found in legacy sources.list", "status": "failed"}

        # Convert to deb822
        deb822_content = self.convert_to_deb822(legacy["entries"], architectures)

        if not deb822_content:
            return {"success": False, "error": "Conversion produced empty output", "status": "failed"}

        # Backup legacy file if requested
        backup_path = None
        if backup:
            backup_path = f"{legacy_path}{self.BACKUP_SUFFIX}"
            result = self.executor.run(f"cp {shlex.quote(legacy_path)} {shlex.quote(backup_path)}", timeout=10)
            if not result.success:
                logger.warning(f"Failed to backup {legacy_path}: {result.stderr}")

        # Write deb822 file
        result = self.executor.run(
            f"mkdir -p $(dirname {shlex.quote(deb822_path)}) && cat > {shlex.quote(deb822_path)} << 'DEB822_EOF'\n{deb822_content}DEB822_EOF",
            timeout=10,
        )

        if not result.success:
            return {"success": False, "error": result.stderr, "status": "failed"}

        # Verify the deb822 file was written
        verify = self.executor.run(f"cat {shlex.quote(deb822_path)}", timeout=10)
        if not verify.success:
            return {"success": False, "error": "Failed to verify deb822 file", "status": "failed"}

        return {
            "success": True,
            "status": "success",
            "legacy_path": legacy_path,
            "deb822_path": deb822_path,
            "backup_path": backup_path,
            "entries_converted": len(legacy["entries"]),
            "deb822_content": deb822_content,
            "architectures": architectures,
        }

    def is_deb822_present(self, path: Optional[str] = None) -> bool:
        """Check if deb822 sources file exists and has content."""
        path = path or self.DEB822_PATH
        result = self.executor.run(f"test -s {shlex.quote(path)}", timeout=5)
        return result.success

    def is_legacy_present(self, path: Optional[str] = None) -> bool:
        """Check if legacy sources.list exists and has content."""
        path = path or self.LEGACY_PATH
        result = self.executor.run(f"test -s {shlex.quote(path)}", timeout=5)
        return result.success

    def read_deb822(self, path: Optional[str] = None) -> Dict[str, Any]:
        """Read and parse deb822 sources file.

        Returns:
            Dict with parsed deb822 entries
        """
        path = path or self.DEB822_PATH
        result = self.executor.run(f"cat {shlex.quote(path)}", timeout=10)
        if not result.success:
            return {"error": result.stderr, "path": path, "entries": []}

        entries = []
        current: Dict[str, str] = {}
        for line in result.stdout.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                if current:
                    entries.append(current)
                    current = {}
                continue
            if ":" in line:
                key, _, value = line.partition(":")
                key = key.strip()
                value = value.strip()
                if key and value:
                    current[key] = value
            elif current:
                # Multi-line value continuation
                last_key = list(current.keys())[-1]
                current[last_key] += " " + line
        if current:
            entries.append(current)

        return {"path": path, "entries": entries, "count": len(entries)}
