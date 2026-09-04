"""THE VOID — Tests for MCPC2 module: Post-exploitation C2 channel."""

import os
import sys
import json
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from c2.mcp_c2 import (
    MCPC2, ChannelState, BeaconResult, Task, ENCODING_SCHEMES,
)
from core.executor import Executor
from core.target import Target
from core.boneyard import Boneyard
from core.warlog import WarLog


# ═══════════════════════════════════════════════════════════════════════════════
#  DATA CLASS TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestChannelState:
    """Tests for ChannelState dataclass."""

    def test_init_defaults(self):
        t = Target("10.0.0.1")
        ch = ChannelState(channel_id="ch-1", target=t,
                          endpoint="/tools", auth={"key": "val"},
                          tool_name="ping")
        assert ch.channel_id == "ch-1"
        assert ch.endpoint == "/tools"
        assert ch.encoding == "base64"
        assert ch.status == "active"
        assert ch.beacon_count == 0
        assert ch.task_count == 0
        assert ch.fail_count == 0

    def test_init_with_optional_fields(self):
        t = Target("10.0.0.1")
        ch = ChannelState(channel_id="ch-2", target=t,
                          endpoint="/tools", auth={},
                          tool_name="ping",
                          resource_uri="file://x",
                          encoding="hex")
        assert ch.resource_uri == "file://x"
        assert ch.encoding == "hex"


class TestBeaconResult:
    """Tests for BeaconResult dataclass."""

    def test_init(self):
        br = BeaconResult(channel_id="ch-1", beacon_id="b-1",
                          timestamp=1000.0, status="success")
        assert br.channel_id == "ch-1"
        assert br.beacon_id == "b-1"
        assert br.status == "success"
        assert br.task_received is None

    def test_init_with_task(self):
        br = BeaconResult(channel_id="ch-1", beacon_id="b-1",
                          timestamp=1000.0, status="success",
                          task_received={"task_id": "t-1"})
        assert br.task_received == {"task_id": "t-1"}


class TestTask:
    """Tests for Task dataclass."""

    def test_init_defaults(self):
        task = Task(task_id="t-1", channel_id="ch-1", command="exec")
        assert task.task_id == "t-1"
        assert task.channel_id == "ch-1"
        assert task.command == "exec"
        assert task.params == {}
        assert task.status == "pending"
        assert task.result is None

    def test_init_with_params(self):
        task = Task(task_id="t-2", channel_id="ch-1",
                    command="ls", params={"path": "/tmp"})
        assert task.params == {"path": "/tmp"}


# ═══════════════════════════════════════════════════════════════════════════════
#  ENCODING SCHEMES CONSTANT
# ═══════════════════════════════════════════════════════════════════════════════

class TestEncodingSchemes:
    """Tests for ENCODING_SCHEMES constant."""

    def test_schemes_count(self):
        assert len(ENCODING_SCHEMES) == 5

    def test_scheme_keys(self):
        assert "base64" in ENCODING_SCHEMES
        assert "hex" in ENCODING_SCHEMES
        assert "field_stego" in ENCODING_SCHEMES
        assert "resource_embed" in ENCODING_SCHEMES

    def test_scheme_values_are_strings(self):
        for k, v in ENCODING_SCHEMES.items():
            assert isinstance(v, str)


# ═══════════════════════════════════════════════════════════════════════════════
#  MCPC2 INIT & BASIC
# ═══════════════════════════════════════════════════════════════════════════════

class TestMCPC2Init:
    """Tests for MCPC2 class initialization."""

    def test_init_default(self):
        c = MCPC2()
        assert c.executor is not None
        assert c.boneyard is not None
        assert c.warlog is not None
        assert c.channels == {}
        assert c.active_beacons == {}
        assert c.tasks == {}

    def test_init_custom_executor(self):
        e = Executor()
        c = MCPC2(executor=e)
        assert c.executor is e

    def test_init_custom_boneyard(self):
        b = Boneyard()
        c = MCPC2(boneyard=b)
        assert c.boneyard is b

    def test_init_custom_warlog(self):
        w = WarLog()
        c = MCPC2(warlog=w)
        assert c.warlog is w


# ═══════════════════════════════════════════════════════════════════════════════
#  MCPC2 PUBLIC METHODS
# ═══════════════════════════════════════════════════════════════════════════════

class TestMCPC2PublicMethods:
    """Tests for MCPC2 public API method existence."""

    def test_establish_channel_exists(self):
        c = MCPC2()
        assert hasattr(c, 'establish_channel')

    def test_beacon_exists(self):
        c = MCPC2()
        assert hasattr(c, 'beacon')

    def test_receive_task_exists(self):
        c = MCPC2()
        assert hasattr(c, 'receive_task')

    def test_send_result_exists(self):
        c = MCPC2()
        assert hasattr(c, 'send_result')

    def test_get_channel_status_exists(self):
        c = MCPC2()
        assert hasattr(c, 'get_channel_status')

    def test_list_channels_exists(self):
        c = MCPC2()
        assert hasattr(c, 'list_channels')

    def test_close_channel_exists(self):
        c = MCPC2()
        assert hasattr(c, 'close_channel')

    def test_get_tasks_exists(self):
        c = MCPC2()
        assert hasattr(c, 'get_tasks')

    def test_check_channel_health_exists(self):
        c = MCPC2()
        assert hasattr(c, 'check_channel_health')

    def test_rotate_channels_exists(self):
        c = MCPC2()
        assert hasattr(c, 'rotate_channels')

    def test_get_active_channel_count_exists(self):
        c = MCPC2()
        assert hasattr(c, 'get_active_channel_count')

    def test_get_total_beacons_exists(self):
        c = MCPC2()
        assert hasattr(c, 'get_total_beacons')

    def test_get_total_tasks_exists(self):
        c = MCPC2()
        assert hasattr(c, 'get_total_tasks')


# ═══════════════════════════════════════════════════════════════════════════════
#  MCPC2 CHANNEL MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

class TestMCPC2Channels:
    """Tests for MCPC2 channel management."""

    def test_list_channels_empty(self):
        c = MCPC2()
        result = c.list_channels()
        assert result == []

    def test_get_active_channel_count_zero(self):
        c = MCPC2()
        assert c.get_active_channel_count() == 0

    def test_get_total_beacons_zero(self):
        c = MCPC2()
        assert c.get_total_beacons() == 0

    def test_get_total_tasks_zero(self):
        c = MCPC2()
        assert c.get_total_tasks() == 0

    def test_get_channel_status_missing(self):
        c = MCPC2()
        result = c.get_channel_status("nonexistent")
        assert result.get("status") in ("error", "not_found")

    def test_close_channel_missing(self):
        c = MCPC2()
        result = c.close_channel("nonexistent")
        assert result.get("status") in ("error", "not_found")

    def test_get_tasks_empty(self):
        c = MCPC2()
        result = c.get_tasks()
        assert result == []

    def test_get_tasks_filtered(self):
        c = MCPC2()
        c.tasks["t-1"] = Task(task_id="t-1", channel_id="ch-1", command="exec", status="pending")
        c.tasks["t-2"] = Task(task_id="t-2", channel_id="ch-1", command="ls", status="completed")
        result = c.get_tasks(status="pending")
        assert len(result) == 1


# ═══════════════════════════════════════════════════════════════════════════════
#  MCPC2 ENCODING
# ═══════════════════════════════════════════════════════════════════════════════

class TestMCPC2Encoding:
    """Tests for MCPC2 encoding/decoding."""

    def test_encode_base64(self):
        c = MCPC2()
        encoded = c._encode("hello", "base64")
        assert isinstance(encoded, str)
        assert len(encoded) > 0

    def test_decode_base64(self):
        c = MCPC2()
        import base64
        encoded = base64.b64encode(b'"hello"').decode()
        decoded = c._decode(encoded, "base64")
        assert decoded == "hello"

    def test_encode_hex(self):
        c = MCPC2()
        encoded = c._encode("hello", "hex")
        assert isinstance(encoded, str)

    def test_decode_hex(self):
        c = MCPC2()
        decoded = c._decode("2268656c6c6f22", "hex")
        assert decoded == "hello"

    def test_encode_unknown_scheme(self):
        c = MCPC2()
        encoded = c._encode("test", "unknown")
        assert isinstance(encoded, str)

    def test_decode_unknown_scheme(self):
        c = MCPC2()
        import base64
        encoded = base64.b64encode(b'"test"').decode()
        decoded = c._decode(encoded, "unknown")
        assert decoded == "test"


# ═══════════════════════════════════════════════════════════════════════════════
#  MCPC2 INTERNAL HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

class TestMCPC2Helpers:
    """Tests for MCPC2 internal helper methods."""

    def test_build_beacon_payload(self):
        c = MCPC2()
        result = c._build_beacon_payload({"status": "ok"})
        assert isinstance(result, dict)

    def test_extract_task_empty(self):
        c = MCPC2()
        result = c._extract_task({})
        assert result is None

    def test_extract_task_with_command(self):
        c = MCPC2()
        result = c._extract_task({"command": "exec", "params": {}})
        assert result is not None

    def test_build_tool_args(self):
        c = MCPC2()
        result = c._build_tool_args("ping", {"payload": "data"})
        assert isinstance(result, dict)

    def test_verify_channel_exists(self):
        c = MCPC2()
        t = Target("10.0.0.1")
        ch = ChannelState(channel_id="ch-1", target=t,
                          endpoint="/tools", auth={}, tool_name="ping")
        result = c._verify_channel(ch)
        assert isinstance(result, dict)

    def test_resolve_url_default(self):
        c = MCPC2()
        t = Target("10.0.0.1")
        url = c._resolve_url(t)
        assert isinstance(url, str)
        assert "10.0.0.1" in url

    def test_resolve_url_with_port(self):
        c = MCPC2()
        t = Target("10.0.0.1", name="10.0.0.1:9090")
        url = c._resolve_url(t)
        assert "9090" in url

    def test_json_rpc_call_exists(self):
        c = MCPC2()
        assert hasattr(c, '_json_rpc_call')

    def test_establish_channel_with_mock(self):
        """Test establish_channel with mocked JSON-RPC."""
        c = MCPC2()
        t = Target("10.0.0.1")
        with patch('c2.mcp_c2.MCPC2._json_rpc_call') as mock_rpc:
            mock_rpc.return_value = {"jsonrpc": "2.0", "result": {}}
            result = c.establish_channel(t, "ping", "/tools", {"key": "val"})
            assert isinstance(result, dict)

    def test_beacon_with_mock(self):
        """Test beacon with mocked JSON-RPC."""
        c = MCPC2()
        t = Target("10.0.0.1")
        c.channels["ch-1"] = ChannelState(
            channel_id="ch-1", target=t,
            endpoint="/tools", auth={},
            tool_name="ping", status="active")
        with patch('c2.mcp_c2.MCPC2._json_rpc_call') as mock_rpc:
            mock_rpc.return_value = {"jsonrpc": "2.0", "result": {}}
            result = c.beacon("ch-1")
            assert isinstance(result, dict)

    def test_check_channel_health_missing(self):
        c = MCPC2()
        result = c.check_channel_health("nonexistent")
        assert isinstance(result, dict)

    def test_rotate_channels_empty(self):
        c = MCPC2()
        result = c.rotate_channels()
        assert isinstance(result, dict)

    def test_send_result_missing_channel(self):
        c = MCPC2()
        result = c.send_result("nonexistent", "b-1", {"output": "ok"})
        assert isinstance(result, dict)

    def test_receive_task_missing_channel(self):
        c = MCPC2()
        result = c.receive_task("nonexistent")
        assert result is None
