"""THE VOID — Tests for C2 module: C2Daemon, Beacon, C2Commands."""

import os
import sys
import json
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.executor import Executor
from core.crypto import Crypto
from c2.daemon import C2Daemon
from c2.beacon import Beacon
from c2.commands import C2Commands


# ═══════════════════════════════════════════════════════════════════════════════
#  C2 DAEMON TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestC2Daemon:
    """Tests for C2Daemon class."""

    def test_init(self):
        d = C2Daemon()
        assert d.host == "0.0.0.0"
        assert d.port == 443

    def test_init_custom_port(self):
        d = C2Daemon(port=9999)
        assert d.port == 9999

    def test_init_custom_host(self):
        d = C2Daemon(host="10.0.0.1")
        assert d.host == "10.0.0.1"

    def test_has_set_handler(self):
        d = C2Daemon()
        assert hasattr(d, 'set_handler')

    def test_has_start(self):
        d = C2Daemon()
        assert hasattr(d, 'start')

    def test_has_stop(self):
        d = C2Daemon()
        assert hasattr(d, 'stop')

    def test_has_get_status(self):
        d = C2Daemon()
        assert hasattr(d, 'get_status')

    def test_has_add_command(self):
        d = C2Daemon()
        assert hasattr(d, 'add_command')

    def test_has_get_commands(self):
        d = C2Daemon()
        assert hasattr(d, 'get_commands')

    def test_has_get_result(self):
        d = C2Daemon()
        assert hasattr(d, 'get_result')

    def test_clients_empty(self):
        d = C2Daemon()
        assert d.clients == {}

    def test_beacons_empty(self):
        d = C2Daemon()
        assert d.beacons == {}

    def test_command_queue_empty(self):
        d = C2Daemon()
        assert d.command_queue == []


# ═══════════════════════════════════════════════════════════════════════════════
#  BEACON TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestBeacon:
    """Tests for Beacon class."""

    def test_init(self):
        b = Beacon()
        assert b.beacon_id.startswith("void-")
        assert b.crypto is not None

    def test_init_custom_id(self):
        b = Beacon(beacon_id="test-beacon")
        assert b.beacon_id == "test-beacon"

    def test_init_custom_crypto(self):
        c = Crypto()
        b = Beacon(crypto=c)
        assert b.crypto is c

    def test_has_checkin(self):
        b = Beacon()
        assert hasattr(b, 'checkin')

    def test_has_get_next_interval(self):
        b = Beacon()
        assert hasattr(b, 'get_next_interval')

    def test_has_set_interval(self):
        b = Beacon()
        assert hasattr(b, 'set_interval')

    def test_has_get_status(self):
        b = Beacon()
        assert hasattr(b, 'get_status')

    def test_has_activate(self):
        b = Beacon()
        assert hasattr(b, 'activate')

    def test_has_deactivate(self):
        b = Beacon()
        assert hasattr(b, 'deactivate')

    def test_interval_default(self):
        b = Beacon()
        assert b.interval == 30

    def test_jitter_default(self):
        b = Beacon()
        assert b.jitter == 0.2

    def test_active_default(self):
        b = Beacon()
        assert b.active is True

    def test_active_default(self):
        b = Beacon()
        assert b.active is True

    def test_deactivate(self):
        b = Beacon()
        b.deactivate()
        assert b.active is False

    def test_activate(self):
        b = Beacon()
        b.deactivate()
        b.activate()
        assert b.active is True

    def test_set_interval(self):
        b = Beacon()
        b.set_interval(60)
        assert b.interval == 60


# ═══════════════════════════════════════════════════════════════════════════════
#  C2 COMMANDS TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestC2Commands:
    """Tests for C2Commands class."""

    def test_init(self):
        c = C2Commands()
        assert c.executor is not None
        assert c.crypto is not None

    def test_init_custom(self):
        e = Executor()
        cr = Crypto()
        c = C2Commands(executor=e, crypto=cr)
        assert c.executor is e
        assert c.crypto is cr

    def test_has_execute(self):
        c = C2Commands()
        assert hasattr(c, 'execute')

    def test_has_batch_execute(self):
        c = C2Commands()
        assert hasattr(c, 'batch_execute')

    def test_has_get_log(self):
        c = C2Commands()
        assert hasattr(c, 'get_log')

    def test_has_get_summary(self):
        c = C2Commands()
        assert hasattr(c, 'get_summary')

    def test_command_log_empty(self):
        c = C2Commands()
        assert c.command_log == []
