"""Live-resource tools for the AI assistant (core/ai_tools.py) and the round separator.

- get_guest_resource_usage: current CPU / memory / disk / swap from Proxmox
- get_guest_performance_history: RRD summary (average / peak) per timeframe
- get_host_status: live node status and storage pools, offline hosts tolerated
- /ai/chat separates text from consecutive model rounds with a blank line
"""
import json
from unittest.mock import MagicMock, patch

from models import AIChatMessage, AIChatSession, Guest, ProxmoxHost, User, db
from tests.test_ai_chat import _ORIGIN, _enable_ai

GIB = 1024 ** 3


def _admin():
    return User.query.options(db.joinedload(User.role_obj)).filter_by(username="admin").first()


def _make_host_and_guest(app, vmid=103, host_type="pve"):
    with app.app_context():
        host = ProxmoxHost(name="ai-live-host", hostname="10.0.0.26", host_type=host_type)
        db.session.add(host)
        db.session.flush()
        guest = Guest(name="swizzin", guest_type="ct", enabled=True, vmid=vmid,
                      proxmox_host_id=host.id, status="error", power_state="running")
        db.session.add(guest)
        db.session.commit()
        return host.id, guest.id


def _cleanup(app, host_id, guest_id):
    with app.app_context():
        guest = Guest.query.get(guest_id)
        if guest:
            db.session.delete(guest)
        host = ProxmoxHost.query.get(host_id)
        if host:
            db.session.delete(host)
        db.session.commit()


def _fake_client(**attrs):
    """A ProxmoxClient stand-in whose methods return the given values."""
    client = MagicMock()
    for name, value in attrs.items():
        getattr(client, name).return_value = value
    return client


class TestGuestResourceUsage:

    def test_unlinked_guest_explains_no_live_data(self, app):
        from core.ai_tools import execute_tool
        with app.app_context():
            guest = Guest(name="ai-unlinked", guest_type="ct", enabled=True)
            db.session.add(guest)
            db.session.commit()
            try:
                result = json.loads(execute_tool("get_guest_resource_usage", {"guest_id": guest.id}, _admin()))
                assert "not linked to a Proxmox host" in result["error"]
            finally:
                db.session.delete(guest)
                db.session.commit()

    def test_reports_live_figures_with_human_strings(self, app):
        from core.ai_tools import execute_tool
        host_id, guest_id = _make_host_and_guest(app)
        fake = _fake_client(find_guest_node="lola", get_guest_current={
            "status": "running", "cpu": 0.052, "cpus": 2, "uptime": 86400,
            "mem": int(1.5 * GIB), "maxmem": 4 * GIB,
            "disk": 10 * GIB, "maxdisk": 40 * GIB,
            "swap": 0, "maxswap": 512 * 1024 ** 2,
            "netin": 123, "netout": 456,
        })
        try:
            with app.app_context(), patch("clients.proxmox_api.ProxmoxClient", return_value=fake):
                result = json.loads(execute_tool("get_guest_resource_usage", {"guest_id": guest_id}, _admin()))
            assert result["vmid"] == 103
            assert result["host"] == "ai-live-host"
            assert result["node"] == "lola"
            assert result["cpu_percent"] == 5.2
            assert result["memory"]["human"] == "1.5 GiB of 4.0 GiB (37.5%)"
            assert result["memory"]["used_bytes"] == int(1.5 * GIB)
            assert result["disk"]["percent"] == 25.0
            assert result["swap"]["human"] == "0 B of 512.0 MiB (0.0%)"
            assert "note" not in result
            fake.get_guest_current.assert_called_once_with("lola", 103, "ct")
        finally:
            _cleanup(app, host_id, guest_id)

    def test_stopped_guest_is_flagged(self, app):
        from core.ai_tools import execute_tool
        host_id, guest_id = _make_host_and_guest(app)
        fake = _fake_client(find_guest_node="lola",
                            get_guest_current={"status": "stopped", "mem": 0, "maxmem": 4 * GIB})
        try:
            with app.app_context(), patch("clients.proxmox_api.ProxmoxClient", return_value=fake):
                result = json.loads(execute_tool("get_guest_resource_usage", {"guest_id": guest_id}, _admin()))
            assert result["status"] == "stopped"
            assert "not running" in result["note"]
        finally:
            _cleanup(app, host_id, guest_id)

    def test_guest_missing_on_host(self, app):
        from core.ai_tools import execute_tool
        host_id, guest_id = _make_host_and_guest(app)
        fake = _fake_client(find_guest_node=None)
        try:
            with app.app_context(), patch("clients.proxmox_api.ProxmoxClient", return_value=fake):
                result = json.loads(execute_tool("get_guest_resource_usage", {"guest_id": guest_id}, _admin()))
            assert "VMID 103" in result["error"]
            fake.get_guest_current.assert_not_called()
        finally:
            _cleanup(app, host_id, guest_id)


class TestGuestPerformanceHistory:

    def test_summarises_average_and_peak(self, app):
        from core.ai_tools import execute_tool
        host_id, guest_id = _make_host_and_guest(app)
        rows = [
            {"time": 1_700_000_000, "cpu": 0.10, "mem": 1 * GIB, "maxmem": 4 * GIB, "netin": 100, "netout": 50},
            {"time": 1_700_000_060, "cpu": 0.30, "mem": 3 * GIB, "maxmem": 4 * GIB, "netin": 300, "netout": 150},
            {"time": 1_700_000_120},  # RRD gap: no samples, must be ignored
        ]
        fake = _fake_client(find_guest_node="lola", get_rrd_data=rows)
        try:
            with app.app_context(), patch("clients.proxmox_api.ProxmoxClient", return_value=fake):
                result = json.loads(execute_tool(
                    "get_guest_performance_history", {"guest_id": guest_id, "timeframe": "hour"}, _admin()))
            assert result["samples"] == 2
            assert result["cpu_percent"] == {"average": 20.0, "peak": 30.0}
            assert result["memory"]["average"]["human"] == "2.0 GiB of 4.0 GiB (50.0%)"
            assert result["memory"]["peak"]["percent"] == 75.0
            assert result["memory"]["peak_at"].startswith("2023-11-14T22:14:20")
            assert result["network_average_bytes_per_second"] == {"in": 200, "out": 100}
            fake.get_rrd_data.assert_called_once_with("lola", 103, "ct", timeframe="hour")
        finally:
            _cleanup(app, host_id, guest_id)

    def test_defaults_to_day_and_rejects_unknown_timeframe(self, app):
        from core.ai_tools import execute_tool
        host_id, guest_id = _make_host_and_guest(app)
        fake = _fake_client(find_guest_node="lola", get_rrd_data=[])
        try:
            with app.app_context(), patch("clients.proxmox_api.ProxmoxClient", return_value=fake):
                empty = json.loads(execute_tool("get_guest_performance_history", {"guest_id": guest_id}, _admin()))
                bad = json.loads(execute_tool(
                    "get_guest_performance_history", {"guest_id": guest_id, "timeframe": "decade"}, _admin()))
            assert empty["samples"] == 0 and empty["timeframe"] == "day"
            assert "Invalid timeframe" in bad["error"]
        finally:
            _cleanup(app, host_id, guest_id)


class TestHostStatusLive:

    def test_online_host_reports_resources_and_storage(self, app):
        from core.ai_tools import execute_tool
        host_id, guest_id = _make_host_and_guest(app)
        fake = _fake_client(
            get_local_node_name="lola",
            get_node_status={"cpu_usage": 12.5, "cpu_threads": 16, "loadavg": [1.0, 0.8, 0.5],
                             "memory_used": 48 * GIB, "memory_total": 64 * GIB,
                             "swap_used": 0, "swap_total": 8 * GIB,
                             "rootfs_used": 20 * GIB, "rootfs_total": 100 * GIB,
                             "uptime": 3600, "pveversion": "pve-manager/8.2"},
            get_node_storage=[{"name": "zfs-vol", "type": "zfspool", "total": 2000 * GIB,
                               "used": 500 * GIB, "avail": 1500 * GIB, "active": 0}],
        )
        try:
            with app.app_context(), patch("clients.proxmox_api.ProxmoxClient", return_value=fake):
                result = json.loads(execute_tool("get_host_status", {"host_id": host_id}, _admin()))
            assert len(result) == 1
            host = result[0]
            assert host["online"] is True
            assert host["guest_count"] == 1
            assert host["cpu_percent"] == 12.5
            assert host["memory"]["human"] == "48.0 GiB of 64.0 GiB (75.0%)"
            assert host["version"] == "pve-manager/8.2"
            assert host["storage"] == [{
                "name": "zfs-vol", "type": "zfspool", "active": False,
                "used_bytes": 500 * GIB, "total_bytes": 2000 * GIB, "percent": 25.0,
                "human": "500.0 GiB of 2.0 TiB (25.0%)",
            }]
        finally:
            _cleanup(app, host_id, guest_id)

    def test_unreachable_host_is_reported_offline(self, app):
        from core.ai_tools import execute_tool
        host_id, guest_id = _make_host_and_guest(app)
        try:
            with app.app_context(), patch("clients.proxmox_api.ProxmoxClient",
                                          side_effect=RuntimeError("connection refused")):
                result = json.loads(execute_tool("get_host_status", {"host_id": host_id}, _admin()))
            assert result[0]["online"] is False
            assert "memory" not in result[0]
            assert "error" not in result[0]
        finally:
            _cleanup(app, host_id, guest_id)

    def test_unknown_host_id(self, app):
        from core.ai_tools import execute_tool
        with app.app_context():
            result = json.loads(execute_tool("get_host_status", {"host_id": 999999}, _admin()))
        assert result == {"error": "Host not found"}


class _TwoRoundClient:
    """Round 1: text then a tool call. Round 2: text only. Neither text ends with whitespace."""

    def __init__(self):
        self.calls = 0

    def stream_chat(self, messages, system_prompt=None, tools=None):
        self.calls += 1
        if self.calls == 1:
            yield {"type": "text", "content": "I'll look that up."}
            yield {"type": "tool_use", "id": "toolu_sep_1", "name": "list_guests", "input": {}}
            yield {"type": "done", "usage": {"input_tokens": 1, "output_tokens": 1}, "stop_reason": "tool_use"}
        else:
            yield {"type": "text", "content": "I found "}
            yield {"type": "text", "content": "the container."}
            yield {"type": "done", "usage": {"input_tokens": 1, "output_tokens": 1}, "stop_reason": "end_turn"}


class TestRoundSeparator:

    def test_text_from_consecutive_rounds_is_separated(self, auth_client, app):
        _enable_ai(app)
        with patch("clients.claude_client.get_claude_client", return_value=_TwoRoundClient()), \
                patch("core.ai_tools.execute_tool", return_value="[]"):
            resp = auth_client.post("/ai/chat", json={"message": "memory of swizzin?"}, headers=_ORIGIN)
            body = resp.get_data(as_text=True)

        assert resp.status_code == 200
        texts = [json.loads(line[6:])["content"] for line in body.splitlines()
                 if line.startswith("data: ") and json.loads(line[6:]).get("type") == "text"]
        assert texts == ["I'll look that up.", "\n\n", "I found ", "the container."]

        with app.app_context():
            session = AIChatSession.query.order_by(AIChatSession.id.desc()).first()
            saved = AIChatMessage.query.filter_by(session_id=session.id, role="assistant").first()
            assert saved.content == "I'll look that up.\n\nI found the container."
