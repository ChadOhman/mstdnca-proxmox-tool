"""IPMI / Redfish tools for the AI assistant (core/ai_tools.py), mirroring routes/ipmi.py.

- get_ipmi_status (can_view_ipmi): health snapshot per IPMI-enabled host, optional SEL.
- control_ipmi_power (can_manage_ipmi): two-phase; the preview reads the current power state.
- Every BMC session is logged out afterwards (routes.ipmi._redfish_session).
"""
import json
from unittest.mock import MagicMock, patch

from models import AuditLog, ProxmoxHost, Role, User, db
from tests.test_ai_live_tools import _admin

SNAPSHOT = {
    "manufacturer": "Supermicro", "model": "X11", "serial": "S123", "bios_version": "3.4", "hostname": "lola",
    "power_state": "On", "health": "Warning", "state": "Enabled",
    "health_issues": [{"subsystem": "Fan: FAN2", "health": "Warning"}],
    "total_memory_gb": 128, "processor_count": 2, "processor_model": "Xeon",
    "cpu_temp": 48, "system_temp": 31, "total_watts": 210,
    "temperatures": [{"name": "CPU Temp", "reading_celsius": 48, "health": "OK", "upper_threshold_critical": 95}],
    "fans": [{"name": "FAN2", "reading_rpm": 900, "units": "RPM", "health": "Warning"}],
    "power_supplies": [{"name": "PSU1", "health": "OK", "state": "Enabled", "power_output_watts": 210,
                        "power_capacity_watts": 750}],
}


def _make_host(app, name="ai-ipmi-host", ipmi_enabled=True):
    with app.app_context():
        host = ProxmoxHost(name=name, hostname="10.0.0.26", host_type="pve", ipmi_enabled=ipmi_enabled,
                           ipmi_address="10.0.0.126", ipmi_username="ADMIN")
        db.session.add(host)
        db.session.commit()
        return host.id


def _cleanup(app, *host_ids):
    with app.app_context():
        for host_id in host_ids:
            host = ProxmoxHost.query.get(host_id)
            if host:
                db.session.delete(host)
        db.session.commit()


def _fake_bmc(**attrs):
    client = MagicMock()
    for name, value in attrs.items():
        getattr(client, name).return_value = value
    return client


def _view_only_user():
    role = Role.query.filter_by(name="_ai_ipmi_viewer").first()
    if not role:
        role = Role(name="_ai_ipmi_viewer", display_name="AI IPMI viewer", level=3, is_builtin=False,
                    can_use_ai=True, can_view_ipmi=True, can_manage_ipmi=False)
        db.session.add(role)
        db.session.commit()
    user = User.query.filter_by(username="_ai_ipmi_viewer").first()
    if not user:
        user = User(username="_ai_ipmi_viewer", display_name="AI IPMI viewer", role_id=role.id)
        user.set_password("test-only-dummy")
        db.session.add(user)
        db.session.commit()
    return User.query.options(db.joinedload(User.role_obj)).get(user.id)


class TestOffering:

    def test_view_only_user_cannot_control_power(self, app):
        from core.ai_tools import execute_tool, get_tools_for_user
        with app.app_context():
            assert {"get_ipmi_status", "control_ipmi_power"} <= {t["name"] for t in get_tools_for_user(_admin())}
            user = _view_only_user()
            names = {t["name"] for t in get_tools_for_user(user)}
            assert "get_ipmi_status" in names and "control_ipmi_power" not in names
            with patch("routes.ipmi._get_redfish_client") as factory:
                denied = json.loads(execute_tool(
                    "control_ipmi_power", {"host_id": 1, "action": "off", "confirm": True}, user))
            assert "can_manage_ipmi" in denied["error"]
            factory.assert_not_called()


class TestGetIpmiStatus:

    def test_single_host_snapshot_with_event_log_and_logout(self, app):
        from core.ai_tools import execute_tool
        host_id = _make_host(app)
        bmc = _fake_bmc(get_health_snapshot=dict(SNAPSHOT),
                        get_sel_entries=[{"id": "1", "created": "2026-09-22T01:00:00Z", "message": "Fan 2 low",
                                          "severity": "Warning", "sensor_type": "Fan"}])
        try:
            with app.app_context(), patch("routes.ipmi._get_redfish_client", return_value=bmc):
                result = json.loads(execute_tool(
                    "get_ipmi_status", {"host_id": host_id, "include_event_log": True, "event_limit": 5}, _admin()))
            assert result["reachable"] is True
            assert result["power_state"] == "On" and result["health"] == "Warning"
            assert result["health_issues"] == [{"subsystem": "Fan: FAN2", "health": "Warning"}]
            assert result["system"]["model"] == "X11" and result["memory_gb"] == 128
            assert result["cpu_temp_c"] == 48 and result["power_consumed_watts"] == 210
            assert result["fans"] == [{"name": "FAN2", "reading": 900, "units": "RPM", "health": "Warning"}]
            assert result["power_supplies"][0]["capacity_watts"] == 750
            assert result["temperatures"][0] == {"name": "CPU Temp", "celsius": 48, "health": "OK", "critical_at": 95}
            assert result["event_log"] == [{"created": "2026-09-22T01:00:00Z", "severity": "Warning",
                                            "message": "Fan 2 low", "sensor_type": "Fan"}]
            bmc.get_sel_entries.assert_called_once_with(limit=5)
            bmc.logout.assert_called_once()
        finally:
            _cleanup(app, host_id)

    def test_all_hosts_and_unreachable_bmc(self, app):
        from core.ai_tools import execute_tool
        good = _make_host(app, name="ai-ipmi-good")
        bad = _make_host(app, name="ai-ipmi-bad")
        off = _make_host(app, name="ai-ipmi-off", ipmi_enabled=False)

        def factory(host):
            if host.name == "ai-ipmi-good":
                return _fake_bmc(get_health_snapshot=dict(SNAPSHOT))
            return _fake_bmc(get_health_snapshot=None)

        try:
            with app.app_context(), patch("routes.ipmi._get_redfish_client", side_effect=factory):
                result = json.loads(execute_tool("get_ipmi_status", {}, _admin()))
                disabled = json.loads(execute_tool("get_ipmi_status", {"host_id": off}, _admin()))
            by_name = {h["name"]: h for h in result["hosts"]}
            assert result["count"] == len(by_name) and {"ai-ipmi-good", "ai-ipmi-bad"} <= set(by_name)
            assert "ai-ipmi-off" not in by_name
            assert by_name["ai-ipmi-good"]["reachable"] is True and "event_log" not in by_name["ai-ipmi-good"]
            assert by_name["ai-ipmi-bad"] == {"host_id": bad, "name": "ai-ipmi-bad", "ipmi_address": "10.0.0.126",
                                              "reachable": False, "error": "The BMC did not answer"}
            assert disabled == {"error": "IPMI is not enabled for host 'ai-ipmi-off'"}
        finally:
            _cleanup(app, good, bad, off)

    def test_unconfigured_bmc(self, app):
        from core.ai_tools import execute_tool
        host_id = _make_host(app)
        try:
            with app.app_context(), patch("routes.ipmi._get_redfish_client", return_value=None):
                result = json.loads(execute_tool("get_ipmi_status", {"host_id": host_id}, _admin()))
            assert result["reachable"] is False and "not fully configured" in result["error"]
        finally:
            _cleanup(app, host_id)


class TestControlIpmiPower:

    def test_invalid_action_and_disabled_host(self, app):
        from core.ai_tools import execute_tool
        host_id = _make_host(app, ipmi_enabled=False)
        try:
            with app.app_context():
                bad = json.loads(execute_tool("control_ipmi_power", {"host_id": host_id, "action": "explode"}, _admin()))
                disabled = json.loads(execute_tool("control_ipmi_power", {"host_id": host_id, "action": "on"}, _admin()))
            assert "Invalid action" in bad["error"]
            assert "not enabled" in disabled["error"]
        finally:
            _cleanup(app, host_id)

    def test_preview_reads_power_state_and_warns_on_hard_actions(self, app):
        from core.ai_tools import execute_tool
        host_id = _make_host(app)
        bmc = _fake_bmc(get_system_info={"power_state": "On"})
        try:
            with app.app_context(), patch("routes.ipmi._get_redfish_client", return_value=bmc):
                hard = json.loads(execute_tool("control_ipmi_power", {"host_id": host_id, "action": "cycle"}, _admin()))
                soft = json.loads(execute_tool(
                    "control_ipmi_power", {"host_id": host_id, "action": "graceful_shutdown"}, _admin()))
            bmc.power_action.assert_not_called()
            assert bmc.logout.call_count == 2
            assert hard["status"] == "confirmation_required"
            assert "currently On" in hard["message"] and "every VM and container" in hard["message"]
            assert hard["pending_action"] == {"tool": "control_ipmi_power", "host_id": host_id, "host": "ai-ipmi-host",
                                              "action": "cycle", "current_power_state": "On"}
            assert "every VM and container" not in soft["message"]
        finally:
            _cleanup(app, host_id)

    def test_preview_survives_bmc_failure(self, app):
        from core.ai_tools import execute_tool
        host_id = _make_host(app)
        bmc = MagicMock()
        bmc.get_system_info.side_effect = RuntimeError("timeout")
        try:
            with app.app_context(), patch("routes.ipmi._get_redfish_client", return_value=bmc):
                result = json.loads(execute_tool("control_ipmi_power", {"host_id": host_id, "action": "on"}, _admin()))
            assert result["status"] == "confirmation_required"
            assert result["pending_action"]["current_power_state"] == "unknown"
        finally:
            _cleanup(app, host_id)

    def test_confirmed_action_runs_once_and_is_audited(self, app):
        from core.ai_tools import execute_tool
        host_id = _make_host(app)
        bmc = _fake_bmc(power_action=(True, "ok"))
        try:
            with app.app_context(), patch("routes.ipmi._get_redfish_client", return_value=bmc):
                result = json.loads(execute_tool(
                    "control_ipmi_power", {"host_id": host_id, "action": "graceful_shutdown", "confirm": True},
                    _admin()))
                audit = AuditLog.query.filter_by(action="ipmi_power_graceful_shutdown").order_by(AuditLog.id.desc()).first()
                assert audit.resource_id == host_id
                assert audit.details == {"ipmi_address": "10.0.0.126", "via": "ai_assistant"}
            assert result == {"success": True, "message": "Power graceful_shutdown command sent to ai-ipmi-host."}
            bmc.power_action.assert_called_once_with("graceful_shutdown")
            bmc.get_system_info.assert_not_called()
            bmc.logout.assert_called_once()
        finally:
            _cleanup(app, host_id)

    def test_bmc_rejection_is_generic_and_not_audited(self, app):
        from core.ai_tools import execute_tool
        host_id = _make_host(app)
        bmc = _fake_bmc(power_action=(False, "401 Unauthorized for ADMIN@10.0.0.126"))
        try:
            with app.app_context(), patch("routes.ipmi._get_redfish_client", return_value=bmc):
                before = AuditLog.query.filter_by(action="ipmi_power_off").count()
                result = json.loads(execute_tool(
                    "control_ipmi_power", {"host_id": host_id, "action": "off", "confirm": True}, _admin()))
                assert AuditLog.query.filter_by(action="ipmi_power_off").count() == before
            assert result["success"] is False
            assert "401" not in result["message"] and "rejected the power off" in result["message"]
        finally:
            _cleanup(app, host_id)
