"""Tests for AI tool registry in core/ai_tools.py.

Covers:
- Permission-based tool filtering
- Tool execution with permission checks
- Tool handler output formats
- control_service dual-permission gate (H1)
- control_service two-phase confirmation (M2)
- Generic error messages that don't leak internals (M3)
"""
import json
from unittest.mock import patch

from models import Guest, GuestService, Role, User, db

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_admin_user():
    """Get admin user. Must be called within an app_context."""
    return User.query.options(db.joinedload(User.role_obj)).filter_by(username="admin").first()


def _create_test_guest(app, name="ai-test-guest"):
    with app.app_context():
        g = Guest(name=name, guest_type="ct", enabled=True,
                  ip_address="10.0.0.1", status="up-to-date", power_state="running")
        db.session.add(g)
        db.session.commit()
        return g.id


def _delete_test_guest(app, guest_id):
    with app.app_context():
        g = Guest.query.get(guest_id)
        if g:
            db.session.delete(g)
            db.session.commit()


# ---------------------------------------------------------------------------
# Tool filtering tests
# ---------------------------------------------------------------------------

class TestToolFiltering:
    """get_tools_for_user returns only permitted tools."""

    def test_admin_gets_all_tools(self, app):
        from core.ai_tools import TOOL_REGISTRY, get_tools_for_user
        with app.app_context():
            user = _get_admin_user()
            tools = get_tools_for_user(user)
            assert len(tools) == len(TOOL_REGISTRY)

    def test_viewer_gets_limited_tools(self, app):
        from core.ai_tools import get_tools_for_user
        with app.app_context():
            viewer_role = Role.query.filter_by(name="viewer").first()
            viewer = User.query.filter_by(username="testviewer_tools").first()
            if not viewer:
                viewer = User(username="testviewer_tools", display_name="Tools Viewer",
                              role_id=viewer_role.id)
                viewer.set_password("dummy")
                db.session.add(viewer)
                db.session.commit()

            tools = get_tools_for_user(viewer)
            tool_names = {t["name"] for t in tools}

            # Viewer should get tools with no permission requirement
            assert "list_guests" in tool_names
            assert "get_guest_details" in tool_names

            # Viewer should NOT get service/audit tools
            assert "list_services" not in tool_names
            assert "control_service" not in tool_names
            assert "list_audit_logs" not in tool_names

    def test_tools_have_required_schema(self, app):
        from core.ai_tools import get_tools_for_user
        with app.app_context():
            user = _get_admin_user()
            tools = get_tools_for_user(user)
            for tool in tools:
                assert "name" in tool
                assert "description" in tool
                assert "input_schema" in tool
                assert tool["input_schema"]["type"] == "object"


# ---------------------------------------------------------------------------
# Tool execution tests
# ---------------------------------------------------------------------------

class TestToolExecution:
    """execute_tool runs handlers and enforces permissions."""

    def test_unknown_tool_returns_error(self, app):
        from core.ai_tools import execute_tool
        with app.app_context():
            user = _get_admin_user()
            result = json.loads(execute_tool("nonexistent_tool", {}, user))
            assert "error" in result

    def test_list_guests_returns_list(self, app):
        from core.ai_tools import execute_tool
        guest_id = _create_test_guest(app)
        try:
            with app.app_context():
                user = _get_admin_user()
                result = json.loads(execute_tool("list_guests", {}, user))
                assert isinstance(result, list)
                names = [g["name"] for g in result]
                assert "ai-test-guest" in names
        finally:
            _delete_test_guest(app, guest_id)

    def test_get_guest_details_not_found(self, app):
        from core.ai_tools import execute_tool
        with app.app_context():
            user = _get_admin_user()
            result = json.loads(execute_tool("get_guest_details", {"guest_id": 99999}, user))
            assert "error" in result

    def test_get_guest_details_success(self, app):
        from core.ai_tools import execute_tool
        guest_id = _create_test_guest(app)
        try:
            with app.app_context():
                user = _get_admin_user()
                result = json.loads(execute_tool("get_guest_details", {"guest_id": guest_id}, user))
                assert result["name"] == "ai-test-guest"
                assert "updates" in result
                assert "services" in result
        finally:
            _delete_test_guest(app, guest_id)

    def test_permission_denied_for_viewer(self, app):
        from core.ai_tools import execute_tool
        with app.app_context():
            viewer_role = Role.query.filter_by(name="viewer").first()
            viewer = User.query.filter_by(username="testviewer_tools").first()
            if not viewer:
                viewer = User(username="testviewer_tools", display_name="Tools Viewer",
                              role_id=viewer_role.id)
                viewer.set_password("dummy")
                db.session.add(viewer)
                db.session.commit()

            result = json.loads(execute_tool("list_services", {}, viewer))
            assert "error" in result
            assert "Permission denied" in result["error"]

    def test_list_audit_logs_returns_list(self, app):
        from core.ai_tools import execute_tool
        with app.app_context():
            user = _get_admin_user()
            result = json.loads(execute_tool("list_audit_logs", {"limit": 5}, user))
            assert isinstance(result, list)

    def test_get_host_status_returns_list(self, app):
        from core.ai_tools import execute_tool
        with app.app_context():
            user = _get_admin_user()
            result = json.loads(execute_tool("get_host_status", {}, user))
            assert isinstance(result, list)


# ---------------------------------------------------------------------------
# control_service: dual-permission gate (H1)
# ---------------------------------------------------------------------------

def _make_service(app, guest_id, name="ai-test-service"):
    with app.app_context():
        svc = GuestService(guest_id=guest_id, service_name=name, unit_name=f"{name}.service")
        db.session.add(svc)
        db.session.commit()
        return svc.id


def _delete_service(app, service_id):
    with app.app_context():
        svc = GuestService.query.get(service_id)
        if svc:
            db.session.delete(svc)
            db.session.commit()


def _role_with(app, name, **perms):
    """Create (or reuse) a role with the given permission flags set True."""
    with app.app_context():
        role = Role.query.filter_by(name=name).first()
        if not role:
            role = Role(name=name, display_name=name, level=2, is_builtin=False)
            db.session.add(role)
        for key, val in perms.items():
            setattr(role, key, val)
        db.session.commit()
        return role.id


def _user_with_role(app, username, role_id):
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        if not user:
            user = User(username=username, display_name=username, role_id=role_id)
            user.set_password("test-only-dummy")
            db.session.add(user)
        else:
            user.role_id = role_id
        db.session.commit()
        return user.id


class TestControlServicePermissions:
    """control_service must require BOTH can_view_services AND can_edit_services (H1)."""

    def test_registry_requires_both_permissions(self, app):
        from core.ai_tools import TOOL_REGISTRY, _required_permissions
        perms = set(_required_permissions(TOOL_REGISTRY["control_service"]))
        assert perms == {"can_view_services", "can_edit_services"}

    def test_edit_only_user_is_denied(self, app):
        """A user with can_edit_services but NOT can_view_services must be blocked."""
        from core.ai_tools import execute_tool, get_tools_for_user
        role_id = _role_with(app, "edit_only_role",
                             can_view_services=False, can_edit_services=True)
        user_id = _user_with_role(app, "edit_only_user", role_id)
        with app.app_context():
            user = User.query.get(user_id)
            # Tool should not even be offered
            assert "control_service" not in {t["name"] for t in get_tools_for_user(user)}
            # And direct execution must be denied
            result = json.loads(execute_tool(
                "control_service", {"service_id": 1, "action": "restart"}, user))
            assert "error" in result
            assert "can_view_services" in result["error"]

    def test_view_only_user_is_denied(self, app):
        """A user with can_view_services but NOT can_edit_services must be blocked."""
        from core.ai_tools import execute_tool, get_tools_for_user
        role_id = _role_with(app, "view_only_role",
                             can_view_services=True, can_edit_services=False)
        user_id = _user_with_role(app, "view_only_user", role_id)
        with app.app_context():
            user = User.query.get(user_id)
            assert "control_service" not in {t["name"] for t in get_tools_for_user(user)}
            result = json.loads(execute_tool(
                "control_service", {"service_id": 1, "action": "restart"}, user))
            assert "error" in result
            assert "can_edit_services" in result["error"]

    def test_user_with_both_permissions_is_offered_tool(self, app):
        from core.ai_tools import get_tools_for_user
        role_id = _role_with(app, "both_perms_role",
                             can_view_services=True, can_edit_services=True)
        user_id = _user_with_role(app, "both_perms_user", role_id)
        with app.app_context():
            user = User.query.get(user_id)
            assert "control_service" in {t["name"] for t in get_tools_for_user(user)}


# ---------------------------------------------------------------------------
# control_service: two-phase confirmation (M2) & single execution
# ---------------------------------------------------------------------------

class TestControlServiceConfirmation:
    """State-changing control_service must not execute until confirm=true (M2)."""

    def test_without_confirm_does_not_execute(self, app):
        from core.ai_tools import execute_tool
        guest_id = _create_test_guest(app, name="ai-confirm-guest")
        service_id = _make_service(app, guest_id)
        try:
            with app.app_context():
                user = _get_admin_user()
                with patch("core.scanner.service_action") as mock_action:
                    result = json.loads(execute_tool(
                        "control_service",
                        {"service_id": service_id, "action": "restart"},
                        user,
                    ))
                # service_action must NOT be called on the propose phase
                mock_action.assert_not_called()
                assert result["status"] == "confirmation_required"
                assert result["pending_action"]["action"] == "restart"
        finally:
            _delete_service(app, service_id)
            _delete_test_guest(app, guest_id)

    def test_with_confirm_executes_exactly_once(self, app):
        """With confirm=true the underlying action fires exactly once."""
        from core.ai_tools import execute_tool
        guest_id = _create_test_guest(app, name="ai-confirm-guest2")
        service_id = _make_service(app, guest_id)
        try:
            with app.app_context():
                user = _get_admin_user()
                # log_action needs a request-scoped current_user; mock it here since
                # these unit tests run in a bare app_context (the end-to-end /ai/chat
                # tests exercise the real audit path).
                with patch("core.scanner.service_action", return_value=(True, "ok")) as mock_action, \
                        patch("auth.audit.log_action"):
                    result = json.loads(execute_tool(
                        "control_service",
                        {"service_id": service_id, "action": "restart", "confirm": True},
                        user,
                    ))
                assert mock_action.call_count == 1
                assert result["success"] is True
        finally:
            _delete_service(app, service_id)
            _delete_test_guest(app, guest_id)

# ---------------------------------------------------------------------------
# Generic error messages (M3)
# ---------------------------------------------------------------------------

class TestErrorMessagesDoNotLeak:
    """execute_tool and handlers must return generic errors, not str(e) internals."""

    def test_handler_exception_returns_generic_message(self, app):
        from core.ai_tools import TOOL_REGISTRY, execute_tool
        with app.app_context():
            user = _get_admin_user()
            secret = "SECRET-INTERNAL-DETAIL-12345"

            def _boom(tool_input, user):
                raise RuntimeError(secret)

            # The registry stores a direct function reference, so patch the entry.
            with patch.dict(TOOL_REGISTRY["list_guests"], {"handler": _boom}):
                result = json.loads(execute_tool("list_guests", {}, user))
            assert "error" in result
            assert secret not in json.dumps(result)
            assert "internal error" in result["error"].lower()

    def test_control_service_action_exception_is_generic(self, app):
        from core.ai_tools import execute_tool
        guest_id = _create_test_guest(app, name="ai-err-guest")
        service_id = _make_service(app, guest_id)
        try:
            with app.app_context():
                user = _get_admin_user()
                secret = "SSH-BACKTRACE-SECRET-99"
                with patch("core.scanner.service_action", side_effect=RuntimeError(secret)):
                    result = json.loads(execute_tool(
                        "control_service",
                        {"service_id": service_id, "action": "restart", "confirm": True},
                        user,
                    ))
                assert "error" in result
                assert secret not in json.dumps(result)
        finally:
            _delete_service(app, service_id)
            _delete_test_guest(app, guest_id)
