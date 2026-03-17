"""Tests for AI tool registry in core/ai_tools.py.

Covers:
- Permission-based tool filtering
- Tool execution with permission checks
- Tool handler output formats
"""
import json

from models import Guest, Role, User, db

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
