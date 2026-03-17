"""Tests for the mobile API v1 blueprint."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import jwt as pyjwt
import pytest

from app import create_app
from models import (
    Guest,
    GuestService,
    ProxmoxHost,
    Role,
    Tag,
    User,
)
from models import db as _db

_TEST_CONFIG = {
    "TESTING": True,
    "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
    "SECRET_KEY": "test-only-api-secret-key-1234567890",
    "WTF_CSRF_ENABLED": False,
}

_ADMIN_PASSWORD = "test-only-AdminPass1!"
_VIEWER_PASSWORD = "test-only-ViewerPass1!"


@pytest.fixture(scope="module")
def app():
    application = create_app(_TEST_CONFIG)
    with application.app_context():
        # Ensure admin user has known password
        admin = User.query.filter_by(username="admin").first()
        if admin:
            admin.set_password(_ADMIN_PASSWORD)

        # Create a viewer role user for permission tests
        viewer_role = Role.query.filter_by(name="viewer").first()
        viewer = User.query.filter_by(username="viewer_api").first()
        if not viewer and viewer_role:
            viewer = User(username="viewer_api", display_name="Viewer User", role_id=viewer_role.id)
            viewer.set_password(_VIEWER_PASSWORD)
            _db.session.add(viewer)

        # Create operator role user
        operator_role = Role.query.filter_by(name="operator").first()
        operator = User.query.filter_by(username="operator_api").first()
        if not operator and operator_role:
            operator = User(username="operator_api", display_name="Operator User", role_id=operator_role.id)
            operator.set_password("test-only-OperatorPass1!")
            _db.session.add(operator)

        # Create a tag and a guest for access control tests
        tag = Tag.query.filter_by(name="test-api-tag").first()
        if not tag:
            tag = Tag(name="test-api-tag", color="#007bff")
            _db.session.add(tag)
            _db.session.flush()

        host = ProxmoxHost.query.filter_by(name="test-api-host").first()
        if not host:
            host = ProxmoxHost(name="test-api-host", hostname="10.0.0.1", host_type="pve")
            _db.session.add(host)
            _db.session.flush()

        guest = Guest.query.filter_by(name="test-api-guest").first()
        if not guest:
            guest = Guest(
                name="test-api-guest", guest_type="vm", vmid=100,
                proxmox_host_id=host.id, status="up-to-date",
                power_state="running", enabled=True,
            )
            guest.tags.append(tag)
            _db.session.add(guest)

        # Create a second guest with updates and failed services
        guest2 = Guest.query.filter_by(name="test-api-guest-updates").first()
        if not guest2:
            guest2 = Guest(
                name="test-api-guest-updates", guest_type="ct", vmid=101,
                proxmox_host_id=host.id, status="updates-available",
                power_state="running", enabled=True, reboot_required=True,
            )
            guest2.tags.append(tag)
            _db.session.add(guest2)
            _db.session.flush()

            from models import UpdatePackage
            _db.session.add(UpdatePackage(
                guest_id=guest2.id, package_name="linux-image-6.1",
                current_version="6.1.0-1", available_version="6.1.0-2",
                severity="critical", status="pending",
            ))
            _db.session.add(GuestService(
                guest_id=guest2.id, service_name="postgresql",
                unit_name="postgresql.service", port=5432, status="failed",
            ))

        # Give the viewer access to the tag
        viewer = User.query.filter_by(username="viewer_api").first()
        if viewer and tag not in viewer.allowed_tags:
            viewer.allowed_tags.append(tag)

        _db.session.commit()

    yield application


@pytest.fixture()
def client(app):
    return app.test_client()


def _login(client, username="admin", password=_ADMIN_PASSWORD):
    """Login via API and return (access_token, refresh_token)."""
    resp = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.get_json()
    data = resp.get_json()["data"]
    return data["access_token"], data["refresh_token"]


def _auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


# ============================================================================
# Auth tests
# ============================================================================


class TestAuthLogin:
    def test_valid_login(self, client):
        resp = client.post("/api/v1/auth/login", json={
            "username": "admin", "password": _ADMIN_PASSWORD,
        })
        assert resp.status_code == 200
        data = resp.get_json()["data"]
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["user"]["username"] == "admin"

    def test_invalid_password(self, client):
        resp = client.post("/api/v1/auth/login", json={
            "username": "admin", "password": "wrong",
        })
        assert resp.status_code == 401
        assert resp.get_json()["error"]["code"] == "UNAUTHORIZED"

    def test_missing_fields(self, client):
        resp = client.post("/api/v1/auth/login", json={"username": "admin"})
        assert resp.status_code == 400

    def test_nonexistent_user(self, client):
        resp = client.post("/api/v1/auth/login", json={
            "username": "nonexistent", "password": "test",
        })
        assert resp.status_code == 401


class TestAuthRefresh:
    def test_valid_refresh(self, client):
        _access, refresh = _login(client)
        resp = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
        assert resp.status_code == 200
        assert "access_token" in resp.get_json()["data"]

    def test_expired_refresh_token(self, client, app):
        """A refresh token with expiry in the past should be rejected."""
        with app.app_context():
            admin = User.query.filter_by(username="admin").first()
            payload = {
                "sub": str(admin.id), "type": "refresh", "jti": "expired-jti",
                "iat": datetime.now(timezone.utc) - timedelta(days=31),
                "exp": datetime.now(timezone.utc) - timedelta(seconds=1),
            }
            expired_token = pyjwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")

        resp = client.post("/api/v1/auth/refresh", json={"refresh_token": expired_token})
        assert resp.status_code == 401
        assert resp.get_json()["error"]["code"] == "TOKEN_EXPIRED"

    def test_revoked_refresh_token(self, client, app):
        _access, refresh = _login(client)
        # Revoke it
        with app.app_context():
            payload = pyjwt.decode(refresh, app.config["SECRET_KEY"], algorithms=["HS256"])
            from auth.jwt_auth import revoke_token
            revoke_token(payload["jti"], datetime.fromtimestamp(payload["exp"], tz=timezone.utc))

        resp = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
        assert resp.status_code == 401
        assert resp.get_json()["error"]["code"] == "TOKEN_REVOKED"

    def test_access_token_as_refresh_rejected(self, client):
        access, _refresh = _login(client)
        resp = client.post("/api/v1/auth/refresh", json={"refresh_token": access})
        assert resp.status_code == 401
        assert resp.get_json()["error"]["code"] == "INVALID_TOKEN"


class TestAuthLogout:
    def test_logout_revokes_refresh(self, client, app):
        _access, refresh = _login(client)
        resp = client.post("/api/v1/auth/logout", json={"refresh_token": refresh})
        assert resp.status_code == 200

        # Refresh should now fail
        resp = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
        assert resp.status_code == 401

    def test_logout_with_invalid_token_still_succeeds(self, client):
        resp = client.post("/api/v1/auth/logout", json={"refresh_token": "garbage"})
        assert resp.status_code == 200


# ============================================================================
# Token validation tests
# ============================================================================


class TestTokenValidation:
    def test_missing_auth_header(self, client):
        resp = client.get("/api/v1/me")
        assert resp.status_code == 401

    def test_malformed_auth_header(self, client):
        resp = client.get("/api/v1/me", headers={"Authorization": "NotBearer xyz"})
        assert resp.status_code == 401

    def test_invalid_signature(self, client):
        fake_token = pyjwt.encode(
            {"sub": "1", "type": "access", "exp": datetime.now(timezone.utc) + timedelta(minutes=15)},
            "wrong-secret-key", algorithm="HS256",
        )
        resp = client.get("/api/v1/me", headers=_auth_headers(fake_token))
        assert resp.status_code == 401

    def test_expired_access_token(self, client, app):
        with app.app_context():
            admin = User.query.filter_by(username="admin").first()
            payload = {
                "sub": str(admin.id), "role": "super_admin", "type": "access",
                "iat": datetime.now(timezone.utc) - timedelta(minutes=20),
                "exp": datetime.now(timezone.utc) - timedelta(seconds=1),
            }
            expired = pyjwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")

        resp = client.get("/api/v1/me", headers=_auth_headers(expired))
        assert resp.status_code == 401
        assert resp.get_json()["error"]["code"] == "TOKEN_EXPIRED"

    def test_refresh_token_as_access_rejected(self, client):
        _access, refresh = _login(client)
        resp = client.get("/api/v1/me", headers=_auth_headers(refresh))
        assert resp.status_code == 401
        assert resp.get_json()["error"]["code"] == "INVALID_TOKEN"


# ============================================================================
# User profile tests
# ============================================================================


class TestMe:
    def test_returns_user_profile(self, client):
        access, _ = _login(client)
        resp = client.get("/api/v1/me", headers=_auth_headers(access))
        assert resp.status_code == 200
        data = resp.get_json()["data"]
        assert data["username"] == "admin"
        assert "permissions" in data
        assert "allowed_tags" in data

    def test_viewer_permissions(self, client):
        access, _ = _login(client, "viewer_api", _VIEWER_PASSWORD)
        resp = client.get("/api/v1/me", headers=_auth_headers(access))
        assert resp.status_code == 200
        perms = resp.get_json()["data"]["permissions"]
        assert perms["can_manage_guests"] is False
        assert perms["can_ssh"] is False


# ============================================================================
# Dashboard tests
# ============================================================================


class TestDashboard:
    def test_summary(self, client):
        access, _ = _login(client)
        resp = client.get("/api/v1/dashboard/summary", headers=_auth_headers(access))
        assert resp.status_code == 200
        data = resp.get_json()["data"]
        assert "total_guests" in data
        assert "total_hosts" in data
        assert "security_updates" in data
        assert "services_running" in data

    def test_summary_etag(self, client):
        access, _ = _login(client)
        resp1 = client.get("/api/v1/dashboard/summary", headers=_auth_headers(access))
        assert resp1.status_code == 200
        etag = resp1.headers.get("ETag", "").strip('"')
        assert etag

        # Same request with If-None-Match should return 304
        headers = _auth_headers(access)
        headers["If-None-Match"] = f'"{etag}"'
        resp2 = client.get("/api/v1/dashboard/summary", headers=headers)
        assert resp2.status_code == 304

    def test_alerts(self, client):
        access, _ = _login(client)
        resp = client.get("/api/v1/dashboard/alerts", headers=_auth_headers(access))
        assert resp.status_code == 200
        data = resp.get_json()["data"]
        assert "security_updates" in data
        assert "failed_services" in data
        assert "reboots_required" in data
        assert "guests_with_errors" in data

    def test_alerts_includes_real_data(self, client):
        """Verify that the test guest with security updates and failed services appears."""
        access, _ = _login(client)
        resp = client.get("/api/v1/dashboard/alerts", headers=_auth_headers(access))
        data = resp.get_json()["data"]
        # Should have at least one security update (from test-api-guest-updates)
        assert len(data["security_updates"]) >= 1
        # Should have at least one failed service
        assert len(data["failed_services"]) >= 1
        # Should have at least one reboot required
        assert len(data["reboots_required"]) >= 1


# ============================================================================
# Guest tests
# ============================================================================


class TestGuests:
    def test_list_guests(self, client):
        access, _ = _login(client)
        resp = client.get("/api/v1/guests", headers=_auth_headers(access))
        assert resp.status_code == 200
        body = resp.get_json()
        assert "data" in body
        assert "meta" in body
        assert body["meta"]["total"] >= 2

    def test_list_pagination(self, client):
        access, _ = _login(client)
        resp = client.get("/api/v1/guests?per_page=1&page=1", headers=_auth_headers(access))
        assert resp.status_code == 200
        body = resp.get_json()
        assert len(body["data"]) == 1
        assert body["meta"]["per_page"] == 1

    def test_filter_by_status(self, client):
        access, _ = _login(client)
        resp = client.get("/api/v1/guests?status=updates-available", headers=_auth_headers(access))
        assert resp.status_code == 200
        for g in resp.get_json()["data"]:
            assert g["status"] == "updates-available"

    def test_filter_by_power_state(self, client):
        access, _ = _login(client)
        resp = client.get("/api/v1/guests?power_state=running", headers=_auth_headers(access))
        assert resp.status_code == 200
        for g in resp.get_json()["data"]:
            assert g["power_state"] == "running"

    def test_search_by_name(self, client):
        access, _ = _login(client)
        resp = client.get("/api/v1/guests?search=test-api-guest", headers=_auth_headers(access))
        assert resp.status_code == 200
        assert resp.get_json()["meta"]["total"] >= 1

    def test_guest_detail(self, client, app):
        access, _ = _login(client)
        with app.app_context():
            guest = Guest.query.filter_by(name="test-api-guest").first()
        resp = client.get(f"/api/v1/guests/{guest.id}", headers=_auth_headers(access))
        assert resp.status_code == 200
        data = resp.get_json()["data"]
        assert data["name"] == "test-api-guest"
        assert "services" in data
        assert "updates" in data

    def test_guest_detail_not_found(self, client):
        access, _ = _login(client)
        resp = client.get("/api/v1/guests/999999", headers=_auth_headers(access))
        assert resp.status_code == 404

    def test_guest_serialization_fields(self, client, app):
        access, _ = _login(client)
        with app.app_context():
            guest = Guest.query.filter_by(name="test-api-guest-updates").first()
        resp = client.get(f"/api/v1/guests/{guest.id}", headers=_auth_headers(access))
        data = resp.get_json()["data"]
        assert data["reboot_required"] is True
        assert data["security_updates_count"] >= 1
        assert data["pending_updates_count"] >= 1
        assert len(data["tags"]) >= 1


class TestGuestPower:
    @patch("clients.proxmox_api.ProxmoxClient")
    def test_power_start(self, mock_cls, client, app):
        mock_client = MagicMock()
        mock_client.find_guest_node.return_value = "node1"
        mock_client.start_guest.return_value = (True, "OK")
        mock_cls.return_value = mock_client

        access, _ = _login(client)
        with app.app_context():
            guest = Guest.query.filter_by(name="test-api-guest").first()

        resp = client.post(
            f"/api/v1/guests/{guest.id}/power",
            json={"action": "start"},
            headers=_auth_headers(access),
        )
        assert resp.status_code == 200
        assert resp.get_json()["data"]["ok"] is True

    def test_power_invalid_action(self, client, app):
        access, _ = _login(client)
        with app.app_context():
            guest = Guest.query.filter_by(name="test-api-guest").first()
        resp = client.post(
            f"/api/v1/guests/{guest.id}/power",
            json={"action": "destroy"},
            headers=_auth_headers(access),
        )
        assert resp.status_code == 400

    def test_power_requires_permission(self, client, app):
        access, _ = _login(client, "viewer_api", _VIEWER_PASSWORD)
        with app.app_context():
            guest = Guest.query.filter_by(name="test-api-guest").first()
        resp = client.post(
            f"/api/v1/guests/{guest.id}/power",
            json={"action": "start"},
            headers=_auth_headers(access),
        )
        assert resp.status_code == 403


# ============================================================================
# Host tests
# ============================================================================


class TestHosts:
    def test_list_hosts(self, client):
        access, _ = _login(client)
        resp = client.get("/api/v1/hosts", headers=_auth_headers(access))
        assert resp.status_code == 200
        data = resp.get_json()["data"]
        assert len(data) >= 1
        assert "guest_count" in data[0]

    def test_host_detail(self, client, app):
        access, _ = _login(client)
        with app.app_context():
            host = ProxmoxHost.query.filter_by(name="test-api-host").first()
        resp = client.get(f"/api/v1/hosts/{host.id}", headers=_auth_headers(access))
        assert resp.status_code == 200
        assert resp.get_json()["data"]["name"] == "test-api-host"

    def test_host_detail_not_found(self, client):
        access, _ = _login(client)
        resp = client.get("/api/v1/hosts/999999", headers=_auth_headers(access))
        assert resp.status_code == 404

    def test_viewer_cannot_list_hosts(self, client):
        access, _ = _login(client, "viewer_api", _VIEWER_PASSWORD)
        resp = client.get("/api/v1/hosts", headers=_auth_headers(access))
        assert resp.status_code == 403


# ============================================================================
# Services tests
# ============================================================================


class TestServices:
    def test_list_services_as_admin(self, client):
        access, _ = _login(client)
        resp = client.get("/api/v1/services", headers=_auth_headers(access))
        assert resp.status_code == 200
        data = resp.get_json()["data"]
        # Should have at least the guest with the failed postgresql service
        assert len(data) >= 1

    def test_viewer_cannot_list_services(self, client):
        access, _ = _login(client, "viewer_api", _VIEWER_PASSWORD)
        resp = client.get("/api/v1/services", headers=_auth_headers(access))
        assert resp.status_code == 403


# ============================================================================
# Push webhook tests
# ============================================================================


class TestPushWebhooks:
    def test_register_webhook(self, client):
        access, _ = _login(client)
        resp = client.post("/api/v1/push/register", json={
            "url": "https://fcm.example.com/push",
            "device_token": "test-only-device-token-12345",
            "platform": "ios",
            "events": ["security_update", "service_down"],
        }, headers=_auth_headers(access))
        assert resp.status_code == 201

    def test_list_webhooks(self, client):
        access, _ = _login(client)
        resp = client.get("/api/v1/push", headers=_auth_headers(access))
        assert resp.status_code == 200
        assert len(resp.get_json()["data"]) >= 1

    def test_register_invalid_platform(self, client):
        access, _ = _login(client)
        resp = client.post("/api/v1/push/register", json={
            "url": "https://fcm.example.com/push",
            "device_token": "test-only-token",
            "platform": "windows",
            "events": ["security_update"],
        }, headers=_auth_headers(access))
        assert resp.status_code == 400

    def test_register_invalid_event(self, client):
        access, _ = _login(client)
        resp = client.post("/api/v1/push/register", json={
            "url": "https://fcm.example.com/push",
            "device_token": "test-only-token",
            "platform": "android",
            "events": ["invalid_event"],
        }, headers=_auth_headers(access))
        assert resp.status_code == 400

    def test_delete_webhook(self, client, app):
        access, _ = _login(client)
        # Register first
        client.post("/api/v1/push/register", json={
            "url": "https://fcm.example.com/push",
            "device_token": "test-only-delete-token",
            "platform": "android",
            "events": ["reboot_required"],
        }, headers=_auth_headers(access))

        # Find the webhook
        resp = client.get("/api/v1/push", headers=_auth_headers(access))
        webhooks = resp.get_json()["data"]
        wh_id = [w for w in webhooks if "test-onl" in w["device_token"]][-1]["id"]

        resp = client.delete(f"/api/v1/push/{wh_id}", headers=_auth_headers(access))
        assert resp.status_code == 200

    def test_cannot_delete_other_users_webhook(self, client, app):
        # Register as admin
        admin_access, _ = _login(client)
        client.post("/api/v1/push/register", json={
            "url": "https://fcm.example.com/push",
            "device_token": "test-only-admin-webhook-token",
            "platform": "ios",
            "events": ["security_update"],
        }, headers=_auth_headers(admin_access))

        resp = client.get("/api/v1/push", headers=_auth_headers(admin_access))
        wh_id = resp.get_json()["data"][-1]["id"]

        # Try to delete as viewer
        viewer_access, _ = _login(client, "viewer_api", _VIEWER_PASSWORD)
        resp = client.delete(f"/api/v1/push/{wh_id}", headers=_auth_headers(viewer_access))
        assert resp.status_code == 403


# ============================================================================
# Access control tests
# ============================================================================


class TestAccessControl:
    def test_viewer_sees_only_tagged_guests(self, client):
        """Viewer should only see guests with tags they have access to."""
        access, _ = _login(client, "viewer_api", _VIEWER_PASSWORD)
        resp = client.get("/api/v1/guests", headers=_auth_headers(access))
        assert resp.status_code == 200
        data = resp.get_json()["data"]
        # All returned guests should have the test-api-tag
        for g in data:
            tag_names = [t["name"] for t in g["tags"]]
            assert "test-api-tag" in tag_names

    def test_viewer_cannot_access_untagged_guest(self, client, app):
        """Viewer should get 403 for guests without matching tags."""
        # Create an untagged guest
        with app.app_context():
            host = ProxmoxHost.query.filter_by(name="test-api-host").first()
            untagged = Guest.query.filter_by(name="test-api-untagged").first()
            if not untagged:
                untagged = Guest(
                    name="test-api-untagged", guest_type="vm", vmid=999,
                    proxmox_host_id=host.id, enabled=True,
                )
                _db.session.add(untagged)
                _db.session.commit()
            untagged_id = untagged.id

        access, _ = _login(client, "viewer_api", _VIEWER_PASSWORD)
        resp = client.get(f"/api/v1/guests/{untagged_id}", headers=_auth_headers(access))
        assert resp.status_code == 403


# ============================================================================
# Response format tests
# ============================================================================


class TestResponseFormat:
    def test_error_format(self, client):
        resp = client.get("/api/v1/me")  # no auth
        body = resp.get_json()
        assert "error" in body
        assert "code" in body["error"]
        assert "message" in body["error"]

    def test_json_content_type(self, client):
        access, _ = _login(client)
        resp = client.get("/api/v1/me", headers=_auth_headers(access))
        assert resp.content_type.startswith("application/json")
