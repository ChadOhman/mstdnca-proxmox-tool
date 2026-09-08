"""Tests for VMID reuse detection during discovery and manual guest reset/type override."""
from unittest.mock import MagicMock, patch

import pytest

from models import Guest, GuestService, ProxmoxHost, ScanResult, UpdatePackage, db

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def host(app):
    """Create a PVE host for discovery tests."""
    host_id = None
    with app.app_context():
        h = ProxmoxHost(
            name="test-pve",
            hostname="10.0.0.1",
            port=8006,
            auth_type="token",
            api_token_id="test@pam!tok",
            api_token_secret="secret",
            host_type="pve",
        )
        db.session.add(h)
        db.session.commit()
        host_id = h.id

    yield host_id

    with app.app_context():
        h = ProxmoxHost.query.get(host_id)
        if h:
            # Clean up any guests on this host first
            for g in Guest.query.filter_by(proxmox_host_id=h.id).all():
                db.session.delete(g)
            db.session.delete(h)
            db.session.commit()


@pytest.fixture()
def vm_guest(app, host):
    """Create a VM guest with stale data (scan results, packages, services)."""
    guest_id = None
    with app.app_context():
        g = Guest(
            name="test-vm",
            guest_type="vm",
            vmid=100,
            proxmox_host_id=host,
            status="up-to-date",
            power_state="running",
        )
        db.session.add(g)
        db.session.flush()

        # Add child data that should be cleared on reuse
        db.session.add(UpdatePackage(guest_id=g.id, package_name="pkg1", severity="normal"))
        db.session.add(ScanResult(guest_id=g.id, total_updates=1))
        db.session.add(GuestService(guest_id=g.id, service_name="postgresql",
                                    unit_name="postgresql.service"))
        db.session.commit()
        guest_id = g.id

    yield guest_id

    with app.app_context():
        g = Guest.query.get(guest_id)
        if g:
            db.session.delete(g)
            db.session.commit()


def _mock_proxmox_client(node_guests, complete=True):
    """Create a mock ProxmoxClient that returns the given guest list.

    Mirrors the real ``get_node_guests``/``get_all_guests`` signature: with
    ``with_completeness=True`` they return ``(guests, complete)``.
    """
    mock_client = MagicMock()
    mock_client.get_local_node_name.return_value = "node1"

    def _get_node_guests(node_name, with_completeness=False):
        return (node_guests, complete) if with_completeness else node_guests

    def _get_all_guests(with_completeness=False):
        return (node_guests, complete) if with_completeness else node_guests

    mock_client.get_node_guests.side_effect = _get_node_guests
    mock_client.get_all_guests.side_effect = _get_all_guests
    mock_client.get_replication_map.return_value = {}
    mock_client.get_guest_ip.return_value = "10.0.0.50"
    mock_client.get_guest_mac.return_value = "AA:BB:CC:DD:EE:FF"
    return mock_client


# ---------------------------------------------------------------------------
# Discovery: VMID reuse detection
# ---------------------------------------------------------------------------


class TestDiscoverVmidReuse:
    """Test that discovery detects guest type changes (VMID reuse)."""

    def test_discover_detects_vm_to_ct_reuse(self, auth_client, app, host, vm_guest):
        """When Proxmox reports vmid 100 as CT but DB has VM, detect reuse."""
        mock_client = _mock_proxmox_client([
            {"vmid": 100, "name": "new-ct", "type": "ct", "status": "running", "node": "node1", "tags": ""},
        ])

        with patch("routes.hosts.ProxmoxClient", return_value=mock_client):
            resp = auth_client.post(f"/hosts/{host}/discover", follow_redirects=True)

        assert resp.status_code == 200
        data = resp.get_data(as_text=True)
        assert "reuse" in data.lower()

        with app.app_context():
            g = Guest.query.get(vm_guest)
            assert g.guest_type == "ct"
            assert g.name == "new-ct"
            assert g.status == "unknown"
            assert g.last_scan is None
            assert g.reboot_required is False
            assert len(g.updates) == 0
            assert len(g.scan_results) == 0
            assert len(g.services) == 0

    def test_discover_detects_ct_to_vm_reuse(self, auth_client, app, host):
        """CT->VM reuse also detected."""
        with app.app_context():
            g = Guest(name="old-ct", guest_type="ct", vmid=200, proxmox_host_id=host, power_state="running")
            db.session.add(g)
            db.session.commit()
            guest_id = g.id

        mock_client = _mock_proxmox_client([
            {"vmid": 200, "name": "new-vm", "type": "vm", "status": "running", "node": "node1", "tags": ""},
        ])

        with patch("routes.hosts.ProxmoxClient", return_value=mock_client):
            resp = auth_client.post(f"/hosts/{host}/discover", follow_redirects=True)

        assert resp.status_code == 200

        with app.app_context():
            g = Guest.query.get(guest_id)
            assert g.guest_type == "vm"
            # Clean up
            db.session.delete(g)
            db.session.commit()

    def test_discover_no_reuse_when_type_matches(self, auth_client, app, host, vm_guest):
        """Same type should NOT trigger reuse detection."""
        mock_client = _mock_proxmox_client([
            {"vmid": 100, "name": "updated-vm", "type": "vm", "status": "running", "node": "node1", "tags": ""},
        ])

        with patch("routes.hosts.ProxmoxClient", return_value=mock_client):
            resp = auth_client.post(f"/hosts/{host}/discover", follow_redirects=True)

        assert resp.status_code == 200

        with app.app_context():
            g = Guest.query.get(vm_guest)
            assert g.guest_type == "vm"
            assert g.name == "updated-vm"
            # Child data should still be present
            assert len(g.updates) == 1
            assert len(g.scan_results) == 1
            assert len(g.services) == 1

    def test_discover_reuse_preserves_guest_id(self, auth_client, app, host, vm_guest):
        """Guest DB id must not change on reuse — critical for Settings references."""
        mock_client = _mock_proxmox_client([
            {"vmid": 100, "name": "new-ct", "type": "ct", "status": "running", "node": "node1", "tags": ""},
        ])

        with patch("routes.hosts.ProxmoxClient", return_value=mock_client):
            auth_client.post(f"/hosts/{host}/discover", follow_redirects=True)

        with app.app_context():
            g = Guest.query.get(vm_guest)
            assert g is not None
            assert g.id == vm_guest

    def test_discover_reuse_preserves_credential(self, auth_client, app, host, vm_guest):
        """Credential assignment should survive reuse."""
        with app.app_context():
            g = Guest.query.get(vm_guest)
            g.credential_id = 999  # fake credential id for test
            db.session.commit()

        mock_client = _mock_proxmox_client([
            {"vmid": 100, "name": "new-ct", "type": "ct", "status": "running", "node": "node1", "tags": ""},
        ])

        with patch("routes.hosts.ProxmoxClient", return_value=mock_client):
            auth_client.post(f"/hosts/{host}/discover", follow_redirects=True)

        with app.app_context():
            g = Guest.query.get(vm_guest)
            assert g.credential_id == 999

    def test_discover_all_detects_reuse(self, auth_client, app, host, vm_guest):
        """discover-all path also detects VMID reuse."""
        mock_client = _mock_proxmox_client([
            {"vmid": 100, "name": "new-ct", "type": "ct", "status": "running", "node": "node1", "tags": ""},
        ])

        with patch("routes.hosts.ProxmoxClient", return_value=mock_client):
            resp = auth_client.post("/hosts/discover-all", follow_redirects=True)

        assert resp.status_code == 200

        with app.app_context():
            g = Guest.query.get(vm_guest)
            assert g.guest_type == "ct"
            assert len(g.updates) == 0
            assert len(g.scan_results) == 0
            assert len(g.services) == 0


# ---------------------------------------------------------------------------
# Manual reset
# ---------------------------------------------------------------------------


class TestResetGuest:
    """Test the POST /guests/<id>/reset endpoint."""

    def test_reset_clears_stale_data(self, auth_client, app, vm_guest):
        """Reset should clear scan results, packages, and services."""
        resp = auth_client.post(f"/guests/{vm_guest}/reset", follow_redirects=True)
        assert resp.status_code == 200
        assert "reset" in resp.get_data(as_text=True).lower()

        with app.app_context():
            g = Guest.query.get(vm_guest)
            assert g.status == "unknown"
            assert g.last_scan is None
            assert g.reboot_required is False
            assert len(g.updates) == 0
            assert len(g.scan_results) == 0
            assert len(g.services) == 0

    def test_reset_preserves_identity(self, auth_client, app, vm_guest):
        """Reset should not change guest name, type, vmid, or host."""
        with app.app_context():
            g = Guest.query.get(vm_guest)
            orig_name = g.name
            orig_type = g.guest_type
            orig_vmid = g.vmid
            orig_host = g.proxmox_host_id

        auth_client.post(f"/guests/{vm_guest}/reset", follow_redirects=True)

        with app.app_context():
            g = Guest.query.get(vm_guest)
            assert g.name == orig_name
            assert g.guest_type == orig_type
            assert g.vmid == orig_vmid
            assert g.proxmox_host_id == orig_host

    def test_reset_requires_permission(self, client, app, vm_guest):
        """Unauthenticated user should be redirected."""
        resp = client.post(f"/guests/{vm_guest}/reset", follow_redirects=False)
        # Should redirect to login
        assert resp.status_code in (302, 401)
