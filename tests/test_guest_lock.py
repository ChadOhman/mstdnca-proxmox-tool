"""Tests for surfacing Proxmox VM/CT config locks (backup, migrate, snapshot, ...).

Proxmox returns a ``lock`` field on each guest in the qemu/lxc list endpoints when
an operation holds a config lock. We persist it as ``Guest.lock_reason`` during
discovery and expose it live via the guest-stats endpoints so the UI can show why
a guest is locked.
"""
from unittest.mock import MagicMock, patch

import pytest

from models import Guest, ProxmoxHost, db


@pytest.fixture()
def host(app):
    """Create a PVE host for lock tests, cleaning up guests afterwards."""
    with app.app_context():
        h = ProxmoxHost(
            name="lock-pve",
            hostname="10.0.4.9",
            port=8006,
            auth_type="token",
            api_token_id="test@pam!tok",
            api_token_secret="secret",  # pragma: allowlist secret
            host_type="pve",
        )
        db.session.add(h)
        db.session.commit()
        host_id = h.id

    yield host_id

    with app.app_context():
        for g in Guest.query.filter_by(proxmox_host_id=host_id).all():
            db.session.delete(g)
        h = ProxmoxHost.query.get(host_id)
        if h:
            db.session.delete(h)
        db.session.commit()


def _mock_proxmox_client(node_guests, complete=True):
    """Mock ProxmoxClient returning the given guest list from every list method.

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
    mock_client.get_guest_ip.return_value = "10.0.4.50"
    mock_client.get_guest_mac.return_value = "AA:BB:CC:DD:EE:FF"
    return mock_client


class TestDiscoveryPersistsLock:
    def test_new_guest_records_lock_reason(self, auth_client, app, host):
        """A guest reported with a lock stores its reason."""
        mock_client = _mock_proxmox_client([
            {"vmid": 300, "name": "locked-vm", "type": "vm", "status": "running",
             "node": "node1", "tags": "", "lock": "backup"},
        ])
        with patch("routes.hosts.ProxmoxClient", return_value=mock_client):
            resp = auth_client.post(f"/hosts/{host}/discover", follow_redirects=True)
        assert resp.status_code == 200

        with app.app_context():
            g = Guest.query.filter_by(proxmox_host_id=host, vmid=300).first()
            assert g is not None
            assert g.lock_reason == "backup"

    def test_unlocked_guest_has_no_lock_reason(self, auth_client, app, host):
        """A guest with no lock field stores None (not an empty string)."""
        mock_client = _mock_proxmox_client([
            {"vmid": 301, "name": "free-vm", "type": "vm", "status": "running",
             "node": "node1", "tags": ""},
        ])
        with patch("routes.hosts.ProxmoxClient", return_value=mock_client):
            auth_client.post(f"/hosts/{host}/discover", follow_redirects=True)

        with app.app_context():
            g = Guest.query.filter_by(proxmox_host_id=host, vmid=301).first()
            assert g is not None
            assert g.lock_reason is None

    def test_lock_cleared_on_rediscovery(self, auth_client, app, host):
        """When a previously locked guest is no longer locked, the reason clears."""
        with app.app_context():
            db.session.add(Guest(
                name="was-locked", guest_type="vm", vmid=302,
                proxmox_host_id=host, power_state="running", lock_reason="snapshot",
            ))
            db.session.commit()

        mock_client = _mock_proxmox_client([
            {"vmid": 302, "name": "was-locked", "type": "vm", "status": "running",
             "node": "node1", "tags": ""},
        ])
        with patch("routes.hosts.ProxmoxClient", return_value=mock_client):
            auth_client.post(f"/hosts/{host}/discover", follow_redirects=True)

        with app.app_context():
            g = Guest.query.filter_by(proxmox_host_id=host, vmid=302).first()
            assert g.lock_reason is None


class TestGuestStatsExposeLock:
    def test_host_guest_stats_includes_lock(self, auth_client, host):
        """Per-host live guest-stats returns the lock reason for each guest."""
        mock_client = _mock_proxmox_client([
            {"vmid": 310, "name": "locked", "type": "vm", "status": "running",
             "node": "node1", "lock": "migrate",
             "cpu": 0.1, "mem": 512, "maxmem": 1024, "disk": 0, "maxdisk": 1024},
        ])
        with patch("clients.proxmox_api.ProxmoxClient", return_value=mock_client):
            resp = auth_client.get(f"/api/hosts/{host}/guest-stats")
        assert resp.status_code == 200
        stats = resp.get_json()["stats"]
        assert stats["310"]["lock"] == "migrate"

    def test_host_guest_stats_lock_empty_when_unlocked(self, auth_client, host):
        mock_client = _mock_proxmox_client([
            {"vmid": 311, "name": "free", "type": "vm", "status": "running",
             "node": "node1", "cpu": 0.1, "mem": 512, "maxmem": 1024, "disk": 0, "maxdisk": 1024},
        ])
        with patch("clients.proxmox_api.ProxmoxClient", return_value=mock_client):
            resp = auth_client.get(f"/api/hosts/{host}/guest-stats")
        assert resp.get_json()["stats"]["311"]["lock"] == ""

    def test_dashboard_guest_stats_includes_lock(self, auth_client, host):
        """Dashboard live guest-stats includes the lock reason for running guests."""
        mock_client = _mock_proxmox_client([
            {"vmid": 320, "name": "locked", "type": "vm", "status": "running",
             "node": "node1", "lock": "backup",
             "cpu": 0.2, "mem": 512, "maxmem": 1024, "disk": 10, "maxdisk": 1024},
        ])
        with patch("clients.proxmox_api.ProxmoxClient", return_value=mock_client):
            resp = auth_client.get("/api/dashboard/guest-stats")
        assert resp.status_code == 200
        guests = resp.get_json()["guests"]
        locked = [g for g in guests if g["vmid"] == 320]
        assert locked and locked[0]["lock"] == "backup"
