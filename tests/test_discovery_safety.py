"""Regression tests for GH-123: discovery must never mass-delete guests.

Both the manual discover routes (routes/hosts.py) and the scheduled discovery
job (core/scheduler.py, covered separately in tests/test_scheduler.py) compute
a "stale" guest set as everything tracked for a host that the freshly-fetched
node/cluster guest list doesn't mention, then hard-deletes it. That is only
safe when the fetch was both non-empty and complete (no per-type API failure).
These tests pin down the guard rails described in the issue:

- an empty guest list must never be treated as "delete everything"
- a partial fetch (e.g. qemu.get() succeeds, lxc.get() fails) must not delete
  the guest types that failed to list
- a normal, complete, non-empty fetch still prunes truly stale guests
  (regression guard for the pre-existing behavior)
- ProxmoxClient.get_node_guests signals partial failure via the new
  with_completeness kwarg
"""
from unittest.mock import MagicMock, patch

import pytest

from models import Guest, ProxmoxHost, db

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def host(app):
    """Create a PVE host for discovery-safety tests."""
    with app.app_context():
        h = ProxmoxHost(
            name="safety-pve",
            hostname="10.0.9.1",
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


@pytest.fixture()
def tracked_guest(app, host):
    """A guest already tracked in the DB for `host`, not present in later fetches."""
    with app.app_context():
        g = Guest(
            name="long-lived-vm", guest_type="vm", vmid=999,
            proxmox_host_id=host, power_state="stopped",
        )
        db.session.add(g)
        db.session.commit()
        guest_id = g.id

    yield guest_id

    with app.app_context():
        g = Guest.query.get(guest_id)
        if g:
            db.session.delete(g)
            db.session.commit()


def _mock_proxmox_client(node_guests, complete=True):
    """Mock ProxmoxClient whose get_node_guests/get_all_guests mirror the real
    signature: passing with_completeness=True returns (guests, complete)."""
    mock_client = MagicMock()
    mock_client.get_local_node_name.return_value = "node1"

    def _get_node_guests(node_name, with_completeness=False):
        return (node_guests, complete) if with_completeness else node_guests

    def _get_all_guests(with_completeness=False):
        return (node_guests, complete) if with_completeness else node_guests

    mock_client.get_node_guests.side_effect = _get_node_guests
    mock_client.get_all_guests.side_effect = _get_all_guests
    mock_client.get_replication_map.return_value = {}
    mock_client.get_guest_ip.return_value = "10.0.9.50"
    mock_client.get_guest_mac.return_value = "AA:BB:CC:DD:EE:FF"
    return mock_client


# ---------------------------------------------------------------------------
# /hosts/<id>/discover
# ---------------------------------------------------------------------------


class TestDiscoverEmptyOrPartialInventory:
    def test_empty_node_list_does_not_delete_guests(self, auth_client, app, host, tracked_guest):
        """An empty guest list must not be treated as 'everything is stale'."""
        mock_client = _mock_proxmox_client([], complete=True)

        with patch("routes.hosts.ProxmoxClient", return_value=mock_client):
            resp = auth_client.post(f"/hosts/{host}/discover", follow_redirects=True)

        assert resp.status_code == 200

        with app.app_context():
            assert Guest.query.get(tracked_guest) is not None

    def test_partial_failure_does_not_delete_guests(self, auth_client, app, host, tracked_guest):
        """qemu.get() succeeding while lxc.get() fails must not delete guests
        of the type that failed to list — even though they're absent from the
        (incomplete) fetched list."""
        # Only a VM comes back; the tracked guest (vmid 999) is absent from
        # this list purely because the CT listing failed, not because it's gone.
        mock_client = _mock_proxmox_client(
            [{"vmid": 100, "name": "vm100", "type": "vm", "status": "stopped", "node": "node1", "tags": ""}],
            complete=False,
        )

        with patch("routes.hosts.ProxmoxClient", return_value=mock_client):
            resp = auth_client.post(f"/hosts/{host}/discover", follow_redirects=True)

        assert resp.status_code == 200

        with app.app_context():
            assert Guest.query.get(tracked_guest) is not None

    def test_normal_complete_fetch_still_removes_stale_guest(self, auth_client, app, host, tracked_guest):
        """Regression guard: a complete, non-empty fetch still prunes guests
        that are genuinely gone from the node."""
        mock_client = _mock_proxmox_client(
            [{"vmid": 100, "name": "vm100", "type": "vm", "status": "stopped", "node": "node1", "tags": ""}],
            complete=True,
        )

        with patch("routes.hosts.ProxmoxClient", return_value=mock_client):
            resp = auth_client.post(f"/hosts/{host}/discover", follow_redirects=True)

        assert resp.status_code == 200

        with app.app_context():
            # Note: don't assert on the deleted row's old primary key — SQLite
            # may reassign it to the newly-inserted guest in the same commit.
            # Assert on the tracked vmid instead.
            assert Guest.query.filter_by(proxmox_host_id=host, vmid=999).first() is None


class TestDiscoverAllEmptyOrPartialInventory:
    def test_empty_node_list_does_not_delete_guests(self, auth_client, app, host, tracked_guest):
        mock_client = _mock_proxmox_client([], complete=True)

        with patch("routes.hosts.ProxmoxClient", return_value=mock_client):
            resp = auth_client.post("/hosts/discover-all", follow_redirects=True)

        assert resp.status_code == 200

        with app.app_context():
            assert Guest.query.get(tracked_guest) is not None

    def test_partial_failure_does_not_delete_guests(self, auth_client, app, host, tracked_guest):
        mock_client = _mock_proxmox_client(
            [{"vmid": 100, "name": "vm100", "type": "vm", "status": "stopped", "node": "node1", "tags": ""}],
            complete=False,
        )

        with patch("routes.hosts.ProxmoxClient", return_value=mock_client):
            resp = auth_client.post("/hosts/discover-all", follow_redirects=True)

        assert resp.status_code == 200

        with app.app_context():
            assert Guest.query.get(tracked_guest) is not None

    def test_normal_complete_fetch_still_removes_stale_guest(self, auth_client, app, host, tracked_guest):
        mock_client = _mock_proxmox_client(
            [{"vmid": 100, "name": "vm100", "type": "vm", "status": "stopped", "node": "node1", "tags": ""}],
            complete=True,
        )

        with patch("routes.hosts.ProxmoxClient", return_value=mock_client):
            resp = auth_client.post("/hosts/discover-all", follow_redirects=True)

        assert resp.status_code == 200

        with app.app_context():
            # See note above: assert on vmid, not the possibly-reassigned PK.
            assert Guest.query.filter_by(proxmox_host_id=host, vmid=999).first() is None


# ---------------------------------------------------------------------------
# ProxmoxClient.get_node_guests / get_all_guests — completeness signalling
# ---------------------------------------------------------------------------


class TestGetNodeGuestsCompleteness:
    def _client(self):
        from clients.proxmox_api import ProxmoxClient

        client = ProxmoxClient(MagicMock())
        client._api = MagicMock()
        return client

    def test_default_call_returns_plain_list(self):
        """Backward compatibility: existing callers get just the list back."""
        client = self._client()
        client._api.nodes.return_value.qemu.get.return_value = [{"vmid": 1}]
        client._api.nodes.return_value.lxc.get.return_value = [{"vmid": 2}]

        result = client.get_node_guests("node1")

        assert isinstance(result, list)
        assert len(result) == 2

    def test_complete_success_reports_complete_true(self):
        client = self._client()
        client._api.nodes.return_value.qemu.get.return_value = [{"vmid": 1}]
        client._api.nodes.return_value.lxc.get.return_value = [{"vmid": 2}]

        guests, complete = client.get_node_guests("node1", with_completeness=True)

        assert complete is True
        assert len(guests) == 2

    def test_lxc_failure_reports_incomplete_but_keeps_vm_results(self):
        """qemu.get() succeeds, lxc.get() raises: guests still include the VMs,
        but the caller must be told the result is incomplete."""
        client = self._client()
        client._api.nodes.return_value.qemu.get.return_value = [{"vmid": 1}]
        client._api.nodes.return_value.lxc.get.side_effect = Exception("connection reset")

        guests, complete = client.get_node_guests("node1", with_completeness=True)

        assert complete is False
        assert len(guests) == 1
        assert guests[0]["vmid"] == 1

    def test_qemu_failure_reports_incomplete_but_keeps_ct_results(self):
        client = self._client()
        client._api.nodes.return_value.qemu.get.side_effect = Exception("timeout")
        client._api.nodes.return_value.lxc.get.return_value = [{"vmid": 2}]

        guests, complete = client.get_node_guests("node1", with_completeness=True)

        assert complete is False
        assert len(guests) == 1
        assert guests[0]["vmid"] == 2

    def test_both_fail_raises_instead_of_reporting_empty_complete(self):
        """When nothing at all could be listed, the existing raise behavior
        is preserved rather than silently returning an empty 'complete' list."""
        client = self._client()
        client._api.nodes.return_value.qemu.get.side_effect = Exception("boom")
        client._api.nodes.return_value.lxc.get.side_effect = Exception("boom")

        with pytest.raises(RuntimeError):
            client.get_node_guests("node1", with_completeness=True)

    def test_get_all_guests_partial_failure_reports_incomplete(self):
        client = self._client()
        client._api.nodes.get.return_value = [{"node": "node1"}]
        client._api.nodes.return_value.qemu.get.return_value = [{"vmid": 1}]
        client._api.nodes.return_value.lxc.get.side_effect = Exception("connection reset")

        guests, complete = client.get_all_guests(with_completeness=True)

        assert complete is False
        assert len(guests) == 1
