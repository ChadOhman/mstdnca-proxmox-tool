"""Tests for the short-TTL vmid->node cache in ProxmoxClient.find_guest_node().

find_guest_node() used to call get_all_guests() (a full cluster enumeration)
on every invocation, and it's called on nearly every guest-facing request.
These tests verify the cache: a hit avoids re-enumerating, a miss/expiry
falls back to enumeration, the cache is isolated per host, and the return
contract (node name or None) is unchanged.
"""
from types import SimpleNamespace
from unittest.mock import patch

import clients.proxmox_api as proxmox_api_module
from clients.proxmox_api import ProxmoxClient


def _make_client(host_id):
    return ProxmoxClient(SimpleNamespace(id=host_id))


class TestFindGuestNodeCache:
    def setup_method(self):
        # The cache is a module-level dict shared across ProxmoxClient
        # instances -- clear it so tests don't leak state into each other.
        with proxmox_api_module._node_cache_lock:
            proxmox_api_module._node_cache.clear()

    def test_cache_miss_enumerates_and_returns_node(self):
        client = _make_client(host_id=1)
        guests = [{"vmid": 100, "node": "pve1"}, {"vmid": 101, "node": "pve2"}]
        with patch.object(client, "get_all_guests", return_value=guests) as mock_get_all:
            node = client.find_guest_node(101)
            assert node == "pve2"
            mock_get_all.assert_called_once()

    def test_cache_hit_skips_enumeration(self):
        client = _make_client(host_id=1)
        guests = [{"vmid": 100, "node": "pve1"}]
        with patch.object(client, "get_all_guests", return_value=guests) as mock_get_all:
            client.find_guest_node(100)
            assert mock_get_all.call_count == 1
            # Second lookup for the same vmid within the TTL window must not
            # re-enumerate.
            node = client.find_guest_node(100)
            assert node == "pve1"
            assert mock_get_all.call_count == 1

    def test_lookup_populates_cache_for_every_guest_seen(self):
        # A single enumeration should warm the cache for *all* guests found,
        # not just the one being searched for.
        client = _make_client(host_id=1)
        guests = [{"vmid": 100, "node": "pve1"}, {"vmid": 200, "node": "pve2"}]
        with patch.object(client, "get_all_guests", return_value=guests) as mock_get_all:
            client.find_guest_node(100)
            assert mock_get_all.call_count == 1
            # A different vmid from the same enumeration should now be a cache hit.
            node = client.find_guest_node(200)
            assert node == "pve2"
            assert mock_get_all.call_count == 1

    def test_unknown_vmid_returns_none_without_caching_a_hit(self):
        client = _make_client(host_id=1)
        guests = [{"vmid": 100, "node": "pve1"}]
        with patch.object(client, "get_all_guests", return_value=guests) as mock_get_all:
            node = client.find_guest_node(999)
            assert node is None
            assert mock_get_all.call_count == 1

    def test_expired_entry_falls_back_to_enumeration(self):
        client = _make_client(host_id=1)
        guests = [{"vmid": 100, "node": "pve1"}]
        with patch.object(client, "get_all_guests", return_value=guests) as mock_get_all, \
             patch.object(proxmox_api_module.time, "monotonic", return_value=1000.0):
            client.find_guest_node(100)
            assert mock_get_all.call_count == 1

        # Advance time past the TTL window -- next lookup must re-enumerate.
        with patch.object(client, "get_all_guests", return_value=guests) as mock_get_all2, \
             patch.object(proxmox_api_module.time, "monotonic", return_value=1000.0 + 31):
            node = client.find_guest_node(100)
            assert node == "pve1"
            mock_get_all2.assert_called_once()

    def test_cache_is_isolated_per_host(self):
        client_a = _make_client(host_id=1)
        client_b = _make_client(host_id=2)
        guests_a = [{"vmid": 100, "node": "pve1"}]
        guests_b = [{"vmid": 100, "node": "pve-other"}]

        with patch.object(client_a, "get_all_guests", return_value=guests_a):
            assert client_a.find_guest_node(100) == "pve1"

        with patch.object(client_b, "get_all_guests", return_value=guests_b) as mock_get_all_b:
            # Same vmid, different host -- must not reuse host A's cache entry.
            node = client_b.find_guest_node(100)
            assert node == "pve-other"
            mock_get_all_b.assert_called_once()

    def test_exception_during_enumeration_returns_none(self):
        client = _make_client(host_id=1)
        with patch.object(client, "get_all_guests", side_effect=RuntimeError("boom")):
            assert client.find_guest_node(100) is None
