"""Tests for the hosts list route: name search, status filters, and session persistence."""
import pytest

from auth.credential_store import encrypt
from models import Credential, HostUpdatePackage, ProxmoxHost, db


@pytest.fixture()
def filter_hosts(app):
    """Seed a set of hosts covering every filter case, clean up after."""
    ids = []
    cred_id = None
    with app.app_context():
        cred = Credential(name="_host-filter-cred", username="root", auth_type="password",
                          encrypted_value=encrypt("test-only-pw"))
        db.session.add(cred)
        db.session.flush()
        cred_id = cred.id

        pve_updates = ProxmoxHost(name="_host-pve-updates", hostname="10.10.0.1",
                                  host_type="pve", auth_type="token", username="root@pam",
                                  ssh_credential_id=cred_id)
        pve_clean = ProxmoxHost(name="_host-pve-clean", hostname="10.10.0.2",
                                host_type="pve", auth_type="token", username="root@pam",
                                ssh_credential_id=cred_id)
        pbs_host = ProxmoxHost(name="_host-pbs-main", hostname="10.10.0.3",
                               host_type="pbs", auth_type="token", username="root@pbs",
                               ssh_credential_id=cred_id)
        no_ssh_host = ProxmoxHost(name="_host-no-ssh", hostname="10.10.0.4",
                                  host_type="pve", auth_type="token", username="root@pam",
                                  ssh_credential_id=None)
        for h in (pve_updates, pve_clean, pbs_host, no_ssh_host):
            db.session.add(h)
        db.session.flush()

        db.session.add(HostUpdatePackage(host_id=pve_updates.id, package_name="libc6",
                                         status="pending", severity="critical"))
        db.session.add(HostUpdatePackage(host_id=pve_updates.id, package_name="curl",
                                         status="pending", severity="normal"))
        db.session.commit()

        ids = [pve_updates.id, pve_clean.id, pbs_host.id, no_ssh_host.id]

    yield

    with app.app_context():
        for hid in ids:
            h = ProxmoxHost.query.get(hid)
            if h:
                db.session.delete(h)
        c = Credential.query.get(cred_id)
        if c:
            db.session.delete(c)
        db.session.commit()


class TestHostList:
    def test_host_list_returns_200(self, auth_client):
        resp = auth_client.get("/hosts/")
        assert resp.status_code == 200

    def test_host_list_unauthenticated_redirects(self, client):
        resp = client.get("/hosts/", follow_redirects=False)
        assert resp.status_code == 302


class TestHostSearch:
    def test_search_matches_name_case_insensitive(self, auth_client, filter_hosts):
        resp = auth_client.get("/hosts/?q=PVE-UPDATES")
        assert resp.status_code == 200
        assert b"_host-pve-updates" in resp.data
        assert b"_host-pbs-main" not in resp.data

    def test_search_matches_hostname_substring(self, auth_client, filter_hosts):
        resp = auth_client.get("/hosts/?q=10.10.0.3")
        assert resp.status_code == 200
        assert b"_host-pbs-main" in resp.data
        assert b"_host-pve-updates" not in resp.data

    def test_search_no_match_shows_empty_state(self, auth_client, filter_hosts):
        resp = auth_client.get("/hosts/?q=_nonexistent-host-xyz")
        assert resp.status_code == 200
        assert b"No Hosts Match Your Search" in resp.data

    def test_empty_search_shows_all(self, auth_client, filter_hosts):
        resp = auth_client.get("/hosts/?q=")
        assert resp.status_code == 200
        assert b"_host-pve-updates" in resp.data
        assert b"_host-pbs-main" in resp.data


class TestHostStatusFilters:
    def test_unknown_filter_shows_all(self, auth_client, filter_hosts):
        resp = auth_client.get("/hosts/?filter=bogus_value")
        assert resp.status_code == 200
        assert b"_host-pve-updates" in resp.data
        assert b"_host-pbs-main" in resp.data

    def test_filter_pve(self, auth_client, filter_hosts):
        resp = auth_client.get("/hosts/?filter=pve")
        assert resp.status_code == 200
        assert b"_host-pve-updates" in resp.data
        assert b"_host-pve-clean" in resp.data
        assert b"_host-pbs-main" not in resp.data

    def test_filter_pbs(self, auth_client, filter_hosts):
        resp = auth_client.get("/hosts/?filter=pbs")
        assert resp.status_code == 200
        assert b"_host-pbs-main" in resp.data
        assert b"_host-pve-updates" not in resp.data

    def test_filter_updates(self, auth_client, filter_hosts):
        resp = auth_client.get("/hosts/?filter=updates")
        assert resp.status_code == 200
        assert b"_host-pve-updates" in resp.data
        assert b"_host-pve-clean" not in resp.data

    def test_filter_security(self, auth_client, filter_hosts):
        resp = auth_client.get("/hosts/?filter=security")
        assert resp.status_code == 200
        assert b"_host-pve-updates" in resp.data
        assert b"_host-pve-clean" not in resp.data

    def test_filter_no_ssh(self, auth_client, filter_hosts):
        resp = auth_client.get("/hosts/?filter=no_ssh")
        assert resp.status_code == 200
        assert b"_host-no-ssh" in resp.data
        assert b"_host-pve-updates" not in resp.data

    def test_active_filter_badge_shown(self, auth_client, filter_hosts):
        resp = auth_client.get("/hosts/?filter=pve")
        assert b"Proxmox VE" in resp.data
        assert b"/hosts/" in resp.data


class TestHostFilterPersistence:
    def test_search_persists_across_requests(self, auth_client, filter_hosts):
        resp = auth_client.get("/hosts/?q=_host-pbs-main")
        assert resp.status_code == 200
        assert b"_host-pbs-main" in resp.data
        assert b"_host-pve-updates" not in resp.data

        # No query params this time — should restore last search from session
        resp2 = auth_client.get("/hosts/")
        assert resp2.status_code == 200
        assert b"_host-pbs-main" in resp2.data
        assert b"_host-pve-updates" not in resp2.data

    def test_filter_persists_across_requests(self, auth_client, filter_hosts):
        resp = auth_client.get("/hosts/?filter=pbs")
        assert resp.status_code == 200
        assert b"_host-pbs-main" in resp.data
        assert b"_host-pve-updates" not in resp.data

        resp2 = auth_client.get("/hosts/")
        assert resp2.status_code == 200
        assert b"_host-pbs-main" in resp2.data
        assert b"_host-pve-updates" not in resp2.data

    def test_explicit_empty_filter_clears_session(self, auth_client, filter_hosts):
        auth_client.get("/hosts/?filter=pbs")
        resp = auth_client.get("/hosts/?filter=")
        assert resp.status_code == 200
        assert b"_host-pbs-main" in resp.data
        assert b"_host-pve-updates" in resp.data

        # Persisted as cleared — next request without params shows all again
        resp2 = auth_client.get("/hosts/")
        assert b"_host-pve-updates" in resp2.data

    def test_explicit_empty_search_clears_session(self, auth_client, filter_hosts):
        auth_client.get("/hosts/?q=_host-pbs-main")
        resp = auth_client.get("/hosts/?q=")
        assert resp.status_code == 200
        assert b"_host-pve-updates" in resp.data

        resp2 = auth_client.get("/hosts/")
        assert b"_host-pve-updates" in resp2.data
