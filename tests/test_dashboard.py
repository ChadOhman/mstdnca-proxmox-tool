"""Tests for the dashboard route."""

from models import Guest, User, db


class TestDashboard:
    def test_dashboard_authenticated_returns_200(self, auth_client):
        resp = auth_client.get("/")
        assert resp.status_code == 200

    def test_dashboard_contains_stat_cards(self, auth_client):
        resp = auth_client.get("/")
        assert b"Proxmox Hosts" in resp.data
        assert b"Pending Updates" in resp.data
        assert b"Security Updates" in resp.data
        assert b"Reboots Required" in resp.data

    def test_dashboard_cards_have_filter_links(self, app, auth_client):
        """Dashboard stat cards should link to filtered guest views."""
        with app.app_context():
            g = Guest(name="test-vm", guest_type="vm", last_scan=None)
            db.session.add(g)
            db.session.commit()
        try:
            resp = auth_client.get("/")
            assert b"filter=updates" in resp.data
            assert b"filter=security" in resp.data
            assert b"filter=reboot" in resp.data
            assert b"filter=never_scanned" in resp.data
        finally:
            with app.app_context():
                Guest.query.filter_by(name="test-vm").delete()
                db.session.commit()

    def test_dashboard_unauthenticated_redirects(self, client):
        resp = client.get("/", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]


class TestDashboardStatsHostUpdates:
    def test_host_update_counts_included(self, app):
        with app.app_context():
            from models import HostUpdatePackage, ProxmoxHost

            host = ProxmoxHost(name="pve1", hostname="pve1.local", host_type="pve")
            db.session.add(host)
            db.session.commit()

            pkg1 = HostUpdatePackage(host_id=host.id, package_name="curl", status="pending", severity="normal")
            pkg2 = HostUpdatePackage(host_id=host.id, package_name="openssl", status="pending", severity="critical")
            pkg3 = HostUpdatePackage(host_id=host.id, package_name="vim", status="applied", severity="normal")
            db.session.add_all([pkg1, pkg2, pkg3])
            db.session.commit()

            try:
                user = User.query.filter_by(username="admin").first()
                from core.dashboard_stats import get_dashboard_stats

                result = get_dashboard_stats(user)

                assert result["stats"]["host_pending_updates"] == 2
                assert result["stats"]["host_security_updates"] == 1
            finally:
                HostUpdatePackage.query.filter_by(host_id=host.id).delete()
                ProxmoxHost.query.filter_by(id=host.id).delete()
                db.session.commit()

    def test_host_updates_zero_when_none(self, app):
        with app.app_context():
            user = User.query.filter_by(username="admin").first()
            from core.dashboard_stats import get_dashboard_stats

            result = get_dashboard_stats(user)

            assert result["stats"]["host_pending_updates"] == 0
            assert result["stats"]["host_security_updates"] == 0
