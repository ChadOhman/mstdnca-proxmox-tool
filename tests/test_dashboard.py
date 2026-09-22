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

    def test_dashboard_current_tag_renders_as_valid_js_when_empty(self, auth_client):
        """With no tag filter, CURRENT_TAG must be an empty JS string literal, not HTML-escaped quotes.

        The inline-if fallback used to bypass |tojson so autoescape turned '""' into &#34;&#34;,
        which is a SyntaxError that kills the whole dashboard script block.
        """
        resp = auth_client.get("/")
        assert resp.status_code == 200
        body = resp.data.decode()
        assert 'const CURRENT_TAG = "";' in body
        assert "&#34;" not in body

    def test_dashboard_current_tag_renders_selected_tag(self, auth_client):
        """A tag filter is rendered through tojson as a proper JS string literal."""
        resp = auth_client.get("/?tag=web")
        assert resp.status_code == 200
        assert 'const CURRENT_TAG = "web";' in resp.data.decode()


class TestAppUpdateBanner:
    """The "new version of MCAT" banner must only appear for a strictly newer release."""

    BANNER = b"A new version of MCAT is available"

    @staticmethod
    def _set_latest(app, version):
        with app.app_context():
            from models import Setting
            Setting.set("latest_app_version", version)
            db.session.commit()

    @staticmethod
    def _run(app, auth_client, monkeypatch, *, running, latest, stale):
        monkeypatch.setitem(app.config, "APP_VERSION", running)
        monkeypatch.setitem(app.config, "APP_VERSION_STALE", stale)
        TestAppUpdateBanner._set_latest(app, latest)
        try:
            return auth_client.get("/").data
        finally:
            TestAppUpdateBanner._set_latest(app, "")

    def test_no_banner_when_ahead_of_the_release_tag(self, app, auth_client, monkeypatch):
        """Regression: a main checkout past v0.2.0 was told v0.2.0 was new."""
        body = self._run(app, auth_client, monkeypatch, running="0.2.0", latest="0.2.0", stale=True)
        assert self.BANNER not in body

    def test_no_banner_when_exactly_on_the_release(self, app, auth_client, monkeypatch):
        body = self._run(app, auth_client, monkeypatch, running="0.2.0", latest="0.2.0", stale=False)
        assert self.BANNER not in body

    def test_banner_when_a_newer_release_exists(self, app, auth_client, monkeypatch):
        body = self._run(app, auth_client, monkeypatch, running="0.2.0", latest="0.3.0", stale=False)
        assert self.BANNER in body
        assert b"v0.3.0" in body

    def test_banner_when_a_newer_release_exists_even_if_ahead_of_tag(self, app, auth_client, monkeypatch):
        """Being on a branch past v0.2.0 does not hide a genuinely newer v0.3.0."""
        body = self._run(app, auth_client, monkeypatch, running="0.2.0", latest="0.3.0", stale=True)
        assert self.BANNER in body

    def test_no_banner_when_latest_is_older(self, app, auth_client, monkeypatch):
        body = self._run(app, auth_client, monkeypatch, running="0.3.0", latest="0.2.0", stale=False)
        assert self.BANNER not in body

    def test_no_banner_when_running_version_is_unknown(self, app, auth_client, monkeypatch):
        body = self._run(app, auth_client, monkeypatch, running="unknown", latest="0.3.0", stale=True)
        assert self.BANNER not in body

    def test_no_banner_when_no_check_has_run(self, app, auth_client, monkeypatch):
        body = self._run(app, auth_client, monkeypatch, running="0.2.0", latest="", stale=True)
        assert self.BANNER not in body
