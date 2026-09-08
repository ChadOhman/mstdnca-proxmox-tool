"""Tests for routes/security.py::save_cloudflare -- team_domain validation.

Scoped narrowly to the POST /security/access/cloudflare handler's team_domain
check (GHSA-gj96-qjq5-q57h). A naive `.endswith(".cloudflareaccess.com")`
check accepts "evil.com#.cloudflareaccess.com", and the saved value is later
used to build both a logout redirect and a JWKS fetch URL (open redirect /
SSRF primitive), so it must be validated strictly on save.
"""
from models import Setting


class TestSaveCloudflareTeamDomainValidation:
    def test_accepts_well_formed_team_domain(self, app, auth_client):
        resp = auth_client.post(
            "/security/access/cloudflare",
            data={
                "cf_access_team_domain": "myteam.cloudflareaccess.com",
                "cf_access_audience": "aud123",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302
        with app.app_context():
            assert Setting.get("cf_access_team_domain") == "myteam.cloudflareaccess.com"

    def test_rejects_endswith_bypass_domain(self, app, auth_client):
        with app.app_context():
            Setting.set("cf_access_team_domain", "")

        resp = auth_client.post(
            "/security/access/cloudflare",
            data={
                "cf_access_team_domain": "evil.com#.cloudflareaccess.com",
                "cf_access_audience": "aud123",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302
        with app.app_context():
            assert Setting.get("cf_access_team_domain") != "evil.com#.cloudflareaccess.com"

    def test_rejects_suffix_bypass_domain(self, app, auth_client):
        with app.app_context():
            Setting.set("cf_access_team_domain", "")

        resp = auth_client.post(
            "/security/access/cloudflare",
            data={
                "cf_access_team_domain": "evil.com.cloudflareaccess.com.evil.com",
                "cf_access_audience": "aud123",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302
        with app.app_context():
            assert Setting.get("cf_access_team_domain") != "evil.com.cloudflareaccess.com.evil.com"

    def test_empty_team_domain_is_still_allowed(self, app, auth_client):
        """Clearing the field (disabling CF Access) must remain possible."""
        with app.app_context():
            Setting.set("cf_access_team_domain", "myteam.cloudflareaccess.com")

        resp = auth_client.post(
            "/security/access/cloudflare",
            data={"cf_access_team_domain": "", "cf_access_audience": ""},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        with app.app_context():
            assert Setting.get("cf_access_team_domain") == ""
