"""Tests for the Mastodon moderation tab: Admin API client and routes."""

import io
import json
import urllib.error
from unittest.mock import MagicMock, patch

import pytest

from core.mastodon_admin import (
    MastodonAdminClient,
    MastodonAPIError,
    strip_html,
    summarize_admin_account,
    summarize_report,
    validate_domain,
)

API = "https://masto.example"


def _resp(payload, headers=None, raw=None):
    """Build a context-manager mock that looks like a urlopen response."""
    m = MagicMock()
    m.__enter__.return_value = m
    m.read.return_value = raw if raw is not None else json.dumps(payload).encode()
    m.headers = headers or {}
    m.status = 200
    return m


def _http_error(code, body=None):
    fp = io.BytesIO(json.dumps(body).encode() if body is not None else b"")
    return urllib.error.HTTPError("https://masto.example/x", code, "reason", {}, fp)


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


class TestHelpers:
    @pytest.mark.parametrize("raw,expected", [
        ("Example.Social", "example.social"),
        ("  spam.example.  ", "spam.example"),
        ("a-b.c-d.example", "a-b.c-d.example"),
    ])
    def test_validate_domain_accepts(self, raw, expected):
        assert validate_domain(raw) == expected

    @pytest.mark.parametrize("raw", [
        "", "localhost", "https://example.social", "example.social/path", "exa mple.social",
        "example.social:443", "-bad.example", "x;rm.example", "ex_ample.social",
    ])
    def test_validate_domain_rejects(self, raw):
        with pytest.raises(ValueError):
            validate_domain(raw)

    def test_strip_html(self):
        assert strip_html('<p>Hello <a href="x">world</a>&amp; more</p>') == "Hello world & more"
        assert strip_html("") == ""
        assert strip_html(None) == ""

    def test_summarize_report_reduces_fields(self):
        rep = {
            "id": "42", "category": "spam", "comment": "bad", "forwarded": True, "action_taken": False,
            "created_at": "2026-09-01T00:00:00Z",
            "account": {"id": "1", "username": "rep", "account": {"id": "1", "acct": "rep", "url": "u1"}},
            "target_account": {
                "id": "2", "username": "bad", "email": "bad@example.com", "ip": "10.0.0.1",
                "suspended": False, "silenced": True, "role": {"name": "User"},
                "account": {"id": "2", "acct": "bad", "display_name": "Bad", "url": "u2", "avatar": "av"},
            },
            "statuses": [{"id": "9", "url": "s9", "content": "<p>buy <b>now</b></p>", "media_attachments": [1, 2]}],
            "rules": [{"id": "1", "text": "No spam"}],
        }
        out = summarize_report(rep)
        assert out["id"] == "42"
        assert out["account"]["acct"] == "rep"
        assert out["target_account"]["acct"] == "bad"
        assert out["target_account"]["email"] == "bad@example.com"
        assert out["target_account"]["silenced"] is True
        assert out["statuses"][0]["excerpt"] == "buy now"
        assert out["statuses"][0]["media_count"] == 2
        assert out["rules"] == ["No spam"]
        # No raw HTML or untouched nested blobs leak through
        assert "content" not in out["statuses"][0]

    def test_summarize_admin_account_builds_acct_from_username_and_domain(self):
        out = summarize_admin_account({"id": "5", "username": "u", "domain": "remote.example"})
        assert out["acct"] == "u@remote.example"
        assert out["id"] == "5"
        out_local = summarize_admin_account({"id": "6", "username": "l", "domain": None})
        assert out_local["acct"] == "l"


# ---------------------------------------------------------------------------
# Client transport
# ---------------------------------------------------------------------------


class TestClientTransport:
    @patch("core.mastodon_admin.urllib.request.urlopen")
    def test_get_sends_bearer_and_parses_json(self, mock_urlopen):
        mock_urlopen.return_value = _resp({"id": "1"})
        c = MastodonAdminClient(API + "/", "test-only-token")
        data, _ = c._request("GET", "/api/v1/x", params={"a": "b", "skip": ""})
        assert data == {"id": "1"}
        req = mock_urlopen.call_args[0][0]
        assert req.full_url == API + "/api/v1/x?a=b"
        assert req.get_header("Authorization") == "Bearer test-only-token"
        assert req.get_method() == "GET"

    @patch("core.mastodon_admin.urllib.request.urlopen")
    def test_post_with_body_is_json(self, mock_urlopen):
        mock_urlopen.return_value = _resp({})
        c = MastodonAdminClient(API, "t")
        c._request("POST", "/api/v1/y", body={"type": "suspend"})
        req = mock_urlopen.call_args[0][0]
        assert req.get_method() == "POST"
        assert req.get_header("Content-type") == "application/json"
        assert json.loads(mock_urlopen.call_args[1]["data"].decode()) == {"type": "suspend"}

    @patch("core.mastodon_admin.urllib.request.urlopen")
    def test_empty_body_is_empty_dict(self, mock_urlopen):
        mock_urlopen.return_value = _resp(None, raw=b"")
        data, _ = MastodonAdminClient(API, "t")._request("POST", "/api/v1/z")
        assert data == {}

    @patch("core.mastodon_admin.urllib.request.urlopen")
    def test_http_error_carries_status_and_api_message(self, mock_urlopen):
        mock_urlopen.side_effect = _http_error(403, {"error": "This action is outside the authorized scopes"})
        with pytest.raises(MastodonAPIError) as ei:
            MastodonAdminClient(API, "t")._request("GET", "/api/v1/admin/reports")
        assert ei.value.http_status == 403
        assert "HTTP 403" in ei.value.message
        assert "outside the authorized scopes" in ei.value.message

    @patch("core.mastodon_admin.urllib.request.urlopen")
    def test_transport_error_never_leaks_exception_text(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.URLError("secret-internal-host.lan refused")
        with pytest.raises(MastodonAPIError) as ei:
            MastodonAdminClient(API, "t")._request("GET", "/api/v1/x")
        assert "secret-internal-host" not in ei.value.message
        assert ei.value.http_status is None

    @patch("core.mastodon_admin.urllib.request.urlopen")
    def test_non_json_response(self, mock_urlopen):
        mock_urlopen.return_value = _resp(None, raw=b"<html>oops</html>")
        with pytest.raises(MastodonAPIError):
            MastodonAdminClient(API, "t")._request("GET", "/api/v1/x")

    @patch("core.mastodon_admin.urllib.request.urlopen")
    def test_pagination_follows_same_origin_link(self, mock_urlopen):
        mock_urlopen.side_effect = [
            _resp([{"id": "1"}], headers={"Link": f'<{API}/api/v1/admin/domain_blocks?max_id=1>; rel="next"'}),
            _resp([{"id": "2"}], headers={}),
        ]
        items = MastodonAdminClient(API, "t")._get_all("/api/v1/admin/domain_blocks")
        assert [i["id"] for i in items] == ["1", "2"]
        second = mock_urlopen.call_args_list[1][0][0]
        assert second.full_url == f"{API}/api/v1/admin/domain_blocks?max_id=1"

    @patch("core.mastodon_admin.urllib.request.urlopen")
    def test_pagination_refuses_cross_origin_link(self, mock_urlopen):
        mock_urlopen.return_value = _resp(
            [{"id": "1"}], headers={"Link": '<https://evil.example/steal?x=1>; rel="next"'},
        )
        with pytest.raises(MastodonAPIError) as ei:
            MastodonAdminClient(API, "t")._get_all("/api/v1/admin/domain_blocks")
        assert "different host" in ei.value.message
        assert mock_urlopen.call_count == 1

    @patch("core.mastodon_admin.urllib.request.urlopen")
    def test_pagination_page_cap(self, mock_urlopen):
        link = {"Link": f'<{API}/api/v1/admin/reports?max_id=0>; rel="next"'}
        mock_urlopen.side_effect = [_resp([{"id": str(i)}], headers=link) for i in range(50)]
        items = MastodonAdminClient(API, "t")._get_all("/api/v1/admin/reports", max_pages=3)
        assert len(items) == 3
        assert mock_urlopen.call_count == 3

    @patch("core.mastodon_admin.urllib.request.urlopen")
    def test_list_endpoint_rejects_non_list(self, mock_urlopen):
        mock_urlopen.return_value = _resp({"error": "nope"})
        with pytest.raises(MastodonAPIError):
            MastodonAdminClient(API, "t")._get_all("/api/v1/admin/reports")


# ---------------------------------------------------------------------------
# Client operations
# ---------------------------------------------------------------------------


class TestClientOperations:
    @patch("core.mastodon_admin.urllib.request.urlopen")
    def test_verify_probes_admin_scope(self, mock_urlopen):
        mock_urlopen.side_effect = [
            _resp({"acct": "admin", "display_name": "A", "role": {"name": "Owner"}}),
            _resp([]),
        ]
        out = MastodonAdminClient(API, "t").verify()
        assert out == {"acct": "admin", "display_name": "A", "role": "Owner"}
        urls = [c[0][0].full_url for c in mock_urlopen.call_args_list]
        assert urls[0].endswith("/api/v1/accounts/verify_credentials")
        assert "/api/v1/admin/reports" in urls[1]

    @patch("core.mastodon_admin.urllib.request.urlopen")
    def test_list_reports_passes_resolved_flag(self, mock_urlopen):
        mock_urlopen.return_value = _resp([])
        MastodonAdminClient(API, "t").list_reports(resolved=True)
        assert "resolved=true" in mock_urlopen.call_args[0][0].full_url

    @patch("core.mastodon_admin.urllib.request.urlopen")
    def test_lookup_account_chains_public_then_admin(self, mock_urlopen):
        mock_urlopen.side_effect = [
            _resp({"id": "77", "acct": "someone"}),
            _resp({"id": "77", "username": "someone", "account": {"acct": "someone"}}),
        ]
        out = MastodonAdminClient(API, "t").lookup_account("@someone")
        assert out["id"] == "77"
        urls = [c[0][0].full_url for c in mock_urlopen.call_args_list]
        assert urls[0] == f"{API}/api/v1/accounts/lookup?acct=someone"
        assert urls[1] == f"{API}/api/v1/admin/accounts/77"

    @patch("core.mastodon_admin.urllib.request.urlopen")
    def test_lookup_account_not_found(self, mock_urlopen):
        mock_urlopen.side_effect = _http_error(404, {"error": "Record not found"})
        with pytest.raises(MastodonAPIError) as ei:
            MastodonAdminClient(API, "t").lookup_account("ghost")
        assert ei.value.http_status == 404

    def test_lookup_account_requires_handle(self):
        with pytest.raises(MastodonAPIError):
            MastodonAdminClient(API, "t").lookup_account("  ")

    @patch("core.mastodon_admin.urllib.request.urlopen")
    def test_account_action_body(self, mock_urlopen):
        mock_urlopen.return_value = _resp({})
        MastodonAdminClient(API, "t").account_action(5, "suspend", text="bye", report_id=9, send_email_notification=True)
        req = mock_urlopen.call_args[0][0]
        assert req.full_url == f"{API}/api/v1/admin/accounts/5/action"
        body = json.loads(mock_urlopen.call_args[1]["data"].decode())
        assert body == {"type": "suspend", "text": "bye", "send_email_notification": True, "report_id": "9"}

    def test_account_action_rejects_unknown_type(self):
        with pytest.raises(MastodonAPIError):
            MastodonAdminClient(API, "t").account_action(5, "nuke")

    def test_lift_rejects_unknown(self):
        with pytest.raises(MastodonAPIError):
            MastodonAdminClient(API, "t").lift_account_action(5, "delete")

    @patch("core.mastodon_admin.urllib.request.urlopen")
    def test_create_domain_block_body(self, mock_urlopen):
        mock_urlopen.return_value = _resp({"id": "3", "domain": "spam.example", "severity": "suspend"})
        out = MastodonAdminClient(API, "t").create_domain_block("Spam.Example", severity="suspend", reject_media=True)
        assert out["domain"] == "spam.example"
        body = json.loads(mock_urlopen.call_args[1]["data"].decode())
        assert body["domain"] == "spam.example"
        assert body["severity"] == "suspend"
        assert body["reject_media"] is True
        assert body["reject_reports"] is False

    def test_create_domain_block_rejects_bad_severity(self):
        with pytest.raises(MastodonAPIError):
            MastodonAdminClient(API, "t").create_domain_block("spam.example", severity="annihilate")

    def test_create_domain_block_rejects_bad_domain(self):
        with pytest.raises(ValueError):
            MastodonAdminClient(API, "t").create_domain_block("https://spam.example")

    @patch("core.mastodon_admin.urllib.request.urlopen")
    def test_delete_domain_block_uses_delete(self, mock_urlopen):
        mock_urlopen.return_value = _resp({})
        MastodonAdminClient(API, "t").delete_domain_block(3)
        req = mock_urlopen.call_args[0][0]
        assert req.get_method() == "DELETE"
        assert req.full_url == f"{API}/api/v1/admin/domain_blocks/3"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


def _last_audit(app, action):
    from models import AuditLog

    with app.app_context():
        return AuditLog.query.filter_by(action=action).order_by(AuditLog.id.desc()).first()


@pytest.fixture()
def masto_client():
    """Patch the route-level client factory with a MagicMock client."""
    client = MagicMock(spec=MastodonAdminClient)
    with patch("routes.moderation._get_mastodon_client", return_value=(client, None)):
        yield client


class TestMastodonRouteAuth:
    @pytest.mark.parametrize("method,path", [
        ("get", "/moderation/mastodon/reports"),
        ("get", "/moderation/mastodon/pending"),
        ("get", "/moderation/mastodon/domain_blocks"),
        ("get", "/moderation/mastodon/accounts/lookup?acct=x"),
        ("post", "/moderation/mastodon/save"),
        ("post", "/moderation/mastodon/test"),
        ("post", "/moderation/mastodon/reports/1/resolve"),
        ("post", "/moderation/mastodon/accounts/1/approve"),
        ("post", "/moderation/mastodon/accounts/1/action"),
        ("post", "/moderation/mastodon/accounts/1/unsuspend"),
        ("post", "/moderation/mastodon/domain_blocks"),
        ("post", "/moderation/mastodon/domain_blocks/1/delete"),
    ])
    def test_requires_login(self, client, method, path):
        resp = getattr(client, method)(path, follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers.get("Location", "")


class TestMastodonSettings:
    def test_not_configured_returns_400(self, app, auth_client):
        from models import Setting

        with app.app_context():
            Setting.set("moderation_mastodon_api_url", "")
            Setting.set("moderation_mastodon_api_token", "")
        resp = auth_client.get("/moderation/mastodon/reports")
        assert resp.status_code == 400
        assert "not configured" in resp.get_json()["error"]

    def test_save_encrypts_token_and_redirects_to_tab(self, app, auth_client):
        from auth.credential_store import decrypt
        from models import Setting

        resp = auth_client.post("/moderation/mastodon/save", data={
            "mastodon_api_url": "https://masto.example/",
            "mastodon_api_token": "test-only-masto-token",
        }, follow_redirects=False)
        assert resp.status_code == 302
        assert "tab=mastodon" in resp.headers["Location"]
        with app.app_context():
            assert Setting.get("moderation_mastodon_api_url") == "https://masto.example"
            stored = Setting.get("moderation_mastodon_api_token")
            assert stored != "test-only-masto-token"
            assert decrypt(stored) == "test-only-masto-token"
        assert _last_audit(app, "moderation_mastodon_config_save") is not None

    def test_save_keeps_token_when_blank(self, app, auth_client):
        from models import Setting

        auth_client.post("/moderation/mastodon/save", data={
            "mastodon_api_url": "https://masto.example", "mastodon_api_token": "test-only-keep",
        })
        with app.app_context():
            before = Setting.get("moderation_mastodon_api_token")
        auth_client.post("/moderation/mastodon/save", data={"mastodon_api_url": "https://masto.example"})
        with app.app_context():
            assert Setting.get("moderation_mastodon_api_token") == before

    def test_save_rejects_non_http_url(self, app, auth_client):
        from models import Setting

        with app.app_context():
            Setting.set("moderation_mastodon_api_url", "https://keep.example")
        resp = auth_client.post("/moderation/mastodon/save", data={"mastodon_api_url": "ftp://x"},
                                follow_redirects=False)
        assert resp.status_code == 302
        with app.app_context():
            assert Setting.get("moderation_mastodon_api_url") == "https://keep.example"

    def test_index_tab_param_activates_mastodon_pane(self, auth_client):
        resp = auth_client.get("/moderation/?tab=mastodon")
        assert resp.status_code == 200
        html = resp.data.decode()
        assert 'class="tab-pane fade show active" id="mastodon-pane"' in html
        assert 'class="tab-pane fade" id="peertube-pane"' in html

    def test_index_default_is_peertube(self, auth_client):
        html = auth_client.get("/moderation/").data.decode()
        assert 'class="tab-pane fade show active" id="peertube-pane"' in html
        assert 'class="tab-pane fade" id="mastodon-pane"' in html

    def test_real_client_factory_decrypts_token(self, app, auth_client):
        from auth.credential_store import encrypt
        from models import Setting
        from routes.moderation import _get_mastodon_client

        with app.app_context():
            Setting.set("moderation_mastodon_api_url", "https://masto.example")
            Setting.set("moderation_mastodon_api_token", encrypt("test-only-plain"))
            with app.test_request_context():
                c, err = _get_mastodon_client()
        assert err is None
        assert c.api_url == "https://masto.example"
        assert c._token == "test-only-plain"


class TestMastodonReadRoutes:
    def test_test_connection(self, auth_client, masto_client):
        masto_client.verify.return_value = {"acct": "admin", "role": "Owner"}
        resp = auth_client.post("/moderation/mastodon/test")
        assert resp.status_code == 200
        assert resp.get_json()["account"]["acct"] == "admin"

    def test_reports_list(self, auth_client, masto_client):
        masto_client.list_reports.return_value = [{"id": "1"}]
        resp = auth_client.get("/moderation/mastodon/reports?resolved=true")
        assert resp.status_code == 200
        assert resp.get_json() == {"ok": True, "reports": [{"id": "1"}]}
        masto_client.list_reports.assert_called_once_with(resolved=True)

    def test_upstream_error_is_502_with_safe_message(self, auth_client, masto_client):
        masto_client.list_reports.side_effect = MastodonAPIError("Mastodon API returned HTTP 401: token rejected", 401)
        resp = auth_client.get("/moderation/mastodon/reports")
        assert resp.status_code == 502
        assert resp.get_json() == {"ok": False, "error": "Mastodon API returned HTTP 401: token rejected"}

    def test_pending_list(self, auth_client, masto_client):
        masto_client.list_pending_accounts.return_value = [{"id": "2", "username": "new"}]
        resp = auth_client.get("/moderation/mastodon/pending")
        assert resp.get_json()["accounts"][0]["username"] == "new"

    def test_domain_blocks_list(self, auth_client, masto_client):
        masto_client.list_domain_blocks.return_value = [{"id": "3", "domain": "spam.example"}]
        resp = auth_client.get("/moderation/mastodon/domain_blocks")
        assert resp.get_json()["blocks"][0]["domain"] == "spam.example"

    def test_lookup_requires_acct(self, auth_client, masto_client):
        resp = auth_client.get("/moderation/mastodon/accounts/lookup")
        assert resp.status_code == 400
        masto_client.lookup_account.assert_not_called()

    def test_lookup(self, auth_client, masto_client):
        masto_client.lookup_account.return_value = {"id": "7", "acct": "x"}
        resp = auth_client.get("/moderation/mastodon/accounts/lookup?acct=%40x")
        assert resp.get_json()["account"]["id"] == "7"
        masto_client.lookup_account.assert_called_once_with("@x")


class TestMastodonMutationRoutes:
    def test_resolve_report_audits(self, app, auth_client, masto_client):
        resp = auth_client.post("/moderation/mastodon/reports/42/resolve")
        assert resp.status_code == 200
        masto_client.resolve_report.assert_called_once_with(42)
        entry = _last_audit(app, "mastodon_report_resolve")
        assert entry.resource_type == "mastodon_report"
        assert entry.details == {"report_id": "42"}

    def test_reopen_report(self, app, auth_client, masto_client):
        auth_client.post("/moderation/mastodon/reports/42/reopen")
        masto_client.reopen_report.assert_called_once_with(42)
        assert _last_audit(app, "mastodon_report_reopen") is not None

    def test_failed_mutation_writes_no_audit(self, app, auth_client, masto_client):
        from models import AuditLog

        with app.app_context():
            before = AuditLog.query.filter_by(action="mastodon_report_resolve").count()
        masto_client.resolve_report.side_effect = MastodonAPIError("HTTP 404", 404)
        resp = auth_client.post("/moderation/mastodon/reports/99/resolve")
        assert resp.status_code == 502
        with app.app_context():
            assert AuditLog.query.filter_by(action="mastodon_report_resolve").count() == before

    def test_approve_and_reject_audit_with_acct(self, app, auth_client, masto_client):
        auth_client.post("/moderation/mastodon/accounts/5/approve", data={"acct": "newbie"})
        masto_client.approve_account.assert_called_once_with(5)
        assert _last_audit(app, "mastodon_account_approve").resource_name == "newbie"

        auth_client.post("/moderation/mastodon/accounts/6/reject")
        masto_client.reject_account.assert_called_once_with(6)
        assert _last_audit(app, "mastodon_account_reject").resource_name == "6"

    def test_account_action_rejects_unknown_type(self, auth_client, masto_client):
        resp = auth_client.post("/moderation/mastodon/accounts/5/action", data={"type": "nuke"})
        assert resp.status_code == 400
        masto_client.account_action.assert_not_called()

    def test_account_action_forwards_fields_and_audits(self, app, auth_client, masto_client):
        masto_client.get_admin_account.return_value = {"id": "5", "acct": "bad", "suspended": True}
        resp = auth_client.post("/moderation/mastodon/accounts/5/action", data={
            "type": "suspend", "text": "spam", "report_id": "42", "send_email_notification": "1", "acct": "bad",
        })
        assert resp.status_code == 200
        assert resp.get_json()["account"]["suspended"] is True
        masto_client.account_action.assert_called_once_with(
            5, "suspend", text="spam", report_id=42, send_email_notification=True,
        )
        entry = _last_audit(app, "mastodon_account_suspend")
        assert entry.resource_name == "bad"
        assert entry.details == {"account_id": "5", "type": "suspend", "notify": True, "report_id": "42"}

    def test_account_action_text_is_capped(self, auth_client, masto_client):
        masto_client.get_admin_account.return_value = {}
        auth_client.post("/moderation/mastodon/accounts/5/action", data={"type": "silence", "text": "x" * 5000})
        assert len(masto_client.account_action.call_args[1]["text"]) == 2000

    def test_lift_unknown_is_404(self, auth_client, masto_client):
        resp = auth_client.post("/moderation/mastodon/accounts/5/obliterate")
        assert resp.status_code == 404
        masto_client.lift_account_action.assert_not_called()

    def test_lift_unsuspend_audits(self, app, auth_client, masto_client):
        masto_client.get_admin_account.return_value = {"id": "5", "suspended": False}
        resp = auth_client.post("/moderation/mastodon/accounts/5/unsuspend", data={"acct": "bad"})
        assert resp.status_code == 200
        masto_client.lift_account_action.assert_called_once_with(5, "unsuspend")
        assert _last_audit(app, "mastodon_account_unsuspend").resource_name == "bad"

    def test_domain_block_create_validates_domain(self, auth_client, masto_client):
        resp = auth_client.post("/moderation/mastodon/domain_blocks", data={"domain": "https://spam.example"})
        assert resp.status_code == 400
        masto_client.create_domain_block.assert_not_called()

    def test_domain_block_create_validates_severity(self, auth_client, masto_client):
        resp = auth_client.post("/moderation/mastodon/domain_blocks",
                                data={"domain": "spam.example", "severity": "annihilate"})
        assert resp.status_code == 400
        masto_client.create_domain_block.assert_not_called()

    def test_domain_block_create_audits(self, app, auth_client, masto_client):
        masto_client.create_domain_block.return_value = {"id": "3", "domain": "spam.example"}
        resp = auth_client.post("/moderation/mastodon/domain_blocks", data={
            "domain": "Spam.Example", "severity": "suspend", "reject_media": "1",
            "public_comment": "spam", "private_comment": "seen 3x",
        })
        assert resp.status_code == 200
        assert resp.get_json()["block"]["id"] == "3"
        masto_client.create_domain_block.assert_called_once_with(
            "spam.example", severity="suspend", reject_media=True, reject_reports=False, obfuscate=False,
            public_comment="spam", private_comment="seen 3x",
        )
        entry = _last_audit(app, "mastodon_domain_block_create")
        assert entry.resource_name == "spam.example"
        assert entry.details["severity"] == "suspend"

    def test_domain_block_delete_audits(self, app, auth_client, masto_client):
        resp = auth_client.post("/moderation/mastodon/domain_blocks/3/delete", data={"domain": "spam.example"})
        assert resp.status_code == 200
        masto_client.delete_domain_block.assert_called_once_with(3)
        assert _last_audit(app, "mastodon_domain_block_delete").resource_name == "spam.example"


class TestMastodonViewerDenied:
    def test_viewer_cannot_reach_mastodon_routes(self, app, client, masto_client):
        from models import Role, User, db

        with app.app_context():
            viewer_role = Role.query.filter_by(name="viewer").first()
            user = User(username="_masto_viewer", display_name="V", role_id=viewer_role.id)
            user.set_password("ViewerPass123!")
            db.session.add(user)
            db.session.commit()
        try:
            client.post("/login", data={"username": "_masto_viewer", "password": "ViewerPass123!"})
            resp = client.post("/moderation/mastodon/reports/1/resolve", follow_redirects=False)
            assert resp.status_code == 302
            masto_client.resolve_report.assert_not_called()
        finally:
            with app.app_context():
                User.query.filter_by(username="_masto_viewer").delete()
                db.session.commit()
