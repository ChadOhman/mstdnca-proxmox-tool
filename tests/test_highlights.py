"""Tests for the admin-only Mastodon monthly highlights email builder."""

import base64
import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from core.mastodon_highlights import (
    CANDIDATE_EXTRA,
    DEFAULT_COUNT,
    MAX_COUNT,
    build_highlights_query,
    clamp_count,
    clamp_per_author,
    default_month,
    excerpt,
    is_safe_link,
    parse_highlights_output,
    parse_month,
    snowflake_floor,
    text_to_html,
)

_RAW = [
    {"id": "113400000000000001", "username": "alice", "display_name": "Alice", "text": "Hello\n<b>world</b>",
     "uri": "https://mstdn.example/users/alice/statuses/113400000000000001", "created_at": "2026-10-03T12:00:00Z",
     "favourites": 120, "reblogs": 40, "replies": 9, "media_count": 1, "score": 209},
    {"id": "113400000000000002", "username": "bob", "display_name": "", "text": "Second",
     "uri": "https://mstdn.example/users/bob/statuses/113400000000000002", "created_at": "2026-10-04T08:00:00Z",
     "favourites": 50, "reblogs": 10, "replies": 3, "media_count": 0, "score": 73},
]


class TestMonthAndQuery:
    def test_default_month_is_previous(self):
        assert default_month(datetime(2026, 11, 1, tzinfo=timezone.utc)) == "2026-10"
        assert default_month(datetime(2026, 1, 15, tzinfo=timezone.utc)) == "2025-12"

    def test_parse_month(self):
        start, end = parse_month("2026-12")
        assert start == datetime(2026, 12, 1, tzinfo=timezone.utc)
        assert end == datetime(2027, 1, 1, tzinfo=timezone.utc)
        for bad in ("", "2026-13", "2026-1", "26-10", "2026-10'; DROP TABLE statuses", None):
            assert parse_month(bad) is None

    def test_clamp_count(self):
        assert clamp_count("3") == 3
        assert clamp_count("0") == 1
        assert clamp_count("999") == MAX_COUNT
        assert clamp_count("x") == DEFAULT_COUNT

    def test_snowflake_floor_matches_mastodon_ids(self):
        # Mastodon IDs are ms-since-epoch << 16.
        dt = datetime(2026, 10, 1, tzinfo=timezone.utc)
        assert snowflake_floor(dt) >> 16 == int(dt.timestamp() * 1000)

    def test_query_filters_and_bounds(self):
        start, end = parse_month("2026-10")
        sql = build_highlights_query(start, end, 15)
        assert f"s.id >= {snowflake_floor(start)} AND s.id < {snowflake_floor(end)}" in sql
        assert "LIMIT 15" in sql
        for clause in ("a.domain IS NULL", "s.deleted_at IS NULL", "s.visibility = 0", "s.reblog_of_id IS NULL",
                       "s.in_reply_to_id IS NULL", "s.sensitive = false", "coalesce(s.spoiler_text, '') = ''",
                       "a.discoverable = true", "a.suspended_at IS NULL", "a.silenced_at IS NULL",
                       "s.trendable IS DISTINCT FROM false", "a.trendable IS DISTINCT FROM false"):
            assert clause in sql

    def test_query_caps_posts_per_author(self):
        start, end = parse_month("2026-10")
        sql = build_highlights_query(start, end, 15)
        assert "PARTITION BY s.account_id" in sql
        assert "t.author_rank <= 1 " in sql
        assert "t.author_rank <= 3 " in build_highlights_query(start, end, 15, per_author="3")
        assert "t.author_rank <= 1 " in build_highlights_query(start, end, 15, per_author="1; DROP")
        assert clamp_per_author("0") == 1
        assert clamp_per_author("999") == MAX_COUNT

    def test_query_limit_is_clamped(self):
        start, end = parse_month("2026-10")
        assert f"LIMIT {MAX_COUNT + CANDIDATE_EXTRA}" in build_highlights_query(start, end, 10_000)


class TestParsing:
    def test_parse_posts(self):
        posts = parse_highlights_output(json.dumps(_RAW))
        assert [p["username"] for p in posts] == ["alice", "bob"]
        assert posts[0]["url"] == "https://mstdn.example/@alice/113400000000000001"
        assert posts[0]["host"] == "mstdn.example"
        assert posts[1]["display_name"] == "bob"

    def test_parse_drops_bad_rows_and_hosts(self):
        rows = [{"id": "not-a-number", "username": "x"}, {"id": "1", "username": "y", "uri": "javascript:alert(1)"}]
        posts = parse_highlights_output(json.dumps(rows))
        assert len(posts) == 1
        assert posts[0]["url"] == ""

    def test_parse_rejects_garbage(self):
        assert parse_highlights_output("") == []
        with pytest.raises(ValueError):
            parse_highlights_output("ERROR: nope")
        with pytest.raises(ValueError):
            parse_highlights_output('{"a": 1}')

    def test_excerpt(self):
        assert excerpt("short") == "short"
        long = "word " * 200
        out = excerpt(long, limit=50)
        assert len(out) <= 51 and out.endswith("…")

    def test_text_to_html_escapes(self):
        html = str(text_to_html("Hello\n<b>world</b>"))
        assert html == "Hello<br>\n&lt;b&gt;world&lt;/b&gt;"

    def test_is_safe_link(self):
        assert is_safe_link("https://example.org/donate")
        assert not is_safe_link("javascript:alert(1)")
        assert not is_safe_link("/donate")
        assert not is_safe_link("")


@pytest.fixture()
def db_guest(app):
    from auth.credential_store import encrypt
    from models import Credential, Guest, Setting
    from models import db as _db

    with app.app_context():
        cred = Credential(name="_hl_test_cred", username="root", encrypted_value=encrypt("test-only-ssh-password"))
        _db.session.add(cred)
        _db.session.flush()
        guest = Guest(name="_hl_test_db_guest", guest_type="ct", ip_address="10.0.0.52", credential_id=cred.id)
        _db.session.add(guest)
        _db.session.commit()
        previous = Setting.get("mastodon_db_guest_id", "")
        Setting.set("mastodon_db_guest_id", str(guest.id))
        guest_id, cred_id = guest.id, cred.id

    yield guest_id

    with app.app_context():
        Setting.set("mastodon_db_guest_id", previous)
        _db.session.delete(_db.session.get(Guest, guest_id))
        _db.session.delete(_db.session.get(Credential, cred_id))
        _db.session.commit()


def _mock_ssh(mock_ssh_class, result):
    ssh = MagicMock()
    ssh.__enter__ = MagicMock(return_value=ssh)
    ssh.__exit__ = MagicMock(return_value=False)
    ssh.execute_sudo.return_value = result
    mock_ssh_class.from_credential.return_value = ssh
    return ssh


class TestFetch:
    def test_bad_month(self, app):
        from core.mastodon_highlights import fetch_highlights

        with app.app_context():
            posts, err = fetch_highlights("October")
        assert posts is None
        assert "YYYY-MM" in err

    @patch("clients.ssh_client.SSHClient")
    def test_success_pipes_sql_on_stdin(self, mock_ssh_class, app, db_guest):
        from core.mastodon_highlights import fetch_highlights

        ssh = _mock_ssh(mock_ssh_class, (json.dumps(_RAW), "", 0))
        with app.app_context():
            posts, err = fetch_highlights("2026-10", 3)
        assert err is None
        assert len(posts) == 2
        cmd = ssh.execute_sudo.call_args[0][0]
        b64 = cmd.split("printf '%s' '")[1].split("'")[0]
        sql = base64.b64decode(b64).decode()
        assert f"LIMIT {3 + CANDIDATE_EXTRA}" in sql

    @patch("clients.ssh_client.SSHClient")
    def test_psql_failure_hides_stderr(self, mock_ssh_class, app, db_guest):
        from core.mastodon_highlights import fetch_highlights

        _mock_ssh(mock_ssh_class, ("", "ERROR: secret detail", 1))
        with app.app_context():
            posts, err = fetch_highlights("2026-10")
        assert posts is None
        assert "exit 1" in err
        assert "secret detail" not in err


class TestRoutes:
    def test_moderator_denied(self, moderator_client):
        for method, path in (("get", "/highlights/"), ("post", "/highlights/build")):
            resp = getattr(moderator_client, method)(path, data={"month": "2026-10"}, follow_redirects=False)
            assert resp.status_code == 302, path
            assert "/highlights" not in resp.headers["Location"]

    def test_admin_index(self, auth_client):
        resp = auth_client.get("/highlights/")
        assert resp.status_code == 200
        assert b"Mastodon Monthly Highlights" in resp.data

    @patch("routes.highlights.fetch_highlights")
    def test_build_renders_email_and_remembers_donate(self, mock_fetch, app, auth_client):
        from models import AuditLog, Setting

        mock_fetch.return_value = (parse_highlights_output(json.dumps(_RAW)), None)
        resp = auth_client.post("/highlights/build", data={
            "month": "2026-10", "count": "1", "per_author": "2", "donate_url": "https://donate.example/give",
            "donate_heading": "Chip in", "donate_message": "Servers cost money.", "donate_button": "Give",
            "unsubscribe": "on",
        })
        assert resp.status_code == 200
        body = resp.data.decode()
        mock_fetch.assert_called_once_with("2026-10", 1, 2)
        assert "The best of October 2026" in body
        assert "https://mstdn.example/@alice/113400000000000001" in body
        # Post text is escaped inside the email fragment.
        assert "&lt;b&gt;world&lt;/b&gt;" in body and "<b>world</b>" not in body
        assert 'href="https://donate.example/give"' in body
        assert "[[UNSUB_LINK_EN]]" in body
        assert "<!--HL_ROWS-->" in body
        # Only the first `count` candidates start ticked.
        assert body.count("checked>") == 2  # unsubscribe box + one post
        with app.app_context():
            assert Setting.get("mastodon_highlights_donate_url") == "https://donate.example/give"
            entry = AuditLog.query.filter_by(action="mastodon_highlights_build").order_by(AuditLog.id.desc()).first()
            assert entry is not None

    @patch("routes.highlights.fetch_highlights")
    def test_rejects_unsafe_donate_link(self, mock_fetch, auth_client):
        resp = auth_client.post("/highlights/build", data={"month": "2026-10", "donate_url": "javascript:alert(1)"})
        assert resp.status_code == 200
        assert b"full http:// or https:// URL" in resp.data
        mock_fetch.assert_not_called()

    @patch("routes.highlights.fetch_highlights")
    def test_fetch_error_flashes(self, mock_fetch, auth_client):
        mock_fetch.return_value = (None, "Mastodon database guest is not configured")
        resp = auth_client.post("/highlights/build", data={"month": "2026-10"})
        assert resp.status_code == 200
        assert b"not configured" in resp.data
