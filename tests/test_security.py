"""Tests for security helpers, secret detection, and the local-bypass migration notice."""
import os
import re

from models import Setting, db

# Import helpers directly from the routes module
from routes.security import _safe_int, _safe_int_list


class TestSafeInt:
    def test_valid_integer_string(self):
        assert _safe_int("42") == 42

    def test_zero(self):
        assert _safe_int("0") == 0

    def test_negative(self):
        assert _safe_int("-5") == -5

    def test_non_numeric_returns_none(self):
        assert _safe_int("abc") is None

    def test_empty_string_returns_none(self):
        assert _safe_int("") is None

    def test_none_returns_none(self):
        assert _safe_int(None) is None

    def test_float_string_returns_none(self):
        assert _safe_int("3.14") is None


class TestSafeIntList:
    def test_valid_list(self):
        assert _safe_int_list(["1", "2", "3"]) == [1, 2, 3]

    def test_empty_list(self):
        assert _safe_int_list([]) == []

    def test_one_invalid_returns_none(self):
        assert _safe_int_list(["1", "bad", "3"]) is None

    def test_all_invalid_returns_none(self):
        assert _safe_int_list(["x", "y"]) is None


# ---------------------------------------------------------------------------
# Hardcoded secret detection — catches credential-like values in source
# before they reach CI / GitGuardian.
# ---------------------------------------------------------------------------

# Patterns that look like real secrets next to credential field names.
# GitGuardian triggers on username+password pairs that look like real
# service credentials.  This regex catches credential-like field names
# paired with values that are NOT clearly fake test data.
_CREDENTIAL_FIELD_RE = re.compile(
    r"""(?:smb_password|client_secret|"""
    r"""xmpp_password|recorder_password|db_password|"""
    r"""smtp_password|ldap_password|ftp_password)"""
    r"""["']?\s*[=:]\s*["'](?!test[-_]only)(?!$)([^"'\n]+)["']""",
    re.IGNORECASE,
)

# Root of the project
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Directories to scan (source + tests, skip venv / .git / __pycache__)
_SCAN_DIRS = ["apps", "routes", "tests", "core", "clients"]


def _scan_file_for_secrets(filepath):
    """Return list of (line_number, matched_text) for credential-like values."""
    hits = []
    with open(filepath, encoding="utf-8", errors="ignore") as f:
        for lineno, line in enumerate(f, 1):
            for m in _CREDENTIAL_FIELD_RE.finditer(line):
                hits.append((lineno, m.group(0).strip()))
    return hits


class TestNoHardcodedSecrets:
    """Scan Python source files for credential-like values that would trigger
    GitGuardian.  This runs as part of the normal test suite so secrets are
    caught locally before they reach a PR."""

    def test_no_secrets_in_source(self):
        violations = []
        for scan_dir in _SCAN_DIRS:
            dirpath = os.path.join(_PROJECT_ROOT, scan_dir)
            if not os.path.isdir(dirpath):
                continue
            for root, _dirs, files in os.walk(dirpath):
                for fname in files:
                    if not fname.endswith(".py"):
                        continue
                    fpath = os.path.join(root, fname)
                    hits = _scan_file_for_secrets(fpath)
                    for lineno, text in hits:
                        relpath = os.path.relpath(fpath, _PROJECT_ROOT)
                        violations.append(f"  {relpath}:{lineno}  {text}")

        assert not violations, (
            "Hardcoded credential-like values detected (would trigger GitGuardian).\n"
            "Use 'test-only-...' prefixed values for test data, or read from env vars.\n"
            + "\n".join(violations)
        )


class TestLocalBypassNotice:
    def test_notice_shown_when_setting_absent(self, app, auth_client):
        """Warning banner appears when local_bypass_enabled has never been saved."""
        with app.app_context():
            existing = Setting.query.filter_by(key="local_bypass_enabled").first()
            if existing:
                db.session.delete(existing)
                db.session.commit()

        resp = auth_client.get("/security/")
        assert resp.status_code == 200
        assert b"Default changed" in resp.data

    def test_notice_hidden_when_setting_present(self, app, auth_client):
        """Warning banner is absent once the setting has been explicitly saved."""
        with app.app_context():
            Setting.set("local_bypass_enabled", "false")

        resp = auth_client.get("/security/")
        assert resp.status_code == 200
        assert b"Default changed" not in resp.data

    def test_dismiss_notice_sets_setting(self, app, auth_client):
        """POSTing to dismiss endpoint explicitly saves the setting."""
        with app.app_context():
            existing = Setting.query.filter_by(key="local_bypass_enabled").first()
            if existing:
                db.session.delete(existing)
                db.session.commit()

        resp = auth_client.post(
            "/security/access/dismiss-bypass-notice",
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            assert Setting.query.filter_by(key="local_bypass_enabled").first() is not None
