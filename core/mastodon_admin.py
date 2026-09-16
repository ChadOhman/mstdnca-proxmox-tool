"""Thin client for the Mastodon Admin REST API used by the Moderation tab.

Talks to ``/api/v1/admin/*`` (and ``/api/v2/admin/accounts``) with an
admin-scoped bearer token. Mirrors the PeerTube client in ``core.moderation``:
plain ``urllib``, no third-party HTTP dependency, and every failure is
surfaced as :class:`MastodonAPIError` carrying a message that is safe to hand
back to the browser (the upstream API's own ``error`` text plus the HTTP
status, or a type-derived description for transport failures -- never raw
exception text).

The token needs the ``read:accounts``, ``admin:read`` and ``admin:write``
scopes. Create it from an application under *Preferences -> Development* on
the Mastodon instance while logged in as an admin.
"""

import json
import logging
import re
import urllib.error
import urllib.parse
import urllib.request
from html import unescape

from core.errors import describe_exception

logger = logging.getLogger(__name__)

# Hard cap on Link-header pagination so a misbehaving instance can't keep us
# fetching forever. 100 items/page -> at most 500 rows per listing.
_MAX_PAGES = 5
_PAGE_SIZE = 100
_TIMEOUT = 30

# Valid ``type`` values for POST /api/v1/admin/accounts/:id/action.
ACCOUNT_ACTION_TYPES = ("none", "disable", "silence", "suspend", "sensitive")
# Endpoints that lift a previously applied action (POST /admin/accounts/:id/<lift>).
ACCOUNT_LIFT_ACTIONS = ("enable", "unsilence", "unsuspend", "unsensitive")
# Valid ``severity`` values for domain blocks.
DOMAIN_BLOCK_SEVERITIES = ("silence", "suspend", "noop")

# RFC 1123-ish hostname: labels of alnum/hyphen joined by dots. Rejects
# anything with a scheme, path, port, whitespace or shell/URL metacharacters.
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$")
_TAG_RE = re.compile(r"<[^>]+>")
_LINK_NEXT_RE = re.compile(r'<([^>]+)>;\s*rel="next"')

# Maximum characters of a reported status kept in the summary sent to the UI.
_STATUS_EXCERPT_LEN = 300


class MastodonAPIError(Exception):
    """An Admin API call failed. ``message`` is safe to show to the user."""

    def __init__(self, message, http_status=None):
        super().__init__(message)
        self.message = message
        self.http_status = http_status


def validate_domain(domain):
    """Return the normalised (lowercased, stripped) domain or raise ValueError."""
    domain = (domain or "").strip().lower().rstrip(".")
    if not _DOMAIN_RE.match(domain):
        raise ValueError("Enter a bare hostname such as example.social (no scheme, path or port)")
    return domain


def strip_html(text):
    """Collapse a Mastodon status body (HTML) to plain text."""
    if not text:
        return ""
    text = _TAG_RE.sub(" ", text)
    return " ".join(unescape(text).split())


class MastodonAdminClient:
    """Minimal Admin API client. All methods raise :class:`MastodonAPIError` on failure."""

    def __init__(self, api_url, token):
        self.api_url = api_url.rstrip("/")
        self._token = token

    # ------------------------------------------------------------------ transport

    def _request(self, method, path, params=None, body=None):
        """Perform one HTTP request. Returns ``(decoded_json, response_headers)``.

        ``path`` may be a full URL on the same origin (used when following a
        pagination ``Link`` header); anything on a different origin is refused.
        """
        if path.startswith("http://") or path.startswith("https://"):
            if not path.startswith(self.api_url + "/"):
                raise MastodonAPIError("Refusing to follow a pagination link to a different host")
            url = path
        else:
            url = f"{self.api_url}{path}"
        if params:
            query = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None and v != ""})
            url = f"{url}{'&' if '?' in url else '?'}{query}"

        data = None
        req = urllib.request.Request(url, method=method)
        req.add_header("Authorization", f"Bearer {self._token}")
        req.add_header("Accept", "application/json")
        if body is not None:
            data = json.dumps(body).encode()
            req.add_header("Content-Type", "application/json")

        try:
            with urllib.request.urlopen(req, data=data, timeout=_TIMEOUT) as resp:  # noqa: S310
                raw = resp.read()
                headers = resp.headers
        except urllib.error.HTTPError as exc:
            raise MastodonAPIError(_describe_http_error(exc), exc.code) from exc
        except Exception as exc:  # URLError, socket timeout, ...
            logger.warning("Mastodon Admin API %s %s failed: %s", method, path, exc)
            raise MastodonAPIError(f"Mastodon API request failed: {describe_exception(exc)}") from exc

        if not raw or not raw.strip():
            return {}, headers
        try:
            return json.loads(raw.decode()), headers
        except (ValueError, UnicodeDecodeError) as exc:
            raise MastodonAPIError("Mastodon API returned a non-JSON response") from exc

    def _get_all(self, path, params=None, max_pages=_MAX_PAGES):
        """GET a paginated list endpoint, following same-origin ``Link: rel=next``."""
        items = []
        params = dict(params or {})
        params.setdefault("limit", _PAGE_SIZE)
        next_url = path
        for page in range(max_pages):
            data, headers = self._request("GET", next_url, params=params if page == 0 else None)
            if not isinstance(data, list):
                raise MastodonAPIError("Mastodon API returned an unexpected payload for a list endpoint")
            items.extend(data)
            match = _LINK_NEXT_RE.search(headers.get("Link", "") or "")
            if not match or not data:
                break
            next_url = match.group(1)
        else:
            logger.warning("Mastodon API listing %s hit the %d-page cap; results truncated", path, max_pages)
        return items

    # ------------------------------------------------------------------ connection

    def verify(self):
        """Check the token works and carries admin scope. Returns a small summary dict."""
        me, _ = self._request("GET", "/api/v1/accounts/verify_credentials")
        # Any admin:read endpoint will do as a scope probe.
        self._request("GET", "/api/v1/admin/reports", params={"limit": 1})
        role = me.get("role") or {}
        return {
            "acct": me.get("acct", ""),
            "display_name": me.get("display_name", ""),
            "role": role.get("name", "") if isinstance(role, dict) else "",
        }

    # ------------------------------------------------------------------ reports

    def list_reports(self, resolved=False):
        raw = self._get_all("/api/v1/admin/reports", params={"resolved": "true" if resolved else "false"})
        return [summarize_report(r) for r in raw]

    def resolve_report(self, report_id):
        data, _ = self._request("POST", f"/api/v1/admin/reports/{int(report_id)}/resolve")
        return data

    def reopen_report(self, report_id):
        data, _ = self._request("POST", f"/api/v1/admin/reports/{int(report_id)}/reopen")
        return data

    # ------------------------------------------------------------------ accounts

    def list_pending_accounts(self):
        raw = self._get_all("/api/v2/admin/accounts", params={"status": "pending"})
        return [summarize_admin_account(a) for a in raw]

    def approve_account(self, account_id):
        data, _ = self._request("POST", f"/api/v1/admin/accounts/{int(account_id)}/approve")
        return data

    def reject_account(self, account_id):
        data, _ = self._request("POST", f"/api/v1/admin/accounts/{int(account_id)}/reject")
        return data

    def lookup_account(self, acct):
        """Resolve a handle (``user`` or ``user@domain``) to its admin view."""
        acct = (acct or "").strip().lstrip("@")
        if not acct:
            raise MastodonAPIError("Enter an account handle to look up")
        public, _ = self._request("GET", "/api/v1/accounts/lookup", params={"acct": acct})
        account_id = public.get("id")
        if not account_id:
            raise MastodonAPIError("Account not found")
        return self.get_admin_account(account_id)

    def get_admin_account(self, account_id):
        data, _ = self._request("GET", f"/api/v1/admin/accounts/{int(account_id)}")
        return summarize_admin_account(data)

    def account_action(self, account_id, action_type, text="", report_id=None, send_email_notification=False):
        if action_type not in ACCOUNT_ACTION_TYPES:
            raise MastodonAPIError(f"Unknown account action '{action_type}'")
        body = {
            "type": action_type,
            "text": text or "",
            "send_email_notification": bool(send_email_notification),
        }
        if report_id:
            body["report_id"] = str(int(report_id))
        data, _ = self._request("POST", f"/api/v1/admin/accounts/{int(account_id)}/action", body=body)
        return data

    def lift_account_action(self, account_id, lift):
        if lift not in ACCOUNT_LIFT_ACTIONS:
            raise MastodonAPIError(f"Unknown account action '{lift}'")
        data, _ = self._request("POST", f"/api/v1/admin/accounts/{int(account_id)}/{lift}")
        return summarize_admin_account(data) if isinstance(data, dict) and data.get("id") else data

    # ------------------------------------------------------------------ domain blocks

    def list_domain_blocks(self):
        raw = self._get_all("/api/v1/admin/domain_blocks")
        return [summarize_domain_block(b) for b in raw]

    def create_domain_block(self, domain, severity="silence", reject_media=False, reject_reports=False,
                            public_comment="", private_comment="", obfuscate=False):
        if severity not in DOMAIN_BLOCK_SEVERITIES:
            raise MastodonAPIError(f"Unknown domain block severity '{severity}'")
        body = {
            "domain": validate_domain(domain),
            "severity": severity,
            "reject_media": bool(reject_media),
            "reject_reports": bool(reject_reports),
            "public_comment": public_comment or "",
            "private_comment": private_comment or "",
            "obfuscate": bool(obfuscate),
        }
        data, _ = self._request("POST", "/api/v1/admin/domain_blocks", body=body)
        return summarize_domain_block(data)

    def delete_domain_block(self, block_id):
        data, _ = self._request("DELETE", f"/api/v1/admin/domain_blocks/{int(block_id)}")
        return data


# ---------------------------------------------------------------------- summaries
# The Admin API objects are large and carry more PII than the UI needs (IP
# history, invite codes, full status HTML). These reducers pick the fields the
# Moderation tab renders so the JSON handed to the browser stays small.

def _account_public(acc):
    """Fields from a public ``Account`` entity, tolerant of a missing/None input."""
    acc = acc or {}
    return {
        "id": acc.get("id"),
        "acct": acc.get("acct", ""),
        "display_name": acc.get("display_name", ""),
        "url": acc.get("url", ""),
        "avatar": acc.get("avatar_static") or acc.get("avatar", ""),
    }


def summarize_admin_account(adm):
    """Reduce an ``Admin::Account`` entity to what the UI shows."""
    adm = adm or {}
    role = adm.get("role") or {}
    out = _account_public(adm.get("account"))
    out.update({
        "id": adm.get("id") or out["id"],
        "username": adm.get("username", ""),
        "domain": adm.get("domain"),
        "email": adm.get("email", ""),
        "ip": adm.get("ip", ""),
        "locale": adm.get("locale", ""),
        "created_at": adm.get("created_at", ""),
        "confirmed": bool(adm.get("confirmed")),
        "approved": bool(adm.get("approved")),
        "disabled": bool(adm.get("disabled")),
        "silenced": bool(adm.get("silenced")),
        "suspended": bool(adm.get("suspended")),
        "sensitized": bool(adm.get("sensitized")),
        "role": role.get("name", "") if isinstance(role, dict) else str(role or ""),
        "invite_request": adm.get("invite_request") or "",
    })
    if not out["acct"]:
        out["acct"] = out["username"] + (f"@{out['domain']}" if out["domain"] else "")
    return out


def summarize_report(rep):
    """Reduce an ``Admin::Report`` entity to what the UI shows."""
    rep = rep or {}
    statuses = []
    for st in rep.get("statuses") or []:
        statuses.append({
            "id": st.get("id"),
            "url": st.get("url") or st.get("uri", ""),
            "created_at": st.get("created_at", ""),
            "excerpt": strip_html(st.get("content", ""))[:_STATUS_EXCERPT_LEN],
            "sensitive": bool(st.get("sensitive")),
            "media_count": len(st.get("media_attachments") or []),
        })
    return {
        "id": rep.get("id"),
        "category": rep.get("category", ""),
        "comment": rep.get("comment", "") or "",
        "forwarded": bool(rep.get("forwarded")),
        "action_taken": bool(rep.get("action_taken")),
        "created_at": rep.get("created_at", ""),
        "account": _account_public((rep.get("account") or {}).get("account") or rep.get("account")),
        "target_account": summarize_admin_account(rep.get("target_account")),
        "assigned_account": _account_public((rep.get("assigned_account") or {}).get("account"))
        if rep.get("assigned_account") else None,
        "statuses": statuses,
        "rules": [r.get("text", "") for r in rep.get("rules") or []],
    }


def summarize_domain_block(blk):
    blk = blk or {}
    return {
        "id": blk.get("id"),
        "domain": blk.get("domain", ""),
        "severity": blk.get("severity", ""),
        "reject_media": bool(blk.get("reject_media")),
        "reject_reports": bool(blk.get("reject_reports")),
        "obfuscate": bool(blk.get("obfuscate")),
        "public_comment": blk.get("public_comment") or "",
        "private_comment": blk.get("private_comment") or "",
        "created_at": blk.get("created_at", ""),
    }


def _describe_http_error(exc):
    """Build a user-safe message from an HTTPError: status plus the API's own ``error`` field."""
    detail = ""
    try:
        payload = json.loads(exc.read().decode())
        if isinstance(payload, dict):
            detail = str(payload.get("error") or payload.get("error_description") or "")
    except Exception:  # noqa: S110 -- body is optional, status alone is still useful
        pass
    hint = {
        401: "token rejected",
        403: "token lacks the required admin scope",
        404: "not found",
        422: "request rejected",
    }.get(exc.code, "")
    parts = [f"Mastodon API returned HTTP {exc.code}"]
    if hint:
        parts.append(hint)
    if detail:
        parts.append(detail[:200])
    return ": ".join([parts[0], " - ".join(parts[1:])]) if len(parts) > 1 else parts[0]
