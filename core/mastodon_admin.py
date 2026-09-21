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
from dataclasses import dataclass
from datetime import datetime, timezone
from html import unescape

from core.errors import describe_exception

logger = logging.getLogger(__name__)

# Hard cap on Link-header pagination so a misbehaving instance can't keep us
# fetching forever. 100 items/page -> at most 500 rows per listing.
_MAX_PAGES = 5
_PAGE_SIZE = 100
_TIMEOUT = 30
# Cloudflare (and similar) block Python's default "Python-urllib/x.y" agent with a
# bare 403 (error code 1010) before the request ever reaches Mastodon. Send the
# same identifier the rest of the app uses for outbound HTTP.
_USER_AGENT = "mstdnca-proxmox-tool"

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

    def __init__(self, message, http_status=None, retry_after=None):
        super().__init__(message)
        self.message = message
        self.http_status = http_status
        self.retry_after = retry_after


@dataclass
class RateLimitState:
    """Last-seen ``X-RateLimit-*`` headers from a Mastodon Admin API response."""

    limit: int | None
    remaining: int | None
    reset_at: datetime | None
    observed_at: datetime


def parse_iso(value):
    """Parse an ISO 8601 timestamp (optionally ``Z``-suffixed) into an aware datetime, or ``None``."""
    if not value or not isinstance(value, str):
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _parse_rate_limit_headers(headers):
    """Build a :class:`RateLimitState` from response headers. Never raises."""
    def _int(name):
        raw = headers.get(name)
        if raw is None:
            return None
        try:
            return int(str(raw).strip())
        except (TypeError, ValueError):
            return None

    limit = _int("X-RateLimit-Limit")
    remaining = _int("X-RateLimit-Remaining")
    reset_at = parse_iso(headers.get("X-RateLimit-Reset"))
    return RateLimitState(limit=limit, remaining=remaining, reset_at=reset_at, observed_at=datetime.now(timezone.utc))


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


class _MastodonClientBase:
    """Transport plumbing shared by every Mastodon Admin API client: auth headers,
    JSON (de)serialisation, same-origin pagination and rate-limit bookkeeping.
    """

    def __init__(self, api_url, token):
        self.api_url = api_url.rstrip("/")
        self._token = token
        self.rate_limit = None

    # ------------------------------------------------------------------ transport

    def _request(self, method, path, params=None, body=None, headers=None):
        """Perform one HTTP request. Returns ``(decoded_json, response_headers)``.

        ``path`` may be a full URL on the same origin (used when following a
        pagination ``Link`` header); anything on a different origin is refused.
        ``headers`` are extra request headers merged in on top of the defaults.
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
        req.add_header("User-Agent", _USER_AGENT)
        if body is not None:
            data = json.dumps(body).encode()
            req.add_header("Content-Type", "application/json")
        for name, value in (headers or {}).items():
            req.add_header(name, value)

        try:
            with urllib.request.urlopen(req, data=data, timeout=_TIMEOUT) as resp:  # noqa: S310
                raw = resp.read()
                resp_headers = resp.headers
        except urllib.error.HTTPError as exc:
            self.rate_limit = _parse_rate_limit_headers(exc.headers or {})
            retry_after = None
            if exc.code == 429:
                header_retry = (exc.headers or {}).get("Retry-After")
                if header_retry is not None:
                    try:
                        retry_after = max(0, int(str(header_retry).strip()))
                    except (TypeError, ValueError):
                        retry_after = None
                if retry_after is None:
                    retry_after = self.retry_after()
            raise MastodonAPIError(_describe_http_error(exc), exc.code, retry_after=retry_after) from exc
        except Exception as exc:  # URLError, socket timeout, ...
            logger.warning("Mastodon Admin API %s %s failed: %s", method, path, exc)
            raise MastodonAPIError(f"Mastodon API request failed: {describe_exception(exc)}") from exc

        self.rate_limit = _parse_rate_limit_headers(resp_headers or {})

        if not raw or not raw.strip():
            return {}, resp_headers
        try:
            return json.loads(raw.decode()), resp_headers
        except (ValueError, UnicodeDecodeError) as exc:
            raise MastodonAPIError("Mastodon API returned a non-JSON response") from exc

    def _iter_pages(self, path, params=None, max_pages=_MAX_PAGES):
        """GET a paginated list endpoint, yielding one list of raw items per page.

        Follows same-origin ``Link: rel=next`` headers, up to ``max_pages``.
        """
        params = dict(params or {})
        params.setdefault("limit", _PAGE_SIZE)
        next_url = path
        for page in range(max_pages):
            data, headers = self._request("GET", next_url, params=params if page == 0 else None)
            if not isinstance(data, list):
                raise MastodonAPIError("Mastodon API returned an unexpected payload for a list endpoint")
            yield data
            match = _LINK_NEXT_RE.search(headers.get("Link", "") or "")
            if not match or not data:
                break
            next_url = match.group(1)
        else:
            logger.warning("Mastodon API listing %s hit the %d-page cap; results truncated", path, max_pages)

    def _get_all(self, path, params=None, max_pages=_MAX_PAGES):
        """GET a paginated list endpoint, following same-origin ``Link: rel=next``."""
        items = []
        for page in self._iter_pages(path, params=params, max_pages=max_pages):
            items.extend(page)
        return items

    # ------------------------------------------------------------------ rate limiting

    def budget_ok(self, reserve):
        """True unless we know (from the last response) that fewer than ``reserve`` calls remain."""
        state = self.rate_limit
        if not state or state.remaining is None:
            return True
        return state.remaining >= reserve

    def retry_after(self):
        """Seconds (int, >= 0) until the current rate-limit window resets, or ``None`` if unknown."""
        state = self.rate_limit
        if not state or not state.reset_at:
            return None
        now = datetime.now(state.reset_at.tzinfo) if state.reset_at.tzinfo else datetime.now(timezone.utc)
        delta = (state.reset_at - now).total_seconds()
        return max(0, int(delta))


class MastodonAdminClient(_MastodonClientBase):
    """Minimal Admin API client. All methods raise :class:`MastodonAPIError` on failure."""

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

    # ------------------------------------------------------------------ account activity / counts

    def list_local_accounts(self, newer_than=None, max_pages=2):
        """List active local accounts (newest first, per the Admin API's default order).

        ``newer_than`` (an aware ``datetime``), when given, drops accounts created at or
        before it and stops paging as soon as a page's oldest row reaches that cutoff, so a
        caller polling for "what's new since last time" doesn't walk the whole account list.
        """
        params = {"origin": "local", "status": "active", "limit": _PAGE_SIZE}
        out = []
        for page in self._iter_pages("/api/v2/admin/accounts", params=params, max_pages=max_pages):
            page_oldest = None
            for adm in page:
                if adm.get("domain"):
                    continue
                created = parse_iso(adm.get("created_at"))
                if newer_than is not None and created is not None:
                    if page_oldest is None or created < page_oldest:
                        page_oldest = created
                    if created <= newer_than:
                        continue
                out.append(summarize_account_activity(adm))
            if newer_than is not None and page_oldest is not None and page_oldest <= newer_than:
                break
        return out

    def account_statuses(self, account_id, since_id=None, limit=40):
        """List an account's recent public statuses (newest first).

        Uses the regular (non-admin) statuses endpoint, so only statuses visible to the
        token's own account are returned -- private/followers-only posts from accounts it
        doesn't follow will not show up here.
        """
        params = {"since_id": since_id, "limit": limit, "exclude_reblogs": "true"}
        data, _ = self._request("GET", f"/api/v1/accounts/{int(account_id)}/statuses", params=params)
        if not isinstance(data, list):
            raise MastodonAPIError("Mastodon API returned an unexpected payload for a list endpoint")
        return [summarize_status(s) for s in data]

    def count_hint(self, path, params=None):
        """Return ``(count, has_next)`` from a single page -- a cheap size estimate for a
        badge count that avoids walking every page of a listing.
        """
        params = dict(params or {})
        params.setdefault("limit", 100)
        data, headers = self._request("GET", path, params=params)
        if not isinstance(data, list):
            raise MastodonAPIError("Mastodon API returned an unexpected payload for a list endpoint")
        has_next = bool(_LINK_NEXT_RE.search(headers.get("Link", "") or ""))
        return len(data), has_next

    def open_report_count(self):
        return self.count_hint("/api/v1/admin/reports", params={"resolved": "false"})

    def pending_account_count(self):
        return self.count_hint("/api/v2/admin/accounts", params={"status": "pending"})


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


def summarize_status(st):
    """Reduce a ``Status`` entity (as embedded in a report or listed for an account)."""
    st = st or {}
    sid = st.get("id")
    account = st.get("account") if isinstance(st.get("account"), dict) else None
    return {
        "id": str(sid) if sid is not None else None,
        "url": st.get("url") or st.get("uri", ""),
        "created_at": st.get("created_at", ""),
        "excerpt": strip_html(st.get("content", ""))[:_STATUS_EXCERPT_LEN],
        "sensitive": bool(st.get("sensitive")),
        "media_count": len(st.get("media_attachments") or []),
        "visibility": st.get("visibility", ""),
        "account_acct": account.get("acct") if account else None,
    }


def summarize_account_activity(adm):
    """Reduce an ``Admin::Account`` entity to an activity summary, deliberately leaving
    out anything that isn't needed to spot new/active local accounts: no ``ips``, ``ip``
    or ``email``.
    """
    adm = adm or {}
    account = adm.get("account") or {}
    role = adm.get("role") or {}
    last_login_at = None
    dated = []
    for ip in adm.get("ips") or []:
        if not isinstance(ip, dict):
            continue
        parsed = parse_iso(ip.get("used_at"))
        if parsed is not None:
            dated.append((parsed, ip.get("used_at")))
    if dated:
        last_login_at = max(dated, key=lambda pair: pair[0])[1]
    aid = adm.get("id")
    if aid is None:
        aid = account.get("id")
    return {
        "id": str(aid) if aid is not None else None,
        "acct": account.get("acct") or adm.get("username", ""),
        "username": adm.get("username", ""),
        "display_name": account.get("display_name", ""),
        "url": account.get("url", ""),
        "domain": adm.get("domain"),
        "created_at": adm.get("created_at", ""),
        "statuses_count": account.get("statuses_count", 0),
        "last_status_at": account.get("last_status_at"),
        "last_login_at": last_login_at,
        "confirmed": bool(adm.get("confirmed")),
        "approved": bool(adm.get("approved")),
        "disabled": bool(adm.get("disabled")),
        "suspended": bool(adm.get("suspended")),
        "silenced": bool(adm.get("silenced")),
        "role": role.get("name", "") if isinstance(role, dict) else str(role or ""),
    }


def summarize_report(rep):
    """Reduce an ``Admin::Report`` entity to what the UI shows."""
    rep = rep or {}
    statuses = [summarize_status(st) for st in rep.get("statuses") or []]
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
    """Build a user-safe message from an HTTPError: status plus the API's own ``error`` field.

    When the body is not JSON the answer almost certainly came from something in
    front of Mastodon (a CDN or firewall page such as Cloudflare's "error code:
    1010"), so say that instead of blaming the token, and keep a short printable
    snippet of the body to make the cause recognisable.
    """
    detail = ""
    raw = b""
    try:
        raw = exc.read() or b""
        payload = json.loads(raw.decode())
        if isinstance(payload, dict):
            detail = str(payload.get("error") or payload.get("error_description") or "")[:200]
    except Exception:  # noqa: S110 -- non-JSON body handled below
        pass
    if not detail and raw and not _looks_like_json(raw):
        snippet = " ".join(_TAG_RE.sub(" ", raw[:400].decode("utf-8", "replace")).split())[:80]
        detail = f"non-JSON reply, probably from a proxy or firewall in front of Mastodon: {snippet!r}"
    hint = {
        401: "token rejected",
        403: "forbidden (token scope, account role, or an upstream firewall)",
        404: "not found",
        422: "request rejected",
        429: "rate limited by Mastodon; try again shortly",
    }.get(exc.code, "")
    parts = [f"Mastodon API returned HTTP {exc.code}"]
    if hint:
        parts.append(hint)
    if detail:
        parts.append(detail)
    return ": ".join([parts[0], " - ".join(parts[1:])]) if len(parts) > 1 else parts[0]


def _looks_like_json(raw):
    try:
        json.loads(raw.decode())
        return True
    except Exception:
        return False
