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

import ipaddress
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
from core.url_safety import is_redirect, open_no_redirect

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
# Valid ``origin``/``status`` values for GET /api/v2/admin/accounts (search_accounts).
ACCOUNT_SEARCH_ORIGINS = ("local", "remote")
ACCOUNT_SEARCH_STATUSES = ("active", "pending", "suspended", "disabled", "silenced", "sensitized")

# Mastodon UserRole::Flags: bit 16 is invite_users, the only permission the default
# "everyone" role carries. Any other bit means the role is staff. Must match the
# deployed Mastodon's app/models/user_role.rb; a wrong bit fails safe (over-refusal).
_ROLE_INVITE_USERS_BIT = 1 << 16
_LEGACY_STAFF_ROLE_NAMES = frozenset({"admin", "owner", "moderator"})


def is_staff_role(role) -> bool:
    """Decide whether an admin account's ``role`` field marks it as staff.

    ``role`` can be the legacy plain-string role name (older Mastodon admin
    API responses / synthetic test data) or the modern ``UserRole`` object
    with ``name``/``permissions``. Falls back to a name check when
    ``permissions`` is absent or unparseable. Anything unrecognized returns
    False so we never refuse a target we can't positively identify as staff
    -- but the permission bit is chosen to fail safe (over-refusal) when it
    doesn't match reality.
    """
    if not role:
        return False
    if isinstance(role, str):
        return role.strip().lower() in _LEGACY_STAFF_ROLE_NAMES
    if isinstance(role, dict):
        permissions = role.get("permissions")
        if permissions is not None:
            try:
                perms = int(str(permissions))
            except (TypeError, ValueError):
                perms = None
            if perms is not None:
                return bool(perms & ~_ROLE_INVITE_USERS_BIT)
        name = str(role.get("name") or "").strip()
        return bool(name) and name.lower() not in ("", "user")
    return False

# RFC 1123-ish hostname: labels of alnum/hyphen joined by dots. Rejects
# anything with a scheme, path, port, whitespace or shell/URL metacharacters.
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$")
_TAG_RE = re.compile(r"<[^>]+>")
_LINK_NEXT_RE = re.compile(r'<([^>]+)>;\s*rel="next"')

# Maximum characters of a reported status kept in the summary sent to the UI.
_STATUS_EXCERPT_LEN = 300

# Mastodon's default hard status-length cap, used until a live instance value
# is known (see ``_MastodonClientBase.max_status_chars``) and as the fallback
# when the instance doesn't tell us. The welcome bot and report-notice DMs
# both post a single direct message, so this doubles as their default budget.
MAX_STATUS_CHARS = 500
# Sane bounds ``max_status_chars`` clamps a live instance's answer to, so a
# misbehaving or misconfigured instance can't hand us a budget of 0 (every
# template fails) or something absurd (no protection against a giant DM).
MIN_STATUS_CHARS = 100
MAX_STATUS_CHARS_CEILING = 25000
# Template variables ``render_welcome``/``validate_welcome_template`` accept.
WELCOME_TEMPLATE_VARS = ("username", "display_name", "acct")
DEFAULT_WELCOME_TEMPLATE = (
    "Welcome to the instance! Take a look at the local timeline to see what "
    "people are posting, and follow anyone who catches your eye -- you can "
    "also follow a hashtag to track a topic. Check out the About page for "
    "our house rules, and consider adding a bio and an avatar so people know "
    "you're a real person."
)
# Template variables ``render_report_notice``/``validate_report_notice_template`` accept.
REPORT_NOTICE_TEMPLATE_VARS = ("username", "display_name", "acct", "report_id")
DEFAULT_REPORT_NOTICE_TEMPLATE = (
    "Thanks for report #{report_id}. Moderators reviewed it and took the action "
    "they felt was appropriate. We don't share details of actions taken on other "
    "accounts, so please keep reporting anything that concerns you."
)


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


def _int_or_zero(value):
    """Coerce ``value`` to ``int``, defaulting to 0 for anything unparseable."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _extract_v2_max_chars(data):
    """Pull ``configuration.statuses.max_characters`` out of a v2 instance payload.

    Returns ``None`` (never raises) if the payload isn't shaped as expected.
    """
    if not isinstance(data, dict):
        return None
    configuration = data.get("configuration")
    if not isinstance(configuration, dict):
        return None
    statuses = configuration.get("statuses")
    if not isinstance(statuses, dict):
        return None
    try:
        return int(statuses.get("max_characters"))
    except (TypeError, ValueError):
        return None


def _extract_v1_max_chars(data):
    """Pull ``max_toot_chars`` out of a v1 instance payload. Returns ``None`` (never raises)."""
    if not isinstance(data, dict):
        return None
    try:
        return int(data.get("max_toot_chars"))
    except (TypeError, ValueError):
        return None


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
            # Never follow a redirect: the bearer token would go wherever the
            # 3xx points, including another host (GHSA-gj96-qjq5-q57h).
            with open_no_redirect(req, data=data, timeout=_TIMEOUT) as resp:
                raw = resp.read()
                resp_headers = resp.headers
        except urllib.error.HTTPError as exc:
            if is_redirect(exc):
                raise MastodonAPIError(
                    f"Mastodon API answered with a redirect (HTTP {exc.code}); not following it. "
                    "Check the configured API URL."
                ) from exc
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

    # ------------------------------------------------------------------ instance metadata

    def max_status_chars(self) -> int:
        """Ask the live instance how long a status may be, clamped to a sane range.

        Tries ``GET /api/v2/instance`` (``configuration.statuses.max_characters``)
        first; if that 404s or doesn't carry a usable number, falls back to
        ``GET /api/v1/instance`` (``max_toot_chars``). A bad or missing payload
        from either endpoint never raises -- it's treated the same as "this
        instance didn't tell us" and yields :data:`MAX_STATUS_CHARS`. This only
        raises :class:`MastodonAPIError` when *both* requests fail for a reason
        other than 404, so callers can still tell a genuine connectivity/auth
        problem apart from an instance that simply doesn't expose the field.
        """
        value = None
        v2_error = None
        try:
            data, _ = self._request("GET", "/api/v2/instance")
            value = _extract_v2_max_chars(data)
        except MastodonAPIError as exc:
            v2_error = exc

        if value is None:
            v1_error = None
            try:
                data, _ = self._request("GET", "/api/v1/instance")
                value = _extract_v1_max_chars(data)
            except MastodonAPIError as exc:
                v1_error = exc

            if value is None:
                v2_hard_fail = v2_error is not None and v2_error.http_status != 404
                v1_hard_fail = v1_error is not None and v1_error.http_status != 404
                if v2_hard_fail and v1_hard_fail:
                    raise v1_error
                return MAX_STATUS_CHARS

        return max(MIN_STATUS_CHARS, min(MAX_STATUS_CHARS_CEILING, value))

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
            "id": me.get("id"),
            "acct": me.get("acct", ""),
            "display_name": me.get("display_name", ""),
            "role": role.get("name", "") if isinstance(role, dict) else "",
            "url": me.get("url", ""),
        }

    # ------------------------------------------------------------------ reports

    def list_reports(self, resolved=False, *, target_account_id=None, account_id=None, max_pages=_MAX_PAGES):
        """List reports, optionally filtered to a target account and/or a reporting account.

        ``target_account_id`` filters to reports *about* that account,
        ``account_id`` to reports *filed by* that account; either (or both)
        may be given.
        """
        params = {"resolved": "true" if resolved else "false"}
        if target_account_id is not None:
            params["target_account_id"] = str(int(target_account_id))
        if account_id is not None:
            params["account_id"] = str(int(account_id))
        raw = self._get_all("/api/v1/admin/reports", params=params, max_pages=max_pages)
        return [summarize_report(r) for r in raw]

    def reports_for_account(self, account_id, *, as_target=True, resolved=None):
        """List reports about (``as_target=True``) or filed by (``as_target=False``) an account.

        When ``resolved`` is ``None`` (the default) both open and resolved
        reports are fetched -- one page each -- and concatenated with open
        reports first; otherwise a single call is made for that ``resolved``
        value.
        """
        filter_kwargs = {"target_account_id": account_id} if as_target else {"account_id": account_id}
        if resolved is None:
            open_reports = self.list_reports(resolved=False, max_pages=1, **filter_kwargs)
            resolved_reports = self.list_reports(resolved=True, max_pages=1, **filter_kwargs)
            return open_reports + resolved_reports
        return self.list_reports(resolved=resolved, **filter_kwargs)

    def get_report(self, report_id):
        """Fetch one report and reduce it with :func:`summarize_report`.

        ``target_account`` in the result carries ``is_staff``/``domain`` (from
        ``summarize_admin_account``) and ``statuses`` carries ``id``/``url``/
        ``excerpt`` (from ``summarize_status``) -- everything the status-action
        UI needs to let a moderator pick which reported posts to act on.
        """
        data, _ = self._request("GET", f"/api/v1/admin/reports/{int(report_id)}")
        return summarize_report(data)

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

    def search_accounts(self, *, email=None, ip=None, username=None, display_name=None,
                        origin=None, status=None, limit=25):
        """Search admin accounts by any combination of filters.

        Mastodon matches ``email``, ``username`` and ``display_name`` as
        prefixes, and ``ip`` by CIDR containment. Only the filters actually
        given are sent; ``origin``/``status`` are validated locally against
        Mastodon's known values before the request is made.
        """
        if origin is not None and origin not in ACCOUNT_SEARCH_ORIGINS:
            raise ValueError(f"Unknown origin '{origin}'")
        if status is not None and status not in ACCOUNT_SEARCH_STATUSES:
            raise ValueError(f"Unknown status '{status}'")
        params = {}
        if email:
            params["email"] = email
        if ip:
            params["ip"] = ip
        if username:
            params["username"] = username
        if display_name:
            params["display_name"] = display_name
        if origin:
            params["origin"] = origin
        if status:
            params["status"] = status
        params["limit"] = str(max(1, min(100, int(limit))))
        raw = self._get_all("/api/v2/admin/accounts", params=params, max_pages=1)
        return [summarize_admin_account(a) for a in raw]

    def accounts_sharing_ip(self, ip, *, exclude_id=None, limit=10):
        """Find other admin accounts that have logged in from ``ip`` (or a CIDR containing it)."""
        try:
            ipaddress.ip_network(ip, strict=False)
        except ValueError as exc:
            raise ValueError("invalid IP or CIDR") from exc
        results = self.search_accounts(ip=ip, limit=limit + 1)
        if exclude_id is not None:
            exclude_id = str(exclude_id)
            results = [a for a in results if str(a.get("id")) != exclude_id]
        return results[:limit]

    def delete_account(self, account_id):
        """Permanently delete an account.

        Mastodon reserves the deleted account's username and email so
        neither can be reused; the API does not check whether the account is
        suspended first, so callers must enforce that themselves before
        calling this.
        """
        self._request("DELETE", f"/api/v1/admin/accounts/{int(account_id)}")
        return True

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


class MastodonBotClient(_MastodonClientBase):
    """Minimal client for the welcome-bot account: verify identity, post a direct message.

    Uses a separate (non-admin) user token -- the bot posts as itself, it does
    not act on other accounts -- so this is kept apart from
    :class:`MastodonAdminClient` even though it shares the same transport.
    """

    def verify(self):
        """Check the bot token works. Returns a small summary dict."""
        me, _ = self._request("GET", "/api/v1/accounts/verify_credentials")
        return {
            "id": me.get("id"),
            "acct": me.get("acct", ""),
            "display_name": me.get("display_name", ""),
            "bot": bool(me.get("bot")),
        }

    def post_direct(self, text, idempotency_key):
        """Post ``text`` as a direct-visibility status. Returns a status summary."""
        data, _ = self._request(
            "POST",
            "/api/v1/statuses",
            body={"status": text, "visibility": "direct"},
            headers={"Idempotency-Key": idempotency_key},
        )
        return summarize_status(data)


class _SafeDict(dict):
    """A ``dict`` for ``str.format_map`` that leaves unknown ``{key}`` placeholders literal
    instead of raising ``KeyError``.
    """

    def __missing__(self, key):
        return "{" + key + "}"


def render_body(template, variables):
    """Render ``template`` against ``variables``, leaving unknown ``{key}`` placeholders literal.

    Shared by every templated-DM feature (welcome messages, report notices):
    just the ``str.format_map`` + strip, with no ``@mention`` prefix or
    length enforcement -- see :func:`compose_direct` for that.
    """
    return template.format_map(_SafeDict(variables)).strip()


def _account_vars(account):
    """Extract the ``{username, display_name, acct}`` template vars from an account dict.

    ``account`` is one of the account dicts carried by
    ``moderation_watch._discover_new_accounts`` (or a report's reporter
    account): has ``username`` and, usually, ``display_name``/``acct``.
    Both fall back to ``username`` when absent or empty.
    """
    username = account["username"]
    display_name = account.get("display_name") or username
    acct = account.get("acct") or username
    return {"username": username, "display_name": display_name, "acct": acct}


def compose_direct(mention, body, *, label, max_chars=MAX_STATUS_CHARS):
    """Prefix ``body`` with ``@mention`` and enforce the status-length budget.

    Raises ``ValueError`` (message safe to show the user) if the composed
    text would exceed ``max_chars``.
    """
    text = f"@{mention} {body}"
    if len(text) > max_chars:
        raise ValueError(f"{label} would be {len(text)} characters; this instance allows {max_chars}")
    return text


def render_welcome(template, account, max_chars=MAX_STATUS_CHARS):
    """Render a welcome-message template for ``account`` and prefix the mention.

    Raises ``ValueError`` if the rendered message would exceed the status
    length budget (``max_chars``, the live instance's limit when known --
    see ``moderation_watch.get_status_limit`` -- else Mastodon's default).
    """
    variables = _account_vars(account)
    body = render_body(template, variables)
    return compose_direct(variables["username"], body, label="Welcome message", max_chars=max_chars)


def validate_welcome_template(template, max_chars=MAX_STATUS_CHARS):
    """Return an error message for a bad welcome template, or ``None`` if it's usable.

    Renders against a worst-case sample account (30-char username/display
    name) so a template that only goes over budget for long names is still
    caught before it's saved.
    """
    sample = {
        "username": "a" * 30,
        "display_name": "a" * 30,
        "acct": "a" * 30,
    }
    return _validate_mention_template(
        template,
        lambda t: render_welcome(t, sample, max_chars=max_chars),
        empty_msg="Welcome message template cannot be empty",
        placeholder_msg=(
            "Welcome message template has an invalid placeholder "
            "(only {username}, {display_name} and {acct} are supported)"
        ),
    )


def render_report_notice_body(template, account, report_id):
    """Render a report-notice template for ``account``/``report_id``. No ``@mention`` prefix.

    ``account`` is the reporter's account dict (has ``username`` and,
    usually, ``display_name``/``acct``); ``report_id`` is substituted as-is
    (stringified).
    """
    variables = _account_vars(account)
    variables["report_id"] = str(report_id)
    return render_body(template, variables)


def report_notice_mention(account):
    """The ``@``-mention a report notice should be addressed to (the reporter's ``acct``).

    Using ``acct`` rather than ``username`` matters here: the reporter may be
    on a different instance, and only ``acct`` (``user@domain``) reaches them.
    """
    return "@" + (account.get("acct") or account.get("username") or "")


def render_report_notice(template, account, report_id, max_chars=MAX_STATUS_CHARS):
    """Render a full report-notice DM (``@mention`` + body), enforcing the status-length budget.

    Mentions ``account["acct"]`` directly (not the ``username``-falls-back-to
    logic ``_account_vars`` applies to the body) so a remote reporter is
    actually reachable -- mentioning by local ``username`` alone would resolve
    to the wrong (or no) account off-instance.
    """
    body = render_report_notice_body(template, account, report_id)
    return compose_direct(account["acct"], body, label="Report notice", max_chars=max_chars)


def _validate_mention_template(template, render, *, placeholder_msg, empty_msg="Template cannot be empty"):
    """Shared validation plumbing for ``validate_welcome_template``/``validate_report_notice_template``.

    ``render(template)`` is called against a worst-case sample; its
    ``ValueError`` (over budget) is passed through as the error text, an
    unresolvable placeholder (``KeyError``/``IndexError``, e.g. a positional
    ``{0}``) is reported as ``placeholder_msg``, and anything else means the
    template is fine (``None``).
    """
    if not template or not template.strip():
        return empty_msg
    try:
        render(template)
    except ValueError as exc:
        return str(exc)
    except (KeyError, IndexError):
        return placeholder_msg
    return None


def validate_report_notice_template(template, max_chars=MAX_STATUS_CHARS):
    """Return an error message for a bad report-notice template, or ``None`` if it's usable.

    Renders against a worst-case sample: 30-char username/display name, a
    71-char ``acct`` (so a long remote handle is accounted for), and a
    20-digit report id.
    """
    sample = {
        "username": "a" * 30,
        "display_name": "a" * 30,
        "acct": ("a" * 30) + "@" + ("b" * 40),
    }
    report_id = "1" * 20
    return _validate_mention_template(
        template,
        lambda t: render_report_notice(t, sample, report_id, max_chars=max_chars),
        empty_msg="Report notice template cannot be empty",
        placeholder_msg=(
            "Report notice template has an invalid placeholder "
            "(only {username}, {display_name}, {acct} and {report_id} are supported)"
        ),
    )


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
    role_name = role.get("name", "") if isinstance(role, dict) else str(role or "")
    account = adm.get("account") or {}
    out = _account_public(account)

    ips = []
    for ip in adm.get("ips") or []:
        if not isinstance(ip, dict):
            continue
        ips.append({"ip": ip.get("ip", ""), "used_at": ip.get("used_at")})
    ips.sort(key=lambda row: parse_iso(row["used_at"]) or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    ips = ips[:10]

    fields = []
    for f in account.get("fields") or []:
        if not isinstance(f, dict):
            continue
        fields.append({"name": strip_html(f.get("name", "")), "value": strip_html(f.get("value", ""))})
        if len(fields) >= 8:
            break

    out.update({
        "id": adm.get("id") or out["id"],
        "username": adm.get("username", ""),
        "domain": adm.get("domain"),
        "email": adm.get("email", ""),
        "ip": adm.get("ip", ""),
        "ips": ips,
        "locale": adm.get("locale", ""),
        "created_at": adm.get("created_at", ""),
        "confirmed": bool(adm.get("confirmed")),
        "approved": bool(adm.get("approved")),
        "disabled": bool(adm.get("disabled")),
        "silenced": bool(adm.get("silenced")),
        "suspended": bool(adm.get("suspended")),
        "sensitized": bool(adm.get("sensitized")),
        "role": role_name,
        "role_name": role_name,
        "is_staff": is_staff_role(role),
        "invite_request": adm.get("invite_request") or "",
        "followers_count": _int_or_zero(account.get("followers_count")),
        "following_count": _int_or_zero(account.get("following_count")),
        "statuses_count": _int_or_zero(account.get("statuses_count")),
        "last_status_at": account.get("last_status_at"),
        "note": strip_html(account.get("note", ""))[:500],
        "fields": fields,
        "bot": bool(account.get("bot")),
        "locked": bool(account.get("locked")),
        "header": account.get("header_static") or account.get("header") or "",
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
