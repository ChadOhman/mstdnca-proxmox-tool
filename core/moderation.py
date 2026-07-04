"""Moderation business logic: cross-check PeerTube users against Mastodon emails."""

import base64
import json
import logging
import urllib.error
import urllib.request
from datetime import datetime, timezone

from apps.utils import _validate_shell_param

logger = logging.getLogger(__name__)

# Hard cap on PeerTube pagination pages to avoid an unbounded loop if the API
# ever returns a bad ``total`` or a non-shrinking page (100 users/page → 100k).
_MAX_PEERTUBE_PAGES = 1000


def _build_mastodon_email_query_cmd(db_name, query):
    """Build a shell-safe command that runs ``query`` against ``db_name`` via psql.

    ``db_name`` must be validated with ``_validate_shell_param`` by the caller so
    it is safe to interpolate as the ``-d`` argument. The SQL statement itself is
    never interpolated into a nested-quoted ``-c`` argument (which reintroduces
    the command-injection class hardened out of ``apps/peertube.py``). Instead we
    base64-encode the query and pipe it to ``psql`` on *stdin* via ``su - postgres``
    — the postgres-access idiom used in ``apps/peertube.py`` and ``apps/mastodon.py``.
    The base64 blob is shell-safe (``[A-Za-z0-9+/=]``) and psql reads clean SQL
    bytes from stdin, so no shell metacharacter in the query can break out.
    """
    query_b64 = base64.b64encode(query.encode("utf-8")).decode("ascii")
    return (
        f"printf '%s' '{query_b64}' | base64 -d"
        f" | su - postgres -c 'psql -d {db_name} -t -A -v ON_ERROR_STOP=1 -f -'"
    )


def fetch_mastodon_emails():
    """Fetch confirmed, active email addresses from the Mastodon PostgreSQL database via SSH.

    Returns (set_of_emails, None) on success or (None, error_message) on failure.
    """
    from models import Guest, Setting

    db_guest_id = Setting.get("mastodon_db_guest_id", "")
    if not db_guest_id:
        return None, "Mastodon DB guest not configured (mastodon_db_guest_id)"

    db_guest = Guest.query.get(int(db_guest_id))
    if not db_guest:
        return None, f"Mastodon DB guest (id={db_guest_id}) not found"
    if not db_guest.ip_address:
        return None, f"Mastodon DB guest '{db_guest.name}' has no IP address"

    credential = db_guest.credential
    if not credential:
        return None, f"Mastodon DB guest '{db_guest.name}' has no SSH credential"

    db_name = Setting.get("mastodon_db_name", "mastodon_production")

    # Validate the database name before it reaches a shell context. This rejects
    # any value carrying shell metacharacters (e.g. `x"; rm -rf / #`) outright.
    try:
        _validate_shell_param(db_name, "Database name")
    except ValueError as exc:
        return None, str(exc)

    query = (
        "SELECT email FROM users "  # noqa: S608 — static SQL, no interpolation
        "WHERE confirmed_at IS NOT NULL "
        "AND disabled = false "
        "AND suspended_at IS NULL"
    )
    cmd = _build_mastodon_email_query_cmd(db_name, query)

    try:
        from clients.ssh_client import SSHClient
        with SSHClient.from_credential(db_guest.ip_address, credential) as ssh:
            stdout, stderr, code = ssh.execute_sudo(cmd, timeout=30)
            if code != 0:
                return None, f"psql query failed (exit {code}): {stderr.strip()}"
            emails = {line.strip().lower() for line in stdout.strip().split("\n") if line.strip()}
            return emails, None
    except Exception as exc:
        return None, f"SSH error querying Mastodon DB: {exc}"


def fetch_peertube_users(api_url, api_token):
    """Fetch all users from PeerTube via REST API (paginated).

    Returns (list_of_user_dicts, None) on success or (None, error_message) on failure.
    Each dict has keys: id, username, email, role (int).
    """
    users = []
    start = 0
    count = 100
    api_url = api_url.rstrip("/")

    for _page in range(_MAX_PEERTUBE_PAGES):
        url = f"{api_url}/api/v1/users?start={start}&count={count}&sort=createdAt"
        req = urllib.request.Request(url)
        req.add_header("Authorization", f"Bearer {api_token}")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
                data = json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            return None, f"PeerTube API error: HTTP {exc.code} - {exc.reason}"
        except Exception as exc:
            return None, f"PeerTube API error: {exc}"

        page_data = data.get("data", [])
        for u in page_data:
            role_obj = u.get("role", {})
            role_id = role_obj.get("id", 2) if isinstance(role_obj, dict) else int(role_obj)
            users.append({
                "id": u["id"],
                "username": u.get("username", ""),
                "email": u.get("email", "").lower(),
                "role": role_id,
            })

        total = data.get("total", 0)
        start += count
        if start >= total or not page_data:
            break
    else:
        logger.warning(
            "PeerTube pagination hit the %d-page cap; results may be truncated",
            _MAX_PEERTUBE_PAGES,
        )

    return users, None


def ban_peertube_user(api_url, api_token, user_id, reason=""):
    """Block a PeerTube user via REST API.

    Returns (True, None) on success or (False, error_message) on failure.
    """
    api_url = api_url.rstrip("/")
    # Coerce the user id to an int so it cannot carry path/query metacharacters
    # into the request URL, regardless of what the PeerTube API returned.
    try:
        user_id = int(user_id)
    except (TypeError, ValueError):
        return False, f"Invalid PeerTube user id: {user_id!r}"
    url = f"{api_url}/api/v1/users/{user_id}/block"
    body = json.dumps({"reason": reason}).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Authorization", f"Bearer {api_token}")
    req.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
            if resp.status in (200, 204):
                return True, None
            return False, f"Unexpected status {resp.status}"
    except urllib.error.HTTPError as exc:
        return False, f"HTTP {exc.code}: {exc.reason}"
    except Exception as exc:
        return False, str(exc)


def run_moderation_check(log_callback=None):
    """Run the full moderation check: compare PeerTube users against Mastodon emails.

    Args:
        log_callback: Optional callable(message) for real-time logging.

    Returns (success_bool, result_dict).
    """
    from auth.audit import log_action
    from models import Setting, db

    def log(msg):
        logger.info(msg)
        if log_callback:
            log_callback(msg)

    result = {
        "total_peertube_users": 0,
        "total_mastodon_emails": 0,
        "matched": 0,
        "unmatched": [],
        "skipped_admins": 0,
        "errors": [],
    }

    # Read settings
    api_url = Setting.get("moderation_peertube_api_url", "")
    api_token = Setting.get("moderation_peertube_api_token", "")
    auto_ban = Setting.get("moderation_auto_ban_enabled", "false") == "true"

    if not api_url or not api_token:
        msg = "PeerTube API URL or token not configured"
        log(f"ERROR: {msg}")
        result["errors"].append(msg)
        return False, result

    # Decrypt token
    from auth.credential_store import decrypt
    decrypted_token = decrypt(api_token)
    if not decrypted_token:
        msg = "Failed to decrypt PeerTube API token"
        log(f"ERROR: {msg}")
        result["errors"].append(msg)
        return False, result

    # Fetch Mastodon emails
    log("Fetching Mastodon user emails...")
    mastodon_emails, err = fetch_mastodon_emails()
    if err:
        log(f"ERROR: {err}")
        result["errors"].append(err)
        return False, result
    result["total_mastodon_emails"] = len(mastodon_emails)
    log(f"Found {len(mastodon_emails)} active Mastodon email(s)")

    # Fetch PeerTube users
    log("Fetching PeerTube users...")
    pt_users, err = fetch_peertube_users(api_url, decrypted_token)
    if err:
        log(f"ERROR: {err}")
        result["errors"].append(err)
        return False, result
    result["total_peertube_users"] = len(pt_users)
    log(f"Found {len(pt_users)} PeerTube user(s)")

    # Compare
    for user in pt_users:
        # Skip PeerTube admin users (role 0 = admin, 1 = moderator)
        if user["role"] == 0:
            result["skipped_admins"] += 1
            continue

        if user["email"] in mastodon_emails:
            result["matched"] += 1
        else:
            entry = {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "banned": False,
            }
            if auto_ban:
                # Log by username/id only — the job log is surfaced via /status,
                # so it must not carry email PII (H1).
                log(f"Banning PeerTube user '{user['username']}' (id={user['id']}) - not in Mastodon DB")
                ok, ban_err = ban_peertube_user(
                    api_url, decrypted_token, user["id"],
                    reason="Email not registered on Mastodon instance"
                )
                if ok:
                    entry["banned"] = True
                else:
                    log(f"  WARNING: Ban failed: {ban_err}")
                    result["errors"].append(f"Failed to ban {user['username']}: {ban_err}")
            else:
                log(f"Unmatched PeerTube user: '{user['username']}' (id={user['id']})")
            result["unmatched"].append(entry)

    log(f"Check complete: {result['matched']} matched, {len(result['unmatched'])} unmatched, "
        f"{result['skipped_admins']} admin(s) skipped")

    # Persist a PII-scrubbed summary only. The general Setting KV store has no
    # field-level access control and is exposed by the config export/import
    # feature, so raw emails must never be written to it. Emails stay in the
    # transient in-memory result returned to the caller (rendered live in the
    # admin view) but are dropped from the persisted copy.
    Setting.set("moderation_last_check_at", datetime.now(timezone.utc).isoformat())
    Setting.set("moderation_last_check_result", json.dumps(_scrub_result_for_storage(result)))
    log_action("moderation_check", "moderation", details={
        "matched": result["matched"],
        "unmatched": len(result["unmatched"]),
        "auto_ban": auto_ban,
    })
    db.session.commit()

    return True, result


def _scrub_result_for_storage(result):
    """Return a copy of the moderation result with email PII removed.

    Persisted to the general Setting store, so it must carry no raw email
    addresses. Keeps counts and non-PII per-user fields (id, username, banned).
    """
    scrubbed = dict(result)
    scrubbed["unmatched"] = [
        {"id": entry.get("id"), "username": entry.get("username"), "banned": entry.get("banned", False)}
        for entry in result.get("unmatched", [])
    ]
    return scrubbed
