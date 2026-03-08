"""Moderation business logic: cross-check PeerTube users against Mastodon emails."""

import json
import logging
import urllib.request
import urllib.error
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def fetch_mastodon_emails():
    """Fetch confirmed, active email addresses from the Mastodon PostgreSQL database via SSH.

    Returns (set_of_emails, None) on success or (None, error_message) on failure.
    """
    from models import Setting, Guest

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

    query = (
        "SELECT email FROM users "
        "WHERE confirmed_at IS NOT NULL "
        "AND disabled = false "
        "AND suspended_at IS NULL"
    )
    cmd = f"su - postgres -c \"psql -d {db_name} -t -A -c \\\"{query}\\\"\""

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

    while True:
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

    return users, None


def ban_peertube_user(api_url, api_token, user_id, reason=""):
    """Block a PeerTube user via REST API.

    Returns (True, None) on success or (False, error_message) on failure.
    """
    api_url = api_url.rstrip("/")
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
    from models import Setting, db
    from auth.audit import log_action

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
                log(f"Banning PeerTube user '{user['username']}' ({user['email']}) - not in Mastodon DB")
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
                log(f"Unmatched PeerTube user: '{user['username']}' ({user['email']})")
            result["unmatched"].append(entry)

    log(f"Check complete: {result['matched']} matched, {len(result['unmatched'])} unmatched, "
        f"{result['skipped_admins']} admin(s) skipped")

    # Store results
    Setting.set("moderation_last_check_at", datetime.now(timezone.utc).isoformat())
    Setting.set("moderation_last_check_result", json.dumps(result))
    log_action("moderation_check", "moderation", details={
        "matched": result["matched"],
        "unmatched": len(result["unmatched"]),
        "auto_ban": auto_ban,
    })
    db.session.commit()

    return True, result
