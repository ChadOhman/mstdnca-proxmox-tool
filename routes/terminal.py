import io
import json
import logging
import queue as _queue
import re
import threading
import time as _time
from urllib.parse import urlsplit

import paramiko
from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required
from flask_sock import Sock

from auth.audit import log_action
from auth.credential_store import decrypt
from auth.session_manager import SESSION_KEY, _hash_session_id
from models import Credential, Guest, Tag, db

logger = logging.getLogger(__name__)

_IDLE_TIMEOUT = 1800  # 30 minutes — close idle SSH terminals automatically

# How long a server-observed sudo password prompt keeps a client "sudo" message
# honourable, plus a rate limit so the stored password cannot be sprayed into
# the shell (and into the follower catch-up buffer and ~/.bash_history).
_SUDO_PROMPT_WINDOW = 15   # seconds
_SUDO_RATE_WINDOW = 60     # seconds
_SUDO_RATE_LIMIT = 3       # injections per _SUDO_RATE_WINDOW

# How often a live terminal re-checks that its operator is still authorised.
_REVOCATION_CHECK_INTERVAL = 60  # seconds

# Prompts emitted by sudo (and by su / ssh password auth) on the outbound stream.
_SUDO_PROMPT_RE = re.compile(
    r"\[sudo\] password for |sorry, try again|^[^\n]{0,40}password[^\n]{0,40}:\s*$",
    re.IGNORECASE | re.MULTILINE,
)


def looks_like_sudo_prompt(data: str) -> bool:
    """True when server output looks like a password prompt awaiting input."""
    if not data:
        return False
    return _SUDO_PROMPT_RE.search(data) is not None


class SudoGate:
    """Server-side gate for the client's sudo-password-injection message.

    The browser used to decide on its own whether a sudo prompt was on screen,
    so any terminal user could send the message at will and have the stored
    sudo password echoed into the shell.  The gate only opens when the server
    itself saw a prompt in the outbound stream recently, and never more than
    ``_SUDO_RATE_LIMIT`` times per ``_SUDO_RATE_WINDOW``.
    """

    def __init__(self, prompt_window=_SUDO_PROMPT_WINDOW, rate_window=_SUDO_RATE_WINDOW,
                 rate_limit=_SUDO_RATE_LIMIT, clock=_time.monotonic):
        self._prompt_window = prompt_window
        self._rate_window = rate_window
        self._rate_limit = rate_limit
        self._clock = clock
        self._last_prompt_at = None
        self._injections = []
        self._lock = threading.Lock()

    def note_prompt(self):
        """Record that a password prompt was just seen on the outbound stream."""
        with self._lock:
            self._last_prompt_at = self._clock()

    def allow(self):
        """Return (allowed, reason). Consumes the prompt when it allows."""
        now = self._clock()
        with self._lock:
            if self._last_prompt_at is None or now - self._last_prompt_at > self._prompt_window:
                return False, "no_recent_sudo_prompt"
            self._injections = [t for t in self._injections if now - t < self._rate_window]
            if len(self._injections) >= self._rate_limit:
                return False, "rate_limited"
            self._injections.append(now)
            # One prompt authorises one injection.
            self._last_prompt_at = None
            return True, None


def ws_origin_allowed(origin, host) -> bool:
    """True when a WebSocket handshake's ``Origin`` matches the served host.

    ``_csrf_origin_check`` in app.py only guards unsafe HTTP methods and a
    WebSocket handshake is a GET, so without this check a page on any other
    site could open a socket to a live root shell using the browser's ambient
    cookies.  Only the host is compared (scheme- and case-insensitively) so a
    TLS-terminating reverse proxy does not break same-origin connections.
    Requests with no ``Origin`` header are refused: every browser sends one on
    a WebSocket handshake.
    """
    if not origin or not host:
        return False
    netloc = urlsplit(origin).netloc or origin
    return netloc.strip().lower() == host.strip().lower()


def _revocation_reason(app, user_id, session_hash):
    """Return a reason string when a live session's operator lost their access.

    ``auth.session_manager`` only enforces revocation in ``before_request``,
    which a long-lived WebSocket never runs again after the handshake.
    """
    try:
        with app.app_context():
            from models import User, UserSession
            user = db.session.get(User, user_id)
            if user is None or not user.is_active:
                return "user_disabled"
            if session_hash:
                record = UserSession.query.filter_by(session_id_hash=session_hash).first()
                if record is None or record.revoked:
                    return "session_revoked"
    except Exception:
        logger.debug("Terminal revocation re-check failed", exc_info=True)
    return None


bp = Blueprint("terminal", __name__)
sock = Sock()


def init_websocket(app):
    """Initialize the WebSocket handler on the app."""
    sock.init_app(app)


def _resolve_guest_ip(guest):
    """Try to resolve a real IP address for a guest. Returns IP string or None."""
    ip = guest.ip_address
    if ip and ip != "dhcp" and not ip.startswith("dhcp"):
        return ip

    # Try Proxmox API to get the actual IP
    if guest.proxmox_host and guest.vmid:
        try:
            from clients.proxmox_api import ProxmoxClient
            client = ProxmoxClient(guest.proxmox_host)
            node = client.find_guest_node(guest.vmid)
            if node:
                resolved_ip = client.get_guest_ip(node, guest.vmid, guest.guest_type)
                if resolved_ip and resolved_ip != "dhcp":
                    guest.ip_address = resolved_ip
                    db.session.commit()
                    return resolved_ip
        except Exception as e:
            logger.debug(f"Proxmox IP resolution failed for {guest.name}: {e}")

    # Try UniFi MAC lookup as fallback
    if guest.mac_address:
        try:
            from models import Setting
            if Setting.get("unifi_enabled", "false") == "true":
                from routes.unifi import _get_unifi_client
                unifi = _get_unifi_client()
                if unifi:
                    clients = unifi.get_clients() or []
                    for c in clients:
                        if c.get("mac", "").lower() == guest.mac_address.lower() and c.get("ip"):
                            resolved_ip = c["ip"]
                            guest.ip_address = resolved_ip
                            db.session.commit()
                            return resolved_ip
        except Exception as e:
            logger.debug(f"UniFi IP resolution failed for {guest.name}: {e}")

    return None


def _ws_send(ws, msg_type, data):
    """Safely send a JSON message over WebSocket."""
    try:
        ws.send(json.dumps({"type": msg_type, "data": data}))
    except Exception:
        pass


# ---------------------------------------------------------------------------
# HTTP routes
# ---------------------------------------------------------------------------

@bp.route("/")
@login_required
def index():
    if not current_user.can_ssh and not current_user.is_admin:
        flash("You don't have SSH terminal permission.", "error")
        return redirect(url_for("dashboard.index"))

    tag_filter = request.args.get("tag", None)
    user_tag_names = [t.name for t in current_user.allowed_tags]

    if tag_filter is not None:
        session["guest_tag_filter"] = tag_filter
    elif "guest_tag_filter" in session:
        tag_filter = session["guest_tag_filter"]
    elif user_tag_names:
        tag_filter = "__my_tags__"
    else:
        tag_filter = ""

    if current_user.is_admin:
        query = Guest.query.filter_by(enabled=True)
    else:
        user_tag_ids = [t.id for t in current_user.allowed_tags]
        if not user_tag_ids:
            query = Guest.query.filter(False)
        else:
            query = Guest.query.filter_by(enabled=True).filter(
                Guest.tags.any(Tag.id.in_(user_tag_ids))
            )

    if tag_filter == "__my_tags__":
        query = query.filter(Guest.tags.any(Tag.name.in_(user_tag_names)))
    elif tag_filter:
        query = query.filter(Guest.tags.any(Tag.name == tag_filter))

    guests = query.order_by(Guest.name).all()
    tags = Tag.query.order_by(Tag.name).all()

    return render_template("terminal.html", guests=guests, tags=tags,
                           current_tag=tag_filter, user_tag_names=user_tag_names)


@bp.route("/<int:guest_id>")
@login_required
def connect(guest_id):
    if not current_user.can_ssh and not current_user.is_admin:
        flash("You don't have SSH terminal permission.", "error")
        return redirect(url_for("dashboard.index"))

    guest = Guest.query.get_or_404(guest_id)

    if not current_user.is_admin and not current_user.can_access_guest(guest):
        flash("You don't have permission to access this guest.", "error")
        return redirect(url_for("terminal.index"))

    # Snapshot gating for non-admin users
    if not current_user.is_admin:
        from routes.guests import auto_snapshot_if_needed, guest_requires_snapshot
        if guest_requires_snapshot(guest):
            ok, msg = auto_snapshot_if_needed(guest)
            if not ok:
                flash(f"Cannot connect: snapshot required but failed — {msg}", "error")
                return redirect(url_for("terminal.index"))

    ip = _resolve_guest_ip(guest)

    credential = guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()

    needs_credentials = credential is None
    has_sudo_password = credential is not None and credential.encrypted_sudo_password is not None

    return render_template("terminal_session.html", guest=guest, resolved_ip=ip,
                           needs_credentials=needs_credentials,
                           has_sudo_password=has_sudo_password,
                           follow_mode=False, follow_session_id=None,
                           follow_owner=None)


@bp.route("/<int:guest_id>/follow/<session_id>")
@login_required
def follow(guest_id, session_id):
    """Read-only follow view that mirrors an active terminal session."""
    if not current_user.can_ssh and not current_user.is_admin:
        flash("You don't have SSH terminal permission.", "error")
        return redirect(url_for("dashboard.index"))

    guest = Guest.query.get_or_404(guest_id)

    if not current_user.is_admin and not current_user.can_access_guest(guest):
        flash("You don't have permission to access this guest.", "error")
        return redirect(url_for("terminal.index"))

    from core.collaboration import terminal_registry
    term_session = terminal_registry.get(session_id)
    if not term_session or term_session.guest_id != guest_id:
        flash("Session not found or has ended.", "warning")
        return redirect(url_for("terminal.index"))

    ip = _resolve_guest_ip(guest)

    return render_template("terminal_session.html", guest=guest, resolved_ip=ip,
                           needs_credentials=False, has_sudo_password=False,
                           follow_mode=True, follow_session_id=session_id,
                           follow_owner=term_session.owner_username)


@bp.route("/<int:guest_id>/popout")
@login_required
def popout(guest_id):
    """Render the terminal in a minimal standalone window (no navbar)."""
    if not current_user.can_ssh and not current_user.is_admin:
        flash("You don't have SSH terminal permission.", "error")
        return redirect(url_for("dashboard.index"))

    guest = Guest.query.get_or_404(guest_id)

    if not current_user.is_admin and not current_user.can_access_guest(guest):
        flash("You don't have permission to access this guest.", "error")
        return redirect(url_for("terminal.index"))

    # Snapshot gating for non-admin users
    if not current_user.is_admin:
        from routes.guests import auto_snapshot_if_needed, guest_requires_snapshot
        if guest_requires_snapshot(guest):
            ok, msg = auto_snapshot_if_needed(guest)
            if not ok:
                flash(f"Cannot connect: snapshot required but failed — {msg}", "error")
                return redirect(url_for("terminal.index"))

    ip = _resolve_guest_ip(guest)

    credential = guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()

    has_sudo_password = credential is not None and credential.encrypted_sudo_password is not None

    return render_template("terminal_popout.html", guest=guest, resolved_ip=ip,
                           has_sudo_password=has_sudo_password)


@bp.route("/<int:guest_id>/connect-adhoc", methods=["POST"])
@login_required
def connect_adhoc(guest_id):
    """Store ad-hoc SSH credentials in the session and redirect to the terminal."""
    if not current_user.can_ssh and not current_user.is_admin:
        flash("You don't have SSH terminal permission.", "error")
        return redirect(url_for("dashboard.index"))

    guest = Guest.query.get_or_404(guest_id)
    if not current_user.is_admin and not current_user.can_access_guest(guest):
        flash("You don't have permission to access this guest.", "error")
        return redirect(url_for("terminal.index"))

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username:
        flash("Username is required.", "error")
        return redirect(url_for("terminal.connect", guest_id=guest_id))

    # Only an opaque single-use token goes into the cookie; the credentials stay
    # in a short-lived server-side store (see core/adhoc_credentials.py).
    from core.adhoc_credentials import store_credentials
    session[f"terminal_cred_token_{guest_id}"] = store_credentials(
        user_id=current_user.id, guest_id=guest_id, username=username, password=password,
    )
    return redirect(url_for("terminal.connect", guest_id=guest_id))


# ---------------------------------------------------------------------------
# WebSocket handler — primary (owner) and follower modes
# ---------------------------------------------------------------------------

@sock.route("/ws/terminal/<int:guest_id>")
def terminal_ws(ws, guest_id):
    """WebSocket handler for SSH terminal sessions.

    Query params:
      mode=follow&session_id=XXXX  — read-only follower; attaches to an
                                     existing shared session.
      (default)                    — primary connection; creates an SSH
                                     channel and registers a shared session.
    """
    if not ws_origin_allowed(request.headers.get("Origin"), request.host):
        logger.warning("Refused terminal WebSocket for guest %s: Origin %r does not match host %r",
                       guest_id, request.headers.get("Origin"), request.host)
        _ws_send(ws, "error", "Cross-origin WebSocket connections are not allowed.")
        try:
            ws.close()
        except Exception:
            pass
        return

    mode = request.args.get("mode", "primary")
    session_id = request.args.get("session_id")

    if mode == "follow" and session_id:
        _ws_follow(ws, guest_id, session_id)
    else:
        _ws_primary(ws, guest_id)


def _ws_primary(ws, guest_id):
    """Handle the primary (owner) WebSocket connection."""
    from flask_login import current_user as ws_user

    from core.collaboration import terminal_registry

    ssh_client = None
    channel = None
    term_session = None
    send_q = None
    _audit_guest_id = guest_id
    _audit_guest_name = None

    try:
        # Auth checks
        if not ws_user.is_authenticated:
            _ws_send(ws, "error", "Not authenticated")
            return
        if not ws_user.can_ssh and not ws_user.is_admin:
            _ws_send(ws, "error", "No SSH permission")
            return

        guest = Guest.query.get(guest_id)
        if not guest:
            _ws_send(ws, "error", "Guest not found")
            return
        if not ws_user.is_admin and not ws_user.can_access_guest(guest):
            _ws_send(ws, "error", "Access denied")
            return

        _audit_guest_name = guest.name

        # Resolve IP
        ssh_host = _resolve_guest_ip(guest)
        if not ssh_host:
            _ws_send(ws, "error", "Could not resolve IP address for this guest. Try running discovery again.")
            return

        # Resolve credentials — consume any single-use ad-hoc credentials first.
        # The cookie only holds an opaque token: popping the session here would
        # never reach the browser (the 101 response bypasses Flask's response
        # handling), so the store itself enforces single use and a 5-minute TTL.
        from core.adhoc_credentials import take_credentials
        adhoc = take_credentials(session.get(f"terminal_cred_token_{guest_id}"),
                                 user_id=ws_user.id, guest_id=guest_id)
        adhoc_username = adhoc.get("username") if adhoc else None
        adhoc_password = (adhoc.get("password") or None) if adhoc else None

        credential = None
        if not adhoc_username:
            credential = guest.credential
            if not credential:
                credential = Credential.query.filter_by(is_default=True).first()

        if not credential and not adhoc_username:
            _ws_send(ws, "error", "No credentials available for this guest.")
            return

        # Build SSH connection
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # noqa: S507

        connect_kwargs = {
            "hostname": ssh_host,
            "port": 22,
            "timeout": 15,
        }

        if adhoc_username:
            connect_kwargs["username"] = adhoc_username
            if adhoc_password:
                connect_kwargs["password"] = adhoc_password
        else:
            connect_kwargs["username"] = credential.username
            decrypted_value = decrypt(credential.encrypted_value)
            if credential.auth_type == "password":
                connect_kwargs["password"] = decrypted_value
            else:
                key_file = io.StringIO(decrypted_value)
                try:
                    pkey = paramiko.RSAKey.from_private_key(key_file)
                except paramiko.SSHException:
                    key_file.seek(0)
                    try:
                        pkey = paramiko.Ed25519Key.from_private_key(key_file)
                    except paramiko.SSHException:
                        key_file.seek(0)
                        pkey = paramiko.ECDSAKey.from_private_key(key_file)
                connect_kwargs["pkey"] = pkey

        # Decrypt sudo password if available
        sudo_password = None
        if credential and credential.encrypted_sudo_password:
            sudo_password = decrypt(credential.encrypted_sudo_password)

        logger.info(f"Terminal SSH connecting to {guest.name} ({ssh_host}) as {connect_kwargs.get('username')}")
        ssh_client.connect(**connect_kwargs)
        channel = ssh_client.invoke_shell(term="xterm-256color", width=120, height=40)

        # Register this session for sharing / follower fan-out
        term_session = terminal_registry.create(
            guest_id=guest.id,
            guest_name=guest.name,
            owner_user_id=ws_user.id,
            owner_username=ws_user.username,  # use login username for identity matching
        )
        send_q = term_session.add_subscriber(ws)

        # Sender thread: drains send_q and writes to the browser from THIS WebSocket's
        # dedicated thread, avoiding cross-thread ws.send() issues in flask-sock.
        def _primary_sender():
            while True:
                try:
                    msg = send_q.get(timeout=2)
                    if msg is None:
                        break
                    ws.send(msg)
                except _queue.Empty:
                    continue
                except Exception:
                    break
        threading.Thread(target=_primary_sender, daemon=True).start()

        _ws_send(ws, "connected", f"Connected to {guest.name} ({ssh_host})")
        _ws_send(ws, "session_id", term_session.session_id)  # let the client know the session ID
        log_action("guest_ssh_connect", "guest", resource_id=guest.id, resource_name=guest.name,
                   details={"username": connect_kwargs.get("username"),
                             "session_id": term_session.session_id})
        db.session.commit()

        sudo_gate = SudoGate()

        # SSH read thread: fans output to all subscribers via the session
        def read_from_ssh():
            try:
                while True:
                    if channel.recv_ready():
                        data = channel.recv(4096).decode("utf-8", errors="replace")
                        if data:
                            if looks_like_sudo_prompt(data):
                                sudo_gate.note_prompt()
                            term_session.broadcast_output(data)
                    if channel.closed:
                        break
                    channel.settimeout(0.1)
                    try:
                        channel.recv(0)
                    except Exception:
                        pass
            except Exception as e:
                logger.debug(f"SSH read thread ended: {e}")
            finally:
                term_session.send_control({"type": "disconnected", "data": "SSH session closed"})
                terminal_registry.remove(term_session.session_id)

        read_thread = threading.Thread(target=read_from_ssh, daemon=True)
        read_thread.start()

        # Watchdog: closes the SSH channel on idle timeout, and also re-checks
        # every _REVOCATION_CHECK_INTERVAL that the operator's account and web
        # session are still valid — before_request never runs again for a
        # long-lived socket, so a revoked user otherwise keeps an open shell.
        _last_activity = [_time.monotonic()]
        _wd_app = current_app._get_current_object()
        _wd_user_id = ws_user.id
        _wd_username = ws_user.username
        _wd_raw_sid = session.get(SESSION_KEY)
        _wd_session_hash = _hash_session_id(_wd_raw_sid) if _wd_raw_sid else None
        _wd_session_id = term_session.session_id

        def _session_watchdog():
            while not channel.closed:
                _time.sleep(_REVOCATION_CHECK_INTERVAL)
                if channel.closed:
                    break
                if _time.monotonic() - _last_activity[0] >= _IDLE_TIMEOUT:
                    logger.info(f"Terminal idle timeout for guest {guest_id} — closing channel")
                    term_session.send_control({"type": "timeout", "data": "Session closed due to inactivity."})
                    try:
                        channel.close()
                    except Exception:
                        pass
                    break
                reason = _revocation_reason(_wd_app, _wd_user_id, _wd_session_hash)
                if reason:
                    logger.warning("Closing terminal for guest %s: %s", guest_id, reason)
                    term_session.send_control({"type": "error",
                                               "data": "Your access was revoked — terminal closed."})
                    with _wd_app.app_context():
                        log_action("guest_terminal_revoked", "guest",
                                   resource_id=_audit_guest_id, resource_name=_audit_guest_name,
                                   details={"reason": reason, "session_id": _wd_session_id},
                                   actor=_wd_username)
                        try:
                            db.session.commit()
                        except Exception:
                            db.session.rollback()
                    try:
                        channel.close()
                    except Exception:
                        pass
                    break

        threading.Thread(target=_session_watchdog, daemon=True).start()

        # Main loop: WebSocket → SSH (primary only)
        while not channel.closed:
            try:
                message = ws.receive()
                if message is None:
                    break
                _last_activity[0] = _time.monotonic()
                msg = json.loads(message)
                if msg.get("type") == "input":
                    channel.send(msg["data"])
                elif msg.get("type") == "sudo":
                    if sudo_password:
                        allowed, reason = sudo_gate.allow()
                        if allowed:
                            channel.send(sudo_password + "\n")
                            log_action("guest_terminal_sudo_injected", "guest",
                                       resource_id=guest.id, resource_name=guest.name,
                                       details={"session_id": term_session.session_id})
                        else:
                            _ws_send(ws, "error",
                                     "Sudo password not sent: no sudo prompt was seen on this session.")
                            log_action("guest_terminal_sudo_blocked", "guest",
                                       resource_id=guest.id, resource_name=guest.name,
                                       details={"session_id": term_session.session_id, "reason": reason})
                        try:
                            db.session.commit()
                        except Exception:
                            db.session.rollback()
                elif msg.get("type") == "resize":
                    cols = msg.get("cols", 120)
                    rows = msg.get("rows", 40)
                    channel.resize_pty(width=cols, height=rows)
            except json.JSONDecodeError:
                continue
            except Exception:
                break

    except paramiko.AuthenticationException:
        logger.warning(f"Terminal SSH auth failed for guest {guest_id}")
        _ws_send(ws, "error", "SSH authentication failed. Check credentials.")
    except paramiko.SSHException as e:
        logger.warning(f"Terminal SSH error for guest {guest_id}: {e}")
        _ws_send(ws, "error", f"SSH error: {e}")
    except Exception as e:
        logger.error(f"Terminal error for guest {guest_id}: {e}", exc_info=True)
        _ws_send(ws, "error", f"Connection failed: {e}")
    finally:
        if term_session and _audit_guest_name:
            log_action("guest_ssh_disconnect", "guest",
                       resource_id=_audit_guest_id, resource_name=_audit_guest_name,
                       details={"session_id": term_session.session_id})
            try:
                db.session.commit()
            except Exception:
                pass
        if send_q is not None:
            try:
                send_q.put_nowait(None)  # sentinel — stop _primary_sender
            except Exception:
                pass
        if term_session:
            term_session.remove_subscriber(ws)
            # If the primary disconnected and no other subscribers remain, clean up
            if term_session.follower_count() == 0:
                terminal_registry.remove(term_session.session_id)
        if channel:
            try:
                channel.close()
            except Exception:
                pass
        if ssh_client:
            try:
                ssh_client.close()
            except Exception:
                pass
        try:
            ws.close()
        except Exception:
            pass


def _ws_follow(ws, guest_id, session_id):
    """Handle a read-only follower WebSocket connection."""
    from flask_login import current_user as ws_user

    from core.collaboration import terminal_registry

    term_session = None
    send_q = None

    try:
        if not ws_user.is_authenticated:
            _ws_send(ws, "error", "Not authenticated")
            return
        if not ws_user.can_ssh and not ws_user.is_admin:
            _ws_send(ws, "error", "No SSH permission")
            return

        guest = Guest.query.get(guest_id)
        if not guest:
            _ws_send(ws, "error", "Guest not found")
            return
        if not ws_user.is_admin and not ws_user.can_access_guest(guest):
            _ws_send(ws, "error", "Access denied")
            return

        term_session = terminal_registry.get(session_id)
        if not term_session or term_session.guest_id != guest_id:
            _ws_send(ws, "error", "Session not found or has ended.")
            return

        # Attach as follower — catch-up snapshot is pre-loaded into the queue
        send_q = term_session.add_subscriber(ws)

        # Sender thread: drains send_q and writes to the follower's browser.
        # Must run in its own thread so ws.send() is never called cross-thread.
        def _follower_sender():
            while True:
                try:
                    msg = send_q.get(timeout=2)
                    if msg is None:
                        break
                    ws.send(msg)
                except _queue.Empty:
                    continue
                except Exception:
                    break
        threading.Thread(target=_follower_sender, daemon=True).start()

        # connected message goes through the queue so it arrives after the catch-up
        send_q.put_nowait(json.dumps({
            "type": "connected",
            "data": f"Following {term_session.owner_username}'s session on {guest.name}",
        }))

        logger.info(f"Follower {ws_user.username} joined session {session_id} on {guest.name}")

        # Keep the connection alive; discard any input from the follower
        while True:
            try:
                message = ws.receive()
                if message is None:
                    break
                # Followers cannot send input — silently ignore everything
            except Exception:
                break

    except Exception as e:
        logger.error(f"Follow session error for guest {guest_id}: {e}", exc_info=True)
    finally:
        if send_q is not None:
            try:
                send_q.put_nowait(None)  # sentinel — stop _follower_sender
            except Exception:
                pass
        if term_session:
            term_session.remove_subscriber(ws)
        try:
            ws.close()
        except Exception:
            pass
