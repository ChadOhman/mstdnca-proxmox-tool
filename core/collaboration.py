"""Real-time collaboration hub.

Manages:
  - User presence tracking (current page + last-seen heartbeat)
  - SSE event fan-out to all connected browsers (activity, presence updates)
  - Terminal session registry (shared SSH sessions with fan-out to followers)

NOTE: Uses in-process state — works correctly with a single gunicorn worker
(``-w 1``) or with threaded workers (``--worker-class gthread``).  For
multi-process deployments, replace the per-process Queue/dict with a Redis
pub/sub backend.
"""

import json
import logging
import queue
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Seconds of silence before a user is considered offline
_PRESENCE_TIMEOUT = 90


# ---------------------------------------------------------------------------
# Collaboration hub (presence + activity SSE fan-out)
# ---------------------------------------------------------------------------

class CollaborationHub:
    """Thread-safe hub that maintains SSE connections and pushes events."""

    def __init__(self):
        self._lock = threading.Lock()
        self._users: dict = {}  # user_id -> {username, display_name, page, last_seen, queue}

    def connect(self, user_id: int, username: str, display_name: str,
                page: str = "/", is_admin: bool = False,
                tag_ids: set | list | None = None) -> queue.Queue:
        """Register an SSE connection and return the event queue for this user.

        ``is_admin``/``tag_ids`` are captured here (while a request context still
        exists) so :meth:`broadcast` can filter guest-scoped events per recipient
        without touching the database on the fan-out path.
        """
        q: queue.Queue = queue.Queue(maxsize=200)
        with self._lock:
            self._users[user_id] = {
                "username": username,
                "display_name": display_name or username,
                "page": page,
                "following": None,
                "last_seen": time.time(),
                "queue": q,
                "is_admin": bool(is_admin),
                "tag_ids": set(tag_ids or ()),
            }
        self._push_presence()
        return q

    def disconnect(self, user_id: int, event_queue=None):
        """Unregister a user's SSE connection and broadcast updated presence.

        Pass event_queue to guard against the reconnect race: if the user has
        already reconnected (new queue registered), this disconnect is a no-op.
        """
        with self._lock:
            entry = self._users.get(user_id)
            if entry is None:
                return
            if event_queue is not None and entry["queue"] is not event_queue:
                return  # stale disconnect from a superseded connection
            self._users.pop(user_id)
        self._push_presence()

    def update_presence(self, user_id: int, page: str, following: str | None = None):
        """Update a user's current page, follow target, and last-seen timestamp."""
        with self._lock:
            if user_id in self._users:
                self._users[user_id]["page"] = page
                self._users[user_id]["following"] = following
                self._users[user_id]["last_seen"] = time.time()
        self._push_presence()

    def broadcast(self, event: dict):
        """Push an event dict to every connected user's SSE queue.

        An event carrying ``guest_tag_ids`` describes a specific guest and is
        delivered only to admins and to users holding one of those tags; the key
        itself is stripped before delivery.  Events without it (presence, host
        activity) go to everyone as before.
        """
        tag_ids = event.get("guest_tag_ids")
        if tag_ids is not None:
            event = {k: v for k, v in event.items() if k != "guest_tag_ids"}
            tag_ids = set(tag_ids)
        with self._lock:
            targets = [(u.get("is_admin", False), u.get("tag_ids") or set(), u["queue"])
                       for u in self._users.values()]
        for is_admin, user_tags, q in targets:
            if tag_ids is not None and not is_admin and not (tag_ids & user_tags):
                continue
            try:
                q.put_nowait(event)
            except queue.Full:
                pass  # Slow consumer — drop rather than block

    def get_online_users(self) -> list:
        now = time.time()
        with self._lock:
            return [
                {
                    "username": u["username"],
                    "display_name": u["display_name"],
                    "page": u["page"],
                    "following": u.get("following"),
                }
                for u in self._users.values()
                if now - u["last_seen"] < _PRESENCE_TIMEOUT
            ]

    def _push_presence(self):
        self.broadcast({"type": "presence", "users": self.get_online_users()})


# ---------------------------------------------------------------------------
# Terminal session sharing
# ---------------------------------------------------------------------------

class TerminalSession:
    """A shared SSH terminal session that fans output to multiple WebSockets."""

    MAX_BUFFER = 100 * 1024  # 100 KB ring buffer for late-joiner catch-up

    def __init__(self, session_id: str, guest_id: int, guest_name: str,
                 owner_user_id: int, owner_username: str):
        self.session_id = session_id
        self.guest_id = guest_id
        self.guest_name = guest_name
        self.owner_user_id = owner_user_id
        self.owner_username = owner_username
        self.started_at = datetime.now(timezone.utc)
        self._lock = threading.Lock()
        self._queues: dict = {}        # id(ws) -> queue.Queue; each connection drains its own
        self._buffer_chunks: deque = deque()
        self._buffer_size: int = 0

    def add_subscriber(self, ws) -> queue.Queue:
        """Register a WebSocket and return its dedicated send queue.

        The caller is responsible for draining the queue and calling ws.send()
        from the WebSocket's own thread.  The catch-up snapshot is pre-loaded
        into the queue so the caller just needs to start draining.
        """
        q: queue.Queue = queue.Queue(maxsize=500)
        catchup = self._snapshot()
        if catchup:
            q.put_nowait(json.dumps({"type": "output", "data": catchup}))
        with self._lock:
            self._queues[id(ws)] = q
        return q

    def remove_subscriber(self, ws):
        with self._lock:
            self._queues.pop(id(ws), None)

    def broadcast_output(self, data: str):
        """Append SSH output to the ring buffer and enqueue it for all subscribers."""
        self._append(data)
        msg = json.dumps({"type": "output", "data": data})
        with self._lock:
            queues = list(self._queues.values())
        for q in queues:
            try:
                q.put_nowait(msg)
            except queue.Full:
                pass  # Slow consumer — drop rather than block

    def send_control(self, msg: dict):
        """Enqueue a control message (e.g. disconnected) for all subscribers."""
        raw = json.dumps(msg)
        with self._lock:
            queues = list(self._queues.values())
        for q in queues:
            try:
                q.put_nowait(raw)
            except queue.Full:
                pass

    def follower_count(self) -> int:
        """Number of follower connections (total subscribers minus the primary)."""
        with self._lock:
            return max(0, len(self._queues) - 1)

    def _append(self, data: str):
        with self._lock:
            self._buffer_chunks.append(data)
            self._buffer_size += len(data)
            while self._buffer_size > self.MAX_BUFFER and self._buffer_chunks:
                removed = self._buffer_chunks.popleft()
                self._buffer_size -= len(removed)

    def _snapshot(self) -> str:
        with self._lock:
            return "".join(self._buffer_chunks)


class TerminalSessionRegistry:
    """Tracks all active shared terminal sessions."""

    def __init__(self):
        self._lock = threading.Lock()
        self._sessions: dict = {}  # session_id -> TerminalSession

    def create(self, guest_id: int, guest_name: str,
               owner_user_id: int, owner_username: str) -> TerminalSession:
        session_id = uuid.uuid4().hex
        session = TerminalSession(session_id, guest_id, guest_name,
                                  owner_user_id, owner_username)
        with self._lock:
            self._sessions[session_id] = session
        logger.debug("Terminal session %s created for guest %s by %s",
                     session_id, guest_name, owner_username)
        return session

    def get(self, session_id: str):
        with self._lock:
            return self._sessions.get(session_id)

    def remove(self, session_id: str):
        with self._lock:
            self._sessions.pop(session_id, None)
        logger.debug("Terminal session %s removed", session_id)

    def get_all(self) -> list:
        with self._lock:
            return list(self._sessions.values())


# ---------------------------------------------------------------------------
# Cursor position tracking
# ---------------------------------------------------------------------------

class CursorHub:
    """Stores the most-recent cursor position per user for co-presence tracking."""

    EXPIRY = 3.0  # seconds without update → cursor considered gone

    def __init__(self):
        self._lock = threading.Lock()
        self._positions: dict = {}  # username -> {display_name, page, x_pct, y_pct, color, ts}

    def update(self, username: str, display_name: str, page: str,
               x_pct: float, y_pct: float, color: str):
        now = time.time()
        with self._lock:
            self._positions[username] = {
                "display_name": display_name,
                "page": page,
                "x_pct": x_pct,
                "y_pct": y_pct,
                "color": color,
                "ts": now,
            }
            # Evict expired cursor positions to prevent unbounded growth
            cutoff = now - self.EXPIRY
            stale = [u for u, v in self._positions.items() if v["ts"] < cutoff]
            for u in stale:
                del self._positions[u]

    def get_for_page(self, page: str, exclude_username: str = None) -> list:
        now = time.time()
        with self._lock:
            return [
                {
                    "username": u,
                    "display_name": v["display_name"],
                    "x_pct": v["x_pct"],
                    "y_pct": v["y_pct"],
                    "color": v["color"],
                }
                for u, v in self._positions.items()
                if v["page"] == page
                and u != exclude_username
                and now - v["ts"] < self.EXPIRY
            ]


# ---------------------------------------------------------------------------
# Module-level singletons
# ---------------------------------------------------------------------------

collab_hub = CollaborationHub()
terminal_registry = TerminalSessionRegistry()
cursor_hub = CursorHub()
