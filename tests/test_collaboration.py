"""Unit tests for the collaboration module.

Tests are pure Python — no Flask app context or database required.
All classes under test (CollaborationHub, TerminalSession,
TerminalSessionRegistry, CursorHub) are self-contained and only
depend on the standard library.
"""
import json
import queue
import threading
import time

from core.collaboration import (
    _PRESENCE_TIMEOUT,
    CollaborationHub,
    CursorHub,
    TerminalSession,
    TerminalSessionRegistry,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _FakeWS:
    """Minimal stand-in for a WebSocket object — identity via id() is all
    that TerminalSession needs."""


def _drain(q: queue.Queue) -> list:
    """Return every item currently in the queue without blocking."""
    items = []
    while True:
        try:
            items.append(q.get_nowait())
        except queue.Empty:
            break
    return items


# ---------------------------------------------------------------------------
# CollaborationHub
# ---------------------------------------------------------------------------

class TestCollaborationHubConnect:
    def test_connect_returns_queue(self):
        hub = CollaborationHub()
        q = hub.connect(1, "alice", "Alice")
        assert isinstance(q, queue.Queue)

    def test_connect_pushes_presence_event(self):
        hub = CollaborationHub()
        q = hub.connect(1, "alice", "Alice")
        events = _drain(q)
        assert len(events) == 1
        assert events[0]["type"] == "presence"

    def test_connect_presence_contains_new_user(self):
        hub = CollaborationHub()
        q = hub.connect(1, "alice", "Alice")
        event = _drain(q)[0]
        usernames = [u["username"] for u in event["users"]]
        assert "alice" in usernames

    def test_connect_display_name_falls_back_to_username(self):
        hub = CollaborationHub()
        q = hub.connect(1, "bob", "")
        event = _drain(q)[0]
        user = next(u for u in event["users"] if u["username"] == "bob")
        assert user["display_name"] == "bob"

    def test_connect_display_name_none_falls_back_to_username(self):
        hub = CollaborationHub()
        q = hub.connect(1, "bob", None)
        event = _drain(q)[0]
        user = next(u for u in event["users"] if u["username"] == "bob")
        assert user["display_name"] == "bob"

    def test_connect_default_page_is_slash(self):
        hub = CollaborationHub()
        q = hub.connect(1, "alice", "Alice")
        event = _drain(q)[0]
        user = next(u for u in event["users"] if u["username"] == "alice")
        assert user["page"] == "/"

    def test_connect_custom_page(self):
        hub = CollaborationHub()
        q = hub.connect(1, "alice", "Alice", page="/guests")
        event = _drain(q)[0]
        user = next(u for u in event["users"] if u["username"] == "alice")
        assert user["page"] == "/guests"

    def test_connect_multiple_users_all_receive_presence(self):
        hub = CollaborationHub()
        q1 = hub.connect(1, "alice", "Alice")
        _drain(q1)  # discard the first presence triggered by alice's own connect
        q2 = hub.connect(2, "bob", "Bob")
        # Both queues should now have a presence event (the one pushed by bob's connect)
        events1 = _drain(q1)
        events2 = _drain(q2)
        assert len(events1) == 1
        assert len(events2) == 1
        usernames1 = {u["username"] for u in events1[0]["users"]}
        assert {"alice", "bob"} == usernames1

    def test_reconnect_replaces_queue(self):
        hub = CollaborationHub()
        q_old = hub.connect(1, "alice", "Alice")
        _drain(q_old)  # clear the presence event from the first connect
        q_new = hub.connect(1, "alice", "Alice")
        assert q_old is not q_new
        # Only the new queue is active after reconnect; drain presence from reconnect
        _drain(q_new)
        hub.broadcast({"type": "ping"})
        # The old queue was replaced in _users, so broadcast does not reach it
        assert not _drain(q_old)
        assert _drain(q_new) == [{"type": "ping"}]


class TestCollaborationHubDisconnect:
    def test_disconnect_removes_user_from_presence(self):
        hub = CollaborationHub()
        hub.connect(1, "alice", "Alice")
        hub.disconnect(1)
        users = hub.get_online_users()
        assert all(u["username"] != "alice" for u in users)

    def test_disconnect_pushes_updated_presence(self):
        hub = CollaborationHub()
        q1 = hub.connect(1, "alice", "Alice")
        q2 = hub.connect(2, "bob", "Bob")
        _drain(q1)
        _drain(q2)
        hub.disconnect(1)
        events = _drain(q2)
        assert len(events) == 1
        assert events[0]["type"] == "presence"
        assert all(u["username"] != "alice" for u in events[0]["users"])

    def test_disconnect_unknown_user_is_noop(self):
        hub = CollaborationHub()
        # Should not raise
        hub.disconnect(999)

    def test_disconnect_with_matching_queue_removes_user(self):
        hub = CollaborationHub()
        q = hub.connect(1, "alice", "Alice")
        hub.disconnect(1, event_queue=q)
        assert all(u["username"] != "alice" for u in hub.get_online_users())

    def test_disconnect_with_stale_queue_is_noop(self):
        """Reconnect-race guard: stale disconnect must not evict the fresh connection."""
        hub = CollaborationHub()
        q_old = hub.connect(1, "alice", "Alice")
        _q_new = hub.connect(1, "alice", "Alice")  # reconnect, replacing queue
        # Disconnect with the OLD queue should be ignored
        hub.disconnect(1, event_queue=q_old)
        users = hub.get_online_users()
        assert any(u["username"] == "alice" for u in users)

    def test_disconnect_with_none_queue_always_removes(self):
        hub = CollaborationHub()
        hub.connect(1, "alice", "Alice")
        hub.disconnect(1, event_queue=None)
        assert all(u["username"] != "alice" for u in hub.get_online_users())


class TestCollaborationHubUpdatePresence:
    def test_update_presence_changes_page(self):
        hub = CollaborationHub()
        hub.connect(1, "alice", "Alice", page="/")
        hub.update_presence(1, page="/guests")
        users = hub.get_online_users()
        alice = next(u for u in users if u["username"] == "alice")
        assert alice["page"] == "/guests"

    def test_update_presence_sets_following(self):
        hub = CollaborationHub()
        hub.connect(1, "alice", "Alice")
        hub.update_presence(1, page="/terminal/abc123", following="abc123")
        users = hub.get_online_users()
        alice = next(u for u in users if u["username"] == "alice")
        assert alice["following"] == "abc123"

    def test_update_presence_clears_following(self):
        hub = CollaborationHub()
        hub.connect(1, "alice", "Alice")
        hub.update_presence(1, page="/terminal/abc123", following="abc123")
        hub.update_presence(1, page="/guests", following=None)
        users = hub.get_online_users()
        alice = next(u for u in users if u["username"] == "alice")
        assert alice["following"] is None

    def test_update_presence_refreshes_last_seen(self):
        hub = CollaborationHub()
        hub.connect(1, "alice", "Alice")
        with hub._lock:
            hub._users[1]["last_seen"] = time.time() - (_PRESENCE_TIMEOUT - 5)
        hub.update_presence(1, page="/")
        # User should still be online (last_seen just refreshed)
        assert any(u["username"] == "alice" for u in hub.get_online_users())

    def test_update_presence_pushes_presence_event(self):
        hub = CollaborationHub()
        q = hub.connect(1, "alice", "Alice")
        _drain(q)
        hub.update_presence(1, page="/new-page")
        events = _drain(q)
        assert len(events) == 1
        assert events[0]["type"] == "presence"

    def test_update_presence_for_unknown_user_is_noop(self):
        hub = CollaborationHub()
        # Should not raise and should not add the user
        hub.update_presence(999, page="/guests")
        assert hub.get_online_users() == []


class TestCollaborationHubBroadcast:
    def test_broadcast_reaches_all_connected_users(self):
        hub = CollaborationHub()
        q1 = hub.connect(1, "alice", "Alice")
        q2 = hub.connect(2, "bob", "Bob")
        _drain(q1)
        _drain(q2)
        hub.broadcast({"type": "custom", "msg": "hello"})
        assert _drain(q1) == [{"type": "custom", "msg": "hello"}]
        assert _drain(q2) == [{"type": "custom", "msg": "hello"}]

    def test_broadcast_no_users_is_noop(self):
        hub = CollaborationHub()
        # Should not raise
        hub.broadcast({"type": "ping"})

    def test_broadcast_full_queue_drops_silently(self):
        hub = CollaborationHub()
        q = hub.connect(1, "alice", "Alice")
        _drain(q)
        # Fill the queue to capacity (maxsize=200)
        for i in range(200):
            q.put_nowait({"seq": i})
        # This must not block or raise
        hub.broadcast({"type": "overflow"})
        # The overflow event was silently dropped
        items = _drain(q)
        assert len(items) == 200
        assert all("seq" in item for item in items)

    def test_broadcast_after_disconnect_does_not_reach_disconnected_user(self):
        hub = CollaborationHub()
        q = hub.connect(1, "alice", "Alice")
        hub.disconnect(1)
        _drain(q)
        hub.broadcast({"type": "ping"})
        assert _drain(q) == []


class TestCollaborationHubModeratorsOnlyBroadcast:
    """moderators_only events must reach only recipients connected with
    can_moderate=True, and the flag itself must be stripped before delivery."""

    def test_reaches_only_moderator_subscribers(self):
        hub = CollaborationHub()
        q_mod = hub.connect(1, "mod", "Mod", can_moderate=True)
        q_plain = hub.connect(2, "plain", "Plain", can_moderate=False)
        _drain(q_mod)
        _drain(q_plain)

        hub.broadcast({"type": "activity", "action": "moderation_watch_hit", "moderators_only": True})

        mod_events = [e for e in _drain(q_mod) if e.get("type") == "activity"]
        plain_events = [e for e in _drain(q_plain) if e.get("type") == "activity"]
        assert len(mod_events) == 1
        assert plain_events == []

    def test_flag_is_stripped_from_delivered_event(self):
        hub = CollaborationHub()
        q_mod = hub.connect(1, "mod", "Mod", can_moderate=True)
        _drain(q_mod)

        hub.broadcast({"type": "activity", "action": "moderation_watch_hit", "moderators_only": True})

        event = next(e for e in _drain(q_mod) if e.get("type") == "activity")
        assert "moderators_only" not in event

    def test_events_without_flag_reach_everyone(self):
        hub = CollaborationHub()
        q_mod = hub.connect(1, "mod", "Mod", can_moderate=True)
        q_plain = hub.connect(2, "plain", "Plain", can_moderate=False)
        _drain(q_mod)
        _drain(q_plain)

        hub.broadcast({"type": "activity", "action": "host_add"})

        assert [e for e in _drain(q_mod) if e.get("type") == "activity"]
        assert [e for e in _drain(q_plain) if e.get("type") == "activity"]

    def test_default_can_moderate_is_false(self):
        """A connection made without passing can_moderate must not receive
        moderators_only events (safe default)."""
        hub = CollaborationHub()
        q = hub.connect(1, "alice", "Alice")
        _drain(q)

        hub.broadcast({"type": "activity", "action": "moderation_watch_hit", "moderators_only": True})

        assert [e for e in _drain(q) if e.get("type") == "activity"] == []


class TestCollaborationHubGetOnlineUsers:
    def test_returns_empty_when_no_users(self):
        hub = CollaborationHub()
        assert hub.get_online_users() == []

    def test_returns_connected_users(self):
        hub = CollaborationHub()
        hub.connect(1, "alice", "Alice")
        users = hub.get_online_users()
        assert len(users) == 1
        assert users[0]["username"] == "alice"

    def test_filters_out_timed_out_users(self):
        hub = CollaborationHub()
        hub.connect(1, "alice", "Alice")
        # Artificially age the last_seen timestamp past the timeout
        with hub._lock:
            hub._users[1]["last_seen"] = time.time() - _PRESENCE_TIMEOUT - 1
        users = hub.get_online_users()
        assert all(u["username"] != "alice" for u in users)

    def test_does_not_include_timed_out_but_keeps_fresh(self):
        hub = CollaborationHub()
        hub.connect(1, "alice", "Alice")
        hub.connect(2, "bob", "Bob")
        with hub._lock:
            hub._users[1]["last_seen"] = time.time() - _PRESENCE_TIMEOUT - 1
        users = hub.get_online_users()
        usernames = [u["username"] for u in users]
        assert "alice" not in usernames
        assert "bob" in usernames

    def test_result_does_not_expose_queue(self):
        hub = CollaborationHub()
        hub.connect(1, "alice", "Alice")
        for user in hub.get_online_users():
            assert "queue" not in user

    def test_result_does_not_expose_last_seen(self):
        hub = CollaborationHub()
        hub.connect(1, "alice", "Alice")
        for user in hub.get_online_users():
            assert "last_seen" not in user

    def test_following_field_is_present(self):
        hub = CollaborationHub()
        hub.connect(1, "alice", "Alice")
        user = hub.get_online_users()[0]
        assert "following" in user

    def test_boundary_exactly_at_timeout_is_excluded(self):
        hub = CollaborationHub()
        hub.connect(1, "alice", "Alice")
        with hub._lock:
            hub._users[1]["last_seen"] = time.time() - _PRESENCE_TIMEOUT
        # Exactly at the boundary: now - last_seen == _PRESENCE_TIMEOUT → NOT < timeout
        users = hub.get_online_users()
        assert all(u["username"] != "alice" for u in users)


# ---------------------------------------------------------------------------
# TerminalSession
# ---------------------------------------------------------------------------

class TestTerminalSessionAddSubscriber:
    def _make_session(self):
        return TerminalSession("abc12345", 10, "vm-web", 1, "alice")

    def test_add_subscriber_returns_queue(self):
        session = self._make_session()
        ws = _FakeWS()
        q = session.add_subscriber(ws)
        assert isinstance(q, queue.Queue)

    def test_add_subscriber_empty_buffer_no_catchup(self):
        session = self._make_session()
        ws = _FakeWS()
        q = session.add_subscriber(ws)
        assert q.empty()

    def test_add_subscriber_with_buffer_sends_catchup(self):
        session = self._make_session()
        session.broadcast_output("Hello, ")
        session.broadcast_output("world!")
        ws = _FakeWS()
        q = session.add_subscriber(ws)
        items = _drain(q)
        assert len(items) == 1
        msg = json.loads(items[0])
        assert msg["type"] == "output"
        assert msg["data"] == "Hello, world!"

    def test_add_two_subscribers_each_gets_own_queue(self):
        session = self._make_session()
        ws1, ws2 = _FakeWS(), _FakeWS()
        q1 = session.add_subscriber(ws1)
        q2 = session.add_subscriber(ws2)
        assert q1 is not q2

    def test_add_subscriber_increments_follower_count(self):
        session = self._make_session()
        ws1, ws2, ws3 = _FakeWS(), _FakeWS(), _FakeWS()
        session.add_subscriber(ws1)
        session.add_subscriber(ws2)
        session.add_subscriber(ws3)
        assert session.follower_count() == 2  # 3 total minus 1 owner


class TestTerminalSessionRemoveSubscriber:
    def _make_session(self):
        return TerminalSession("abc12345", 10, "vm-web", 1, "alice")

    def test_remove_subscriber_stops_receiving_output(self):
        session = self._make_session()
        ws = _FakeWS()
        q = session.add_subscriber(ws)
        session.remove_subscriber(ws)
        session.broadcast_output("after-remove")
        assert q.empty()

    def test_remove_subscriber_unknown_ws_is_noop(self):
        session = self._make_session()
        ws = _FakeWS()
        # Should not raise
        session.remove_subscriber(ws)

    def test_remove_subscriber_decrements_follower_count(self):
        session = self._make_session()
        ws1, ws2 = _FakeWS(), _FakeWS()
        session.add_subscriber(ws1)
        session.add_subscriber(ws2)
        assert session.follower_count() == 1
        session.remove_subscriber(ws2)
        assert session.follower_count() == 0


class TestTerminalSessionBroadcastOutput:
    def _make_session(self):
        return TerminalSession("abc12345", 10, "vm-web", 1, "alice")

    def test_broadcast_output_reaches_subscriber(self):
        session = self._make_session()
        ws = _FakeWS()
        q = session.add_subscriber(ws)
        session.broadcast_output("data chunk")
        items = _drain(q)
        assert len(items) == 1
        msg = json.loads(items[0])
        assert msg["type"] == "output"
        assert msg["data"] == "data chunk"

    def test_broadcast_output_reaches_all_subscribers(self):
        session = self._make_session()
        ws1, ws2 = _FakeWS(), _FakeWS()
        q1 = session.add_subscriber(ws1)
        q2 = session.add_subscriber(ws2)
        session.broadcast_output("shared data")
        msg1 = json.loads(_drain(q1)[0])
        msg2 = json.loads(_drain(q2)[0])
        assert msg1["data"] == "shared data"
        assert msg2["data"] == "shared data"

    def test_broadcast_output_full_queue_drops_silently(self):
        session = self._make_session()
        ws = _FakeWS()
        q = session.add_subscriber(ws)
        # Fill to maxsize (500)
        for _ in range(500):
            q.put_nowait("x")
        # Must not block or raise
        session.broadcast_output("overflow")
        assert q.full()

    def test_broadcast_output_appends_to_buffer(self):
        session = self._make_session()
        session.broadcast_output("part1")
        session.broadcast_output("part2")
        assert session._snapshot() == "part1part2"

    def test_broadcast_output_no_subscribers_only_buffers(self):
        session = self._make_session()
        session.broadcast_output("stored")
        assert session._snapshot() == "stored"


class TestTerminalSessionRingBuffer:
    def test_ring_buffer_does_not_exceed_max_size(self):
        session = TerminalSession("ring01", 1, "guest", 1, "alice")
        chunk = "x" * 10_000  # 10 KB chunk
        # Write 15 chunks = 150 KB, which exceeds MAX_BUFFER (100 KB)
        for _ in range(15):
            session.broadcast_output(chunk)
        assert session._buffer_size <= session.MAX_BUFFER

    def test_ring_buffer_evicts_oldest_chunks(self):
        session = TerminalSession("ring02", 1, "guest", 1, "alice")
        # Fill buffer with distinguishable chunks
        chunk = "A" * (session.MAX_BUFFER // 2)  # 50 KB each
        session.broadcast_output(chunk)           # chunk 0 — will be evicted
        session.broadcast_output(chunk)           # chunk 1 — will be evicted
        session.broadcast_output("B" * 1000)      # chunk 2 — should survive
        snapshot = session._snapshot()
        # The oldest large chunks should have been removed to stay within MAX_BUFFER
        assert "B" * 1000 in snapshot

    def test_ring_buffer_size_tracks_correctly_after_eviction(self):
        session = TerminalSession("ring03", 1, "guest", 1, "alice")
        big = "Z" * session.MAX_BUFFER
        session.broadcast_output(big)
        # Writing another large chunk should evict the first
        session.broadcast_output("A" * 1000)
        assert session._buffer_size <= session.MAX_BUFFER

    def test_ring_buffer_exact_max_size_stays(self):
        session = TerminalSession("ring04", 1, "guest", 1, "alice")
        exact = "E" * session.MAX_BUFFER
        session.broadcast_output(exact)
        # Exactly at the limit: nothing should be evicted yet
        assert session._buffer_size == session.MAX_BUFFER

    def test_ring_buffer_one_byte_over_evicts(self):
        session = TerminalSession("ring05", 1, "guest", 1, "alice")
        session.broadcast_output("A" * session.MAX_BUFFER)
        session.broadcast_output("B")  # one byte over: first chunk evicted
        assert "A" not in session._snapshot()
        assert session._snapshot() == "B"

    def test_late_joiner_gets_catchup_from_buffer(self):
        session = TerminalSession("ring06", 1, "guest", 1, "alice")
        session.broadcast_output("line1\n")
        session.broadcast_output("line2\n")
        ws = _FakeWS()
        q = session.add_subscriber(ws)
        items = _drain(q)
        assert len(items) == 1
        msg = json.loads(items[0])
        assert "line1\n" in msg["data"]
        assert "line2\n" in msg["data"]


class TestTerminalSessionSendControl:
    def _make_session(self):
        return TerminalSession("ctrl01", 10, "vm-web", 1, "alice")

    def test_send_control_reaches_all_subscribers(self):
        session = self._make_session()
        ws1, ws2 = _FakeWS(), _FakeWS()
        q1 = session.add_subscriber(ws1)
        q2 = session.add_subscriber(ws2)
        session.send_control({"type": "disconnected", "reason": "timeout"})
        msg1 = json.loads(_drain(q1)[-1])
        msg2 = json.loads(_drain(q2)[-1])
        assert msg1["type"] == "disconnected"
        assert msg2["type"] == "disconnected"

    def test_send_control_full_queue_drops_silently(self):
        session = self._make_session()
        ws = _FakeWS()
        q = session.add_subscriber(ws)
        for _ in range(500):
            q.put_nowait("filler")
        # Must not block or raise
        session.send_control({"type": "disconnected"})

    def test_send_control_no_subscribers_is_noop(self):
        session = self._make_session()
        # Should not raise
        session.send_control({"type": "disconnected"})

    def test_send_control_serialises_to_json(self):
        session = self._make_session()
        ws = _FakeWS()
        q = session.add_subscriber(ws)
        session.send_control({"type": "resize", "cols": 80, "rows": 24})
        raw = _drain(q)[0]
        msg = json.loads(raw)
        assert msg["cols"] == 80
        assert msg["rows"] == 24


class TestTerminalSessionFollowerCount:
    def _make_session(self):
        return TerminalSession("fc01", 10, "vm-web", 1, "alice")

    def test_zero_subscribers(self):
        assert self._make_session().follower_count() == 0

    def test_one_subscriber_is_owner_not_follower(self):
        session = self._make_session()
        session.add_subscriber(_FakeWS())
        assert session.follower_count() == 0

    def test_two_subscribers_one_follower(self):
        session = self._make_session()
        # Keep explicit references so CPython does not reuse the same id()
        ws1, ws2 = _FakeWS(), _FakeWS()
        session.add_subscriber(ws1)
        session.add_subscriber(ws2)
        assert session.follower_count() == 1

    def test_follower_count_after_remove(self):
        session = self._make_session()
        ws1, ws2, ws3 = _FakeWS(), _FakeWS(), _FakeWS()
        session.add_subscriber(ws1)
        session.add_subscriber(ws2)
        session.add_subscriber(ws3)
        assert session.follower_count() == 2
        session.remove_subscriber(ws3)
        assert session.follower_count() == 1


# ---------------------------------------------------------------------------
# TerminalSessionRegistry
# ---------------------------------------------------------------------------

class TestTerminalSessionRegistry:
    def test_create_returns_terminal_session(self):
        reg = TerminalSessionRegistry()
        session = reg.create(10, "vm-web", 1, "alice")
        assert isinstance(session, TerminalSession)

    def test_create_assigns_session_id(self):
        reg = TerminalSessionRegistry()
        session = reg.create(10, "vm-web", 1, "alice")
        assert len(session.session_id) == 32

    def test_create_stores_guest_metadata(self):
        reg = TerminalSessionRegistry()
        session = reg.create(42, "lxc-db", 7, "bob")
        assert session.guest_id == 42
        assert session.guest_name == "lxc-db"
        assert session.owner_user_id == 7
        assert session.owner_username == "bob"

    def test_get_returns_created_session(self):
        reg = TerminalSessionRegistry()
        created = reg.create(10, "vm-web", 1, "alice")
        retrieved = reg.get(created.session_id)
        assert retrieved is created

    def test_get_returns_none_for_unknown_id(self):
        reg = TerminalSessionRegistry()
        assert reg.get("doesnotexist") is None

    def test_remove_makes_session_unreachable(self):
        reg = TerminalSessionRegistry()
        session = reg.create(10, "vm-web", 1, "alice")
        reg.remove(session.session_id)
        assert reg.get(session.session_id) is None

    def test_remove_nonexistent_is_noop(self):
        reg = TerminalSessionRegistry()
        # Should not raise
        reg.remove("ghost")

    def test_get_all_returns_all_sessions(self):
        reg = TerminalSessionRegistry()
        s1 = reg.create(1, "vm-a", 1, "alice")
        s2 = reg.create(2, "vm-b", 2, "bob")
        all_sessions = reg.get_all()
        assert s1 in all_sessions
        assert s2 in all_sessions

    def test_get_all_returns_empty_when_none(self):
        reg = TerminalSessionRegistry()
        assert reg.get_all() == []

    def test_get_all_after_remove(self):
        reg = TerminalSessionRegistry()
        s1 = reg.create(1, "vm-a", 1, "alice")
        s2 = reg.create(2, "vm-b", 2, "bob")
        reg.remove(s1.session_id)
        remaining = reg.get_all()
        assert s1 not in remaining
        assert s2 in remaining

    def test_get_all_returns_copy(self):
        reg = TerminalSessionRegistry()
        reg.create(1, "vm-a", 1, "alice")
        first = reg.get_all()
        reg.create(2, "vm-b", 2, "bob")
        second = reg.get_all()
        assert len(first) == 1
        assert len(second) == 2

    def test_create_generates_unique_ids(self):
        reg = TerminalSessionRegistry()
        ids = {reg.create(i, f"vm-{i}", 1, "alice").session_id for i in range(20)}
        assert len(ids) == 20


# ---------------------------------------------------------------------------
# CursorHub
# ---------------------------------------------------------------------------

class TestCursorHubUpdate:
    def test_update_stores_position(self):
        ch = CursorHub()
        ch.update("alice", "Alice A", "/guests", 0.5, 0.3, "#ff0000")
        entries = ch.get_for_page("/guests")
        assert len(entries) == 1
        assert entries[0]["username"] == "alice"

    def test_update_overwrites_previous_position(self):
        ch = CursorHub()
        ch.update("alice", "Alice A", "/guests", 0.1, 0.2, "#ff0000")
        ch.update("alice", "Alice A", "/guests", 0.9, 0.8, "#ff0000")
        entries = ch.get_for_page("/guests")
        assert len(entries) == 1
        assert entries[0]["x_pct"] == 0.9
        assert entries[0]["y_pct"] == 0.8

    def test_update_stores_all_fields(self):
        ch = CursorHub()
        ch.update("bob", "Bob B", "/hosts", 0.25, 0.75, "#00ff00")
        entry = ch.get_for_page("/hosts")[0]
        assert entry["display_name"] == "Bob B"
        assert entry["x_pct"] == 0.25
        assert entry["y_pct"] == 0.75
        assert entry["color"] == "#00ff00"

    def test_update_multiple_users(self):
        ch = CursorHub()
        ch.update("alice", "Alice", "/guests", 0.1, 0.2, "#red")
        ch.update("bob", "Bob", "/guests", 0.3, 0.4, "#blue")
        entries = ch.get_for_page("/guests")
        usernames = {e["username"] for e in entries}
        assert usernames == {"alice", "bob"}


class TestCursorHubGetForPage:
    def test_only_returns_cursors_on_matching_page(self):
        ch = CursorHub()
        ch.update("alice", "Alice", "/guests", 0.5, 0.5, "#fff")
        ch.update("bob", "Bob", "/hosts", 0.5, 0.5, "#fff")
        guests_entries = ch.get_for_page("/guests")
        assert all(e["username"] != "bob" for e in guests_entries)

    def test_returns_empty_for_page_with_no_cursors(self):
        ch = CursorHub()
        assert ch.get_for_page("/nonexistent") == []

    def test_excludes_specified_username(self):
        ch = CursorHub()
        ch.update("alice", "Alice", "/guests", 0.1, 0.2, "#fff")
        ch.update("bob", "Bob", "/guests", 0.3, 0.4, "#fff")
        entries = ch.get_for_page("/guests", exclude_username="alice")
        assert all(e["username"] != "alice" for e in entries)
        assert any(e["username"] == "bob" for e in entries)

    def test_exclude_none_returns_all(self):
        ch = CursorHub()
        ch.update("alice", "Alice", "/guests", 0.1, 0.2, "#fff")
        ch.update("bob", "Bob", "/guests", 0.3, 0.4, "#fff")
        entries = ch.get_for_page("/guests", exclude_username=None)
        usernames = {e["username"] for e in entries}
        assert usernames == {"alice", "bob"}

    def test_expired_cursors_are_excluded(self):
        ch = CursorHub()
        ch.update("alice", "Alice", "/guests", 0.5, 0.5, "#fff")
        # Wind back the timestamp past the expiry window
        with ch._lock:
            ch._positions["alice"]["ts"] = time.time() - CursorHub.EXPIRY - 0.1
        entries = ch.get_for_page("/guests")
        assert all(e["username"] != "alice" for e in entries)

    def test_cursor_at_exact_expiry_is_excluded(self):
        ch = CursorHub()
        ch.update("alice", "Alice", "/guests", 0.5, 0.5, "#fff")
        with ch._lock:
            ch._positions["alice"]["ts"] = time.time() - CursorHub.EXPIRY
        entries = ch.get_for_page("/guests")
        # Exactly at expiry: now - ts == EXPIRY → NOT < EXPIRY → excluded
        assert all(e["username"] != "alice" for e in entries)

    def test_fresh_cursor_is_included(self):
        ch = CursorHub()
        ch.update("alice", "Alice", "/guests", 0.5, 0.5, "#fff")
        entries = ch.get_for_page("/guests")
        assert any(e["username"] == "alice" for e in entries)

    def test_result_does_not_include_page_or_ts_fields(self):
        ch = CursorHub()
        ch.update("alice", "Alice", "/guests", 0.5, 0.5, "#fff")
        entry = ch.get_for_page("/guests")[0]
        assert "page" not in entry
        assert "ts" not in entry

    def test_mix_of_expired_and_fresh(self):
        ch = CursorHub()
        ch.update("alice", "Alice", "/guests", 0.1, 0.2, "#fff")
        ch.update("bob", "Bob", "/guests", 0.3, 0.4, "#fff")
        with ch._lock:
            ch._positions["alice"]["ts"] = time.time() - CursorHub.EXPIRY - 1
        entries = ch.get_for_page("/guests")
        usernames = {e["username"] for e in entries}
        assert "alice" not in usernames
        assert "bob" in usernames


# ---------------------------------------------------------------------------
# Thread-safety smoke tests
# ---------------------------------------------------------------------------

class TestThreadSafety:
    """Concurrent access must not raise exceptions or corrupt state."""

    def test_collaboration_hub_concurrent_connect_disconnect(self):
        hub = CollaborationHub()
        errors = []

        def worker(user_id):
            try:
                q = hub.connect(user_id, f"user{user_id}", f"User {user_id}")
                hub.update_presence(user_id, page="/page")
                hub.get_online_users()
                hub.broadcast({"type": "ping"})
                hub.disconnect(user_id, event_queue=q)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Exceptions in threads: {errors}"

    def test_terminal_session_concurrent_broadcast(self):
        session = TerminalSession("thr01", 1, "vm", 1, "alice")
        ws_list = [_FakeWS() for _ in range(10)]
        for ws in ws_list:
            session.add_subscriber(ws)
        errors = []

        def broadcaster(n):
            try:
                for _ in range(50):
                    session.broadcast_output(f"chunk-{n}")
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=broadcaster, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Exceptions in threads: {errors}"

    def test_cursor_hub_concurrent_update_and_read(self):
        ch = CursorHub()
        errors = []

        def updater(username):
            try:
                for i in range(50):
                    ch.update(username, username.title(), "/page",
                               i / 100, i / 100, "#000")
                    ch.get_for_page("/page", exclude_username=username)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=updater, args=(f"user{i}",))
                   for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Exceptions in threads: {errors}"
