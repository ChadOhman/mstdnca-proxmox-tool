# Unified Notifications & Host Update Tracking Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist host APT updates in the database, add "applied/resolved" Discord notifications for updates and services, unify the notification lifecycle across all entity types, and update the mobile API + wiki.

**Architecture:** New `HostUpdatePackage` model mirrors the existing `UpdatePackage` pattern. Three new notification functions in `core/notifier.py`. Service state transition detection in `core/scanner.py`. Dashboard, mobile API, and wiki updated to surface host update data.

**Tech Stack:** Python 3.13, Flask, SQLAlchemy, Discord webhooks, pytest

**Spec:** `docs/superpowers/specs/2026-03-18-unified-notifications-host-tracking-design.md`

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `models.py` | Modify | Add `HostUpdatePackage` model, `ProxmoxHost` relationship + helpers, update `PushWebhook.VALID_EVENTS` |
| `core/notifier.py` | Modify | Add `send_updates_applied_notification`, `send_service_failed_notification`, `send_service_recovery_notification` |
| `core/scanner.py` | Modify | Service state transition detection in `_upsert_service` |
| `core/scheduler.py` | Modify | Persist host packages in `_check_host_updates`, batch applied notifications in `_run_auto_updates` |
| `core/dashboard_stats.py` | Modify | Add host update counts to stats dict |
| `core/push_notifier.py` | Modify | Handle `service_failed`/`service_down` alias, dispatch `service_recovered` |
| `routes/api.py` | Modify | Call `send_updates_applied_notification` in `_run_update_background` success paths |
| `routes/api_v1.py` | Modify | Add host update fields to dashboard/hosts/alerts endpoints |
| `routes/hosts.py` | Modify | Call `send_updates_applied_notification` in `_run_apply` success path |
| `templates/dashboard.html` | Modify | Add host update stat cards |
| `tests/test_models.py` | Modify | Add `HostUpdatePackage` model tests |
| `tests/test_notifier.py` | Modify | Add tests for 3 new notification functions |
| `tests/test_scanner_transitions.py` | Create | Service transition detection tests |
| `tests/test_dashboard.py` | Modify | Add host update count tests |
| `tests/test_api_v1.py` | Modify | Add host update fields to API response tests |
| `tests/test_push_notifier.py` | Create | Alias mapping + `service_recovered` tests |
| Wiki (5 files) | Modify | Documentation updates |

---

## Task 0: Create Feature Branch

- [ ] **Step 1: Create and switch to feature branch**

```bash
git checkout -b feature/unified-notifications-host-tracking
```

All subsequent commits will land on this branch.

---

## Task 1: `HostUpdatePackage` Model

**Files:**
- Modify: `models.py:343-373` (ProxmoxHost), `models.py:478-500` (after UpdatePackage)
- Test: `tests/test_models.py`

- [ ] **Step 1: Write failing test for HostUpdatePackage creation**

In `tests/test_models.py`, add:

```python
from models import HostUpdatePackage, ProxmoxHost, db


class TestHostUpdatePackageModel:
    def test_create_host_update_package(self, app):
        with app.app_context():
            host = ProxmoxHost(name="pve1", hostname="pve1.local", host_type="pve")
            db.session.add(host)
            db.session.commit()

            pkg = HostUpdatePackage(
                host_id=host.id,
                package_name="linux-image-6.1",
                current_version="6.1.0-1",
                available_version="6.1.0-2",
                severity="critical",
                status="pending",
            )
            db.session.add(pkg)
            db.session.commit()

            assert pkg.id is not None
            assert pkg.host_id == host.id
            assert pkg.package_name == "linux-image-6.1"
            assert pkg.severity == "critical"
            assert pkg.status == "pending"
            assert pkg.applied_at is None

    def test_pending_updates_method(self, app):
        with app.app_context():
            host = ProxmoxHost(name="pve2", hostname="pve2.local", host_type="pve")
            db.session.add(host)
            db.session.commit()

            pkg1 = HostUpdatePackage(host_id=host.id, package_name="curl", status="pending", severity="normal")
            pkg2 = HostUpdatePackage(host_id=host.id, package_name="vim", status="applied", severity="normal")
            pkg3 = HostUpdatePackage(host_id=host.id, package_name="openssl", status="pending", severity="critical")
            db.session.add_all([pkg1, pkg2, pkg3])
            db.session.commit()

            pending = host.pending_updates()
            assert len(pending) == 2
            assert all(p.status == "pending" for p in pending)

    def test_security_updates_method(self, app):
        with app.app_context():
            host = ProxmoxHost(name="pve3", hostname="pve3.local", host_type="pve")
            db.session.add(host)
            db.session.commit()

            pkg1 = HostUpdatePackage(host_id=host.id, package_name="curl", status="pending", severity="normal")
            pkg2 = HostUpdatePackage(host_id=host.id, package_name="openssl", status="pending", severity="critical")
            db.session.add_all([pkg1, pkg2])
            db.session.commit()

            sec = host.security_updates()
            assert len(sec) == 1
            assert sec[0].package_name == "openssl"

    def test_cascade_delete(self, app):
        with app.app_context():
            host = ProxmoxHost(name="pve-del", hostname="pve-del.local", host_type="pve")
            db.session.add(host)
            db.session.commit()

            pkg = HostUpdatePackage(host_id=host.id, package_name="curl", status="pending", severity="normal")
            db.session.add(pkg)
            db.session.commit()
            pkg_id = pkg.id

            db.session.delete(host)
            db.session.commit()

            assert HostUpdatePackage.query.get(pkg_id) is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev pytest tests/test_models.py::TestHostUpdatePackageModel -v`
Expected: ImportError — `HostUpdatePackage` does not exist

- [ ] **Step 3: Implement HostUpdatePackage model**

In `models.py`, after the `UpdatePackage` model and its index (after line ~500), add:

```python
class HostUpdatePackage(db.Model):
    """APT package update available on a Proxmox host."""

    __tablename__ = "host_update_package"

    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey("proxmox_hosts.id", ondelete="CASCADE"), nullable=False)
    package_name = db.Column(db.String(256))
    current_version = db.Column(db.String(128))
    available_version = db.Column(db.String(128))
    severity = db.Column(db.String(32), default="normal")
    discovered_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    applied_at = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(32), default="pending")


db.Index("ix_host_update_pkg_host_status", HostUpdatePackage.host_id, HostUpdatePackage.status)
```

In the `ProxmoxHost` model (around line 365), add the relationship and helper methods:

```python
    host_update_packages = db.relationship(
        "HostUpdatePackage", backref="host", lazy=True, cascade="all, delete-orphan"
    )

    def pending_updates(self):
        return [u for u in self.host_update_packages if u.status == "pending"]

    def security_updates(self):
        return [u for u in self.host_update_packages if u.status == "pending" and u.severity == "critical"]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev pytest tests/test_models.py::TestHostUpdatePackageModel -v`
Expected: All 4 tests PASS

- [ ] **Step 5: Commit**

```bash
git add models.py tests/test_models.py
git commit -m "feat: add HostUpdatePackage model with cascade delete and helper methods"
```

---

## Task 2: Update `PushWebhook.VALID_EVENTS`

**Files:**
- Modify: `models.py:730`
- Test: `tests/test_models.py`

- [ ] **Step 1: Write failing test for new event types**

In `tests/test_models.py`, add:

```python
from models import PushWebhook


class TestPushWebhookValidEvents:
    def test_service_failed_is_valid_event(self):
        assert "service_failed" in PushWebhook.VALID_EVENTS

    def test_service_recovered_is_valid_event(self):
        assert "service_recovered" in PushWebhook.VALID_EVENTS

    def test_service_down_still_valid_for_backwards_compat(self):
        assert "service_down" in PushWebhook.VALID_EVENTS
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev pytest tests/test_models.py::TestPushWebhookValidEvents -v`
Expected: FAIL — `service_failed` and `service_recovered` not in set

- [ ] **Step 3: Update VALID_EVENTS**

In `models.py` line 730, change:

```python
VALID_EVENTS = {"security_update", "service_down", "reboot_required", "guest_error"}
```

to:

```python
VALID_EVENTS = {"security_update", "service_down", "service_failed", "service_recovered", "reboot_required", "guest_error"}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev pytest tests/test_models.py::TestPushWebhookValidEvents -v`
Expected: All 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add models.py tests/test_models.py
git commit -m "feat: add service_failed and service_recovered to PushWebhook.VALID_EVENTS"
```

---

## Task 3: `send_updates_applied_notification`

**Files:**
- Modify: `core/notifier.py` (add after line ~487)
- Test: `tests/test_notifier.py`

- [ ] **Step 1: Write failing tests**

In `tests/test_notifier.py`, add the import and test class:

```python
# Add to imports at top:
from core.notifier import send_updates_applied_notification

class TestSendUpdatesAppliedNotification:
    def _enable(self, app):
        Setting.set("discord_enabled", "true")
        Setting.set("discord_webhook_url", "https://discord.com/api/webhooks/1/tok")
        Setting.set("discord_notify_updates", "true")

    def test_empty_results_sends_nothing(self, app):
        with app.app_context():
            self._enable(app)

        with patch("urllib.request.urlopen") as mock_open:
            with app.app_context():
                send_updates_applied_notification([])

        mock_open.assert_not_called()

    def test_single_guest_sends_green_notification(self, app):
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        results = [{"name": "web01", "type": "CT", "applied": 5, "security": 1}]
        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_updates_applied_notification(results)

        assert len(captured) == 1
        body = json.loads(captured[0].data.decode())
        embed = body["embeds"][0]
        assert embed["color"] == 8505220  # _COLOR_GREEN
        assert "5" in embed["description"]
        assert "1 security" in embed["fields"][0]["value"]

    def test_batch_with_hosts_and_guests(self, app):
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        results = [
            {"name": "web01", "type": "CT", "applied": 5, "security": 0},
            {"name": "pve1", "type": "PVE", "applied": 3, "security": 0},
        ]
        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_updates_applied_notification(results)

        assert len(captured) == 1
        body = json.loads(captured[0].data.decode())
        assert "8" in body["embeds"][0]["description"]  # 5 + 3
        assert len(body["embeds"][0]["fields"]) == 2

    def test_disabled_sends_nothing(self, app):
        with app.app_context():
            Setting.set("discord_enabled", "true")
            Setting.set("discord_webhook_url", "https://discord.com/api/webhooks/1/tok")
            Setting.set("discord_notify_updates", "false")

        results = [{"name": "web01", "type": "CT", "applied": 5, "security": 0}]
        with patch("urllib.request.urlopen") as mock_open:
            with app.app_context():
                send_updates_applied_notification(results)

        mock_open.assert_not_called()

    def test_no_dedup(self, app):
        """Applied notifications should always send (no dedup)."""
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        results = [{"name": "web01", "type": "CT", "applied": 5, "security": 0}]

        for _ in range(2):
            with patch("urllib.request.urlopen", return_value=fake_resp) as mock_open:
                with app.app_context():
                    send_updates_applied_notification(results)
            mock_open.assert_called_once()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev pytest tests/test_notifier.py::TestSendUpdatesAppliedNotification -v`
Expected: ImportError — function does not exist

- [ ] **Step 3: Implement send_updates_applied_notification**

In `core/notifier.py`, add at the end of the file:

```python
def send_updates_applied_notification(results):
    """Send notification about updates that were just applied.

    results: list of dicts with keys name, type, applied, security.
    """
    if Setting.get("discord_notify_updates", "true") != "true":
        return

    if not results:
        return

    total_applied = sum(r["applied"] for r in results)
    entity_count = len(results)
    entity_word = "guest(s)" if all(r["type"] in ("CT", "VM") for r in results) else "target(s)"

    fields = []
    for r in results:
        value = f"{r['applied']} applied"
        if r["security"] > 0:
            value += f" ({r['security']} security)"
        fields.append({
            "name": f"{r['name']} ({r['type']})",
            "value": value,
            "inline": False,
        })

    embeds = [{
        "title": "\u2705 Updates applied",
        "description": f"**{total_applied}** update(s) applied across **{entity_count}** {entity_word}.",
        "color": _COLOR_GREEN,
        "fields": fields,
        "footer": {"text": "Log in to MCAT to review details."},
    }]

    ok, msg = _send_discord(embeds)
    if ok:
        logger.info(f"Updates-applied notification sent for {entity_count} target(s)")
    else:
        logger.error(f"Failed to send updates-applied notification: {msg}")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev pytest tests/test_notifier.py::TestSendUpdatesAppliedNotification -v`
Expected: All 5 tests PASS

- [ ] **Step 5: Commit**

```bash
git add core/notifier.py tests/test_notifier.py
git commit -m "feat: add send_updates_applied_notification for guest and host updates"
```

---

## Task 4: Service State Change Notifications

**Files:**
- Modify: `core/notifier.py`
- Test: `tests/test_notifier.py`

- [ ] **Step 1: Write failing tests**

In `tests/test_notifier.py`, add:

```python
from core.notifier import send_service_failed_notification, send_service_recovery_notification

class TestSendServiceFailedNotification:
    def _enable(self, app):
        Setting.set("discord_enabled", "true")
        Setting.set("discord_webhook_url", "https://discord.com/api/webhooks/1/tok")
        Setting.set("discord_notify_services", "true")

    def test_sends_red_notification(self, app):
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_service_failed_notification("web01", "nginx")

        assert len(captured) == 1
        body = json.loads(captured[0].data.decode())
        embed = body["embeds"][0]
        assert embed["color"] == 14431557  # _COLOR_RED
        assert "nginx" in embed["title"]
        assert "web01" in embed["description"]

    def test_disabled_sends_nothing(self, app):
        with app.app_context():
            Setting.set("discord_notify_services", "false")

        with patch("urllib.request.urlopen") as mock_open:
            with app.app_context():
                send_service_failed_notification("web01", "nginx")

        mock_open.assert_not_called()


class TestSendServiceRecoveryNotification:
    def _enable(self, app):
        Setting.set("discord_enabled", "true")
        Setting.set("discord_webhook_url", "https://discord.com/api/webhooks/1/tok")
        Setting.set("discord_notify_services", "true")

    def test_sends_green_notification(self, app):
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_service_recovery_notification("web01", "nginx")

        assert len(captured) == 1
        body = json.loads(captured[0].data.decode())
        embed = body["embeds"][0]
        assert embed["color"] == 8505220  # _COLOR_GREEN
        assert "nginx" in embed["title"]
        assert "web01" in embed["description"]

    def test_disabled_sends_nothing(self, app):
        with app.app_context():
            Setting.set("discord_notify_services", "false")

        with patch("urllib.request.urlopen") as mock_open:
            with app.app_context():
                send_service_recovery_notification("web01", "nginx")

        mock_open.assert_not_called()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev pytest tests/test_notifier.py::TestSendServiceFailedNotification tests/test_notifier.py::TestSendServiceRecoveryNotification -v`
Expected: ImportError

- [ ] **Step 3: Implement both functions**

In `core/notifier.py`, add:

```python
def send_service_failed_notification(guest_name, service_name):
    """Send notification when a service transitions to failed state."""
    if Setting.get("discord_notify_services", "true") != "true":
        return

    embeds = [{
        "title": f"\u274c Service failed: {service_name}",
        "description": f"**{service_name}** on **{guest_name}** has stopped running.",
        "color": _COLOR_RED,
        "footer": {"text": "Log in to MCAT to investigate."},
    }]

    ok, msg = _send_discord(embeds)
    if ok:
        logger.info(f"Service-failed notification sent: {service_name} on {guest_name}")
    else:
        logger.error(f"Failed to send service-failed notification: {msg}")


def send_service_recovery_notification(guest_name, service_name):
    """Send notification when a service recovers from failed state."""
    if Setting.get("discord_notify_services", "true") != "true":
        return

    embeds = [{
        "title": f"\u2705 Service recovered: {service_name}",
        "description": f"**{service_name}** on **{guest_name}** is running again.",
        "color": _COLOR_GREEN,
        "footer": {"text": "Log in to MCAT to review."},
    }]

    ok, msg = _send_discord(embeds)
    if ok:
        logger.info(f"Service-recovery notification sent: {service_name} on {guest_name}")
    else:
        logger.error(f"Failed to send service-recovery notification: {msg}")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev pytest tests/test_notifier.py::TestSendServiceFailedNotification tests/test_notifier.py::TestSendServiceRecoveryNotification -v`
Expected: All 4 tests PASS

- [ ] **Step 5: Commit**

```bash
git add core/notifier.py tests/test_notifier.py
git commit -m "feat: add service failed/recovery Discord notifications"
```

---

## Task 5: Service State Transition Detection in Scanner

**Files:**
- Modify: `core/scanner.py:1228-1267` (`_upsert_service`)
- Test: `tests/test_scanner_transitions.py` (new file)

- [ ] **Step 1: Write failing tests for transition detection**

Create `tests/test_scanner_transitions.py`:

```python
"""Tests for service state transition detection in _upsert_service."""
from datetime import datetime, timezone
from unittest.mock import patch

from core.scanner import _upsert_service
from models import Guest, GuestService, ProxmoxHost, db


class TestUpsertServiceTransitions:
    def _make_guest(self, app):
        with app.app_context():
            host = ProxmoxHost(name="pve1", hostname="pve1.local", host_type="pve")
            db.session.add(host)
            db.session.commit()
            guest = Guest(name="web01", vmid=100, guest_type="ct", proxmox_host_id=host.id)
            db.session.add(guest)
            db.session.commit()
            return guest.id

    def test_running_to_failed_sends_discord_and_push(self, app):
        guest_id = self._make_guest(app)
        with app.app_context():
            guest = Guest.query.get(guest_id)
            now = datetime.now(timezone.utc)
            svc = GuestService(guest_id=guest.id, service_name="nginx", unit_name="nginx.service", status="running", last_checked=now)
            db.session.add(svc)
            db.session.commit()

            with patch("core.notifier.send_service_failed_notification") as mock_discord, \
                 patch("core.push_notifier.dispatch_push_alerts") as mock_push:
                _upsert_service(guest, "nginx", "nginx.service", 80, "failed", now)
                mock_discord.assert_called_once_with("web01", "nginx")
                mock_push.assert_called_once()

    def test_failed_to_running_sends_recovery(self, app):
        guest_id = self._make_guest(app)
        with app.app_context():
            guest = Guest.query.get(guest_id)
            now = datetime.now(timezone.utc)
            svc = GuestService(guest_id=guest.id, service_name="nginx", unit_name="nginx.service", status="failed", last_checked=now)
            db.session.add(svc)
            db.session.commit()

            with patch("core.notifier.send_service_recovery_notification") as mock_discord, \
                 patch("core.push_notifier.dispatch_push_alerts") as mock_push:
                _upsert_service(guest, "nginx", "nginx.service", 80, "running", now)
                mock_discord.assert_called_once_with("web01", "nginx")
                mock_push.assert_called_once()

    def test_failed_to_failed_no_notification(self, app):
        guest_id = self._make_guest(app)
        with app.app_context():
            guest = Guest.query.get(guest_id)
            now = datetime.now(timezone.utc)
            svc = GuestService(guest_id=guest.id, service_name="nginx", unit_name="nginx.service", status="failed", last_checked=now)
            db.session.add(svc)
            db.session.commit()

            with patch("core.notifier.send_service_failed_notification") as mock_discord:
                _upsert_service(guest, "nginx", "nginx.service", 80, "failed", now)
                mock_discord.assert_not_called()

    def test_new_service_failed_sends_notification(self, app):
        guest_id = self._make_guest(app)
        with app.app_context():
            guest = Guest.query.get(guest_id)
            now = datetime.now(timezone.utc)

            with patch("core.notifier.send_service_failed_notification") as mock_discord, \
                 patch("core.push_notifier.dispatch_push_alerts") as mock_push:
                _upsert_service(guest, "nginx", "nginx.service", 80, "failed", now)
                mock_discord.assert_called_once_with("web01", "nginx")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev pytest tests/test_scanner_transitions.py::TestUpsertServiceTransitions -v`
Expected: FAIL — `send_service_failed_notification` not called in scanner (function doesn't exist yet or isn't wired up)

- [ ] **Step 3: Modify `_upsert_service` in `core/scanner.py`**

Replace the `_upsert_service` function (lines 1228-1267) with:

```python
def _upsert_service(guest, service_key, unit_name, default_port, status, now):
    """Create or update a GuestService record."""
    try:
        _safe_unit_name(unit_name)
    except ValueError:
        logger.warning(f"Skipping service with invalid unit name: {unit_name!r}")
        return
    existing = GuestService.query.filter_by(guest_id=guest.id, unit_name=unit_name).first()
    if status in ("running", "failed"):
        if existing:
            old_status = existing.status
            existing.status = status
            existing.last_checked = now
            # Transition: running -> failed
            if status == "failed" and old_status != "failed":
                try:
                    from core.notifier import send_service_failed_notification
                    send_service_failed_notification(guest.name, service_key)
                except Exception:
                    pass
                try:
                    from core.push_notifier import dispatch_push_alerts
                    dispatch_push_alerts(guest, "service_failed", {"service": service_key, "unit": unit_name})
                except Exception:
                    pass
            # Transition: failed -> running
            elif status == "running" and old_status == "failed":
                try:
                    from core.notifier import send_service_recovery_notification
                    send_service_recovery_notification(guest.name, service_key)
                except Exception:
                    pass
                try:
                    from core.push_notifier import dispatch_push_alerts
                    dispatch_push_alerts(guest, "service_recovered", {"service": service_key, "unit": unit_name})
                except Exception:
                    pass
        else:
            svc = GuestService(
                guest_id=guest.id,
                service_name=service_key,
                unit_name=unit_name,
                port=default_port,
                status=status,
                last_checked=now,
                auto_detected=True,
            )
            db.session.add(svc)
            # New service discovered as failed
            if status == "failed":
                try:
                    from core.notifier import send_service_failed_notification
                    send_service_failed_notification(guest.name, service_key)
                except Exception:
                    pass
                try:
                    from core.push_notifier import dispatch_push_alerts
                    dispatch_push_alerts(guest, "service_failed", {"service": service_key, "unit": unit_name})
                except Exception:
                    pass
    elif status == "stopped" and existing:
        existing.status = status
        existing.last_checked = now
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev pytest tests/test_scanner_transitions.py::TestUpsertServiceTransitions -v`
Expected: All 4 tests PASS

- [ ] **Step 5: Run full test suite to check for regressions**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev pytest --tb=short -q`
Expected: All existing tests still pass

- [ ] **Step 6: Commit**

```bash
git add core/scanner.py tests/test_scanner_transitions.py
git commit -m "feat: add service state transition detection with Discord + push notifications"
```

---

## Task 6: Push Notifier Alias Mapping

**Files:**
- Modify: `core/push_notifier.py:20-81`
- Test: `tests/test_push_notifier.py`

- [ ] **Step 1: Write failing test for alias mapping**

Create `tests/test_push_notifier.py`:

```python
"""Tests for push notification dispatch with event alias mapping."""
from unittest.mock import MagicMock, patch

from models import PushWebhook


class TestServiceFailedAliasMapping:
    """When service_failed fires, webhooks subscribed to service_down should also match."""

    def test_service_failed_matches_service_down_subscription(self, app):
        with app.app_context():
            # Create a webhook subscribed to "service_down" (old name)
            from models import PushWebhook, User, db
            user = User.query.filter_by(username="admin").first()
            wh = PushWebhook(
                user_id=user.id,
                url="https://example.com/push",
                device_token="test-token",
                platform="ios",
                events='["service_down"]',
            )
            db.session.add(wh)
            db.session.commit()

            from models import Guest, ProxmoxHost
            host = ProxmoxHost(name="pve1", hostname="pve1.local", host_type="pve")
            db.session.add(host)
            db.session.commit()
            guest = Guest(name="web01", vmid=100, guest_type="ct", proxmox_host_id=host.id)
            db.session.add(guest)
            db.session.commit()

            with patch("core.push_notifier.http_requests") as mock_http:
                mock_http.post.return_value = MagicMock(status_code=200)
                from core.push_notifier import dispatch_push_alerts
                dispatch_push_alerts(guest, "service_failed", {"service": "nginx"})

            mock_http.post.assert_called_once()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev pytest tests/test_push_notifier.py::TestServiceFailedAliasMapping -v`
Expected: FAIL — `service_failed` not in subscribed events `["service_down"]`

- [ ] **Step 3: Add alias mapping to dispatch_push_alerts**

In `core/push_notifier.py`, at the top of `dispatch_push_alerts` (after the VALID_EVENTS check), add alias expansion logic:

```python
    # Alias mapping: service_failed also matches subscriptions to service_down
    _EVENT_ALIASES = {"service_failed": "service_down"}
```

Then in the subscription check loop, change:

```python
        if event_type not in subscribed_events:
            continue
```

to:

```python
        alias = _EVENT_ALIASES.get(event_type)
        if event_type not in subscribed_events and (alias is None or alias not in subscribed_events):
            continue
```

- [ ] **Step 4: Run test to verify it passes**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev pytest tests/test_push_notifier.py::TestServiceFailedAliasMapping -v`
Expected: PASS

- [ ] **Step 5: Run full push notifier tests**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev pytest tests/test_push_notifier.py -v --tb=short`
Expected: All tests pass

- [ ] **Step 6: Commit**

```bash
git add core/push_notifier.py tests/test_push_notifier.py
git commit -m "feat: add service_failed/service_down alias mapping in push notifier"
```

---

## Task 7: Persist Host Packages in Scheduler

**Files:**
- Modify: `core/scheduler.py:471-506` (`_check_host_updates`)
- Test: `tests/test_scheduler.py`

- [ ] **Step 1: Write failing test**

In `tests/test_scheduler.py`, add a test for host package persistence. The exact test depends on existing patterns in that file. Add:

```python
class TestCheckHostUpdatesPersistence:
    def test_host_packages_persisted_to_db(self, app):
        with app.app_context():
            from models import HostUpdatePackage, ProxmoxHost, db

            host = ProxmoxHost(name="pve-test", hostname="pve-test.local", host_type="pve")
            db.session.add(host)
            db.session.commit()

            # Simulate what _check_host_updates should do
            fake_updates = [
                {"Package": "linux-image-6.1", "OldVersion": "6.1.0-1", "Version": "6.1.0-2", "Priority": "important"},
                {"Package": "curl", "OldVersion": "7.81.0", "Version": "7.85.0", "Priority": "optional"},
            ]

            # After _check_host_updates runs, packages should be in DB
            from core.scheduler import _persist_host_packages
            _persist_host_packages(host, fake_updates)

            pkgs = HostUpdatePackage.query.filter_by(host_id=host.id, status="pending").all()
            assert len(pkgs) == 2
            assert any(p.package_name == "linux-image-6.1" and p.severity == "critical" for p in pkgs)
            assert any(p.package_name == "curl" and p.severity == "normal" for p in pkgs)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev pytest tests/test_scheduler.py::TestCheckHostUpdatesPersistence -v`
Expected: ImportError — `_persist_host_packages` does not exist

- [ ] **Step 3: Add `_persist_host_packages` helper and update `_check_host_updates`**

In `core/scheduler.py`, add a helper function:

```python
def _persist_host_packages(host, api_updates):
    """Persist APT update packages from Proxmox API to HostUpdatePackage table."""
    from models import HostUpdatePackage, db

    # Clear old pending packages
    HostUpdatePackage.query.filter_by(host_id=host.id, status="pending").delete()

    _PRIORITY_MAP = {"important": "critical", "required": "important"}

    for upd in api_updates:
        severity = _PRIORITY_MAP.get(upd.get("Priority", ""), "normal")
        pkg = HostUpdatePackage(
            host_id=host.id,
            package_name=upd.get("Package", "unknown"),
            current_version=upd.get("OldVersion", ""),
            available_version=upd.get("Version") or upd.get("NewVersion", ""),
            severity=severity,
            status="pending",
        )
        db.session.add(pkg)

    db.session.commit()
```

Then modify `_check_host_updates` (lines 471-506) to call `_persist_host_packages` and pass the raw update list:

In the loop body where `host_results` is built (around line 496), after getting `updates`, add:

```python
                _persist_host_packages(host, updates)
```

Keep the existing notification logic unchanged — it still uses `update_count: len(updates)`.

- [ ] **Step 4: Run test to verify it passes**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev pytest tests/test_scheduler.py::TestCheckHostUpdatesPersistence -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add core/scheduler.py tests/test_scheduler.py
git commit -m "feat: persist host APT packages to database during scheduled checks"
```

---

## Task 8: Batch Applied Notification in Auto-Updates

**Files:**
- Modify: `core/scheduler.py:30-69` (`_run_auto_updates`)
- Modify: `routes/api.py:133-150,180-195` (`_run_update_background` success paths)
- Modify: `routes/hosts.py:606-641` (`_run_apply` success path)

- [ ] **Step 1: Modify `_run_auto_updates` to collect results and send batch notification**

In `core/scheduler.py`, modify `_run_auto_updates` to collect apply results. After the loop that processes guests (around line 64-68), add:

```python
        # Collect results for batch notification
        apply_results = []
```

Before the loop, and inside the `if ok:` success branch, add. Note: `apply_updates` marks packages as "applied" and sets `applied_at` with `datetime.now(timezone.utc)`, so use a UTC-aware timestamp for comparison:

```python
                from datetime import timezone as _tz
                batch_start = datetime.now(_tz.utc)
```

Set `batch_start` before the loop starts. Then inside the `if ok:` branch:

```python
                applied_count = len([u for u in guest.updates if u.status == "applied" and u.applied_at and u.applied_at >= batch_start])
                security_count = len([u for u in guest.updates if u.status == "applied" and u.applied_at and u.applied_at >= batch_start and u.severity == "critical"])
                apply_results.append({
                    "name": guest.name,
                    "type": guest.guest_type.upper(),
                    "applied": applied_count,
                    "security": security_count,
                })
```

After the loop ends, add:

```python
        if apply_results:
            from core.notifier import send_updates_applied_notification
            send_updates_applied_notification(apply_results)
```

- [ ] **Step 2: Modify `_run_update_background` in `routes/api.py` for manual guest apply**

In `routes/api.py`, in both SSH success path (after line 148 `db.session.commit()`) and agent success path (after line 193 `db.session.commit()`), add before `job.finish(True)`:

```python
                                try:
                                    from core.notifier import send_updates_applied_notification
                                    applied_count = len([p for p in guest.updates if p.status == "applied" and p.applied_at == now])
                                    security_count = len([p for p in guest.updates if p.status == "applied" and p.applied_at == now and p.severity == "critical"])
                                    send_updates_applied_notification([{
                                        "name": guest.name,
                                        "type": guest.guest_type.upper(),
                                        "applied": applied_count,
                                        "security": security_count,
                                    }])
                                except Exception:
                                    pass
```

- [ ] **Step 3: Modify `_run_apply` in `routes/hosts.py` for manual host apply**

In `routes/hosts.py`, in `_run_apply` (line 606), after the `success = exit_code == 0` check and before the final `with _apply_lock:` block, add:

```python
            if success:
                try:
                    from models import HostUpdatePackage, ProxmoxHost
                    host = ProxmoxHost.query.get(host_id)
                    if host:
                        now_utc = datetime.now(timezone.utc)
                        pending = HostUpdatePackage.query.filter_by(host_id=host_id, status="pending").all()
                        applied_count = len(pending)
                        security_count = len([p for p in pending if p.severity == "critical"])
                        for pkg in pending:
                            pkg.status = "applied"
                            pkg.applied_at = now_utc
                        db.session.commit()

                        from core.notifier import send_updates_applied_notification
                        type_label = "PBS" if host.host_type == "pbs" else "PVE"
                        send_updates_applied_notification([{
                            "name": host.name,
                            "type": type_label,
                            "applied": applied_count,
                            "security": security_count,
                        }])
                except Exception as e:
                    logger.error(f"Failed to record host update apply: {e}")
```

Note: You'll need to add the required imports (`datetime`, `timezone`, `db`) at the top of `routes/hosts.py` if not already present.

- [ ] **Step 4: Run full test suite**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev pytest --tb=short -q`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
git add core/scheduler.py routes/api.py routes/hosts.py
git commit -m "feat: send applied notification after manual and auto guest/host updates"
```

---

## Task 9: Dashboard Stats & Template

**Files:**
- Modify: `core/dashboard_stats.py:52-61`
- Modify: `templates/dashboard.html:138-172`
- Test: `tests/test_dashboard.py`

- [ ] **Step 1: Write failing test for host update counts in dashboard stats**

In `tests/test_dashboard.py`, add:

```python
class TestDashboardStatsHostUpdates:
    def test_host_update_counts_included(self, app):
        with app.app_context():
            from models import HostUpdatePackage, ProxmoxHost, User, db

            host = ProxmoxHost(name="pve1", hostname="pve1.local", host_type="pve")
            db.session.add(host)
            db.session.commit()

            pkg1 = HostUpdatePackage(host_id=host.id, package_name="curl", status="pending", severity="normal")
            pkg2 = HostUpdatePackage(host_id=host.id, package_name="openssl", status="pending", severity="critical")
            pkg3 = HostUpdatePackage(host_id=host.id, package_name="vim", status="applied", severity="normal")
            db.session.add_all([pkg1, pkg2, pkg3])
            db.session.commit()

            user = User.query.filter_by(username="admin").first()
            from core.dashboard_stats import get_dashboard_stats
            result = get_dashboard_stats(user)

            assert result["stats"]["host_pending_updates"] == 2
            assert result["stats"]["host_security_updates"] == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev pytest tests/test_dashboard.py::TestDashboardStatsHostUpdates -v`
Expected: KeyError — `host_pending_updates` not in stats

- [ ] **Step 3: Add host update counts to `get_dashboard_stats`**

In `core/dashboard_stats.py`, add import:

```python
from models import Guest, GuestService, HostUpdatePackage, ProxmoxHost, Tag, UpdatePackage, db
```

After the existing `security_updates` query (around line 61), add:

```python
    host_pending_updates = HostUpdatePackage.query.filter(
        HostUpdatePackage.status == "pending",
    ).count()
    host_security_updates = HostUpdatePackage.query.filter(
        HostUpdatePackage.status == "pending",
        HostUpdatePackage.severity == "critical",
    ).count()
```

Add to the `stats` dict (around line 96):

```python
        "host_pending_updates": host_pending_updates,
        "host_security_updates": host_security_updates,
```

- [ ] **Step 4: Run test to verify it passes**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev pytest tests/test_dashboard.py::TestDashboardStatsHostUpdates -v`
Expected: PASS

- [ ] **Step 5: Add host update stat cards to dashboard template**

In `templates/dashboard.html`, after the "Up to Date" card (after line 172, before the closing `</div>` of the Update Summary row), add the host update cards. Change the row to include 6 cards instead of 4. After the "Up to Date" `col` div, add:

```html
    <div class="col-6 col-md-3">
        <div class="card bg-dark h-100 stat-card">
            <div class="card-body text-center py-3">
                <div class="fs-3 fw-bold {% if stats.host_pending_updates > 0 %}text-warning{% else %}text-muted{% endif %}">{{ stats.host_pending_updates }}</div>
                <div class="small text-muted">Host Updates</div>
            </div>
        </div>
    </div>
    <div class="col-6 col-md-3">
        <div class="card bg-dark h-100 stat-card">
            <div class="card-body text-center py-3">
                <div class="fs-3 fw-bold {% if stats.host_security_updates > 0 %}text-danger{% else %}text-muted{% endif %}">{{ stats.host_security_updates }}</div>
                <div class="small text-muted">Host Security</div>
            </div>
        </div>
    </div>
```

- [ ] **Step 6: Run full test suite**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev pytest --tb=short -q`
Expected: All tests pass

- [ ] **Step 7: Commit**

```bash
git add core/dashboard_stats.py templates/dashboard.html tests/test_dashboard.py
git commit -m "feat: add host update counts to dashboard stats and template"
```

---

## Task 10: Mobile API Updates

**Files:**
- Modify: `routes/api_v1.py:248-298` (dashboard), `routes/api_v1.py:419-482` (hosts)
- Test: `tests/test_api_v1.py`

- [ ] **Step 1: Write failing tests for new API fields**

In `tests/test_api_v1.py`, add tests using the existing `_login` / `_auth_headers` helper pattern:

```python
class TestDashboardSummaryHostUpdates:
    def test_summary_includes_host_update_counts(self, client):
        """GET /api/v1/dashboard/summary should include host_pending_updates and host_security_updates."""
        access, _ = _login(client)
        with client.application.app_context():
            from models import HostUpdatePackage, ProxmoxHost, db
            host = ProxmoxHost(name="pve1", hostname="pve1.local", host_type="pve")
            db.session.add(host)
            db.session.commit()
            pkg = HostUpdatePackage(host_id=host.id, package_name="curl", status="pending", severity="normal")
            db.session.add(pkg)
            db.session.commit()

        resp = client.get("/api/v1/dashboard/summary", headers=_auth_headers(access))
        data = resp.get_json()["data"]
        assert "host_pending_updates" in data
        assert "host_security_updates" in data
        assert data["host_pending_updates"] == 1


class TestHostsEndpointUpdates:
    def test_host_list_includes_update_counts(self, client):
        """GET /api/v1/hosts should include pending_updates_count per host."""
        access, _ = _login(client)
        with client.application.app_context():
            from models import HostUpdatePackage, ProxmoxHost, db
            host = ProxmoxHost(name="pve1", hostname="pve1.local", host_type="pve")
            db.session.add(host)
            db.session.commit()
            pkg = HostUpdatePackage(host_id=host.id, package_name="curl", status="pending", severity="critical")
            db.session.add(pkg)
            db.session.commit()

        resp = client.get("/api/v1/hosts", headers=_auth_headers(access))
        data = resp.get_json()["data"]
        host_data = [h for h in data if h["name"] == "pve1"][0]
        assert host_data["pending_updates_count"] == 1
        assert host_data["security_updates_count"] == 1

    def test_host_detail_includes_updates_array(self, client):
        """GET /api/v1/hosts/<id> should include updates array."""
        access, _ = _login(client)
        with client.application.app_context():
            from models import HostUpdatePackage, ProxmoxHost, db
            host = ProxmoxHost(name="pve1", hostname="pve1.local", host_type="pve")
            db.session.add(host)
            db.session.commit()
            host_id = host.id
            pkg = HostUpdatePackage(host_id=host.id, package_name="curl", current_version="7.81", available_version="7.85", status="pending", severity="normal")
            db.session.add(pkg)
            db.session.commit()

        resp = client.get(f"/api/v1/hosts/{host_id}", headers=_auth_headers(access))
        data = resp.get_json()["data"]
        assert "updates" in data
        assert len(data["updates"]) == 1
        assert data["updates"][0]["package_name"] == "curl"


class TestDashboardAlertsHostSecurity:
    def test_alerts_include_host_security_updates(self, client):
        """GET /api/v1/dashboard/alerts should include host_security_updates."""
        access, _ = _login(client)
        with client.application.app_context():
            from models import HostUpdatePackage, ProxmoxHost, db
            host = ProxmoxHost(name="pve1", hostname="pve1.local", host_type="pve")
            db.session.add(host)
            db.session.commit()
            pkg = HostUpdatePackage(host_id=host.id, package_name="openssl", status="pending", severity="critical")
            db.session.add(pkg)
            db.session.commit()

        resp = client.get("/api/v1/dashboard/alerts", headers=_auth_headers(access))
        data = resp.get_json()["data"]
        assert "host_security_updates" in data
        assert len(data["host_security_updates"]) == 1
        assert data["host_security_updates"][0]["host_name"] == "pve1"
```

Note: These use the existing `_login(client)` and `_auth_headers(token)` helpers already defined in `tests/test_api_v1.py`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev pytest tests/test_api_v1.py::TestDashboardSummaryHostUpdates tests/test_api_v1.py::TestHostsEndpointUpdates tests/test_api_v1.py::TestDashboardAlertsHostSecurity -v`
Expected: FAIL — new fields not present in responses

- [ ] **Step 3: Update dashboard_summary endpoint**

The dashboard summary endpoint at `routes/api_v1.py:248-257` already returns `result["stats"]` from `get_dashboard_stats()`. Since we added `host_pending_updates` and `host_security_updates` to that dict in Task 9, this endpoint should already work. No code change needed here.

- [ ] **Step 4: Update hosts list endpoint**

In `routes/api_v1.py`, in the `host_list` function (around line 419-439), add update counts to each host dict:

```python
            "pending_updates_count": len(host.pending_updates()),
            "security_updates_count": len(host.security_updates()),
```

- [ ] **Step 5: Update host detail endpoint**

In `routes/api_v1.py`, in the `host_detail` function (around line 442-482), add:

```python
            "pending_updates_count": len(host.pending_updates()),
            "security_updates_count": len(host.security_updates()),
            "updates": [
                {
                    "package_name": p.package_name,
                    "current_version": p.current_version,
                    "available_version": p.available_version,
                    "severity": p.severity,
                }
                for p in host.pending_updates()
            ],
```

- [ ] **Step 6: Update dashboard alerts endpoint**

In `routes/api_v1.py`, in the `dashboard_alerts` function (around line 260-298), after the guest loop, add host security alerts:

```python
    from models import HostUpdatePackage, ProxmoxHost
    host_security_updates = []
    hosts = ProxmoxHost.query.all()
    for host in hosts:
        sec_count = len(host.security_updates())
        if sec_count > 0:
            host_security_updates.append({"host_id": host.id, "host_name": host.name, "count": sec_count})
```

Then add `"host_security_updates": host_security_updates` to the response dict.

- [ ] **Step 7: Run tests to verify they pass**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev pytest tests/test_api_v1.py::TestDashboardSummaryHostUpdates tests/test_api_v1.py::TestHostsEndpointUpdates tests/test_api_v1.py::TestDashboardAlertsHostSecurity -v`
Expected: All tests PASS

- [ ] **Step 8: Run full API test suite**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev pytest tests/test_api_v1.py -v --tb=short`
Expected: All tests pass

- [ ] **Step 9: Commit**

```bash
git add routes/api_v1.py tests/test_api_v1.py
git commit -m "feat: add host update fields to mobile API endpoints"
```

---

## Task 11: Full Test Suite Validation

- [ ] **Step 1: Run lint**

Run: `ruff check .`
Expected: No errors (fix any that appear)

- [ ] **Step 2: Run security checks**

Run: `make security`
Expected: No new findings

- [ ] **Step 3: Run full test suite**

Run: `make test`
Expected: All tests pass, no regressions

- [ ] **Step 4: Fix any failures, re-run until green**

- [ ] **Step 5: Commit any fixes**

```bash
git add -A
git commit -m "fix: address lint and test issues from unified notifications feature"
```

---

## Task 12: Wiki Documentation

**Files:**
- Modify: `c:/tmp/mstdnca-proxmox-tool.wiki/Configuration.md`
- Modify: `c:/tmp/mstdnca-proxmox-tool.wiki/Mobile-API.md`
- Modify: `c:/tmp/mstdnca-proxmox-tool.wiki/API-Reference.md`
- Modify: `c:/tmp/mstdnca-proxmox-tool.wiki/Hosts.md`
- Modify: `c:/tmp/mstdnca-proxmox-tool.wiki/Services.md`

- [ ] **Step 1: Update Configuration.md**

In the Discord notifications section (around line 104-123), add the new notification types:

```markdown
### Notification Events

| Event | Description | Default |
|-------|-------------|---------|
| Updates Available | When new APT updates are discovered on guests | Enabled |
| Security Updates Only | Only notify when critical/security packages are found | Disabled |
| **Updates Applied** | When updates are applied to guests or hosts (manual or auto) | Enabled |
| Upgrade Started | When an application upgrade begins | Enabled |
| Upgrade Result | When an application upgrade completes (success/failure) | Enabled |
| **Service Failed** | When a monitored service transitions to failed state | Enabled |
| **Service Recovered** | When a previously failed service starts running again | Enabled |
| App Update Available | When a new version of MCAT is available | Enabled |
```

Add the new setting:

```markdown
- **Service Notifications** (`discord_notify_services`) — Toggle Discord notifications for service state changes (failed/recovered). Default: enabled.
```

- [ ] **Step 2: Update Mobile-API.md**

Update the `GET /api/v1/dashboard/summary` response to include:
- `host_pending_updates` (integer)
- `host_security_updates` (integer)

Update the `GET /api/v1/hosts` response to include per-host:
- `pending_updates_count` (integer)
- `security_updates_count` (integer)

Update the `GET /api/v1/hosts/<id>` response to include:
- `pending_updates_count`, `security_updates_count`
- `updates` array with `package_name`, `current_version`, `available_version`, `severity`

Update the `GET /api/v1/dashboard/alerts` response to include:
- `host_security_updates` array with `host_id`, `host_name`, `count`

Update the Push Webhook events list to include:
- `service_failed` — Service transitioned to failed state (replaces `service_down`)
- `service_recovered` — Previously failed service is running again
- `service_down` — Backwards-compatible alias for `service_failed`

- [ ] **Step 3: Update Hosts.md**

Add a section on host update tracking:

```markdown
## Host Update Tracking

MCAT now tracks individual APT packages available on each Proxmox host. During scheduled scans, the application queries the Proxmox API for pending updates and persists them in the database.

Host updates are visible in:
- **Dashboard** — "Host Updates" and "Host Security" stat cards
- **Mobile API** — `/api/v1/hosts` and `/api/v1/hosts/<id>` endpoints
- **Discord** — Notifications when host updates are available and when they are applied
```

- [ ] **Step 4: Update Services.md**

Add a section on Discord notifications:

```markdown
## Discord Notifications

When **Service Notifications** are enabled in Settings > Discord, MCAT sends Discord alerts for service state changes:

- **Service Failed** — Sent when a monitored service transitions from running to failed, or when a newly discovered service is found in a failed state.
- **Service Recovered** — Sent when a previously failed service transitions back to running.

These notifications are sent in addition to push webhook alerts for mobile apps.
```

- [ ] **Step 5: Update API-Reference.md if needed**

Review and update any internal API endpoint documentation affected by the changes.

- [ ] **Step 6: Commit wiki changes**

```bash
cd /path/to/mstdnca-proxmox-tool.wiki
git add -A
git commit -m "docs: add unified notifications, host update tracking, and service state change documentation"
```

- [ ] **Step 7: Commit main repo docs**

```bash
cd /path/to/mstdnca-proxmox-tool
git add docs/
git commit -m "docs: add implementation plan for unified notifications feature"
```

---

## Task 13: Create Pull Request

- [ ] **Step 1: Push branch** (created in Task 0)

```bash
git push -u origin feature/unified-notifications-host-tracking
```

- [ ] **Step 2: Create PR**

```bash
gh pr create --title "Add unified notifications and host update tracking" --body "$(cat <<'EOF'
## Summary
- Add `HostUpdatePackage` model to persist Proxmox host APT updates in the database
- Add "updates applied" Discord notification for guest and host updates (batched for auto-updates, immediate for manual)
- Add service failed/recovered Discord notifications with state transition detection
- Add host update counts to web dashboard and mobile API
- Update wiki documentation for all changes

Resolves the discrepancy between Discord notification counts and web dashboard counts by persisting host update data and providing resolved/applied notifications.

## Test plan
- [ ] Verify `HostUpdatePackage` model CRUD and cascade delete
- [ ] Verify `send_updates_applied_notification` with single and batched results
- [ ] Verify `send_service_failed_notification` and `send_service_recovery_notification`
- [ ] Verify service state transition detection (only fires on actual changes)
- [ ] Verify dashboard stats include host update counts
- [ ] Verify mobile API endpoints return host update fields
- [ ] Verify push webhook alias mapping (service_failed -> service_down)
- [ ] Run full test suite: `make all`

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```
