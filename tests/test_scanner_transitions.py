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
            svc = GuestService(
                guest_id=guest.id, service_name="nginx", unit_name="nginx.service",
                status="running", last_checked=now,
            )
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
            svc = GuestService(
                guest_id=guest.id, service_name="nginx", unit_name="nginx.service",
                status="failed", last_checked=now,
            )
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
            svc = GuestService(
                guest_id=guest.id, service_name="nginx", unit_name="nginx.service",
                status="failed", last_checked=now,
            )
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
                 patch("core.push_notifier.dispatch_push_alerts"):
                _upsert_service(guest, "nginx", "nginx.service", 80, "failed", now)
                mock_discord.assert_called_once_with("web01", "nginx")
