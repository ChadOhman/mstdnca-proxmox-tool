"""Tests for service state transition detection in _upsert_service."""
from datetime import datetime, timezone
from unittest.mock import patch

from core.scanner import _upsert_service, check_service_statuses
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


class TestCheckServiceStatusesTransitions:
    """The 5-minute health check must raise the same alerts as the 6-hourly scan.

    Regression cover for #126: `check_service_statuses` used to write
    status="failed" straight to the row, so by the time `_upsert_service` ran
    during the next scan the transition had already been consumed and no alert
    was ever sent.
    """

    def _make_guest_with_service(self, app, status="running", name="svc-host"):
        with app.app_context():
            host = ProxmoxHost(name=f"pve-{name}", hostname=f"{name}.local", host_type="pve")
            db.session.add(host)
            db.session.commit()
            guest = Guest(name=name, vmid=910, guest_type="ct", proxmox_host_id=host.id)
            db.session.add(guest)
            db.session.flush()
            db.session.add(GuestService(
                guest_id=guest.id, service_name="nginx", unit_name="nginx.service",
                status=status, last_checked=datetime.now(timezone.utc),
            ))
            db.session.commit()
            return guest.id

    def test_health_check_failure_notifies_exactly_once(self, app):
        guest_id = self._make_guest_with_service(app, status="running", name="svc-fail")
        with app.app_context():
            guest = Guest.query.get(guest_id)

            with patch("core.scanner._execute_command", return_value=("failed", None)), \
                 patch("core.notifier.send_service_failed_notification") as mock_discord, \
                 patch("core.push_notifier.dispatch_push_alerts") as mock_push:
                check_service_statuses(guest)
                mock_discord.assert_called_once_with("svc-fail", "nginx")
                assert mock_push.call_count == 1

                # A second check with the service still failed must not re-alert.
                check_service_statuses(guest)
                assert mock_discord.call_count == 1
                assert mock_push.call_count == 1

            assert guest.services[0].status == "failed"

    def test_later_scan_upsert_does_not_renotify(self, app):
        guest_id = self._make_guest_with_service(app, status="running", name="svc-once")
        with app.app_context():
            guest = Guest.query.get(guest_id)

            with patch("core.scanner._execute_command", return_value=("failed", None)), \
                 patch("core.notifier.send_service_failed_notification") as mock_discord, \
                 patch("core.push_notifier.dispatch_push_alerts"):
                check_service_statuses(guest)
                assert mock_discord.call_count == 1

            # The 6-hourly scan path then upserts the same failed status.
            with patch("core.notifier.send_service_failed_notification") as mock_discord, \
                 patch("core.push_notifier.dispatch_push_alerts") as mock_push:
                _upsert_service(guest, "nginx", "nginx.service", 80, "failed",
                                datetime.now(timezone.utc))
                mock_discord.assert_not_called()
                mock_push.assert_not_called()

    def test_health_check_recovery_notifies_once(self, app):
        guest_id = self._make_guest_with_service(app, status="failed", name="svc-recover")
        with app.app_context():
            guest = Guest.query.get(guest_id)

            with patch("core.scanner._execute_command", return_value=("active", None)), \
                 patch("core.notifier.send_service_recovery_notification") as mock_discord, \
                 patch("core.push_notifier.dispatch_push_alerts") as mock_push:
                check_service_statuses(guest)
                mock_discord.assert_called_once_with("svc-recover", "nginx")
                assert mock_push.call_count == 1

                check_service_statuses(guest)
                assert mock_discord.call_count == 1

            assert guest.services[0].status == "running"

    def test_health_check_stop_is_not_an_alert(self, app):
        guest_id = self._make_guest_with_service(app, status="running", name="svc-stop")
        with app.app_context():
            guest = Guest.query.get(guest_id)

            with patch("core.scanner._execute_command", return_value=("inactive", None)), \
                 patch("core.notifier.send_service_failed_notification") as mock_discord, \
                 patch("core.push_notifier.dispatch_push_alerts") as mock_push:
                check_service_statuses(guest)
                mock_discord.assert_not_called()
                mock_push.assert_not_called()

            assert guest.services[0].status == "stopped"
