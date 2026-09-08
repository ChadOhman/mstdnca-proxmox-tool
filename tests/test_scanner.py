"""Tests for core.scanner: determine_severity token matching,
scan_guest's guest_error push-notification dispatch, and the per-guest scan
lock that keeps a user-triggered scan and scan_all_guests() from racing."""
import threading
import time as _time
from unittest.mock import patch

from core.scanner import determine_severity, scan_guest
from models import Guest, ProxmoxHost, db


class TestDetermineSeverity:
    def test_no_security_output_is_normal(self):
        assert determine_severity("openssl", "") == "normal"
        assert determine_severity("openssl", None) == "normal"

    def test_exact_token_match_is_critical(self):
        security_output = (
            "Inst openssl [1.1.1-1] (1.1.1-2 Debian-Security:11/oldstable [amd64])\n"
        )
        assert determine_severity("openssl", security_output) == "critical"

    def test_conf_line_matches_too(self):
        security_output = "Conf curl (7.74.0-1.3+deb11u9 Debian-Security:11/oldstable [amd64])\n"
        assert determine_severity("curl", security_output) == "critical"

    def test_substring_of_another_package_is_not_critical(self):
        # "ssl" must not match inside "openssl" -- this is the bug being fixed.
        security_output = (
            "Inst openssl [1.1.1-1] (1.1.1-2 Debian-Security:11/oldstable [amd64])\n"
        )
        assert determine_severity("ssl", security_output) == "normal"

    def test_package_name_in_version_string_is_not_critical(self):
        # A package name appearing only inside another line's version/origin text
        # (not as the parsed package token) must not count as a substring hit.
        security_output = "Inst libfoo [1.0] (1.1 Debian-Security-cron:11 [amd64])\n"
        assert determine_severity("cron", security_output) == "normal"


class TestScanGuestErrorPush:
    def _make_guest(self, app):
        with app.app_context():
            host = ProxmoxHost(name="pve1", hostname="pve1.local", host_type="pve")
            db.session.add(host)
            db.session.commit()
            guest = Guest(name="web01", vmid=100, guest_type="ct", proxmox_host_id=host.id)
            db.session.add(guest)
            db.session.commit()
            return guest.id

    def test_scan_error_dispatches_guest_error_push(self, app):
        guest_id = self._make_guest(app)
        with app.app_context():
            guest = Guest.query.get(guest_id)

            with patch("core.scanner._execute_on_guest", return_value=(None, None, "SSH connection failed")), \
                 patch("core.push_notifier.dispatch_push_alerts") as mock_push:
                result = scan_guest(guest)

            assert result.status == "error"
            mock_push.assert_called_once_with(guest, "guest_error", {"error": "SSH connection failed"})

    def test_scan_success_does_not_dispatch_guest_error(self, app):
        guest_id = self._make_guest(app)
        with app.app_context():
            guest = Guest.query.get(guest_id)

            with patch("core.scanner._execute_on_guest", return_value=("", "", None)), \
                 patch("core.push_notifier.dispatch_push_alerts") as mock_push:
                result = scan_guest(guest)

            assert result.status == "success"
            for call in mock_push.call_args_list:
                assert call.args[1] != "guest_error"


class TestScanGuestLock:
    def _make_guest(self, app):
        with app.app_context():
            host = ProxmoxHost(name="pve1", hostname="pve1.local", host_type="pve")
            db.session.add(host)
            db.session.commit()
            guest = Guest(name="web01", vmid=100, guest_type="ct", proxmox_host_id=host.id)
            db.session.add(guest)
            db.session.commit()
            return guest.id

    def test_concurrent_scans_of_same_guest_are_serialised(self, app):
        """A user-triggered scan and a scheduled scan_all_guests() run both
        call scan_guest() for the same guest. The per-guest lock added for
        item 11 must ensure they never execute _execute_on_guest concurrently."""
        guest_id = self._make_guest(app)
        state = {"concurrent": 0, "max_concurrent": 0}
        state_lock = threading.Lock()

        def fake_execute_on_guest(guest):
            with state_lock:
                state["concurrent"] += 1
                state["max_concurrent"] = max(state["max_concurrent"], state["concurrent"])
            _time.sleep(0.05)
            with state_lock:
                state["concurrent"] -= 1
            return "", "", None

        def run_scan():
            with app.app_context():
                guest = Guest.query.get(guest_id)
                with patch("core.scanner._execute_on_guest", side_effect=fake_execute_on_guest), \
                     patch("core.push_notifier.dispatch_push_alerts"):
                    scan_guest(guest)

        threads = [threading.Thread(target=run_scan) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert state["max_concurrent"] == 1

    def test_scans_of_different_guests_are_not_serialised_against_each_other(self, app):
        """The lock is per-guest-id -- unrelated guests must still be able to
        scan concurrently."""
        with app.app_context():
            host = ProxmoxHost(name="pve1", hostname="pve1.local", host_type="pve")
            db.session.add(host)
            db.session.commit()
            guest_a = Guest(name="a", vmid=101, guest_type="ct", proxmox_host_id=host.id)
            guest_b = Guest(name="b", vmid=102, guest_type="ct", proxmox_host_id=host.id)
            db.session.add_all([guest_a, guest_b])
            db.session.commit()
            guest_ids = [guest_a.id, guest_b.id]

        started = threading.Event()
        release = threading.Event()

        def blocking_execute(guest):
            started.set()
            release.wait(timeout=5)
            return "", "", None

        def run_scan(guest_id):
            with app.app_context():
                guest = Guest.query.get(guest_id)
                with patch("core.scanner._execute_on_guest", side_effect=blocking_execute), \
                     patch("core.push_notifier.dispatch_push_alerts"):
                    scan_guest(guest)

        t1 = threading.Thread(target=run_scan, args=(guest_ids[0],))
        t1.start()
        assert started.wait(timeout=5)
        started.clear()

        t2 = threading.Thread(target=run_scan, args=(guest_ids[1],))
        t2.start()
        # If the lock were global (not per-guest), t2 would block here and
        # never call _execute_on_guest until t1's is released.
        assert started.wait(timeout=2)

        release.set()
        t1.join(timeout=5)
        t2.join(timeout=5)
