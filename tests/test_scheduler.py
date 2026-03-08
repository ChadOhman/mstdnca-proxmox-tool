"""Tests for scheduler.py — setup, configuration, and utility paths.

These tests exercise the scheduler module's public API and configuration
logic without triggering any real Proxmox, SSH, or external network calls.
APScheduler and all job-body imports are mocked at the boundary.

Patching strategy
-----------------
All heavy imports inside the job functions happen lazily inside
``with app.app_context()`` blocks, using local ``from X import Y``
statements.  Because those names are resolved at call-time (not at module
import time), we patch via ``sys.modules`` so that every subsequent
``import`` or ``from … import`` in scheduler.py sees our mock objects.
"""
import logging
import sys
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_app(config=None):
    """Return a minimal Flask-like app mock with working app_context()."""
    app = MagicMock()
    app.config = config or {
        "GITHUB_REPO": "",
        "APP_VERSION": "1.0.0",
    }

    ctx = MagicMock()
    ctx.__enter__ = MagicMock(return_value=ctx)
    ctx.__exit__ = MagicMock(return_value=False)
    app.app_context.return_value = ctx
    return app


def _default_setting_get(key, default=""):
    """Simulate Setting.get() for scheduler interval settings."""
    values = {
        "scan_interval": "6",
        "discovery_interval": "4",
        "service_check_interval": "5",
        "unifi_api_poll_interval": "5",
    }
    return values.get(key, default)


class _SysModulesPatch:
    """Context-manager: temporarily inject mock modules into sys.modules."""

    def __init__(self, mocks: dict):
        self._mocks = mocks
        self._saved = {}

    def __enter__(self):
        for name, mock in self._mocks.items():
            self._saved[name] = sys.modules.get(name)
            sys.modules[name] = mock
        return self

    def __exit__(self, *_):
        for name, original in self._saved.items():
            if original is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = original


# ---------------------------------------------------------------------------
# Import / module-level attribute tests
# ---------------------------------------------------------------------------


class TestModuleImport:
    def test_scheduler_module_imports_without_error(self):
        import core.scheduler  # noqa: F401

    def test_module_exposes_init_scheduler(self):
        import core.scheduler as scheduler

        assert callable(scheduler.init_scheduler)

    def test_module_exposes_reschedule_jobs(self):
        import core.scheduler as scheduler

        assert callable(scheduler.reschedule_jobs)

    def test_module_level_scheduler_starts_as_none(self):
        """_scheduler global is None before init_scheduler is called."""
        import core.scheduler as sched_mod

        original = sched_mod._scheduler
        sched_mod._scheduler = None
        try:
            assert sched_mod._scheduler is None
        finally:
            sched_mod._scheduler = original

    def test_module_has_logger(self):
        import core.scheduler as scheduler

        assert isinstance(scheduler.logger, logging.Logger)

    def test_private_job_functions_are_callable(self):
        import core.scheduler as scheduler

        for fn_name in (
            "_run_scan",
            "_run_auto_updates",
            "_check_mastodon_release",
            "_check_ghost_release",
            "_run_discovery",
            "_check_app_update",
            "_purge_old_audit_logs",
            "_poll_unifi_events",
            "_purge_old_unifi_logs",
            "_run_service_health_checks",
        ):
            assert callable(getattr(scheduler, fn_name)), f"{fn_name} not callable"


# ---------------------------------------------------------------------------
# init_scheduler — job registration and idempotency
# ---------------------------------------------------------------------------


class TestInitScheduler:
    @pytest.fixture(autouse=True)
    def _reset_global(self):
        import core.scheduler as sched_mod

        sched_mod._scheduler = None
        yield
        sched_mod._scheduler = None

    @pytest.fixture()
    def app(self):
        return _make_app()

    @pytest.fixture()
    def mock_setting(self):
        s = MagicMock()
        s.get.side_effect = _default_setting_get
        return s

    @patch("core.scheduler.BackgroundScheduler")
    def test_returns_scheduler_instance(self, MockBGS, app, mock_setting):
        mock_sched = MagicMock()
        MockBGS.return_value = mock_sched

        mocks = {"models": MagicMock(Setting=mock_setting)}
        with _SysModulesPatch(mocks):
            import core.scheduler as sched_mod

            result = sched_mod.init_scheduler(app)

        assert result is mock_sched

    @patch("core.scheduler.BackgroundScheduler")
    def test_starts_scheduler(self, MockBGS, app, mock_setting):
        mock_sched = MagicMock()
        MockBGS.return_value = mock_sched

        mocks = {"models": MagicMock(Setting=mock_setting)}
        with _SysModulesPatch(mocks):
            import core.scheduler as sched_mod

            sched_mod.init_scheduler(app)

        mock_sched.start.assert_called_once()

    @patch("core.scheduler.BackgroundScheduler")
    def test_registers_all_expected_job_ids(self, MockBGS, app, mock_setting):
        mock_sched = MagicMock()
        MockBGS.return_value = mock_sched

        mocks = {"models": MagicMock(Setting=mock_setting)}
        with _SysModulesPatch(mocks):
            import core.scheduler as sched_mod

            sched_mod.init_scheduler(app)

        registered_ids = {
            c.kwargs.get("id") or c[1].get("id")
            for c in mock_sched.add_job.call_args_list
        }

        expected_ids = {
            "discovery",
            "scan_all",
            "auto_update",
            "mastodon_check",
            "ghost_check",
            "peertube_check",
            "host_update_check",
            "service_health",
            "app_update_check",
            "audit_log_purge",
            "elk_check",
            "jitsi_check",
            "unifi_event_poll",
            "unifi_log_purge",
            "prometheus_collect",
            "prometheus_check",
            "unpoller_check",
            "ipmi_sensor_poll",
            "ipmi_snapshot_purge",
            "revoked_token_prune",
            "moderation_check",
        }
        assert expected_ids == registered_ids

    @patch("core.scheduler.BackgroundScheduler")
    def test_is_idempotent_on_double_call(self, MockBGS, app, mock_setting):
        mock_sched = MagicMock()
        MockBGS.return_value = mock_sched

        mocks = {"models": MagicMock(Setting=mock_setting)}
        with _SysModulesPatch(mocks):
            import core.scheduler as sched_mod

            first = sched_mod.init_scheduler(app)
            second = sched_mod.init_scheduler(app)

        assert first is second
        MockBGS.assert_called_once()

    @patch("core.scheduler.BackgroundScheduler")
    def test_all_jobs_pass_app_as_arg(self, MockBGS, app, mock_setting):
        mock_sched = MagicMock()
        MockBGS.return_value = mock_sched

        mocks = {"models": MagicMock(Setting=mock_setting)}
        with _SysModulesPatch(mocks):
            import core.scheduler as sched_mod

            sched_mod.init_scheduler(app)

        for c in mock_sched.add_job.call_args_list:
            args_list = c.kwargs.get("args") or c[1].get("args") or []
            assert app in args_list, f"Job missing app in args: {c}"

    @patch("core.scheduler.BackgroundScheduler")
    def test_all_jobs_have_replace_existing_true(self, MockBGS, app, mock_setting):
        mock_sched = MagicMock()
        MockBGS.return_value = mock_sched

        mocks = {"models": MagicMock(Setting=mock_setting)}
        with _SysModulesPatch(mocks):
            import core.scheduler as sched_mod

            sched_mod.init_scheduler(app)

        for c in mock_sched.add_job.call_args_list:
            replace = c.kwargs.get("replace_existing") or c[1].get("replace_existing")
            assert replace is True, f"Job missing replace_existing=True: {c}"

    @patch("core.scheduler.BackgroundScheduler")
    def test_scan_interval_drives_scan_and_mastodon_ghost_jobs(self, MockBGS, app):
        mock_sched = MagicMock()
        MockBGS.return_value = mock_sched

        setting = MagicMock()
        setting.get.side_effect = lambda k, d="": {
            "scan_interval": "12",
            "discovery_interval": "4",
            "service_check_interval": "5",
            "unifi_api_poll_interval": "5",
        }.get(k, d)

        mocks = {"models": MagicMock(Setting=setting)}
        with _SysModulesPatch(mocks):
            import core.scheduler as sched_mod

            sched_mod.init_scheduler(app)

        trigger_hours = {}
        for c in mock_sched.add_job.call_args_list:
            job_id = c.kwargs.get("id") or c[1].get("id")
            trigger = c.kwargs.get("trigger") or c[1].get("trigger")
            if hasattr(trigger, "interval"):
                trigger_hours[job_id] = trigger.interval.total_seconds() / 3600

        assert trigger_hours.get("scan_all") == pytest.approx(12.0)
        assert trigger_hours.get("mastodon_check") == pytest.approx(12.0)
        assert trigger_hours.get("ghost_check") == pytest.approx(12.0)

    @patch("core.scheduler.BackgroundScheduler")
    def test_discovery_interval_setting_is_respected(self, MockBGS, app):
        mock_sched = MagicMock()
        MockBGS.return_value = mock_sched

        setting = MagicMock()
        setting.get.side_effect = lambda k, d="": {
            "scan_interval": "6",
            "discovery_interval": "8",
            "service_check_interval": "5",
            "unifi_api_poll_interval": "5",
        }.get(k, d)

        mocks = {"models": MagicMock(Setting=setting)}
        with _SysModulesPatch(mocks):
            import core.scheduler as sched_mod

            sched_mod.init_scheduler(app)

        trigger_hours = {}
        for c in mock_sched.add_job.call_args_list:
            job_id = c.kwargs.get("id") or c[1].get("id")
            trigger = c.kwargs.get("trigger") or c[1].get("trigger")
            if hasattr(trigger, "interval"):
                trigger_hours[job_id] = trigger.interval.total_seconds() / 3600

        assert trigger_hours.get("discovery") == pytest.approx(8.0)

    @patch("core.scheduler.BackgroundScheduler")
    def test_auto_update_job_fixed_at_15_minutes(self, MockBGS, app, mock_setting):
        mock_sched = MagicMock()
        MockBGS.return_value = mock_sched

        mocks = {"models": MagicMock(Setting=mock_setting)}
        with _SysModulesPatch(mocks):
            import core.scheduler as sched_mod

            sched_mod.init_scheduler(app)

        trigger_minutes = {}
        for c in mock_sched.add_job.call_args_list:
            job_id = c.kwargs.get("id") or c[1].get("id")
            trigger = c.kwargs.get("trigger") or c[1].get("trigger")
            if hasattr(trigger, "interval"):
                trigger_minutes[job_id] = trigger.interval.total_seconds() / 60

        assert trigger_minutes.get("auto_update") == pytest.approx(15.0)

    @patch("core.scheduler.BackgroundScheduler")
    def test_purge_jobs_run_every_24_hours(self, MockBGS, app, mock_setting):
        mock_sched = MagicMock()
        MockBGS.return_value = mock_sched

        mocks = {"models": MagicMock(Setting=mock_setting)}
        with _SysModulesPatch(mocks):
            import core.scheduler as sched_mod

            sched_mod.init_scheduler(app)

        trigger_hours = {}
        for c in mock_sched.add_job.call_args_list:
            job_id = c.kwargs.get("id") or c[1].get("id")
            trigger = c.kwargs.get("trigger") or c[1].get("trigger")
            if hasattr(trigger, "interval"):
                trigger_hours[job_id] = trigger.interval.total_seconds() / 3600

        assert trigger_hours.get("audit_log_purge") == pytest.approx(24.0)
        assert trigger_hours.get("unifi_log_purge") == pytest.approx(24.0)

    @patch("core.scheduler.BackgroundScheduler")
    def test_app_update_check_fixed_at_6_hours(self, MockBGS, app, mock_setting):
        mock_sched = MagicMock()
        MockBGS.return_value = mock_sched

        mocks = {"models": MagicMock(Setting=mock_setting)}
        with _SysModulesPatch(mocks):
            import core.scheduler as sched_mod

            sched_mod.init_scheduler(app)

        trigger_hours = {}
        for c in mock_sched.add_job.call_args_list:
            job_id = c.kwargs.get("id") or c[1].get("id")
            trigger = c.kwargs.get("trigger") or c[1].get("trigger")
            if hasattr(trigger, "interval"):
                trigger_hours[job_id] = trigger.interval.total_seconds() / 3600

        assert trigger_hours.get("app_update_check") == pytest.approx(6.0)


# ---------------------------------------------------------------------------
# reschedule_jobs
# ---------------------------------------------------------------------------


class TestRescheduleJobs:
    @pytest.fixture(autouse=True)
    def _reset_global(self):
        import core.scheduler as sched_mod

        sched_mod._scheduler = None
        yield
        sched_mod._scheduler = None

    def test_noop_when_scheduler_is_none(self):
        import core.scheduler as sched_mod

        sched_mod._scheduler = None
        sched_mod.reschedule_jobs(6, 4, 5)  # must not raise

    def test_noop_when_scheduler_not_running(self):
        import core.scheduler as sched_mod

        mock_sched = MagicMock()
        mock_sched.running = False
        sched_mod._scheduler = mock_sched

        sched_mod.reschedule_jobs(6, 4, 5)

        mock_sched.reschedule_job.assert_not_called()

    def test_reschedules_all_configurable_jobs(self):
        import core.scheduler as sched_mod

        mock_sched = MagicMock()
        mock_sched.running = True
        sched_mod._scheduler = mock_sched

        sched_mod.reschedule_jobs(6, 4, 5)

        assert mock_sched.reschedule_job.call_count == 9

    def test_reschedules_scan_all_with_new_interval(self):
        import core.scheduler as sched_mod

        mock_sched = MagicMock()
        mock_sched.running = True
        sched_mod._scheduler = mock_sched

        sched_mod.reschedule_jobs(12, 4, 5)

        calls = {c.args[0]: c for c in mock_sched.reschedule_job.call_args_list}
        assert "scan_all" in calls
        trigger = calls["scan_all"].kwargs.get("trigger") or calls["scan_all"][1]["trigger"]
        assert trigger.interval.total_seconds() / 3600 == pytest.approx(12.0)

    def test_reschedules_discovery_with_new_interval(self):
        import core.scheduler as sched_mod

        mock_sched = MagicMock()
        mock_sched.running = True
        sched_mod._scheduler = mock_sched

        sched_mod.reschedule_jobs(6, 8, 5)

        calls = {c.args[0]: c for c in mock_sched.reschedule_job.call_args_list}
        assert "discovery" in calls
        trigger = calls["discovery"].kwargs.get("trigger") or calls["discovery"][1]["trigger"]
        assert trigger.interval.total_seconds() / 3600 == pytest.approx(8.0)

    def test_reschedules_service_health_with_new_minutes(self):
        import core.scheduler as sched_mod

        mock_sched = MagicMock()
        mock_sched.running = True
        sched_mod._scheduler = mock_sched

        sched_mod.reschedule_jobs(6, 4, 10)

        calls = {c.args[0]: c for c in mock_sched.reschedule_job.call_args_list}
        assert "service_health" in calls
        trigger = calls["service_health"].kwargs.get("trigger") or calls["service_health"][1]["trigger"]
        assert trigger.interval.total_seconds() / 60 == pytest.approx(10.0)

    def test_reschedules_mastodon_and_ghost_jobs(self):
        import core.scheduler as sched_mod

        mock_sched = MagicMock()
        mock_sched.running = True
        sched_mod._scheduler = mock_sched

        sched_mod.reschedule_jobs(24, 4, 5)

        calls = {c.args[0]: c for c in mock_sched.reschedule_job.call_args_list}
        assert "mastodon_check" in calls
        assert "ghost_check" in calls

    def test_mastodon_and_ghost_share_scan_interval(self):
        import core.scheduler as sched_mod

        mock_sched = MagicMock()
        mock_sched.running = True
        sched_mod._scheduler = mock_sched

        sched_mod.reschedule_jobs(18, 4, 5)

        calls = {c.args[0]: c for c in mock_sched.reschedule_job.call_args_list}
        for job_id in ("mastodon_check", "ghost_check"):
            trigger = calls[job_id].kwargs.get("trigger") or calls[job_id][1]["trigger"]
            assert trigger.interval.total_seconds() / 3600 == pytest.approx(18.0)


# ---------------------------------------------------------------------------
# _run_scan — lazy-import job function tests
# ---------------------------------------------------------------------------


class TestRunScan:
    """_run_scan uses lazy imports inside app_context; patch via sys.modules."""

    def _build_mocks(self, scan_enabled="true", scan_results=None):
        """Return (app, sys_modules_dict) pair configured for _run_scan."""
        app = _make_app()
        scan_results = scan_results or []

        mock_setting = MagicMock()
        mock_setting.get.return_value = scan_enabled

        mock_scanner = MagicMock()
        mock_scanner.scan_all_guests.return_value = scan_results

        mock_notifier = MagicMock()

        mocks = {
            "models": MagicMock(Setting=mock_setting),
            "core.scanner": mock_scanner,
            "core.notifier": mock_notifier,
        }
        return app, mocks, mock_scanner, mock_notifier

    def test_scan_skipped_when_disabled(self):
        from core.scheduler import _run_scan

        app, mocks, mock_scanner, _ = self._build_mocks(scan_enabled="false")
        with _SysModulesPatch(mocks):
            _run_scan(app)

        mock_scanner.scan_all_guests.assert_not_called()

    def test_scan_runs_when_enabled(self):
        from core.scheduler import _run_scan

        results = [MagicMock(), MagicMock()]
        app, mocks, mock_scanner, mock_notifier = self._build_mocks(
            scan_enabled="true", scan_results=results
        )
        with _SysModulesPatch(mocks):
            _run_scan(app)

        mock_scanner.scan_all_guests.assert_called_once()

    def test_scan_passes_results_to_notifier(self):
        from core.scheduler import _run_scan

        results = [MagicMock(), MagicMock(), MagicMock()]
        app, mocks, _, mock_notifier = self._build_mocks(
            scan_enabled="true", scan_results=results
        )
        with _SysModulesPatch(mocks):
            _run_scan(app)

        mock_notifier.send_update_notification.assert_called_once_with(results)


# ---------------------------------------------------------------------------
# _purge_old_audit_logs
# ---------------------------------------------------------------------------


def _make_model_with_comparable_timestamp(delete_return=0):
    """Return a mock model whose .timestamp attribute supports < comparison.

    The scheduler purge functions use ``Model.timestamp < cutoff`` as a
    SQLAlchemy filter expression.  When Model is a plain MagicMock its
    .timestamp attribute is also a MagicMock, and Python's ``<`` operator
    calls ``MagicMock.__lt__(datetime)`` which raises TypeError because
    MagicMock does not define __lt__ for non-Mock right-hand operands.

    We solve this by making timestamp a MagicMock that has __lt__ wired to
    return a MagicMock (simulating a SQLAlchemy BinaryExpression), so the
    filter() call receives a truthy mock rather than raising.
    """
    mock_model = MagicMock()
    # Make the timestamp attribute support the < operator.
    ts_mock = MagicMock()
    ts_mock.__lt__ = MagicMock(return_value=MagicMock())
    mock_model.timestamp = ts_mock
    mock_model.query.filter.return_value.delete.return_value = delete_return
    return mock_model


class TestPurgeOldAuditLogs:
    def test_delete_is_called_and_session_committed(self):
        from core.scheduler import _purge_old_audit_logs

        app = _make_app()
        mock_audit_log = _make_model_with_comparable_timestamp(delete_return=5)
        mock_db = MagicMock()

        mocks = {
            "models": MagicMock(db=mock_db, AuditLog=mock_audit_log),
        }
        with _SysModulesPatch(mocks):
            _purge_old_audit_logs(app)

        mock_db.session.commit.assert_called_once()

    def test_commit_happens_even_when_nothing_to_delete(self):
        from core.scheduler import _purge_old_audit_logs

        app = _make_app()
        mock_audit_log = _make_model_with_comparable_timestamp(delete_return=0)
        mock_db = MagicMock()

        mocks = {
            "models": MagicMock(db=mock_db, AuditLog=mock_audit_log),
        }
        with _SysModulesPatch(mocks):
            _purge_old_audit_logs(app)

        mock_db.session.commit.assert_called_once()


# ---------------------------------------------------------------------------
# _purge_old_unifi_logs
# ---------------------------------------------------------------------------


class TestPurgeOldUnifiLogs:
    def test_uses_configured_retention_days_and_commits(self):
        from core.scheduler import _purge_old_unifi_logs

        app = _make_app()
        mock_setting = MagicMock()
        mock_setting.get.return_value = "30"
        mock_entry = _make_model_with_comparable_timestamp(delete_return=2)
        mock_db = MagicMock()

        mocks = {
            "models": MagicMock(db=mock_db, Setting=mock_setting, UnifiLogEntry=mock_entry),
        }
        with _SysModulesPatch(mocks):
            _purge_old_unifi_logs(app)

        mock_db.session.commit.assert_called_once()

    def test_falls_back_to_60_days_on_non_numeric_value(self):
        """ValueError from int() conversion must be caught; function must not raise."""
        from core.scheduler import _purge_old_unifi_logs

        app = _make_app()
        mock_setting = MagicMock()
        mock_setting.get.return_value = "not-a-number"
        mock_entry = _make_model_with_comparable_timestamp(delete_return=0)
        mock_db = MagicMock()

        mocks = {
            "models": MagicMock(db=mock_db, Setting=mock_setting, UnifiLogEntry=mock_entry),
        }
        with _SysModulesPatch(mocks):
            _purge_old_unifi_logs(app)

        mock_db.session.commit.assert_called_once()

    def test_falls_back_to_60_on_none_value(self):
        """Setting returning None must also not raise."""
        from core.scheduler import _purge_old_unifi_logs

        app = _make_app()
        mock_setting = MagicMock()
        mock_setting.get.return_value = None
        mock_entry = _make_model_with_comparable_timestamp(delete_return=0)
        mock_db = MagicMock()

        mocks = {
            "models": MagicMock(db=mock_db, Setting=mock_setting, UnifiLogEntry=mock_entry),
        }
        with _SysModulesPatch(mocks):
            _purge_old_unifi_logs(app)

        mock_db.session.commit.assert_called_once()


# ---------------------------------------------------------------------------
# _run_service_health_checks
# ---------------------------------------------------------------------------


class TestRunServiceHealthChecks:
    def test_skipped_when_disabled(self):
        from core.scheduler import _run_service_health_checks

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.return_value = "false"
        mock_guest = MagicMock()
        mock_scanner = MagicMock()

        mocks = {
            "models": MagicMock(Setting=mock_setting, Guest=mock_guest),
            "core.scanner": mock_scanner,
        }
        with _SysModulesPatch(mocks):
            _run_service_health_checks(app)

        mock_scanner.check_service_statuses.assert_not_called()

    def test_skipped_when_no_guests_with_services(self):
        from core.scheduler import _run_service_health_checks

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.return_value = "true"
        mock_guest = MagicMock()
        mock_guest.query.filter.return_value.all.return_value = []
        mock_scanner = MagicMock()

        mocks = {
            "models": MagicMock(Setting=mock_setting, Guest=mock_guest),
            "core.scanner": mock_scanner,
        }
        with _SysModulesPatch(mocks):
            _run_service_health_checks(app)

        mock_scanner.check_service_statuses.assert_not_called()

    def test_runs_for_each_eligible_guest(self):
        from core.scheduler import _run_service_health_checks

        app = _make_app()
        guests = [MagicMock(name=f"g{i}") for i in range(3)]

        mock_setting = MagicMock()
        mock_setting.get.return_value = "true"
        mock_guest = MagicMock()
        mock_guest.query.filter.return_value.all.return_value = guests
        mock_scanner = MagicMock()

        mocks = {
            "models": MagicMock(Setting=mock_setting, Guest=mock_guest),
            "core.scanner": mock_scanner,
        }
        with _SysModulesPatch(mocks):
            _run_service_health_checks(app)

        assert mock_scanner.check_service_statuses.call_count == 3

    def test_exception_in_one_guest_does_not_abort_others(self):
        from core.scheduler import _run_service_health_checks

        app = _make_app()
        g1, g2 = MagicMock(), MagicMock()

        mock_setting = MagicMock()
        mock_setting.get.return_value = "true"
        mock_guest = MagicMock()
        mock_guest.query.filter.return_value.all.return_value = [g1, g2]
        mock_scanner = MagicMock()
        mock_scanner.check_service_statuses.side_effect = [Exception("SSH timeout"), None]

        mocks = {
            "models": MagicMock(Setting=mock_setting, Guest=mock_guest),
            "core.scanner": mock_scanner,
        }
        with _SysModulesPatch(mocks):
            _run_service_health_checks(app)

        assert mock_scanner.check_service_statuses.call_count == 2


# ---------------------------------------------------------------------------
# _check_app_update
# ---------------------------------------------------------------------------


class TestCheckAppUpdate:
    def test_returns_early_when_no_repo_configured(self):
        from core.scheduler import _check_app_update

        app = _make_app(config={"GITHUB_REPO": "", "APP_VERSION": "1.0.0"})

        mock_setting = MagicMock()
        mock_setting.get.return_value = ""

        mocks = {"models": MagicMock(Setting=mock_setting)}
        with _SysModulesPatch(mocks), \
             patch("urllib.request.urlopen") as mock_urlopen:
            _check_app_update(app)

        mock_urlopen.assert_not_called()

    def test_network_failure_does_not_raise(self):
        from core.scheduler import _check_app_update

        app = _make_app(config={"GITHUB_REPO": "org/repo", "APP_VERSION": "1.0.0"})

        mock_setting = MagicMock()
        mock_setting.get.return_value = ""

        mocks = {"models": MagicMock(Setting=mock_setting)}
        with _SysModulesPatch(mocks), \
             patch("urllib.request.urlopen", side_effect=OSError("network down")):
            _check_app_update(app)  # must not raise

    def test_invalid_branch_name_rejects_popen(self):
        import json

        from core.scheduler import _check_app_update

        app = _make_app(config={"GITHUB_REPO": "org/repo", "APP_VERSION": "1.0.0"})

        mock_setting = MagicMock()
        mock_setting.get.side_effect = lambda k, d="": {
            "app_update_branch": "../../evil; rm -rf /",
            "app_auto_update": "true",
            "latest_app_version": "",
            "latest_app_check": "",
            "app_last_notified_version": "",
        }.get(k, d)

        fake_resp = MagicMock()
        fake_resp.__enter__ = MagicMock(return_value=fake_resp)
        fake_resp.__exit__ = MagicMock(return_value=False)
        fake_resp.read.return_value = json.dumps({"tag_name": "v1.1.0"}).encode()

        mock_notifier = MagicMock()
        mock_notifier.send_app_update_notification.return_value = (True, "ok")
        mocks = {"models": MagicMock(Setting=mock_setting), "core.notifier": mock_notifier}
        with _SysModulesPatch(mocks), \
             patch("urllib.request.urlopen", return_value=fake_resp), \
             patch("subprocess.Popen") as mock_popen:
            _check_app_update(app)

        mock_popen.assert_not_called()

    def test_branch_starting_with_dash_is_rejected(self):
        import json

        from core.scheduler import _check_app_update

        app = _make_app(config={"GITHUB_REPO": "org/repo", "APP_VERSION": "1.0.0"})

        mock_setting = MagicMock()
        mock_setting.get.side_effect = lambda k, d="": {
            "app_update_branch": "--bad-flag",
            "app_auto_update": "true",
            "app_last_notified_version": "",
        }.get(k, d)

        fake_resp = MagicMock()
        fake_resp.__enter__ = MagicMock(return_value=fake_resp)
        fake_resp.__exit__ = MagicMock(return_value=False)
        fake_resp.read.return_value = json.dumps({"tag_name": "v2.0.0"}).encode()

        mock_notifier = MagicMock()
        mock_notifier.send_app_update_notification.return_value = (True, "ok")
        mocks = {"models": MagicMock(Setting=mock_setting), "core.notifier": mock_notifier}
        with _SysModulesPatch(mocks), \
             patch("urllib.request.urlopen", return_value=fake_resp), \
             patch("subprocess.Popen") as mock_popen:
            _check_app_update(app)

        mock_popen.assert_not_called()

    def test_valid_branch_triggers_popen_when_script_exists(self):
        import json

        from core.scheduler import _check_app_update

        app = _make_app(config={"GITHUB_REPO": "org/repo", "APP_VERSION": "1.0.0"})

        mock_setting = MagicMock()
        mock_setting.get.side_effect = lambda k, d="": {
            "app_update_branch": "main",
            "app_auto_update": "true",
            "latest_app_version": "",
            "latest_app_check": "",
            "app_last_notified_version": "",
        }.get(k, d)

        fake_resp = MagicMock()
        fake_resp.__enter__ = MagicMock(return_value=fake_resp)
        fake_resp.__exit__ = MagicMock(return_value=False)
        fake_resp.read.return_value = json.dumps({"tag_name": "v1.1.0"}).encode()

        mock_notifier = MagicMock()
        mock_notifier.send_app_update_notification.return_value = (True, "ok")
        mocks = {"models": MagicMock(Setting=mock_setting), "core.notifier": mock_notifier}
        with _SysModulesPatch(mocks), \
             patch("urllib.request.urlopen", return_value=fake_resp), \
             patch("subprocess.Popen") as mock_popen, \
             patch("os.path.exists", return_value=True):
            _check_app_update(app)

        mock_popen.assert_called_once()
        call_args = mock_popen.call_args[0][0]
        assert "--branch" in call_args
        assert "main" in call_args

    def test_no_auto_update_skips_popen(self):
        import json

        from core.scheduler import _check_app_update

        app = _make_app(config={"GITHUB_REPO": "org/repo", "APP_VERSION": "1.0.0"})

        mock_setting = MagicMock()
        mock_setting.get.side_effect = lambda k, d="": {
            "app_update_branch": "",
            "app_auto_update": "false",
            "latest_app_version": "1.1.0",
            "latest_app_check": "",
            "app_last_notified_version": "",
        }.get(k, d)

        fake_resp = MagicMock()
        fake_resp.__enter__ = MagicMock(return_value=fake_resp)
        fake_resp.__exit__ = MagicMock(return_value=False)
        fake_resp.read.return_value = json.dumps({"tag_name": "v1.1.0"}).encode()

        mock_notifier = MagicMock()
        mock_notifier.send_app_update_notification.return_value = (True, "ok")
        mocks = {"models": MagicMock(Setting=mock_setting), "core.notifier": mock_notifier}
        with _SysModulesPatch(mocks), \
             patch("urllib.request.urlopen", return_value=fake_resp), \
             patch("subprocess.Popen") as mock_popen:
            _check_app_update(app)

        mock_popen.assert_not_called()

    def test_notification_sent_even_without_auto_update(self):
        """Notification fires for new versions regardless of auto_update setting."""
        import json

        from core.scheduler import _check_app_update

        app = _make_app(config={"GITHUB_REPO": "org/repo", "APP_VERSION": "1.0.0"})

        mock_setting = MagicMock()
        mock_setting.get.side_effect = lambda k, d="": {
            "app_update_branch": "",
            "app_auto_update": "false",
            "app_last_notified_version": "",
        }.get(k, d)

        fake_resp = MagicMock()
        fake_resp.__enter__ = MagicMock(return_value=fake_resp)
        fake_resp.__exit__ = MagicMock(return_value=False)
        fake_resp.read.return_value = json.dumps({"tag_name": "v2.0.0"}).encode()

        mock_notifier = MagicMock()
        mock_notifier.send_app_update_notification.return_value = (True, "ok")
        mocks = {"models": MagicMock(Setting=mock_setting), "core.notifier": mock_notifier}
        with _SysModulesPatch(mocks), \
             patch("urllib.request.urlopen", return_value=fake_resp):
            _check_app_update(app)

        mock_notifier.send_app_update_notification.assert_called_once_with("1.0.0", "2.0.0")

    def test_app_notification_dedup_skips_already_notified(self):
        import json

        from core.scheduler import _check_app_update

        app = _make_app(config={"GITHUB_REPO": "org/repo", "APP_VERSION": "1.0.0"})

        mock_setting = MagicMock()
        mock_setting.get.side_effect = lambda k, d="": {
            "app_update_branch": "",
            "app_auto_update": "false",
            "app_last_notified_version": "2.0.0",
        }.get(k, d)

        fake_resp = MagicMock()
        fake_resp.__enter__ = MagicMock(return_value=fake_resp)
        fake_resp.__exit__ = MagicMock(return_value=False)
        fake_resp.read.return_value = json.dumps({"tag_name": "v2.0.0"}).encode()

        mock_notifier = MagicMock()
        mocks = {"models": MagicMock(Setting=mock_setting), "core.notifier": mock_notifier}
        with _SysModulesPatch(mocks), \
             patch("urllib.request.urlopen", return_value=fake_resp):
            _check_app_update(app)

        mock_notifier.send_app_update_notification.assert_not_called()

    def test_auto_update_branch_injects_token_env(self):
        import json

        from core.scheduler import _check_app_update

        app = _make_app(config={"GITHUB_REPO": "org/repo", "APP_VERSION": "1.0.0"})

        mock_setting = MagicMock()
        mock_setting.get.side_effect = lambda k, d="": {
            "app_update_branch": "main",
            "app_auto_update": "true",
            "latest_app_version": "",
            "latest_app_check": "",
            "app_last_notified_version": "",
        }.get(k, d)

        fake_resp = MagicMock()
        fake_resp.__enter__ = MagicMock(return_value=fake_resp)
        fake_resp.__exit__ = MagicMock(return_value=False)
        fake_resp.read.return_value = json.dumps({"tag_name": "v1.1.0"}).encode()

        mock_notifier = MagicMock()
        mock_notifier.send_app_update_notification.return_value = (True, "ok")
        mocks = {"models": MagicMock(Setting=mock_setting), "core.notifier": mock_notifier}
        with _SysModulesPatch(mocks), \
             patch("urllib.request.urlopen", return_value=fake_resp), \
             patch("core.app_update_auth.github_token_env", return_value={"GITHUB_TOKEN": "ghp_sched", "PATH": "/usr/bin"}), \
             patch("subprocess.Popen") as mock_popen:
            _check_app_update(app)

        assert mock_popen.called
        assert mock_popen.call_args.kwargs.get("env", {}).get("GITHUB_TOKEN") == "ghp_sched"


# ---------------------------------------------------------------------------
# _check_mastodon_release
# ---------------------------------------------------------------------------


class TestCheckMastodonRelease:
    def test_returns_early_when_no_mastodon_guest_configured(self):
        from core.scheduler import _check_mastodon_release

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.return_value = ""
        mock_mastodon = MagicMock()

        mocks = {
            "models": MagicMock(Setting=mock_setting),
            "apps.mastodon": mock_mastodon,
        }
        with _SysModulesPatch(mocks):
            _check_mastodon_release(app)

        mock_mastodon.check_mastodon_release.assert_not_called()

    def test_sends_notification_when_update_available(self):
        from core.scheduler import _check_mastodon_release

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.side_effect = lambda k, d="": {
            "mastodon_guest_id": "42",
            "mastodon_current_version": "4.2.0",
            "mastodon_auto_upgrade": "false",
            "mastodon_last_notified_version": "",
        }.get(k, d)

        mock_mastodon = MagicMock()
        mock_mastodon.check_mastodon_release.return_value = (True, "4.3.0", "https://example.com")
        mock_notifier = MagicMock()
        mock_notifier.send_mastodon_update_notification.return_value = (True, "ok")

        mocks = {
            "models": MagicMock(Setting=mock_setting),
            "apps.mastodon": mock_mastodon,
            "core.notifier": mock_notifier,
        }
        with _SysModulesPatch(mocks):
            _check_mastodon_release(app)

        mock_notifier.send_mastodon_update_notification.assert_called_once_with(
            "4.2.0", "4.3.0", "https://example.com"
        )

    def test_skips_notification_when_already_notified_for_version(self):
        from core.scheduler import _check_mastodon_release

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.side_effect = lambda k, d="": {
            "mastodon_guest_id": "42",
            "mastodon_current_version": "4.2.0",
            "mastodon_auto_upgrade": "false",
            "mastodon_last_notified_version": "4.3.0",
        }.get(k, d)

        mock_mastodon = MagicMock()
        mock_mastodon.check_mastodon_release.return_value = (True, "4.3.0", "https://example.com")
        mock_notifier = MagicMock()

        mocks = {
            "models": MagicMock(Setting=mock_setting),
            "apps.mastodon": mock_mastodon,
            "core.notifier": mock_notifier,
        }
        with _SysModulesPatch(mocks):
            _check_mastodon_release(app)

        mock_notifier.send_mastodon_update_notification.assert_not_called()

    def test_no_notification_when_no_update_available(self):
        from core.scheduler import _check_mastodon_release

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.return_value = "42"
        mock_mastodon = MagicMock()
        mock_mastodon.check_mastodon_release.return_value = (False, "4.2.0", "")
        mock_notifier = MagicMock()

        mocks = {
            "models": MagicMock(Setting=mock_setting),
            "apps.mastodon": mock_mastodon,
            "core.notifier": mock_notifier,
        }
        with _SysModulesPatch(mocks):
            _check_mastodon_release(app)

        mock_notifier.send_mastodon_update_notification.assert_not_called()

    def test_auto_upgrade_triggered_when_enabled(self):
        from core.scheduler import _check_mastodon_release

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.side_effect = lambda k, d="": {
            "mastodon_guest_id": "42",
            "mastodon_current_version": "4.2.0",
            "mastodon_auto_upgrade": "true",
            "mastodon_last_notified_version": "",
        }.get(k, d)

        mock_mastodon = MagicMock()
        mock_mastodon.check_mastodon_release.return_value = (True, "4.3.0", "https://example.com")
        mock_mastodon.run_mastodon_upgrade.return_value = (True, "")
        mock_notifier = MagicMock()
        mock_notifier.send_mastodon_update_notification.return_value = (True, "ok")
        mock_audit = MagicMock()
        mock_db = MagicMock()

        mocks = {
            "models": MagicMock(Setting=mock_setting, db=mock_db),
            "apps.mastodon": mock_mastodon,
            "core.notifier": mock_notifier,
            "auth.audit": mock_audit,
        }
        with _SysModulesPatch(mocks):
            _check_mastodon_release(app)

        mock_mastodon.run_mastodon_upgrade.assert_called_once()


# ---------------------------------------------------------------------------
# _check_ghost_release
# ---------------------------------------------------------------------------


class TestCheckGhostRelease:
    def test_returns_early_when_no_ghost_guest_configured(self):
        from core.scheduler import _check_ghost_release

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.return_value = ""
        mock_ghost = MagicMock()

        mocks = {
            "models": MagicMock(Setting=mock_setting),
            "apps.ghost": mock_ghost,
        }
        with _SysModulesPatch(mocks):
            _check_ghost_release(app)

        mock_ghost.check_ghost_release.assert_not_called()

    def test_sends_notification_when_update_available(self):
        from core.scheduler import _check_ghost_release

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.side_effect = lambda k, d="": {
            "ghost_guest_id": "7",
            "ghost_current_version": "5.80.0",
            "ghost_auto_upgrade": "false",
            "ghost_last_notified_version": "",
        }.get(k, d)

        mock_ghost = MagicMock()
        mock_ghost.check_ghost_release.return_value = (True, "5.81.0", "https://ghost.org")
        mock_notifier = MagicMock()
        mock_notifier.send_ghost_update_notification.return_value = (True, "ok")

        mocks = {
            "models": MagicMock(Setting=mock_setting),
            "apps.ghost": mock_ghost,
            "core.notifier": mock_notifier,
        }
        with _SysModulesPatch(mocks):
            _check_ghost_release(app)

        mock_notifier.send_ghost_update_notification.assert_called_once_with(
            "5.80.0", "5.81.0", "https://ghost.org"
        )

    def test_skips_notification_when_already_notified_for_version(self):
        from core.scheduler import _check_ghost_release

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.side_effect = lambda k, d="": {
            "ghost_guest_id": "7",
            "ghost_current_version": "5.80.0",
            "ghost_auto_upgrade": "false",
            "ghost_last_notified_version": "5.81.0",
        }.get(k, d)

        mock_ghost = MagicMock()
        mock_ghost.check_ghost_release.return_value = (True, "5.81.0", "https://ghost.org")
        mock_notifier = MagicMock()

        mocks = {
            "models": MagicMock(Setting=mock_setting),
            "apps.ghost": mock_ghost,
            "core.notifier": mock_notifier,
        }
        with _SysModulesPatch(mocks):
            _check_ghost_release(app)

        mock_notifier.send_ghost_update_notification.assert_not_called()

    def test_no_notification_when_no_update_available(self):
        from core.scheduler import _check_ghost_release

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.return_value = "7"
        mock_ghost = MagicMock()
        mock_ghost.check_ghost_release.return_value = (False, "5.80.0", "")
        mock_notifier = MagicMock()

        mocks = {
            "models": MagicMock(Setting=mock_setting),
            "apps.ghost": mock_ghost,
            "core.notifier": mock_notifier,
        }
        with _SysModulesPatch(mocks):
            _check_ghost_release(app)

        mock_notifier.send_ghost_update_notification.assert_not_called()

    def test_auto_upgrade_triggered_when_enabled(self):
        from core.scheduler import _check_ghost_release

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.side_effect = lambda k, d="": {
            "ghost_guest_id": "7",
            "ghost_current_version": "5.80.0",
            "ghost_auto_upgrade": "true",
            "ghost_last_notified_version": "",
        }.get(k, d)

        mock_ghost = MagicMock()
        mock_ghost.check_ghost_release.return_value = (True, "5.81.0", "https://ghost.org")
        mock_ghost.run_ghost_upgrade.return_value = (True, "")
        mock_notifier = MagicMock()
        mock_notifier.send_ghost_update_notification.return_value = (True, "ok")
        mock_audit = MagicMock()
        mock_db = MagicMock()

        mocks = {
            "models": MagicMock(Setting=mock_setting, db=mock_db),
            "apps.ghost": mock_ghost,
            "core.notifier": mock_notifier,
            "auth.audit": mock_audit,
        }
        with _SysModulesPatch(mocks):
            _check_ghost_release(app)

        mock_ghost.run_ghost_upgrade.assert_called_once()

    def test_auto_upgrade_not_triggered_when_disabled(self):
        from core.scheduler import _check_ghost_release

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.side_effect = lambda k, d="": {
            "ghost_guest_id": "7",
            "ghost_current_version": "5.80.0",
            "ghost_auto_upgrade": "false",
            "ghost_last_notified_version": "",
        }.get(k, d)

        mock_ghost = MagicMock()
        mock_ghost.check_ghost_release.return_value = (True, "5.81.0", "https://ghost.org")
        mock_notifier = MagicMock()
        mock_notifier.send_ghost_update_notification.return_value = (True, "ok")

        mocks = {
            "models": MagicMock(Setting=mock_setting),
            "apps.ghost": mock_ghost,
            "core.notifier": mock_notifier,
        }
        with _SysModulesPatch(mocks):
            _check_ghost_release(app)

        mock_ghost.run_ghost_upgrade.assert_not_called()


# ---------------------------------------------------------------------------
# _check_host_updates
# ---------------------------------------------------------------------------


class TestCheckHostUpdates:
    def test_returns_early_when_scan_disabled(self):
        from core.scheduler import _check_host_updates

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.side_effect = lambda k, d="": {
            "scan_enabled": "false",
        }.get(k, d)
        mock_host_model = MagicMock()
        mock_notifier = MagicMock()

        mocks = {
            "models": MagicMock(Setting=mock_setting, ProxmoxHost=mock_host_model),
            "core.notifier": mock_notifier,
        }
        with _SysModulesPatch(mocks):
            _check_host_updates(app)

        mock_host_model.query.all.assert_not_called()

    def test_returns_early_when_no_hosts(self):
        from core.scheduler import _check_host_updates

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.return_value = "true"
        mock_host_model = MagicMock()
        mock_host_model.query.all.return_value = []
        mock_notifier = MagicMock()

        mocks = {
            "models": MagicMock(Setting=mock_setting, ProxmoxHost=mock_host_model),
            "core.notifier": mock_notifier,
        }
        with _SysModulesPatch(mocks):
            _check_host_updates(app)

        mock_notifier.send_host_update_notification.assert_not_called()

    def test_sends_notification_for_pve_host_with_updates(self):
        from core.scheduler import _check_host_updates

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.return_value = "true"

        mock_host = MagicMock()
        mock_host.name = "pve1"
        mock_host.host_type = "pve"
        mock_host.is_pbs = False

        mock_host_model = MagicMock()
        mock_host_model.query.all.return_value = [mock_host]

        mock_proxmox_client = MagicMock()
        mock_proxmox_client.get_local_node_name.return_value = "node1"
        mock_proxmox_client.get_apt_updates.return_value = [{"Package": "pve-manager"}]

        mock_notifier = MagicMock()
        mock_proxmox_api = MagicMock()
        mock_proxmox_api.ProxmoxClient.return_value = mock_proxmox_client

        mocks = {
            "models": MagicMock(Setting=mock_setting, ProxmoxHost=mock_host_model),
            "clients.proxmox_api": mock_proxmox_api,
            "core.notifier": mock_notifier,
        }
        with _SysModulesPatch(mocks):
            _check_host_updates(app)

        mock_notifier.send_host_update_notification.assert_called_once()
        results = mock_notifier.send_host_update_notification.call_args[0][0]
        assert len(results) == 1
        assert results[0]["name"] == "pve1"
        assert results[0]["update_count"] == 1

    def test_sends_notification_for_pbs_host(self):
        from core.scheduler import _check_host_updates

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.return_value = "true"

        mock_host = MagicMock()
        mock_host.name = "pbs1"
        mock_host.host_type = "pbs"
        mock_host.is_pbs = True

        mock_host_model = MagicMock()
        mock_host_model.query.all.return_value = [mock_host]

        mock_pbs_client_inst = MagicMock()
        mock_pbs_client_inst.get_apt_updates.return_value = [{"Package": "proxmox-backup-server"}, {"Package": "pbs-i18n"}]

        mock_pbs = MagicMock()
        mock_pbs.PBSClient.return_value = mock_pbs_client_inst

        mock_notifier = MagicMock()

        mocks = {
            "models": MagicMock(Setting=mock_setting, ProxmoxHost=mock_host_model),
            "clients.pbs_client": mock_pbs,
            "core.notifier": mock_notifier,
        }
        with _SysModulesPatch(mocks):
            _check_host_updates(app)

        results = mock_notifier.send_host_update_notification.call_args[0][0]
        assert results[0]["update_count"] == 2
        assert results[0]["host_type"] == "pbs"

    def test_skips_host_on_api_error(self):
        from core.scheduler import _check_host_updates

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.return_value = "true"

        mock_host_ok = MagicMock()
        mock_host_ok.name = "pve1"
        mock_host_ok.host_type = "pve"
        mock_host_ok.is_pbs = False

        mock_host_fail = MagicMock()
        mock_host_fail.name = "pve2"
        mock_host_fail.host_type = "pve"
        mock_host_fail.is_pbs = False

        mock_host_model = MagicMock()
        mock_host_model.query.all.return_value = [mock_host_fail, mock_host_ok]

        call_count = [0]

        def make_client(host):
            call_count[0] += 1
            client = MagicMock()
            if host.name == "pve2":
                client.get_local_node_name.side_effect = Exception("unreachable")
            else:
                client.get_local_node_name.return_value = "node1"
                client.get_apt_updates.return_value = [{"Package": "pkg1"}]
            return client

        mock_proxmox_api = MagicMock()
        mock_proxmox_api.ProxmoxClient.side_effect = make_client
        mock_notifier = MagicMock()

        mocks = {
            "models": MagicMock(Setting=mock_setting, ProxmoxHost=mock_host_model),
            "clients.proxmox_api": mock_proxmox_api,
            "core.notifier": mock_notifier,
        }
        with _SysModulesPatch(mocks):
            _check_host_updates(app)

        # Only the successful host should be in results
        results = mock_notifier.send_host_update_notification.call_args[0][0]
        assert len(results) == 1
        assert results[0]["name"] == "pve1"


# ---------------------------------------------------------------------------
# _run_discovery — unit tests (no real Proxmox calls)
# ---------------------------------------------------------------------------


class TestRunDiscovery:
    def test_returns_early_when_discovery_disabled(self):
        from core.scheduler import _run_discovery

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.return_value = "false"
        mock_host_model = MagicMock()
        mock_proxmox_api = MagicMock()

        mocks = {
            "models": MagicMock(Setting=mock_setting, ProxmoxHost=mock_host_model),
            "clients.proxmox_api": mock_proxmox_api,
        }
        with _SysModulesPatch(mocks):
            _run_discovery(app)

        mock_proxmox_api.ProxmoxClient.assert_not_called()

    def test_returns_early_when_no_hosts(self):
        from core.scheduler import _run_discovery

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.return_value = "true"
        mock_host_model = MagicMock()
        mock_host_model.query.all.return_value = []
        mock_proxmox_api = MagicMock()

        mocks = {
            "models": MagicMock(Setting=mock_setting, ProxmoxHost=mock_host_model),
            "clients.proxmox_api": mock_proxmox_api,
        }
        with _SysModulesPatch(mocks):
            _run_discovery(app)

        mock_proxmox_api.ProxmoxClient.assert_not_called()

    def test_logs_error_on_client_exception_without_propagating(self):
        from core.scheduler import _run_discovery

        app = _make_app()

        mock_host = MagicMock()
        mock_host.name = "pve01"

        mock_setting = MagicMock()
        mock_setting.get.return_value = "true"
        mock_host_model = MagicMock()
        mock_host_model.query.all.return_value = [mock_host]
        mock_proxmox_api = MagicMock()
        mock_proxmox_api.ProxmoxClient.side_effect = Exception("connection refused")
        mock_db = MagicMock()

        mocks = {
            "models": MagicMock(Setting=mock_setting, ProxmoxHost=mock_host_model, db=mock_db),
            "clients.proxmox_api": mock_proxmox_api,
        }
        with _SysModulesPatch(mocks):
            _run_discovery(app)  # must not raise

    def test_multiple_host_failures_all_handled(self):
        from core.scheduler import _run_discovery

        app = _make_app()

        hosts = [MagicMock(name=f"pve0{i}") for i in range(3)]

        mock_setting = MagicMock()
        mock_setting.get.return_value = "true"
        mock_host_model = MagicMock()
        mock_host_model.query.all.return_value = hosts
        mock_proxmox_api = MagicMock()
        mock_proxmox_api.ProxmoxClient.side_effect = Exception("fail")
        mock_db = MagicMock()

        mocks = {
            "models": MagicMock(Setting=mock_setting, ProxmoxHost=mock_host_model, db=mock_db),
            "clients.proxmox_api": mock_proxmox_api,
        }
        with _SysModulesPatch(mocks):
            _run_discovery(app)  # all three failures handled

        # ProxmoxClient was attempted once per host
        assert mock_proxmox_api.ProxmoxClient.call_count == 3


# ---------------------------------------------------------------------------
# _persist_host_packages — DB persistence of APT update packages
# ---------------------------------------------------------------------------


class TestPersistHostPackages:
    def test_host_packages_persisted_to_db(self, app):
        with app.app_context():
            from models import HostUpdatePackage, ProxmoxHost, db

            host = ProxmoxHost(name="pve-test", hostname="pve-test.local", host_type="pve")
            db.session.add(host)
            db.session.commit()

            fake_updates = [
                {"Package": "linux-image-6.1", "OldVersion": "6.1.0-1", "Version": "6.1.0-2", "Priority": "important"},
                {"Package": "curl", "OldVersion": "7.81.0", "Version": "7.85.0", "Priority": "optional"},
            ]

            from core.scheduler import _persist_host_packages

            _persist_host_packages(host, fake_updates)

            pkgs = HostUpdatePackage.query.filter_by(host_id=host.id, status="pending").all()
            assert len(pkgs) == 2
            assert any(p.package_name == "linux-image-6.1" and p.severity == "critical" for p in pkgs)
            assert any(p.package_name == "curl" and p.severity == "normal" for p in pkgs)

    def test_clears_old_pending_before_inserting(self, app):
        with app.app_context():
            from models import HostUpdatePackage, ProxmoxHost, db

            host = ProxmoxHost(name="pve-clear", hostname="pve-clear.local", host_type="pve")
            db.session.add(host)
            db.session.commit()

            # Add an old pending package
            old = HostUpdatePackage(host_id=host.id, package_name="old-pkg", status="pending", severity="normal")
            db.session.add(old)
            db.session.commit()

            from core.scheduler import _persist_host_packages

            _persist_host_packages(
                host, [{"Package": "new-pkg", "OldVersion": "1.0", "Version": "2.0", "Priority": "optional"}]
            )

            pkgs = HostUpdatePackage.query.filter_by(host_id=host.id, status="pending").all()
            assert len(pkgs) == 1
            assert pkgs[0].package_name == "new-pkg"

    def test_preserves_applied_packages(self, app):
        with app.app_context():
            from models import HostUpdatePackage, ProxmoxHost, db

            host = ProxmoxHost(name="pve-keep", hostname="pve-keep.local", host_type="pve")
            db.session.add(host)
            db.session.commit()

            applied = HostUpdatePackage(
                host_id=host.id, package_name="applied-pkg", status="applied", severity="normal"
            )
            db.session.add(applied)
            db.session.commit()

            from core.scheduler import _persist_host_packages

            _persist_host_packages(
                host, [{"Package": "new-pkg", "OldVersion": "1.0", "Version": "2.0", "Priority": "optional"}]
            )

            all_pkgs = HostUpdatePackage.query.filter_by(host_id=host.id).all()
            assert len(all_pkgs) == 2
            assert any(p.package_name == "applied-pkg" and p.status == "applied" for p in all_pkgs)

    def test_priority_mapping(self, app):
        with app.app_context():
            from models import HostUpdatePackage, ProxmoxHost, db

            host = ProxmoxHost(name="pve-prio", hostname="pve-prio.local", host_type="pve")
            db.session.add(host)
            db.session.commit()

            fake_updates = [
                {"Package": "pkg1", "OldVersion": "1.0", "Version": "2.0", "Priority": "important"},
                {"Package": "pkg2", "OldVersion": "1.0", "Version": "2.0", "Priority": "required"},
                {"Package": "pkg3", "OldVersion": "1.0", "Version": "2.0", "Priority": "standard"},
                {"Package": "pkg4", "OldVersion": "1.0", "Version": "2.0", "Priority": "extra"},
            ]

            from core.scheduler import _persist_host_packages

            _persist_host_packages(host, fake_updates)

            pkgs = {p.package_name: p.severity for p in HostUpdatePackage.query.filter_by(host_id=host.id).all()}
            assert pkgs["pkg1"] == "critical"
            assert pkgs["pkg2"] == "important"
            assert pkgs["pkg3"] == "normal"
            assert pkgs["pkg4"] == "normal"
