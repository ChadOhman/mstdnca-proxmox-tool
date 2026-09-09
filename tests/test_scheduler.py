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

# Imported at collection time, before any _SysModulesPatch window: auth.audit
# binds `models` at import, so a lazy first import from inside a mocked window
# would leave it holding MagicMocks for the rest of the session.
from auth.audit import log_action

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
            "update_history_purge",
            "ai_upgrade_analysis",
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

    @staticmethod
    def _base_mocks(node_guests, complete=True):
        """Build the standard mock set for a single-host _run_discovery run.

        ``node_guests`` / ``complete`` control what the mocked ProxmoxClient's
        get_node_guests(with_completeness=True) returns.
        """
        mock_host = MagicMock()
        mock_host.name = "pve01"
        mock_host.id = 1

        mock_setting = MagicMock()
        mock_setting.get.return_value = "true"

        mock_host_model = MagicMock()
        mock_host_model.query.all.return_value = [mock_host]

        mock_guest_model = MagicMock()
        # Default: no existing guests match by (host, vmid), and no VMID collision
        # on another host -> each reported guest is treated as newly added.
        mock_guest_model.query.filter_by.return_value.first.return_value = None
        mock_guest_model.query.filter.return_value.first.return_value = None

        mock_tag_model = MagicMock()
        mock_tag_model.query.filter.return_value.all.return_value = []

        mock_db = MagicMock()

        mock_client = MagicMock()
        mock_client.get_local_node_name.return_value = "node1"
        mock_client.get_node_guests.return_value = (node_guests, complete)
        mock_client.get_all_guests.return_value = (node_guests, complete)
        mock_client.get_replication_map.return_value = {}
        mock_client.get_guest_ip.return_value = None
        mock_client.get_guest_mac.return_value = None

        mock_proxmox_api = MagicMock()
        mock_proxmox_api.ProxmoxClient.return_value = mock_client

        mocks = {
            "models": MagicMock(
                Setting=mock_setting, ProxmoxHost=mock_host_model, Guest=mock_guest_model,
                Tag=mock_tag_model, db=mock_db,
            ),
            "clients.proxmox_api": mock_proxmox_api,
        }
        return mock_host, mock_guest_model, mock_db, mocks

    def test_empty_node_list_skips_stale_deletion(self):
        """An empty guest list must never be treated as 'delete everything'."""
        from core.scheduler import _run_discovery

        app = _make_app()
        _host, _mock_guest_model, mock_db, mocks = self._base_mocks([], complete=True)

        with _SysModulesPatch(mocks):
            _run_discovery(app)

        mock_db.session.delete.assert_not_called()

    def test_partial_failure_skips_stale_deletion(self):
        """qemu.get() succeeding while lxc.get() fails must not delete the missing CTs."""
        from core.scheduler import _run_discovery

        app = _make_app()
        node_guests = [
            {"vmid": 1, "name": "vm1", "type": "vm", "status": "stopped", "node": "node1", "tags": ""},
        ]
        _host, _mock_guest_model, mock_db, mocks = self._base_mocks(node_guests, complete=False)

        with _SysModulesPatch(mocks):
            _run_discovery(app)

        mock_db.session.delete.assert_not_called()

    def test_normal_case_still_removes_truly_stale_guest(self):
        """Regression guard: a complete, non-empty inventory still prunes stale guests."""
        from core.scheduler import _run_discovery

        app = _make_app()
        node_guests = [
            {"vmid": 1, "name": "vm1", "type": "vm", "status": "stopped", "node": "node1", "tags": ""},
        ]
        _host, mock_guest_model, mock_db, mocks = self._base_mocks(node_guests, complete=True)

        stale_guest = MagicMock()
        mock_guest_model.query.filter.return_value.all.return_value = [stale_guest]
        mock_guest_model.query.filter.return_value.count.return_value = 5

        with _SysModulesPatch(mocks):
            _run_discovery(app)

        mock_db.session.delete.assert_called_once_with(stale_guest)


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


# ---------------------------------------------------------------------------
# Issue #126 — background-job reliability
#
# These classes use the real app fixture from conftest (no local override), so
# they exercise the real DB/session behaviour the scheduler depends on.
# ---------------------------------------------------------------------------


class TestLogActionOutsideRequestContext:
    """Scheduler jobs run under an app context only — log_action must not raise."""

    def test_writes_audit_row_without_request_context(self, app):
        from models import AuditLog, db

        with app.app_context():
            log_action("_sched_audit_test", "system", resource_name="nightly")
            db.session.commit()
            row = AuditLog.query.filter_by(action="_sched_audit_test").first()
            try:
                assert row is not None
                assert row.user_id is None
                assert row.ip_address is None
            finally:
                if row:
                    db.session.delete(row)
                    db.session.commit()

    def test_broadcast_username_falls_back_to_system(self, app):
        from models import AuditLog, db

        with app.app_context():
            with patch("core.collaboration.collab_hub.broadcast") as mock_broadcast:
                log_action("_sched_audit_bc", "system")
                assert mock_broadcast.call_args.args[0]["username"] == "system"

                log_action("_sched_audit_bc", "system", actor="scheduler")
                assert mock_broadcast.call_args.args[0]["username"] == "scheduler"

            db.session.rollback()
            AuditLog.query.filter_by(action="_sched_audit_bc").delete()
            db.session.commit()


class TestMaintenanceWindowParsing:
    def test_parse_window_time_accepts_zero_padded(self):
        from datetime import time as _time

        from core.scheduler import parse_window_time
        assert parse_window_time("02:00") == _time(2, 0)
        assert parse_window_time(" 23:59 ") == _time(23, 59)

    @pytest.mark.parametrize("bad", ["", None, "2:00", "24:00", "23:60", "abc", "0200", "23:0"])
    def test_parse_window_time_rejects_bad_values(self, bad):
        from core.scheduler import parse_window_time
        assert parse_window_time(bad) is None


class TestInMaintenanceWindow:
    """A window spanning midnight must fire on both sides of it (#126)."""

    def _window(self, day="daily", start="23:00", end="02:00"):
        from types import SimpleNamespace
        return SimpleNamespace(name="nightly", day_of_week=day, start_time=start, end_time=end)

    def test_wraparound_matches_before_midnight(self):
        from datetime import datetime as _dt

        from core.scheduler import _in_maintenance_window
        assert _in_maintenance_window(self._window(), _dt(2026, 1, 5, 23, 30))

    def test_wraparound_matches_after_midnight(self):
        from datetime import datetime as _dt

        from core.scheduler import _in_maintenance_window
        assert _in_maintenance_window(self._window(), _dt(2026, 1, 6, 1, 0))

    def test_wraparound_excludes_midday(self):
        from datetime import datetime as _dt

        from core.scheduler import _in_maintenance_window
        assert not _in_maintenance_window(self._window(), _dt(2026, 1, 5, 12, 0))

    def test_same_day_window(self):
        from datetime import datetime as _dt

        from core.scheduler import _in_maintenance_window
        w = self._window(start="02:00", end="05:00")
        assert _in_maintenance_window(w, _dt(2026, 1, 5, 3, 0))
        assert not _in_maintenance_window(w, _dt(2026, 1, 5, 6, 0))

    def test_day_name_matched_case_insensitively(self):
        from datetime import datetime as _dt

        from core.scheduler import _in_maintenance_window
        # 2026-01-05 is a Monday, 2026-01-06 a Tuesday.
        assert _in_maintenance_window(self._window(day="Monday"), _dt(2026, 1, 5, 23, 30))
        assert not _in_maintenance_window(self._window(day="MONDAY"), _dt(2026, 1, 6, 23, 30))

    def test_invalid_times_never_match(self):
        from datetime import datetime as _dt

        from core.scheduler import _in_maintenance_window
        assert not _in_maintenance_window(self._window(start="2am", end="5am"),
                                          _dt(2026, 1, 5, 3, 0))


class TestRunAutoUpdatesWindow:
    """End-to-end: _run_auto_updates honours a midnight-spanning window."""

    def _seed(self, app, name):
        from models import Guest, MaintenanceWindow, UpdatePackage, db
        with app.app_context():
            window = MaintenanceWindow(name=f"win-{name}", day_of_week="daily",
                                       start_time="23:00", end_time="02:00", enabled=True)
            db.session.add(window)
            db.session.flush()
            guest = Guest(name=name, guest_type="ct", enabled=True, auto_update=True,
                          power_state="running", maintenance_window_id=window.id)
            db.session.add(guest)
            db.session.flush()
            db.session.add(UpdatePackage(guest_id=guest.id, package_name="bash",
                                         status="pending", severity="normal"))
            db.session.commit()
            return guest.id, window.id

    def _cleanup(self, app, guest_id, window_id):
        from models import Guest, MaintenanceWindow, db
        with app.app_context():
            g = Guest.query.get(guest_id)
            if g:
                db.session.delete(g)
            w = MaintenanceWindow.query.get(window_id)
            if w:
                db.session.delete(w)
            db.session.commit()

    def _run_at(self, app, when):
        from datetime import datetime as _dt

        import core.scheduler as sched_mod

        applied = []

        def fake_apply(guest, dist_upgrade=False):
            applied.append(guest.name)
            return True, "ok"

        with patch("core.scanner.apply_updates", side_effect=fake_apply), \
             patch("core.update_history.record_update_history"), \
             patch("core.notifier.send_updates_applied_notification"), \
             patch.object(sched_mod, "datetime", wraps=_dt) as mock_dt:
            mock_dt.now.return_value = when
            sched_mod._run_auto_updates(app)
        return applied

    def test_fires_before_midnight(self, app):
        from datetime import datetime as _dt
        gid, wid = self._seed(app, "_auto-win-a")
        try:
            assert "_auto-win-a" in self._run_at(app, _dt(2026, 1, 5, 23, 30))
        finally:
            self._cleanup(app, gid, wid)

    def test_fires_after_midnight(self, app):
        from datetime import datetime as _dt
        gid, wid = self._seed(app, "_auto-win-b")
        try:
            assert "_auto-win-b" in self._run_at(app, _dt(2026, 1, 6, 1, 0))
        finally:
            self._cleanup(app, gid, wid)

    def test_does_not_fire_at_midday(self, app):
        from datetime import datetime as _dt
        gid, wid = self._seed(app, "_auto-win-c")
        try:
            assert "_auto-win-c" not in self._run_at(app, _dt(2026, 1, 5, 12, 0))
        finally:
            self._cleanup(app, gid, wid)


class TestIntervalValidation:
    def test_parse_interval_accepts_in_range(self):
        from core.scheduler import parse_interval
        assert parse_interval("scan_interval", "12") == (12, None)
        assert parse_interval("scan_interval", " 6 ") == (6, None)

    @pytest.mark.parametrize("bad", ["0", "-1", "6h", "", None, "99999", "1.5"])
    def test_parse_interval_rejects_bad_values(self, bad):
        from core.scheduler import parse_interval
        value, error = parse_interval("scan_interval", bad)
        assert value is None
        assert error

    def test_interval_setting_falls_back_on_garbage(self, app):
        from core.scheduler import interval_setting
        from models import Setting, db
        with app.app_context():
            original = Setting.get("scan_interval", "6")
            try:
                Setting.set("scan_interval", "6h")
                db.session.commit()
                assert interval_setting("scan_interval") == 6
            finally:
                Setting.set("scan_interval", original)
                db.session.commit()

    def test_interval_setting_clamps_out_of_range(self, app):
        from core.scheduler import interval_setting
        from models import Setting, db
        with app.app_context():
            original = Setting.get("service_check_interval", "5")
            try:
                Setting.set("service_check_interval", "0")
                db.session.commit()
                assert interval_setting("service_check_interval") == 1
            finally:
                Setting.set("service_check_interval", original)
                db.session.commit()

    def test_init_scheduler_boots_with_unusable_stored_interval(self, app):
        """A bad stored value must never raise inside create_app()."""
        from datetime import timedelta as _td

        import core.scheduler as sched_mod
        from models import Setting, db

        with app.app_context():
            original = Setting.get("scan_interval", "6")
            Setting.set("scan_interval", "every-six-hours")
            db.session.commit()

        sched_mod._scheduler = None
        try:
            with patch("core.scheduler.BackgroundScheduler") as MockBGS:
                MockBGS.return_value = MagicMock()
                result = sched_mod.init_scheduler(app)
            assert result is MockBGS.return_value

            triggers = {
                c.kwargs.get("id"): c.kwargs.get("trigger")
                for c in MockBGS.return_value.add_job.call_args_list
            }
            assert triggers["scan_all"].interval == _td(hours=6)
        finally:
            sched_mod._scheduler = None
            with app.app_context():
                Setting.set("scan_interval", original)
                db.session.commit()


class TestSchedulerJobDefaults:
    """21 jobs on a 10-thread pool need a real misfire grace window (#126)."""

    def test_job_defaults_and_executor_are_configured(self, app):
        import core.scheduler as sched_mod

        sched_mod._scheduler = None
        try:
            with patch("core.scheduler.BackgroundScheduler") as MockBGS:
                MockBGS.return_value = MagicMock()
                sched_mod.init_scheduler(app)

            kwargs = MockBGS.call_args.kwargs
            assert kwargs["job_defaults"]["misfire_grace_time"] == sched_mod.JOB_MISFIRE_GRACE_SECONDS
            assert sched_mod.JOB_MISFIRE_GRACE_SECONDS >= 60
            assert kwargs["job_defaults"]["coalesce"] is True
            assert "default" in kwargs["executors"]
        finally:
            sched_mod._scheduler = None

    def test_init_scheduler_still_idempotent(self, app):
        import core.scheduler as sched_mod

        sched_mod._scheduler = None
        try:
            with patch("core.scheduler.BackgroundScheduler") as MockBGS:
                MockBGS.return_value = MagicMock()
                first = sched_mod.init_scheduler(app)
                second = sched_mod.init_scheduler(app)
            assert first is second
            MockBGS.assert_called_once()
        finally:
            sched_mod._scheduler = None


class TestScanAllGuestsRollback:
    """A guest whose scan poisons the session must not break the next guest."""

    def test_failure_does_not_poison_next_guest(self, app):
        from core.scanner import scan_all_guests
        from models import Guest, db

        with app.app_context():
            bad = Guest(name="_rb-a-bad", guest_type="ct", enabled=True, power_state="running")
            good = Guest(name="_rb-b-good", guest_type="ct", enabled=True, power_state="running")
            db.session.add_all([bad, good])
            db.session.commit()
            bad_id, good_id = bad.id, good.id

        def fake_scan(guest):
            if guest.name == "_rb-a-bad":
                # NOT NULL violation leaves the session needing a rollback.
                db.session.add(Guest(name=None, guest_type="ct"))
                db.session.commit()
            db.session.commit()
            return {"guest": guest.name}

        try:
            with app.app_context():
                with patch("core.scanner.scan_guest", side_effect=fake_scan):
                    results = scan_all_guests()
                names = [r["guest"] for r in results]
                assert "_rb-a-bad" not in names
                assert "_rb-b-good" in names
        finally:
            with app.app_context():
                db.session.rollback()
                for gid in (bad_id, good_id):
                    g = Guest.query.get(gid)
                    if g:
                        db.session.delete(g)
                db.session.commit()


class TestPollUnifiEventsBatching:
    """#126: one IN(...) dedup query, a capped batch, and rollback on failure."""

    _SETTINGS = {
        "unifi_enabled": "true",
        "unifi_api_poll_enabled": "true",
        "unifi_base_url": "https://unifi.example",
        "unifi_username": "admin",
        "unifi_password": "encrypted",
        "unifi_site": "default",
    }

    def _configure(self, app):
        from models import Setting, db
        with app.app_context():
            saved = {k: Setting.get(k, "") for k in self._SETTINGS}
            for k, v in self._SETTINGS.items():
                Setting.set(k, v)
            db.session.commit()
            return saved

    def _restore(self, app, saved):
        from models import Setting, UnifiLogEntry, db
        with app.app_context():
            db.session.rollback()
            for k, v in saved.items():
                Setting.set(k, v)
            UnifiLogEntry.query.filter_by(source="api").delete()
            db.session.commit()

    def _run(self, app, api_get):
        import core.scheduler as sched_mod
        client = MagicMock()
        client._api_get.side_effect = api_get
        with patch("auth.credential_store.decrypt", return_value="pw"), \
             patch("clients.unifi_client.get_cached_client", return_value=client):
            sched_mod._poll_unifi_events(app)
        return client

    def test_existing_rule_ids_are_not_reinserted(self, app):
        from datetime import datetime as _dt
        from datetime import timezone as _tz

        from models import UnifiLogEntry, db
        saved = self._configure(app)
        try:
            with app.app_context():
                db.session.add(UnifiLogEntry(timestamp=_dt.now(_tz.utc), source="api",
                                             log_type="system", rule_id="evt-1"))
                db.session.commit()

            events = [{"_id": "evt-1", "msg": "dup"}, {"_id": "evt-2", "msg": "new"}]
            self._run(app, [events, []])

            with app.app_context():
                keys = {e.rule_id for e in UnifiLogEntry.query.filter_by(source="api").all()}
                assert keys == {"evt-1", "evt-2"}
                assert UnifiLogEntry.query.filter_by(source="api", rule_id="evt-1").count() == 1
        finally:
            self._restore(app, saved)

    def test_duplicate_ids_within_one_batch_inserted_once(self, app):
        from models import UnifiLogEntry
        saved = self._configure(app)
        try:
            events = [{"_id": "evt-dup", "msg": "a"}, {"_id": "evt-dup", "msg": "b"}]
            self._run(app, [events, []])
            with app.app_context():
                assert UnifiLogEntry.query.filter_by(source="api", rule_id="evt-dup").count() == 1
        finally:
            self._restore(app, saved)

    def test_batch_is_capped(self, app):
        import core.scheduler as sched_mod
        from models import UnifiLogEntry
        saved = self._configure(app)
        try:
            cap = sched_mod.UNIFI_POLL_MAX_EVENTS
            events = [{"_id": f"evt-{i}", "msg": "x"} for i in range(cap + 50)]
            self._run(app, [events, []])
            with app.app_context():
                assert UnifiLogEntry.query.filter_by(source="api").count() == cap
        finally:
            self._restore(app, saved)

    def test_api_failure_rolls_back_and_does_not_raise(self, app):
        from models import Setting, UnifiLogEntry, db
        saved = self._configure(app)
        try:
            self._run(app, RuntimeError("controller down"))
            with app.app_context():
                assert UnifiLogEntry.query.filter_by(source="api").count() == 0
                # Session is still usable — no PendingRollbackError.
                Setting.set("_unifi_probe", "ok")
                db.session.commit()
                Setting.query.filter_by(key="_unifi_probe").delete()
                db.session.commit()
        finally:
            self._restore(app, saved)


class TestDiscoveryMacReuse:
    """A changed MAC on the same guest type also signals VMID reuse (#126)."""

    CRED_NAME = "_mac-reuse-cred"

    def _seed(self, app, mac):
        from auth import credential_store
        from models import Credential, Guest, ProxmoxHost, ScanResult, Setting, UpdatePackage, db
        with app.app_context():
            # FK enforcement is on (#127): the guest must reference a real credential.
            cred = Credential.query.filter_by(name=self.CRED_NAME).first()
            if cred is None:
                cred = Credential(name=self.CRED_NAME, username="root", auth_type="password",
                                  encrypted_value=credential_store.encrypt("test-only-password"))
                db.session.add(cred)
                db.session.flush()
            # Other suites toggle this off via POST /settings/scan and don't restore it.
            Setting.set("discovery_enabled", "true")
            host = ProxmoxHost(name="_mac-pve", hostname="10.9.9.9", host_type="pve",
                               auth_type="token", api_token_id="t@pam!x", api_token_secret="s")
            db.session.add(host)
            db.session.flush()
            guest = Guest(name="old", guest_type="ct", vmid=777, proxmox_host_id=host.id,
                          mac_address=mac, status="up-to-date", power_state="running",
                          auto_update=True, credential_id=cred.id)
            db.session.add(guest)
            db.session.flush()
            db.session.add(UpdatePackage(guest_id=guest.id, package_name="p", status="pending"))
            db.session.add(ScanResult(guest_id=guest.id, total_updates=1))
            db.session.commit()
            return host.id, guest.id

    def _cleanup(self, app, host_id):
        from models import Guest, ProxmoxHost, db
        with app.app_context():
            db.session.rollback()
            for g in Guest.query.filter_by(proxmox_host_id=host_id).all():
                db.session.delete(g)
            h = ProxmoxHost.query.get(host_id)
            if h:
                db.session.delete(h)
            db.session.commit()

    def _discover(self, app, mac):
        import core.scheduler as sched_mod
        client = MagicMock()
        client.get_local_node_name.return_value = "node1"
        node_guests = [
            {"vmid": 777, "name": "rebuilt", "type": "ct", "status": "running",
             "node": "node1", "tags": ""},
        ]
        client.get_node_guests.return_value = (node_guests, True)
        client.get_all_guests.return_value = (node_guests, True)
        client.get_replication_map.return_value = {}
        client.get_guest_ip.return_value = "10.9.9.50"
        client.get_guest_mac.return_value = mac
        with patch("clients.proxmox_api.ProxmoxClient", return_value=client):
            sched_mod._run_discovery(app)

    def test_changed_mac_clears_stale_data(self, app):
        from models import Guest
        host_id, guest_id = self._seed(app, "AA:BB:CC:DD:EE:01")
        try:
            self._discover(app, "AA:BB:CC:DD:EE:99")
            with app.app_context():
                g = Guest.query.get(guest_id)
                assert g.mac_address == "AA:BB:CC:DD:EE:99"
                assert g.status == "unknown"
                assert len(g.updates) == 0
                assert len(g.scan_results) == 0
                # Deliberately preserved — a MAC can also change legitimately.
                assert g.auto_update is True
                from models import Credential
                assert g.credential_id == Credential.query.filter_by(name=self.CRED_NAME).first().id
        finally:
            self._cleanup(app, host_id)

    def test_same_mac_keeps_stale_data(self, app):
        from models import Guest
        host_id, guest_id = self._seed(app, "AA:BB:CC:DD:EE:01")
        try:
            self._discover(app, "aa:bb:cc:dd:ee:01")  # case-insensitive match
            with app.app_context():
                g = Guest.query.get(guest_id)
                assert g.status == "up-to-date"
                assert len(g.updates) == 1
                assert len(g.scan_results) == 1
        finally:
            self._cleanup(app, host_id)

    def test_missing_mac_is_not_treated_as_reuse(self, app):
        from models import Guest
        host_id, guest_id = self._seed(app, "AA:BB:CC:DD:EE:01")
        try:
            self._discover(app, "")
            with app.app_context():
                g = Guest.query.get(guest_id)
                assert g.status == "up-to-date"
                assert len(g.updates) == 1
        finally:
            self._cleanup(app, host_id)


# ---------------------------------------------------------------------------
# _purge_old_update_history (issue #127)
# ---------------------------------------------------------------------------


class TestPurgeOldUpdateHistory:
    """Exercised against the real database rather than module mocks."""

    def _seed(self, app):
        from datetime import datetime, timedelta, timezone

        from models import Guest, ScanResult, UpdateHistory, db

        now = datetime.now(timezone.utc)
        with app.app_context():
            guest = Guest(name="_retention-guest", guest_type="ct")
            db.session.add(guest)
            db.session.commit()
            gid = guest.id

            db.session.add_all([
                UpdateHistory(guest_id=gid, package_count=1, applied_at=now - timedelta(days=400)),
                UpdateHistory(guest_id=gid, package_count=1, applied_at=now - timedelta(days=10)),
                ScanResult(guest_id=gid, scanned_at=now - timedelta(days=200)),
                ScanResult(guest_id=gid, scanned_at=now - timedelta(days=10)),
            ])
            db.session.commit()
        return gid

    def _cleanup(self, app, gid):
        from models import Guest, db

        with app.app_context():
            guest = Guest.query.get(gid)
            if guest:
                db.session.delete(guest)
                db.session.commit()

    def test_prunes_rows_past_the_default_retention(self, app):
        from core.scheduler import _purge_old_update_history
        from models import ScanResult, UpdateHistory

        gid = self._seed(app)
        try:
            _purge_old_update_history(app)
            with app.app_context():
                assert UpdateHistory.query.filter_by(guest_id=gid).count() == 1
                assert ScanResult.query.filter_by(guest_id=gid).count() == 1
        finally:
            self._cleanup(app, gid)

    def test_retention_windows_are_configurable(self, app):
        from core.scheduler import _purge_old_update_history
        from models import ScanResult, Setting, UpdateHistory

        gid = self._seed(app)
        try:
            with app.app_context():
                Setting.set("update_history_retention_days", "5")
                Setting.set("scan_result_retention_days", "5")

            _purge_old_update_history(app)
            with app.app_context():
                assert UpdateHistory.query.filter_by(guest_id=gid).count() == 0
                assert ScanResult.query.filter_by(guest_id=gid).count() == 0
        finally:
            with app.app_context():
                from models import Setting as _S
                _S.set("update_history_retention_days", "365")
                _S.set("scan_result_retention_days", "90")
            self._cleanup(app, gid)

    def test_non_numeric_retention_falls_back_to_defaults(self, app):
        from core.scheduler import _purge_old_update_history
        from models import ScanResult, Setting, UpdateHistory

        gid = self._seed(app)
        try:
            with app.app_context():
                Setting.set("update_history_retention_days", "not-a-number")
                Setting.set("scan_result_retention_days", "")

            _purge_old_update_history(app)  # must not raise
            with app.app_context():
                assert UpdateHistory.query.filter_by(guest_id=gid).count() == 1
                assert ScanResult.query.filter_by(guest_id=gid).count() == 1
        finally:
            with app.app_context():
                from models import Setting as _S
                _S.set("update_history_retention_days", "365")
                _S.set("scan_result_retention_days", "90")
            self._cleanup(app, gid)
