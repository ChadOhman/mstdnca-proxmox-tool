"""Shared per-app upgrade lock (issue #125).

The per-blueprint JobTracker only guarded the manual upgrade path, so a
scheduled auto-upgrade could run concurrently with an operator-triggered one on
the same host.  Both paths now take the same process-wide, per-app lock.
"""
from unittest.mock import MagicMock, patch

from apps.utils import acquire_upgrade_lock, release_upgrade_lock, upgrade_lock
from tests.test_scheduler import _make_app, _SysModulesPatch


class TestUpgradeLockPrimitives:
    def test_second_acquire_fails_while_held(self):
        assert acquire_upgrade_lock("_test-app-a") is True
        try:
            assert acquire_upgrade_lock("_test-app-a") is False
        finally:
            release_upgrade_lock("_test-app-a")
        assert acquire_upgrade_lock("_test-app-a") is True
        release_upgrade_lock("_test-app-a")

    def test_locks_are_per_app(self):
        assert acquire_upgrade_lock("_test-app-b") is True
        try:
            assert acquire_upgrade_lock("_test-app-c") is True
            release_upgrade_lock("_test-app-c")
        finally:
            release_upgrade_lock("_test-app-b")

    def test_context_manager_reports_and_releases(self):
        with upgrade_lock("_test-app-d") as acquired:
            assert acquired is True
            with upgrade_lock("_test-app-d") as nested:
                assert nested is False
        # Released on exit — and the failed nested acquire released nothing.
        assert acquire_upgrade_lock("_test-app-d") is True
        release_upgrade_lock("_test-app-d")

    def test_double_release_is_a_noop(self):
        acquire_upgrade_lock("_test-app-e")
        release_upgrade_lock("_test-app-e")
        release_upgrade_lock("_test-app-e")  # must not raise
        assert acquire_upgrade_lock("_test-app-e") is True
        release_upgrade_lock("_test-app-e")


class TestSchedulerHonoursUpgradeLock:
    """A cron auto-upgrade must stand down while a manual upgrade holds the lock."""

    def _run_ghost_check(self):
        from core.scheduler import _check_ghost_release

        app = _make_app()
        mock_setting = MagicMock()
        mock_setting.get.side_effect = lambda k, d="": {
            "ghost_guest_id": "7",
            "ghost_current_version": "5.80.0",
            "ghost_auto_upgrade": "true",
            "ghost_last_notified_version": "5.81.0",
        }.get(k, d)

        mock_ghost = MagicMock()
        mock_ghost.check_ghost_release.return_value = (True, "5.81.0", "https://ghost.org")
        mock_ghost.run_ghost_upgrade.return_value = (True, "log")

        mocks = {
            "models": MagicMock(Setting=mock_setting, db=MagicMock()),
            "apps.ghost": mock_ghost,
            "core.notifier": MagicMock(),
            "auth.audit": MagicMock(),
        }
        with _SysModulesPatch(mocks):
            _check_ghost_release(app)
        return mock_ghost

    def test_auto_upgrade_skipped_while_lock_is_held(self):
        assert acquire_upgrade_lock("ghost") is True
        try:
            mock_ghost = self._run_ghost_check()
        finally:
            release_upgrade_lock("ghost")
        mock_ghost.run_ghost_upgrade.assert_not_called()

    def test_auto_upgrade_runs_when_lock_is_free(self):
        mock_ghost = self._run_ghost_check()
        mock_ghost.run_ghost_upgrade.assert_called_once()

    def test_lock_is_released_after_the_auto_upgrade(self):
        self._run_ghost_check()
        assert acquire_upgrade_lock("ghost") is True
        release_upgrade_lock("ghost")


class TestManualUpgradeHonoursUpgradeLock:
    def test_manual_upgrade_refused_while_lock_is_held(self, auth_client):
        assert acquire_upgrade_lock("ghost") is True
        try:
            with patch("apps.ghost.run_ghost_upgrade") as mock_upgrade:
                resp = auth_client.post("/ghost/upgrade", follow_redirects=True)
            assert resp.status_code == 200
            assert b"already in progress" in resp.data
            mock_upgrade.assert_not_called()
        finally:
            release_upgrade_lock("ghost")
