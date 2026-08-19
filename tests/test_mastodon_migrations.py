"""Tests for the database-migration steps of the Mastodon upgrade.

Both migrate steps must lift the session statement_timeout. The mastodon role carries a
server-side statement_timeout that cancels the long materialized-view rebuilds, and a
cancelled statement aborts the run and strands the schema mid-upgrade.
"""
import sys
from unittest.mock import MagicMock, patch

import apps.mastodon as m


class FakeSSH:
    """Mock SSHClient recording (command, timeout) for every call. Everything succeeds."""

    def __init__(self, responses=None):
        self.responses = responses or []
        self.calls = []

    def execute_sudo(self, cmd, timeout=None):
        self.calls.append((cmd, timeout))
        for substr, resp in self.responses:
            if substr in cmd:
                return resp
        return ("", "", 0)

    def matching(self, substr):
        return [(c, t) for c, t in self.calls if substr in c]


def _run_full_upgrade():
    """Drive run_mastodon_upgrade through a fully successful SSH sequence."""
    cfg = {
        "guest_id": "1", "db_guest_id": "2", "db_name": "mastodon_production",
        "user": "mastodon", "app_dir": "/srv/live", "branch": "main",
        "pgbouncer_host": "10.0.0.9", "pgbouncer_port": "6432",
        "direct_db_host": "10.0.0.2", "direct_db_port": "5432",
        "protection_type": "snapshot", "backup_storage": "", "backup_mode": "snapshot",
        "guest_id_2": "", "current_version": "4.0.0", "latest_version": "4.1.0",
        "auto_upgrade": False,
    }

    mastodon_guest = MagicMock()
    mastodon_guest.ip_address = "10.0.0.5"
    mastodon_guest.credential = MagicMock()
    mastodon_guest.name = "mastodon-app"

    db_guest = MagicMock()
    db_guest.ip_address = None  # skip pg_dump
    db_guest.name = "mastodon-db"

    fake_ssh = FakeSSH([
        ("git ls-files --unmerged", ("", "", 0)),
        # "git stash pop" must precede "git stash" — first contained substring wins.
        ("git stash pop", ("Dropped stash", "", 0)),
        ("git stash", ("No local changes", "", 0)),
        ("git pull", ("Updating aa6da88..deadbee", "", 0)),
    ])
    ssh_ctx = MagicMock()
    ssh_ctx.__enter__ = MagicMock(return_value=fake_ssh)
    ssh_ctx.__exit__ = MagicMock(return_value=False)

    models_stub = MagicMock()

    with patch.object(m, "_get_mastodon_config", return_value=cfg), \
         patch.object(m, "Guest") as mock_guest_cls, \
         patch.object(m, "Setting") as mock_setting, \
         patch.object(m, "snapshot_guest", return_value=(True, "ok")), \
         patch.object(m, "SSHClient") as mock_ssh_cls, \
         patch.object(m, "_swap_env_db", return_value=(True, "swapped")), \
         patch.object(m, "_remediate_environment", return_value=True), \
         patch.dict(sys.modules, {"models": models_stub}):

        mock_setting.get.return_value = ""
        mock_guest_cls.query.get.side_effect = lambda gid: mastodon_guest if gid == 1 else db_guest
        mock_ssh_cls.from_credential.return_value = ssh_ctx

        ok, log_out = m.run_mastodon_upgrade()

    return ok, log_out, fake_ssh


class TestMigrationStatementTimeout:
    def test_both_migrate_steps_lift_statement_timeout(self):
        ok, _log, ssh = _run_full_upgrade()
        assert ok is True

        migrates = ssh.matching("rails db:migrate")
        assert len(migrates) == 2, [c for c, _ in migrates]

        pre = [c for c, _ in migrates if "SKIP_POST_DEPLOYMENT_MIGRATIONS=true" in c]
        post = [c for c, _ in migrates if "SKIP_POST_DEPLOYMENT_MIGRATIONS" not in c]
        assert len(pre) == 1 and len(post) == 1

        for cmd in (pre[0], post[0]):
            assert 'PGOPTIONS="-c statement_timeout=0"' in cmd
            # PGOPTIONS must precede the command it applies to, inside the su - quoting.
            assert cmd.index("PGOPTIONS") < cmd.index("bundle exec rails db:migrate")

    def test_migrate_steps_allow_more_than_ten_minutes(self):
        _ok, _log, ssh = _run_full_upgrade()
        for cmd, timeout in ssh.matching("rails db:migrate"):
            assert timeout == m._MIGRATE_TIMEOUT, cmd
            assert timeout > 600

    def test_pgoptions_is_scoped_to_migrations_only(self):
        _ok, _log, ssh = _run_full_upgrade()
        polluted = [c for c, _ in ssh.calls if "PGOPTIONS" in c and "db:migrate" not in c]
        assert polluted == []
