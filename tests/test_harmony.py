"""Harmony upgrade automation: version parsing, doctor gating, upgrade flow, routes."""
import json
from unittest.mock import MagicMock, patch

import pytest

from models import Setting, db

# ---------------------------------------------------------------------------
# Fixtures / fakes
# ---------------------------------------------------------------------------

# A real-world shaped `harmony doctor --offline` run for an instance behind a
# Cloudflare tunnel: the DNS WARNs and the reachability FAIL are permanent and
# must not block anything.
HEALTHY_DOCTOR = """\
Harmony doctor  https://chat.example.com  (images 1.9.0, TLS internal CA)

Host
[ OK ] compose        Docker Compose 2.29.1
[ OK ] memory         7940 MB RAM (5120 MB available), 2047 MB swap
[ OK ] disk           40 GB free on /
[ OK ] backup         last backup 20261021-040000 (0 days old)

Containers
[ OK ] containers     all 14 services running

Database
[ OK ] migrations     212 applied, at the checkout's head
[ OK ] domain         instance_config.domain = chat.example.com
[ OK ] admin          1 admin(s), first: @admin
[ OK ] registration   invite
[ OK ] listener       harmony_listener role exists

DNS
[WARN] chat.example.com points to 104.16.1.1, this server is 203.0.113.9
       fix: set: A chat.example.com -> 203.0.113.9 (DNS only, not proxied, while certificates are issued)

TLS certificates
[ OK ] chat.example.com Caddy's internal CA (short-lived, renewed by Caddy; devices must trust its root)

Federation (the public URL)
[ OK ] webfinger      https://chat.example.com/.well-known/webfinger?resource=acct:admin@chat.example.com (internal TLS)
[ OK ] nodeinfo       https://chat.example.com/.well-known/nodeinfo (internal TLS)

Services
[ OK ] push           VAPID configured (subject mailto:admin@example.com)
[WARN] email          no SMTP server: password reset and email confirmation do not work
       fix: harmony config (answer y to SMTP)
[ OK ] auth           https://db.chat.example.com/auth/v1/health

Voice
[ OK ] livekit        the backend reaches LiveKit
[ OK ] media tcp      203.0.113.9:7881 accepts connections

Security
[ OK ] event triggers only Supabase's
[FAIL] reachable      listening on the public address (tried from this server): 8443
       fix: firewall them

Versions
[ OK ] supabase       stack at 1234567890ab (pinned)
"""


def _doctor(replace=None, drop=None):
    text = HEALTHY_DOCTOR
    for old, new in (replace or {}).items():
        assert old in text
        text = text.replace(old, new)
    for line in drop or []:
        text = "\n".join(ln for ln in text.splitlines() if not ln.startswith(line))
    return text


class FakeSSH:
    """Mock SSHClient: matches command substrings to canned (stdout, stderr, code).

    A response may be a list, consumed one per matching call (the last one
    repeats), for commands whose answer changes over the run.
    """

    def __init__(self, responses=None, stream_output="", stream_code=0, stream_stops=False):
        self.responses = responses or []
        self.calls = []
        self.stream_output = stream_output
        self.stream_code = stream_code
        self.stream_stops = stream_stops

    def execute_sudo(self, cmd, timeout=None):
        self.calls.append(cmd)
        for substr, resp in self.responses:
            if substr in cmd:
                if isinstance(resp, list):
                    return resp.pop(0) if len(resp) > 1 else resp[0]
                return resp
        return ("", "", 0)

    def execute_sudo_streaming(self, cmd, callback, timeout=600, stop_fn=None):
        self.calls.append(cmd)
        if self.stream_stops and stop_fn and stop_fn():
            return -1
        if self.stream_output:
            callback(self.stream_output)
        return self.stream_code

    def ran(self, substr):
        return any(substr in c for c in self.calls)

    def index_of(self, substr):
        for i, c in enumerate(self.calls):
            if substr in c:
                return i
        return -1

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _healthy_ssh(**kwargs):
    return FakeSSH([
        ("harmony version", [("v1.8.9\n1.8.9\n", "", 0), ("v1.9.0\n1.9.0\n", "", 0)]),
        ("harmony backup", ("==> Dumping the database...\n ✓ Backup written\n", "", 0)),
        ("doctor --offline", (HEALTHY_DOCTOR, "", 1)),
        ("pg_policies", ("2\n", "", 0)),
    ], **kwargs)


def _settings(overrides=None):
    base = {
        "harmony_guest_id": "1",
        "harmony_dir": "/opt/harmony",
        "harmony_current_version": "1.8.9",
        "harmony_latest_version": "1.9.0",
        "harmony_protection_type": "snapshot",
        "harmony_backup_storage": "",
        "harmony_backup_mode": "snapshot",
        "harmony_auto_upgrade": "false",
        "harmony_installed": "true",
    }
    base.update(overrides or {})
    return base


def _run(fn_name, ssh, settings_overrides=None, sink=None, snapshot=(True, "ok"), **kwargs):
    import apps.harmony as harmony

    settings = _settings(settings_overrides)
    fake_setting = MagicMock()
    fake_setting.get.side_effect = lambda k, d="": settings.get(k, d)
    if sink is not None:
        fake_setting.set.side_effect = lambda k, v: sink.update({k: v})

    guest = MagicMock()
    guest.credential = MagicMock()
    guest.ip_address = "10.0.0.132"
    guest.name = "harmony-vm"
    guest.proxmox_host = None
    fake_guest_cls = MagicMock()
    fake_guest_cls.query.get.return_value = guest

    with (
        patch("apps.harmony.Setting", fake_setting),
        patch("apps.harmony.Guest", fake_guest_cls),
        patch("apps.harmony.SSHClient") as fake_sshclient,
        patch("apps.harmony.snapshot_guest", return_value=snapshot) as fake_snapshot,
        patch("apps.harmony.time.sleep"),
    ):
        fake_sshclient.from_credential.return_value = ssh
        ok, log = getattr(harmony, fn_name)(**kwargs)
    return ok, log, fake_snapshot


# ---------------------------------------------------------------------------
# Version parsing
# ---------------------------------------------------------------------------

class TestParseVersion:
    def test_release_checkout(self):
        from apps.harmony import parse_harmony_version
        assert parse_harmony_version("v1.8.9\n1.8.9\n") == ("1.8.9", "v1.8.9", "1.8.9")

    def test_edge_channel_has_no_version(self):
        from apps.harmony import parse_harmony_version
        version, code_ref, image_tag = parse_harmony_version("v1.8.9-14-gabc1234\nedge\n")
        assert version is None
        assert (code_ref, image_tag) == ("v1.8.9-14-gabc1234", "edge")

    def test_falls_back_to_code_ref(self):
        from apps.harmony import parse_harmony_version
        assert parse_harmony_version("v2.0.1\n")[0] == "2.0.1"

    def test_strips_ansi(self):
        from apps.harmony import parse_harmony_version
        assert parse_harmony_version("\x1b[1mv1.8.9\x1b[0m\n\x1b[32m1.8.9\x1b[0m\n")[0] == "1.8.9"

    def test_rejects_prerelease_tags(self):
        from apps.harmony import parse_harmony_version
        assert parse_harmony_version("v1.9.0-rc1\n1.9.0-rc1\n")[0] is None


# ---------------------------------------------------------------------------
# Doctor gating
# ---------------------------------------------------------------------------

def _gate(results, label):
    return next(r for r in results if r[0] == label)


class TestEvaluateDoctor:
    def test_healthy_despite_permanent_tunnel_fails_and_warns(self):
        from apps.harmony import evaluate_doctor_output
        ok, results = evaluate_doctor_output(HEALTHY_DOCTOR)
        assert ok is True, results
        assert {r[0] for r in results} == {"containers", "migrations", "auth", "livekit"}

    def test_container_fail_blocks(self):
        from apps.harmony import evaluate_doctor_output
        out = _doctor({"[ OK ] containers     all 14 services running":
                       "[FAIL] federation-server running, unhealthy\n"
                       "       fix: harmony logs federation-server"})
        ok, results = evaluate_doctor_output(out)
        assert ok is False
        assert "federation-server" in _gate(results, "containers")[2]

    def test_starting_container_warn_is_not_a_fail(self):
        from apps.harmony import evaluate_doctor_output
        out = _doctor({"[ OK ] containers     all 14 services running":
                       "[WARN] web            running, health check starting"})
        assert evaluate_doctor_output(out)[0] is True

    def test_missing_containers_section_blocks(self):
        from apps.harmony import evaluate_doctor_output
        out = _doctor(drop=["Containers", "[ OK ] containers"])
        ok, results = evaluate_doctor_output(out)
        assert ok is False
        assert _gate(results, "containers")[1] is False

    def test_container_named_auth_does_not_satisfy_auth_check(self):
        from apps.harmony import evaluate_doctor_output
        out = _doctor(
            {"[ OK ] containers     all 14 services running": "[FAIL] auth           running, unhealthy"},
            drop=["[ OK ] auth"],
        )
        ok, results = evaluate_doctor_output(out)
        assert ok is False
        assert _gate(results, "auth")[2] == "check missing from doctor output"

    @pytest.mark.parametrize("line, replacement", [
        ("[ OK ] migrations     212 applied, at the checkout's head",
         "[FAIL] migrations     3 of 215 migrations not applied (first: 20261001000000)"),
        ("[ OK ] auth           https://db.chat.example.com/auth/v1/health",
         "[FAIL] auth           https://db.chat.example.com/auth/v1/health: HTTP 502"),
        ("[ OK ] livekit        the backend reaches LiveKit",
         "[FAIL] livekit        the backend cannot use LiveKit (HTTP 500: )"),
        ("[ OK ] event triggers only Supabase's",
         "[FAIL] database       Postgres does not answer; security checks skipped"),
    ])
    def test_gated_check_fail_blocks(self, line, replacement):
        from apps.harmony import evaluate_doctor_output
        assert evaluate_doctor_output(_doctor({line: replacement}))[0] is False

    @pytest.mark.parametrize("check", ["[ OK ] migrations", "[ OK ] auth"])
    def test_required_check_missing_blocks(self, check):
        from apps.harmony import evaluate_doctor_output
        assert evaluate_doctor_output(_doctor(drop=[check]))[0] is False

    def test_livekit_optional_without_voice(self):
        from apps.harmony import evaluate_doctor_output
        ok, results = evaluate_doctor_output(_doctor(drop=["Voice", "[ OK ] livekit", "[ OK ] media tcp"]))
        assert ok is True
        assert "livekit" not in {r[0] for r in results}

    def test_migrations_warn_does_not_block(self):
        from apps.harmony import evaluate_doctor_output
        out = _doctor({"[ OK ] migrations     212 applied, at the checkout's head":
                       "[WARN] migrations     the database has 1 migration(s) this checkout lacks"})
        assert evaluate_doctor_output(out)[0] is True

    def test_ansi_colours_are_ignored(self):
        from apps.harmony import evaluate_doctor_output
        coloured = HEALTHY_DOCTOR.replace("[ OK ]", "\x1b[32m[ OK ]\x1b[0m").replace(
            "Containers", "\x1b[1mContainers\x1b[0m")
        assert evaluate_doctor_output(coloured)[0] is True


class TestRealtimePolicy:
    def test_policy_present(self):
        from apps.harmony import check_realtime_policy
        ok, detail = check_realtime_policy(FakeSSH([("pg_policies", ("2\n", "", 0))]), "/opt/harmony")
        assert ok is True

    def test_policy_missing_names_upstream_bug(self):
        from apps.harmony import check_realtime_policy
        ok, detail = check_realtime_policy(FakeSSH([("pg_policies", ("0\n", "", 0))]), "/opt/harmony")
        assert ok is False
        assert "#168" in detail

    def test_query_error(self):
        from apps.harmony import check_realtime_policy
        ok, detail = check_realtime_policy(
            FakeSSH([("pg_policies", ("", "Error: No such container", 1))]), "/opt/harmony")
        assert ok is False
        assert "exit 1" in detail

    def test_query_runs_from_self_host_with_quoted_sql(self):
        from apps.harmony import _realtime_policy_cmd
        cmd = _realtime_policy_cmd("/opt/harmony")
        assert cmd.startswith("cd /opt/harmony/self-host && ")
        assert "docker compose ps -q --status running db" in cmd
        assert "-c 'SELECT count(*) FROM pg_policies" in cmd


# ---------------------------------------------------------------------------
# Release check
# ---------------------------------------------------------------------------

def _urlopen_json(payload):
    resp = MagicMock()
    resp.read.return_value = json.dumps(payload).encode()
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


class TestCheckRelease:
    def test_newer_release_flags_update(self, app):
        from apps.harmony import check_harmony_release
        with app.app_context():
            Setting.set("harmony_current_version", "1.8.9")
            with patch("apps.harmony.urlopen", return_value=_urlopen_json({"tag_name": "v1.9.0"})):
                update, latest, url = check_harmony_release()
            assert (update, latest) == (True, "1.9.0")
            assert url.endswith("/releases/tag/v1.9.0")
            assert Setting.get("harmony_update_available") == "true"
            Setting.set("harmony_current_version", "")

    @pytest.mark.parametrize("tag", ["v1.9.0-rc1", "v1.9", "v1.9.0;reboot", "master"])
    def test_non_release_tags_rejected(self, app, tag):
        from apps.harmony import check_harmony_release
        with app.app_context():
            Setting.set("harmony_latest_version", "")
            with patch("apps.harmony.urlopen", return_value=_urlopen_json({"tag_name": tag})):
                assert check_harmony_release() == (False, "", "")
            assert Setting.get("harmony_latest_version", "") == ""

    def test_network_error(self, app):
        from apps.harmony import check_harmony_release
        with app.app_context(), patch("apps.harmony.urlopen", side_effect=OSError("boom")):
            assert check_harmony_release() == (False, "", "")


# ---------------------------------------------------------------------------
# Upgrade
# ---------------------------------------------------------------------------

class TestUpgrade:
    def test_success_path(self):
        written = {}
        ssh = _healthy_ssh(stream_output="==> Fetching origin...\n ✓ Update complete (1.9.0).\n")
        ok, log, snap = _run("run_harmony_upgrade", ssh, sink=written)
        assert ok is True, log
        snap.assert_called_once()
        assert written["harmony_current_version"] == "1.9.0"
        assert written["harmony_update_available"] == "false"
        # backup strictly before update; update targets the exact release and
        # skips its own (redundant) backup since ours succeeded
        update = ssh.index_of(" update --version ")
        assert -1 < ssh.index_of("harmony backup --no-storage --label mcat-pre-1.9.0") < update
        update_cmd = ssh.calls[update]
        assert update_cmd == ("cd /opt/harmony/self-host && HARMONY_SKIP_BACKUP=1 "
                              "/opt/harmony/self-host/harmony update --version 1.9.0")
        assert "  ✓ Update complete (1.9.0)." in log
        assert "[PASS] realtime policy" in log
        # the permanent tunnel FAIL is shown but does not block
        assert "reachable" in log

    def test_streamed_output_is_cleaned(self):
        ssh = _healthy_ssh(stream_output="\x1b[34m==>\x1b[0m Pulling\r\nline two\rline three")
        ok, log, _ = _run("run_harmony_upgrade", ssh)
        assert ok is True
        assert "  ==> Pulling" in log
        assert "  line two" in log and "  line three" in log
        assert "\x1b" not in log

    def test_update_failure_is_reported_and_version_untouched(self):
        written = {}
        ssh = _healthy_ssh(stream_output="Update stopped during: images\n", stream_code=1)
        ok, log, _ = _run("run_harmony_upgrade", ssh, sink=written)
        assert ok is False
        assert "harmony update failed (exit 1)" in log
        assert "harmony_current_version" not in written
        assert not ssh.ran("doctor")

    def test_update_timeout(self):
        ssh = _healthy_ssh(stream_stops=True)
        with patch("apps.harmony._UPDATE_TIMEOUT", 0):
            ok, log, _ = _run("run_harmony_upgrade", ssh)
        assert ok is False
        assert "did not finish within" in log

    def test_backup_failure_aborts_before_update(self):
        ssh = _healthy_ssh()
        ssh.responses.insert(0, ("harmony backup", ("", "Error: pg_dump failed; no backup written", 1)))
        ok, log, _ = _run("run_harmony_upgrade", ssh)
        assert ok is False
        assert "Aborting" in log
        assert not ssh.ran(" update --version ")

    def test_backup_failure_with_skip_protection_lets_update_back_up(self):
        ssh = _healthy_ssh()
        ssh.responses.insert(0, ("harmony backup", ("", "pg_dump failed", 1)))
        ok, log, snap = _run("run_harmony_upgrade", ssh, skip_protection=True)
        assert ok is True, log
        snap.assert_not_called()
        update_cmd = ssh.calls[ssh.index_of(" update --version ")]
        assert "HARMONY_SKIP_BACKUP" not in update_cmd

    def test_snapshot_failure_aborts_before_ssh(self):
        ssh = _healthy_ssh()
        ok, log, _ = _run("run_harmony_upgrade", ssh, snapshot=(False, "snapshot failed"))
        assert ok is False
        assert ssh.calls == []

    def test_verification_failure_retries_then_fails(self):
        written = {}
        ssh = _healthy_ssh()
        ssh.responses.insert(0, ("pg_policies", ("0\n", "", 0)))
        ok, log, _ = _run("run_harmony_upgrade", ssh, sink=written)
        assert ok is False
        assert sum(1 for c in ssh.calls if "doctor --offline" in c) == 3
        assert "[FAIL] realtime policy" in log
        assert "harmony_current_version" not in written

    def test_verification_recovers_after_containers_start(self):
        ssh = _healthy_ssh()
        starting = _doctor({"[ OK ] containers     all 14 services running":
                            "[FAIL] web            running, unhealthy"})
        ssh.responses.insert(0, ("doctor --offline", [(starting, "", 1), (HEALTHY_DOCTOR, "", 1)]))
        ok, log, _ = _run("run_harmony_upgrade", ssh)
        assert ok is True, log
        assert "Attempt 1/3: not healthy yet (containers)" in log

    def test_version_mismatch_fails_verification(self):
        ssh = _healthy_ssh()
        ssh.responses.insert(0, ("harmony version", [("v1.8.9\n1.8.9\n", "", 0)]))
        # after the "update" the version is still 1.8.9
        ok, log, _ = _run("run_harmony_upgrade", ssh)
        assert ok is False
        assert "(expected 1.9.0)" in log

    def test_refuses_when_not_newer(self):
        ssh = _healthy_ssh()
        ok, msg, snap = _run("run_harmony_upgrade", ssh, {"harmony_latest_version": "1.8.9"})
        assert ok is False
        assert "already at or above" in msg
        snap.assert_not_called()

    @pytest.mark.parametrize("target", ["", "1.9.0; reboot", "master", "1.9.0-rc1"])
    def test_refuses_bad_target(self, target):
        ssh = _healthy_ssh()
        ok, _, snap = _run("run_harmony_upgrade", ssh, {"harmony_latest_version": target})
        assert ok is False
        snap.assert_not_called()
        assert ssh.calls == []

    @pytest.mark.parametrize("bad_dir", ["/", "/opt/harmony;reboot", "relative", "/opt/$(id)"])
    def test_refuses_unsafe_dir(self, bad_dir):
        ssh = _healthy_ssh()
        ok, _, _ = _run("run_harmony_upgrade", ssh, {"harmony_dir": bad_dir})
        assert ok is False
        assert ssh.calls == []

    def test_refuses_edge_channel(self):
        ssh = _healthy_ssh()
        ssh.responses.insert(0, ("harmony version", ("v1.8.9-3-gabc\nedge\n", "", 0)))
        ok, log, _ = _run("run_harmony_upgrade", ssh, {"harmony_current_version": ""})
        assert ok is False
        assert "not on a release" in log
        assert not ssh.ran(" update ")


class TestHealthCheck:
    def test_healthy(self):
        ok, log, _ = _run("run_harmony_health_check", _healthy_ssh())
        assert ok is True
        assert "doctor exit 1 (informational, not a gate)" in log
        assert "=== Healthy ===" in log

    def test_unhealthy(self):
        ssh = _healthy_ssh()
        ssh.responses.insert(0, ("pg_policies", ("0\n", "", 0)))
        ok, log, _ = _run("run_harmony_health_check", ssh)
        assert ok is False
        assert "Unhealthy" in log

    def test_no_guest(self):
        ok, log, _ = _run("run_harmony_health_check", _healthy_ssh(), {"harmony_guest_id": ""})
        assert ok is False
        assert "not configured" in log


class TestPreflight:
    def _ssh(self, git_status=""):
        return FakeSSH([
            ("test -x", ("ok\n", "", 0)),
            ("test -f", ("ok\n", "", 0)),
            ("docker compose version", ("2.29.1\n", "", 0)),
            ("git -C /opt/harmony status", (git_status, "", 0)),
            ("df -Pk", ("41943040\n", "", 0)),
            ("harmony version", ("v1.8.9\n1.8.9\n", "", 0)),
            ("docker compose ps", ("web: running\ncaddy: running\n", "", 0)),
        ])

    def test_all_clear(self):
        ok, log, _ = _run("run_harmony_preflight", self._ssh())
        assert ok is True, log
        assert "all clear" in log
        assert "2 container(s), 0 not running" in log

    def test_tracked_changes_block(self):
        ok, log, _ = _run("run_harmony_preflight", self._ssh(" M self-host/Caddyfile\n"))
        assert ok is False
        assert "self-host/Caddyfile" in log

    def test_untracked_overlay_is_not_inspected(self):
        ssh = self._ssh()
        _run("run_harmony_preflight", ssh)
        assert ssh.ran("--untracked-files=no")

    def test_low_disk_blocks(self):
        ssh = self._ssh()
        ssh.responses.insert(0, ("df -Pk", ("524288\n", "", 0)))
        ok, log, _ = _run("run_harmony_preflight", ssh)
        assert ok is False
        assert "under 2 GB free" in log

    def test_backup_without_storage_blocks_before_ssh(self):
        ssh = self._ssh()
        ok, _, _ = _run("run_harmony_preflight", ssh, {"harmony_protection_type": "backup"})
        assert ok is False
        assert ssh.calls == []


class TestDetect:
    def test_detects_release(self):
        from apps.harmony import detect_harmony_version
        guest = MagicMock(ip_address="10.0.0.132", credential=MagicMock())
        ssh = FakeSSH([("test -x", ("ok\n", "", 0)), ("harmony version", ("v1.8.9\n1.8.9\n", "", 0))])
        with patch("apps.harmony.SSHClient") as fake:
            fake.from_credential.return_value = ssh
            assert detect_harmony_version(guest, "/opt/harmony") == ("1.8.9", None)

    def test_missing_cli(self):
        from apps.harmony import detect_harmony_version
        guest = MagicMock(ip_address="10.0.0.132", credential=MagicMock())
        with patch("apps.harmony.SSHClient") as fake:
            fake.from_credential.return_value = FakeSSH([("test -x", ("", "", 1))])
            version, err = detect_harmony_version(guest, "/opt/harmony")
        assert version is None
        assert "CLI not found" in err

    def test_ssh_error_does_not_leak_exception_text(self):
        from apps.harmony import detect_harmony_version
        guest = MagicMock(ip_address="10.0.0.132", credential=MagicMock())
        with patch("apps.harmony.SSHClient") as fake:
            fake.from_credential.side_effect = RuntimeError("secret-internal-detail")
            version, err = detect_harmony_version(guest, "/opt/harmony")
        assert version is None
        assert "secret-internal-detail" not in err


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@pytest.fixture()
def clean_harmony(app):
    keys = ["harmony_guest_id", "harmony_dir", "harmony_installed", "harmony_current_version",
            "harmony_latest_version", "harmony_update_available", "harmony_auto_upgrade",
            "harmony_last_health_status", "harmony_last_upgrade_status", "harmony_last_upgrade_log",
            "harmony_last_notified_version"]

    def _clear():
        with app.app_context():
            for k in keys:
                Setting.set(k, "")
            db.session.commit()

    _clear()
    yield
    _clear()


def _sync_spawn(fn):
    fn()


class TestRoutes:
    def test_page_renders(self, auth_client, clean_harmony):
        resp = auth_client.get("/harmony/upgrade")
        assert resp.status_code == 200
        assert b"Harmony Checkout Directory" in resp.data

    def test_applications_card(self, auth_client, clean_harmony):
        resp = auth_client.get("/applications/")
        assert b"/harmony/upgrade" in resp.data

    def test_save_valid(self, app, auth_client, clean_harmony):
        resp = auth_client.post("/harmony/save", data={
            "harmony_dir": "/srv/harmony", "harmony_protection_type": "backup",
            "harmony_backup_mode": "bogus", "harmony_auto_upgrade": "on",
        })
        assert resp.status_code == 302
        with app.app_context():
            assert Setting.get("harmony_dir") == "/srv/harmony"
            assert Setting.get("harmony_protection_type") == "backup"
            assert Setting.get("harmony_backup_mode") == "snapshot"
            assert Setting.get("harmony_auto_upgrade") == "true"

    def test_auto_upgrade_defaults_off(self, app, auth_client, clean_harmony):
        auth_client.post("/harmony/save", data={"harmony_dir": "/opt/harmony"})
        with app.app_context():
            assert Setting.get("harmony_auto_upgrade") == "false"

    def test_detect_sets_installed_and_update_flag(self, app, auth_client, clean_harmony):
        with app.app_context():
            Setting.set("harmony_guest_id", "1")
            Setting.set("harmony_latest_version", "1.9.0")
            db.session.commit()
        with patch("routes.harmony.Guest") as fake_guest, \
                patch("apps.harmony.detect_harmony_version", return_value=("1.8.9", None)):
            fake_guest.query.get.return_value = MagicMock()
            resp = auth_client.post("/harmony/detect-versions", follow_redirects=True)
        assert b"Detected Harmony version: 1.8.9" in resp.data
        with app.app_context():
            assert Setting.get("harmony_installed") == "true"
            assert Setting.get("harmony_current_version") == "1.8.9"
            assert Setting.get("harmony_update_available") == "true"

    def test_health_job_records_result(self, app, auth_client, clean_harmony):
        with patch("routes.harmony._spawn", _sync_spawn), \
                patch("apps.harmony.run_harmony_health_check", return_value=(True, "fine")):
            assert auth_client.post("/harmony/health").get_json() == {"started": True}
        status = auth_client.get("/harmony/health/status").get_json()
        assert status["running"] is False and status["success"] is True
        with app.app_context():
            assert Setting.get("harmony_last_health_status") == "healthy"

    def test_upgrade_refusal_reason_reaches_live_log(self, app, auth_client, clean_harmony):
        with patch("routes.harmony._spawn", _sync_spawn), \
                patch("core.notifier.send_upgrade_started_notification") as started, \
                patch("core.notifier.send_upgrade_result_notification") as result:
            resp = auth_client.post("/harmony/upgrade")
        assert resp.status_code == 302
        status = auth_client.get("/harmony/upgrade/status").get_json()
        assert status["success"] is False
        assert status["log"] == ["ERROR: Harmony guest not configured"]
        started.assert_called_once_with("harmony", "", "manual")
        result.assert_called_once_with("harmony", "", False, "manual")
        with app.app_context():
            assert Setting.get("harmony_last_upgrade_status") == "error"

    def test_upgrade_lock_blocks_concurrent_run(self, auth_client, clean_harmony):
        from apps.utils import acquire_upgrade_lock, release_upgrade_lock
        assert acquire_upgrade_lock("harmony")
        try:
            with patch("routes.harmony._spawn") as spawn:
                resp = auth_client.post("/harmony/upgrade", follow_redirects=True)
            spawn.assert_not_called()
            assert b"already in progress" in resp.data
        finally:
            release_upgrade_lock("harmony")

    def test_requires_update_permission(self, client, clean_harmony):
        resp = client.get("/harmony/upgrade")
        assert resp.status_code == 302


# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------

class TestSchedulerCheck:
    def test_skips_until_detected(self, app, clean_harmony):
        from core.scheduler import _check_harmony_release
        with app.app_context():
            Setting.set("harmony_guest_id", "1")
            db.session.commit()
        with patch("apps.harmony.check_harmony_release") as check:
            _check_harmony_release(app)
        check.assert_not_called()

    def test_notifies_once_and_does_not_auto_upgrade_by_default(self, app, clean_harmony):
        from core.scheduler import _check_harmony_release
        with app.app_context():
            Setting.set("harmony_guest_id", "1")
            Setting.set("harmony_installed", "true")
            Setting.set("harmony_current_version", "1.8.9")
            db.session.commit()
        with patch("apps.harmony.check_harmony_release", return_value=(True, "1.9.0", "u")), \
                patch("core.notifier.send_harmony_update_notification", return_value=(True, "")) as notify, \
                patch("apps.harmony.run_harmony_upgrade") as upgrade:
            _check_harmony_release(app)
            _check_harmony_release(app)
        notify.assert_called_once_with("1.8.9", "1.9.0", "u")
        upgrade.assert_not_called()

    def test_auto_upgrade_when_enabled(self, app, clean_harmony):
        from core.scheduler import _check_harmony_release
        with app.app_context():
            Setting.set("harmony_guest_id", "1")
            Setting.set("harmony_installed", "true")
            Setting.set("harmony_auto_upgrade", "true")
            db.session.commit()
        with patch("apps.harmony.check_harmony_release", return_value=(True, "1.9.0", "u")), \
                patch("core.notifier.send_harmony_update_notification", return_value=(True, "")), \
                patch("core.notifier.send_upgrade_started_notification"), \
                patch("core.notifier.send_upgrade_result_notification") as result, \
                patch("apps.harmony.run_harmony_upgrade", return_value=(True, "log")) as upgrade:
            _check_harmony_release(app)
        upgrade.assert_called_once_with()
        result.assert_called_once_with("harmony", "1.9.0", True, "auto")
        with app.app_context():
            assert Setting.get("harmony_last_upgrade_status") == "success"


class TestNotifier:
    def test_update_notification(self, app):
        from core.notifier import send_harmony_update_notification
        with app.app_context(), patch("core.notifier._send_discord", return_value=(True, "")) as send:
            Setting.set("discord_notify_harmony", "true")
            ok, _ = send_harmony_update_notification("1.8.9", "1.9.0", "https://example.com/r")
        assert ok is True
        embed = send.call_args.args[0][0]
        assert "Harmony update available: v1.9.0" in embed["title"]

    def test_disabled(self, app):
        from core.notifier import send_harmony_update_notification
        with app.app_context():
            Setting.set("discord_notify_harmony", "false")
            ok, msg = send_harmony_update_notification("1.8.9", "1.9.0", "")
            Setting.set("discord_notify_harmony", "true")
        assert ok is False
        assert "disabled" in msg
