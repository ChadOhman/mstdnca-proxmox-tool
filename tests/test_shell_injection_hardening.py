"""Shell-injection hardening for the app-upgrade modules (GHSA-hx66-9rjm-v8mx).

Every settings value that reaches a root shell on a managed guest is validated
twice — in the save handler (so a hostile value is never persisted) and at the
point of use (so a value stored by an older release still cannot reach a shell)
— and quoted at the sink.  These tests are table-driven per sink family:

* hostile values are rejected at save (route flashes an error, setting unchanged)
* hostile values are rejected at use (the function returns before any SSH call)
* valid values still produce the expected, correctly-quoted commands
* release tags from third-party feeds are validated before use
* release tarballs are SHA-256 verified against the upstream checksum file
* Jibri secrets are encrypted at rest and legacy plaintext migrates once
"""

import re
from unittest.mock import patch

import pytest

from models import Setting, db

# Values that must never survive validation at any sink.
HOSTILE = [
    "a'b",                       # single quote — breaks out of '...'
    'a"b',                       # double quote
    "a;id",                      # command separator
    "a$(id)",                    # command substitution
    "a`id`",                     # backtick substitution
    "a b",                       # whitespace (splits an rm -rf target)
    "a\nEOF\nid",                # newline + heredoc terminator
    "a|id",
    "a&id",
    "a>b",
]


class _FakeSSH:
    """Records every command; returns canned responses matched by substring."""

    def __init__(self, responses=None):
        self.responses = responses or []
        self.calls = []

    def execute_sudo(self, cmd, timeout=None):
        self.calls.append(cmd)
        for substr, resp in self.responses:
            if substr in cmd:
                return resp
        return ("", "", 0)

    execute = execute_sudo

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


# ---------------------------------------------------------------------------
# The shared validators
# ---------------------------------------------------------------------------


class TestValidators:
    @pytest.mark.parametrize("value", HOSTILE)
    def test_abs_path_rejects_hostile(self, value):
        from apps.utils import _validate_abs_path
        with pytest.raises(ValueError):
            _validate_abs_path(f"/srv/{value}", "dir")

    @pytest.mark.parametrize("value", ["", "/", "relative/path", "/srv/../etc", "/srv/..", ".."])
    def test_abs_path_rejects_traversal_and_root(self, value):
        from apps.utils import _validate_abs_path
        with pytest.raises(ValueError):
            _validate_abs_path(value, "dir")

    @pytest.mark.parametrize("value", ["/srv/recordings", "/home/mastodon/live", "/opt/elk"])
    def test_abs_path_accepts_real_paths(self, value):
        from apps.utils import _validate_abs_path
        _validate_abs_path(value, "dir")

    @pytest.mark.parametrize("value", HOSTILE)
    def test_hostname_rejects_hostile(self, value):
        from apps.utils import _validate_hostname
        with pytest.raises(ValueError):
            _validate_hostname(f"meet.{value}.example.com", "hostname")

    @pytest.mark.parametrize("value", ["meet.example.com", "jitsi", "a-b.c-d.example"])
    def test_hostname_accepts_fqdns(self, value):
        from apps.utils import _validate_hostname
        _validate_hostname(value, "hostname")

    @pytest.mark.parametrize(
        "value",
        ["admin@example.com", "first.last+tag@sub.example.co.uk", "a_b-c@example.org"],
    )
    def test_email_accepts_real_addresses(self, value):
        """Regression: these were all rejected by _validate_shell_param.

        _SHELL_SAFE_RE has no '@' or '+', so running it over an address failed
        every valid one — which made the Let's Encrypt path unusable.
        """
        from apps.utils import _SHELL_SAFE_RE, _validate_email
        _validate_email(value, "Email")
        assert not _SHELL_SAFE_RE.match(value)

    @pytest.mark.parametrize("value", HOSTILE)
    def test_email_rejects_hostile(self, value):
        from apps.utils import _validate_email
        with pytest.raises(ValueError):
            _validate_email(f"admin{value}@example.com", "Email")

    @pytest.mark.parametrize(
        "value",
        ["https://mastodon.example.com", "http://10.0.0.5:5000", "https://example.com/path/to"],
    )
    def test_http_url_accepts(self, value):
        from apps.utils import _validate_http_url
        _validate_http_url(value, "URL")

    @pytest.mark.parametrize(
        "value",
        [
            "https://example.com'; id; #",
            'https://example.com"',
            "https://exa mple.com",
            "https://example.com/%73",     # percent escape — printf format hazard
            "https://example.com/\\x",     # backslash
            "ftp://example.com",
            "example.com",
            "https://example.com\nEOF",
        ],
    )
    def test_http_url_rejects(self, value):
        from apps.utils import _validate_http_url
        with pytest.raises(ValueError):
            _validate_http_url(value, "URL")

    @pytest.mark.parametrize("value", ["v1.2.3", "1.2.3", "3.14.0-rc.1", "v0.15.0", "1.2.3.4"])
    def test_release_tag_accepts(self, value):
        from apps.utils import _validate_release_tag
        _validate_release_tag(value)

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "latest",
            "v1.2.3; id",
            "v1.2.3'",
            "v1.2.3 ../../etc",
            "../../etc/passwd",
            "v1.2.3\nEOF",
            "v" + "1" * 100,
        ],
    )
    def test_release_tag_rejects(self, value):
        from apps.utils import _validate_release_tag
        with pytest.raises(ValueError):
            _validate_release_tag(value)

    @pytest.mark.parametrize(
        "value", ["..", "../etc/passwd", "/etc/passwd", "a'b.mp4", "a/b/c.mp4", "a b.mp4", ""]
    )
    def test_safe_filename_rejects(self, value):
        from apps.utils import _validate_safe_filename
        with pytest.raises(ValueError):
            _validate_safe_filename(value, "name", allow_subdir=True)

    @pytest.mark.parametrize("value", ["rec.mp4", "2026-01-01/rec.mkv"])
    def test_safe_filename_accepts(self, value):
        from apps.utils import _validate_safe_filename
        _validate_safe_filename(value, "name", allow_subdir=True)

    def test_safe_filename_subdir_only_when_allowed(self):
        from apps.utils import _validate_safe_filename
        with pytest.raises(ValueError):
            _validate_safe_filename("dir/rec.mp4", "name")

    @pytest.mark.parametrize("value", ["a\nb", "a\rb", "a\x00b", "a\tb", "a\x7fb"])
    def test_no_control_chars_rejects(self, value):
        from apps.utils import _validate_no_control_chars
        with pytest.raises(ValueError):
            _validate_no_control_chars(value, "value")


class TestRemoteWriteCmd:
    def test_payload_is_base64_and_path_is_quoted(self):
        import base64

        from apps.utils import _remote_write_cmd
        body = "SECRET=value\nENVEOF\nEXTRA=injected\n"
        cmd = _remote_write_cmd("/etc/default/x y", body, mode="600", owner="root")
        assert "<<" not in cmd          # no heredoc for a body line to terminate
        assert "SECRET=value" not in cmd  # raw content never on the command line
        assert "'/etc/default/x y'" in cmd
        b64 = re.search(r"echo (\S+) \| base64 -d", cmd).group(1)
        assert base64.b64decode(b64).decode() == body

    def test_append_mode_uses_append_redirect(self):
        from apps.utils import _remote_write_cmd
        cmd = _remote_write_cmd("/home/m/.env.production", "A=1\n", append=True)
        assert cmd.endswith(">> /home/m/.env.production")
        assert "<<" not in cmd
        # a destination that needs quoting gets it
        assert _remote_write_cmd("/home/a b/.env", "A=1\n", append=True).endswith(
            ">> '/home/a b/.env'"
        )


# ---------------------------------------------------------------------------
# Save handlers — hostile values are rejected and nothing is persisted
# ---------------------------------------------------------------------------


def _assert_rejected(auth_client, app, url, data, keys, redirect_prefix):
    """POST `data` to `url`; assert it is rejected and `keys` are unchanged."""
    with app.app_context():
        before = {k: Setting.get(k) for k in keys}
    resp = auth_client.post(url, data=data, follow_redirects=False)
    assert resp.status_code == 302
    assert redirect_prefix in resp.headers.get("Location", "")
    with app.app_context():
        for k in keys:
            assert Setting.get(k) == before[k], f"{k} was modified by a rejected save"


class TestSaveHandlersRejectHostileValues:
    @pytest.mark.parametrize("value", HOSTILE)
    def test_elk_instance_url(self, app, auth_client, value):
        _assert_rejected(
            auth_client, app, "/elk/save",
            {"elk_user": "elk", "elk_dir": "/opt/elk",
             "elk_instance_url": f"https://mastodon.example.com/{value}"},
            ["elk_instance_url"], "/elk/upgrade",
        )

    @pytest.mark.parametrize("value", HOSTILE)
    def test_elk_dir(self, app, auth_client, value):
        _assert_rejected(
            auth_client, app, "/elk/save",
            {"elk_user": "elk", "elk_dir": f"/opt/{value}"},
            ["elk_dir"], "/elk/upgrade",
        )

    def test_elk_dir_rejects_root(self, app, auth_client):
        _assert_rejected(
            auth_client, app, "/elk/save",
            {"elk_user": "elk", "elk_dir": "/"},
            ["elk_dir"], "/elk/upgrade",
        )

    @pytest.mark.parametrize("field,key", [
        ("mastodon_user", "mastodon_user"),
        ("mastodon_app_dir", "mastodon_app_dir"),
        ("mastodon_db_name", "mastodon_db_name"),
        ("mastodon_branch", "mastodon_branch"),
    ])
    @pytest.mark.parametrize("value", ["a'b", "a;id", "a$(id)", "a\nEOF\nid"])
    def test_mastodon_fields(self, app, auth_client, field, key, value):
        base = {
            "mastodon_user": "mastodon",
            "mastodon_app_dir": "/home/mastodon/live",
            "mastodon_db_name": "mastodon_production",
            "mastodon_branch": "",
        }
        base[field] = f"/home/{value}" if field == "mastodon_app_dir" else value
        _assert_rejected(auth_client, app, "/mastodon/save", base, [key], "/mastodon/upgrade")

    def test_mastodon_app_dir_rejects_traversal(self, app, auth_client):
        _assert_rejected(
            auth_client, app, "/mastodon/save",
            {"mastodon_user": "mastodon", "mastodon_app_dir": "/home/mastodon/../../etc",
             "mastodon_db_name": "mastodon_production"},
            ["mastodon_app_dir"], "/mastodon/upgrade",
        )

    @pytest.mark.parametrize("value", HOSTILE)
    def test_jitsi_hostname(self, app, auth_client, value):
        _assert_rejected(
            auth_client, app, "/jitsi/save",
            {"jitsi_hostname": f"meet.{value}.example.com"},
            ["jitsi_hostname"], "/jitsi/upgrade",
        )

    @pytest.mark.parametrize("value", ["1.2.3.4; id", "not-an-ip", "999.1.1.1", "1.2.3.4'"])
    def test_jitsi_public_ip(self, app, auth_client, value):
        _assert_rejected(
            auth_client, app, "/jitsi/save",
            {"jitsi_hostname": "meet.example.com", "jitsi_public_ip": value},
            ["jitsi_public_ip"], "/jitsi/upgrade",
        )

    @pytest.mark.parametrize("value", HOSTILE)
    def test_jibri_recording_dir(self, app, auth_client, value):
        _assert_rejected(
            auth_client, app, "/jibri/save",
            {"jibri_recording_dir": f"/srv/{value}"},
            ["jibri_recording_dir"], "/jibri/manage",
        )

    def test_jibri_recording_dir_rejects_root(self, app, auth_client):
        """`/` alone made the fstab `sed` delete every line of /etc/fstab."""
        _assert_rejected(
            auth_client, app, "/jibri/save",
            {"jibri_recording_dir": "/"},
            ["jibri_recording_dir"], "/jibri/manage",
        )

    @pytest.mark.parametrize("value", ["a'b", "a;id", "a$(id)"])
    def test_peertube_fields(self, app, auth_client, value):
        _assert_rejected(
            auth_client, app, "/peertube/save",
            {"peertube_user": "peertube", "peertube_db_name": "peertube",
             "peertube_dir": f"/var/www/{value}"},
            ["peertube_dir"], "/peertube/upgrade",
        )

    @pytest.mark.parametrize("value", ["a'b", "a;id", "a$(id)"])
    def test_ghost_dir(self, app, auth_client, value):
        _assert_rejected(
            auth_client, app, "/ghost/save",
            {"ghost_user": "ghost_user", "ghost_dir": f"/opt/{value}"},
            ["ghost_dir"], "/ghost/upgrade",
        )

    @pytest.mark.parametrize("value", ["DSN\nEXTRA=1", "DSN\rEXTRA=1"])
    def test_exporter_config_rejects_newlines(self, app, auth_client, value):
        """A newline in an env value smuggles an extra systemd variable in."""
        with app.app_context():
            guest_id = _make_guest(app, 9911, "pg-inj").id

        resp = auth_client.post("/prometheus/exporters/add", data={
            "guest_id": str(guest_id),
            "exporter_type": "postgres_exporter",
            "config_DATA_SOURCE_NAME": value,
        }, follow_redirects=False)
        assert resp.status_code == 302
        with app.app_context():
            from models import ExporterInstance
            assert ExporterInstance.query.filter_by(guest_id=guest_id).count() == 0


class TestSaveHandlersAcceptValidValues:
    def test_elk_accepts_valid(self, app, auth_client):
        auth_client.post("/elk/save", data={
            "elk_user": "elk", "elk_dir": "/opt/elk",
            "elk_url": "https://elk.example.com",
            "elk_instance_url": "https://mastodon.example.com",
        }, follow_redirects=False)
        with app.app_context():
            assert Setting.get("elk_instance_url") == "https://mastodon.example.com"

    def test_jitsi_accepts_valid_letsencrypt_email(self, app, auth_client):
        auth_client.post("/jitsi/save", data={
            "jitsi_hostname": "meet.example.com",
            "jitsi_cert_type": "letsencrypt",
            "jitsi_letsencrypt_email": "admin+jitsi@example.com",
            "jitsi_public_ip": "203.0.113.10",
        }, follow_redirects=False)
        with app.app_context():
            assert Setting.get("jitsi_letsencrypt_email") == "admin+jitsi@example.com"
            assert Setting.get("jitsi_hostname") == "meet.example.com"


# ---------------------------------------------------------------------------
# Use-time validation — hostile stored values never reach an SSH connection
# ---------------------------------------------------------------------------


def _no_ssh():
    """Patch every SSHClient the app modules use; assert none is opened."""
    return (
        patch("apps.elk.SSHClient"),
        patch("apps.jitsi.SSHClient"),
        patch("apps.jibri.SSHClient"),
        patch("apps.exporters.SSHClient"),
    )


class TestUseTimeValidation:
    @pytest.mark.parametrize("value", ["https://example.com'; id; #", "https://exa mple.com"])
    def test_elk_install_rejects_instance_url(self, app, value):
        from apps.elk import run_elk_install
        with app.app_context():
            guest = _make_guest(app, 9801, "elk-inj")
            Setting.set("elk_guest_id", str(guest.id))
            Setting.set("elk_dir", "/opt/elk")
            Setting.set("elk_user", "elk")
            Setting.set("elk_instance_url", value)
            Setting.set("elk_deploy_method", "docker")
            db.session.commit()
            with patch("apps.elk.SSHClient") as mock_ssh:
                ok, msg = run_elk_install()
            assert ok is False
            assert "Mastodon instance URL" in msg
            mock_ssh.from_credential.assert_not_called()

    @pytest.mark.parametrize("func", ["run_cloudflare_configure", "run_secure_domain_configure"])
    @pytest.mark.parametrize("value", ["meet.example.com'; id; #", "meet example.com"])
    def test_jitsi_configure_rejects_hostname(self, app, func, value):
        import apps.jitsi as jitsi_mod
        with app.app_context():
            Setting.set("jitsi_installed", "true")
            Setting.set("jitsi_hostname", value)
            Setting.set("jitsi_cf_mode", "tcp_only")
            db.session.commit()
            with patch("apps.jitsi.SSHClient") as mock_ssh:
                ok, msg = getattr(jitsi_mod, func)()
            assert ok is False
            assert "hostname" in msg.lower()
            mock_ssh.from_credential.assert_not_called()

    @pytest.mark.parametrize("value", ["meet.example.com'; id; #", "meet example.com"])
    def test_jitsi_sd_list_users_rejects_hostname(self, app, value):
        from apps.jitsi import sd_list_users
        with app.app_context():
            Setting.set("jitsi_installed", "true")
            Setting.set("jitsi_hostname", value)
            db.session.commit()
            with patch("apps.jitsi.SSHClient") as mock_ssh:
                users, err = sd_list_users()
            assert users == []
            assert err and "hostname" in err.lower()
            mock_ssh.from_credential.assert_not_called()

    @pytest.mark.parametrize("value", ["rec.mp4'; id; #", "../../etc/passwd", "a/b/c.mp4", "/etc/passwd"])
    def test_jibri_delete_recording_rejects_filename(self, app, value):
        from apps.jibri import delete_recording
        with app.app_context():
            Setting.set("jibri_installed", "true")
            Setting.set("jibri_recording_dir", "/srv/recordings")
            db.session.commit()
            with patch("apps.jibri.SSHClient") as mock_ssh:
                ok, msg = delete_recording(value)
            assert ok is False
            assert msg == "Invalid filename"
            mock_ssh.from_credential.assert_not_called()

    @pytest.mark.parametrize("value", ["/srv/rec'; id; #", "/"])
    def test_jibri_smb_rejects_recording_dir(self, app, value):
        from apps.jibri import configure_smb_mount
        with app.app_context():
            Setting.set("jibri_installed", "true")
            Setting.set("jibri_recording_dir", value)
            Setting.set("jibri_smb_share", "//nas/recordings")
            Setting.set("jibri_smb_username", "jibri_user")
            db.session.commit()
            with patch("apps.jibri.SSHClient") as mock_ssh:
                ok, msg = configure_smb_mount()
            assert ok is False
            assert "recording directory" in msg.lower()
            mock_ssh.from_credential.assert_not_called()

    @pytest.mark.parametrize("value", ["/home/mastodon/live'; id; #", "/home/mastodon/../../etc"])
    def test_mastodon_exporter_rejects_app_dir(self, app, value):
        from apps.exporters import enable_mastodon_exporter
        with app.app_context():
            guest = _make_guest(app, 9802, "masto-inj")
            Setting.set("mastodon_app_dir", value)
            db.session.commit()
            with patch("apps.exporters.SSHClient") as mock_ssh:
                ok = enable_mastodon_exporter(guest.id, {"mode": "external"})
            assert ok is False
            mock_ssh.from_credential.assert_not_called()


def _credential():
    from auth import credential_store
    from models import Credential
    cred = Credential.query.filter_by(name="test-injection-cred").first()
    if cred:
        return cred
    cred = Credential(
        name="test-injection-cred",
        username="root",
        auth_type="password",
        encrypted_value=credential_store.encrypt("test-only-password"),
    )
    db.session.add(cred)
    db.session.commit()
    return cred


def _make_guest(app, vmid, name):
    """Create a guest (with an SSH credential) on a shared test host.

    (proxmox_host_id, vmid) is unique and the app fixture is session-scoped, so
    take the next free VMID rather than a fixed one.
    """
    from models import Guest, ProxmoxHost
    host = ProxmoxHost.query.filter_by(name="pve-injection").first()
    if not host:
        host = ProxmoxHost(name="pve-injection", hostname="10.0.0.1", host_type="pve")
        db.session.add(host)
        db.session.commit()
    highest = (
        db.session.query(db.func.max(Guest.vmid))
        .filter(Guest.proxmox_host_id == host.id)
        .scalar()
    )
    guest = Guest(proxmox_host_id=host.id, vmid=max(highest or 0, vmid) + 1, name=name,
                  guest_type="lxc", ip_address="10.0.0.90", credential_id=_credential().id)
    db.session.add(guest)
    db.session.commit()
    return guest


# ---------------------------------------------------------------------------
# Valid values still produce the expected (quoted) commands
# ---------------------------------------------------------------------------


class TestValidValuesProduceExpectedCommands:
    def test_elk_env_written_via_base64_not_printf_format(self, app):
        """The .env write must not interpolate the URL into a printf format."""
        import base64

        from apps.elk import run_elk_install
        fake = _FakeSSH(responses=[
            ("docker --version", ("Docker version 27", "", 0)),
            ("docker compose version", ("v2", "", 0)),
            ("test -d /opt/elk", ("", "", 1)),
            ("docker compose -f", ("running", "", 0)),
        ])
        with app.app_context():
            guest = _make_guest(app, 9803, "elk-ok")
            Setting.set("elk_guest_id", str(guest.id))
            Setting.set("elk_dir", "/opt/elk")
            Setting.set("elk_user", "elk")
            Setting.set("elk_instance_url", "https://mastodon.example.com")
            Setting.set("elk_deploy_method", "docker")
            Setting.set("elk_protection_type", "snapshot")
            db.session.commit()
            with patch("apps.elk.SSHClient") as MockSSH, \
                 patch("apps.elk.snapshot_guest", return_value=(True, "ok")), \
                 patch("apps.elk.time.sleep"):
                MockSSH.from_credential.return_value = fake
                run_elk_install()

        env_calls = [c for c in fake.calls if "/opt/elk/.env" in c]
        assert env_calls, fake.calls
        cmd = env_calls[0]
        assert "printf '" not in cmd          # no printf format string to corrupt
        assert cmd.endswith("> /opt/elk/.env")
        b64 = re.search(r"echo (\S+) \| base64 -d", cmd).group(1)
        assert "NUXT_PUBLIC_DEFAULT_SERVER=https://mastodon.example.com" in \
            base64.b64decode(b64).decode()

    def test_jibri_fstab_sed_is_anchored_and_entry_is_not_echoed(self, app):
        from apps.jibri import configure_smb_mount
        fake = _FakeSSH(responses=[("id -u jibri", ("1001", "", 0)),
                                   ("id -g jibri", ("1001", "", 0))])
        with app.app_context():
            guest = _make_guest(app, 9804, "jibri-ok")
            Setting.set("jibri_installed", "true")
            Setting.set("jibri_guest_id", str(guest.id))
            Setting.set("jibri_recording_dir", "/srv/recordings")
            Setting.set("jibri_smb_share", "//nas/recordings")
            Setting.set("jibri_smb_username", "jibri_user")
            db.session.commit()
            with patch("apps.jibri.SSHClient") as MockSSH:
                MockSSH.from_credential.return_value = fake
                configure_smb_mount()

        sed_calls = [c for c in fake.calls if "sed -i" in c and "/etc/fstab" in c]
        assert len(sed_calls) == 1
        # anchored to the mount-point field, not "matches anywhere on the line"
        assert "[[:space:]]\\+" in sed_calls[0]
        assert "\\/srv\\/recordings[[:space:]]" in sed_calls[0]
        fstab_writes = [c for c in fake.calls if c.endswith(">> /etc/fstab")]
        assert len(fstab_writes) == 1
        # base64 pipe, not `echo '<entry>' >> /etc/fstab`
        assert "base64 -d" in fstab_writes[0]
        assert "cifs" not in fstab_writes[0]

    def test_jibri_delete_recording_quotes_path(self, app):
        from apps.jibri import delete_recording
        fake = _FakeSSH(responses=[("test -f", ("exists", "", 0))])
        with app.app_context():
            guest = _make_guest(app, 9805, "jibri-del")
            Setting.set("jibri_installed", "true")
            Setting.set("jibri_guest_id", str(guest.id))
            Setting.set("jibri_recording_dir", "/srv/recordings")
            db.session.commit()
            with patch("apps.jibri.SSHClient") as MockSSH:
                MockSSH.from_credential.return_value = fake
                ok, msg = delete_recording("2026-01-01/rec.mp4")
        import shlex
        assert ok is True
        expected = f"rm -f {shlex.quote('/srv/recordings/2026-01-01/rec.mp4')} 2>&1"
        assert expected in fake.calls, fake.calls


# ---------------------------------------------------------------------------
# Release tags from third-party feeds
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def read(self):
        import json
        return json.dumps(self._payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


HOSTILE_TAGS = ["v1.2.3; rm -rf /", "v1.2.3'", "v1.2.3 ../../etc", "$(id)", "../../../etc"]


class TestReleaseTagValidation:
    @pytest.mark.parametrize("tag", HOSTILE_TAGS)
    def test_exporter_release_rejects(self, app, tag):
        from apps.exporters import check_exporter_release
        with patch("apps.exporters.urllib.request.urlopen",
                   return_value=_FakeResponse({"tag_name": tag})):
            latest, err = check_exporter_release("node_exporter")
        assert latest is None
        assert err

    def test_exporter_release_accepts_good_tag(self, app):
        from apps.exporters import check_exporter_release
        with patch("apps.exporters.urllib.request.urlopen",
                   return_value=_FakeResponse({"tag_name": "v1.9.1"})):
            latest, err = check_exporter_release("node_exporter")
        assert (latest, err) == ("1.9.1", "")

    @pytest.mark.parametrize("tag", HOSTILE_TAGS)
    def test_prometheus_release_rejects(self, app, tag):
        from apps.prometheus_app import check_prometheus_release
        with app.app_context():
            with patch("apps.prometheus_app.urllib.request.urlopen",
                       return_value=_FakeResponse({"tag_name": tag, "html_url": "u"})):
                assert check_prometheus_release() == (False, "", "")

    @pytest.mark.parametrize("tag", HOSTILE_TAGS)
    def test_unpoller_release_rejects(self, app, tag):
        from apps.unpoller import check_unpoller_release
        with app.app_context():
            with patch("apps.unpoller.urllib.request.urlopen",
                       return_value=_FakeResponse({"tag_name": tag, "html_url": "u"})):
                assert check_unpoller_release() == (False, "", "")

    @pytest.mark.parametrize("tag", HOSTILE_TAGS)
    def test_peertube_release_rejects(self, app, tag):
        from apps.peertube import check_peertube_release
        with app.app_context():
            with patch("apps.peertube.urlopen",
                       return_value=_FakeResponse({"tag_name": tag})):
                assert check_peertube_release() == (False, "", "")


# ---------------------------------------------------------------------------
# Checksum verification and heredoc-free config writes
# ---------------------------------------------------------------------------


class TestVerifiedDownloads:
    def _install(self, app, fake):
        from apps.exporters import run_exporter_install
        from models import ExporterInstance
        with app.app_context():
            guest = _make_guest(app, 9806, "exp-verify")
            inst = ExporterInstance(guest_id=guest.id, exporter_type="node_exporter",
                                    port=9100, status="pending")
            db.session.add(inst)
            db.session.commit()
            inst_id = inst.id
            with patch("apps.exporters.SSHClient") as MockSSH, \
                 patch("apps.exporters.check_exporter_release", return_value=("1.9.1", "")), \
                 patch("apps.exporters._regenerate_prometheus_config", return_value=True), \
                 patch("apps.exporters.time.sleep"):
                MockSSH.from_credential.return_value = fake
                ok, logs = run_exporter_install(inst_id)
            status = ExporterInstance.query.get(inst_id).status
        return ok, logs, status

    def test_install_verifies_sha256_from_the_same_release(self, app):
        fake = _FakeSSH(responses=[("systemctl is-active", ("active", "", 0))])
        ok, logs, status = self._install(app, fake)
        assert ok is True, "\n".join(logs)
        dl = [c for c in fake.calls if "sha256sum -c" in c]
        assert len(dl) == 1, fake.calls
        cmd = dl[0]
        assert "sha256sums.txt" in cmd
        assert "node_exporter-1.9.1.linux-amd64.tar.gz" in cmd
        assert "mkdir -m 700 /tmp/mstdnca-rel-" in cmd  # unpredictable work dir
        assert cmd.startswith("set -e; ")                # a failed step aborts the rest

    def test_install_fails_on_checksum_mismatch(self, app):
        fake = _FakeSSH(responses=[("sha256sum -c", ("", "FAILED checksum", 1))])
        ok, logs, status = self._install(app, fake)
        assert ok is False
        assert status == "failed"
        # nothing was copied into /usr/local/bin after a failed verification
        assert not any("cp " in c and "/usr/local/bin" in c for c in fake.calls)

    def test_install_writes_no_heredocs(self, app):
        fake = _FakeSSH(responses=[("systemctl is-active", ("active", "", 0))])
        ok, logs, _ = self._install(app, fake)
        assert ok is True, "\n".join(logs)
        assert not any("<<" in c for c in fake.calls), \
            "config files must be written via the base64 pipe, never a heredoc"

    def test_unpoller_install_verifies_and_avoids_heredocs(self, app):
        from apps.unpoller import run_unpoller_install
        fake = _FakeSSH(responses=[("systemctl is-active", ("active", "", 0))])
        with app.app_context():
            guest = _make_guest(app, 9807, "unpoller-verify")
            Setting.set("prometheus_guest_id", str(guest.id))
            Setting.set("unpoller_latest_version", "5.2.4")
            Setting.set("unifi_base_url", "https://unifi.example.com")
            Setting.set("unifi_username", "unifi-ro")
            Setting.set("unifi_password", "test-only-unifi-pass")
            db.session.commit()
            with patch("apps.unpoller.SSHClient") as MockSSH, \
                 patch("apps.unpoller._snapshot_guest", return_value=(True, "ok")), \
                 patch("apps.unpoller._regenerate_prometheus_config_stub", create=True), \
                 patch("apps.exporters._regenerate_prometheus_config", return_value=True), \
                 patch("apps.unpoller.time.sleep"):
                MockSSH.from_credential.return_value = fake
                ok, logs = run_unpoller_install()
            Setting.set("prometheus_guest_id", "")
            db.session.commit()
        assert ok is True, "\n".join(logs)
        dl = [c for c in fake.calls if "sha256sum -c" in c]
        assert len(dl) == 1, fake.calls
        assert "unpoller_5.2.4_checksums.txt" in dl[0]
        assert "unpoller_5.2.4_linux_amd64.tar.gz" in dl[0]
        assert not any("<<" in c for c in fake.calls)


# ---------------------------------------------------------------------------
# Jibri secrets at rest
# ---------------------------------------------------------------------------


class TestJibriSecretsAtRest:
    def test_round_trip_encrypted(self, app):
        from apps.jibri import _get_jibri_secret, _set_jibri_secret
        with app.app_context():
            _set_jibri_secret("jibri_xmpp_password", "test-only-xmpp-secret")
            stored = Setting.get("jibri_xmpp_password")
            assert stored != "test-only-xmpp-secret"
            assert _get_jibri_secret("jibri_xmpp_password") == "test-only-xmpp-secret"

    def test_legacy_plaintext_is_migrated_once(self, app):
        from apps.jibri import _get_jibri_secret
        with app.app_context():
            Setting.set("jibri_recorder_password", "test-only-legacy-plaintext")
            # first read returns the legacy value and re-encrypts it in place
            assert _get_jibri_secret("jibri_recorder_password") == "test-only-legacy-plaintext"
            assert Setting.get("jibri_recorder_password") != "test-only-legacy-plaintext"
            # subsequent reads take the normal decrypt path
            assert _get_jibri_secret("jibri_recorder_password") == "test-only-legacy-plaintext"

    def test_smb_password_used_decrypted(self, app):
        """configure_smb_mount must write the plaintext password, not ciphertext."""
        import base64

        from apps.jibri import configure_smb_mount
        fake = _FakeSSH(responses=[("id -u jibri", ("1001", "", 0)),
                                   ("id -g jibri", ("1001", "", 0))])
        with app.app_context():
            from auth.credential_store import encrypt
            guest = _make_guest(app, 9808, "jibri-smb")
            Setting.set("jibri_installed", "true")
            Setting.set("jibri_guest_id", str(guest.id))
            Setting.set("jibri_recording_dir", "/srv/recordings")
            Setting.set("jibri_smb_share", "//nas/recordings")
            Setting.set("jibri_smb_username", "jibri_user")
            Setting.set("jibri_smb_password", encrypt("test-only-smb-pass"))
            db.session.commit()
            with patch("apps.jibri.SSHClient") as MockSSH:
                MockSSH.from_credential.return_value = fake
                configure_smb_mount()

        creds = [c for c in fake.calls if ".smbcredentials" in c and "base64 -d" in c]
        assert creds, fake.calls
        b64 = re.search(r"printf '%s' '(\S+)' \| base64 -d", creds[0]).group(1)
        body = base64.b64decode(b64).decode()
        assert body == "username=jibri_user\npassword=test-only-smb-pass\n"


# ---------------------------------------------------------------------------
# Remote-sourced content in the Mastodon upgrade path
# ---------------------------------------------------------------------------


class TestMastodonRemoteContent:
    @pytest.mark.parametrize("content", [
        "3.4.2'; id; #",
        "3.4.2\nid",
        "$(id)",
        "; rm -rf /",
        "not-a-version",
    ])
    def test_ruby_version_file_content_is_validated(self, content):
        from apps.mastodon import _remediate_ruby
        fake = _FakeSSH(responses=[(".ruby-version", (content, "", 0))])
        logs = []
        assert _remediate_ruby(fake, "mastodon", "/home/mastodon/live", logs.append) is False
        # aborted before running rbenv with the untrusted content
        assert not any("rbenv install" in c for c in fake.calls)

    def test_valid_ruby_version_proceeds(self):
        from apps.mastodon import _remediate_ruby
        fake = _FakeSSH(responses=[
            (".ruby-version", ("3.4.2\n", "", 0)),
            ("ruby --version", ("ruby 3.4.2 (2025-01-01)", "", 0)),
        ])
        logs = []
        assert _remediate_ruby(fake, "mastodon", "/home/mastodon/live", logs.append) is True
