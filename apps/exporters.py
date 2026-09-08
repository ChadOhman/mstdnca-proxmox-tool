"""
Prometheus exporter install and management automation.

Supports installing node_exporter, postgres_exporter, and redis_exporter
on target guests via SSH, and regenerating the Prometheus scrape config.
"""

import json
import logging
import re
import shlex
import time
import urllib.request

from apps.utils import (
    _cleanup_workdir,
    _fetch_verified_tarball,
    _log_cmd_output,
    _remote_write_cmd,
    _validate_abs_path,
    _validate_no_control_chars,
    _validate_release_tag,
)
from clients.ssh_client import SSHClient

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Known exporter registry
# ---------------------------------------------------------------------------

KNOWN_EXPORTERS = {
    "node_exporter": {
        "display_name": "Node Exporter",
        "github_repo": "prometheus/node_exporter",
        "binary_name": "node_exporter",
        "default_port": 9100,
        "systemd_unit": "node_exporter.service",
        "requires_config": False,
        "job_name": "node",
    },
    "postgres_exporter": {
        "display_name": "PostgreSQL Exporter",
        "github_repo": "prometheus-community/postgres_exporter",
        "binary_name": "postgres_exporter",
        "default_port": 9187,
        "systemd_unit": "postgres_exporter.service",
        "requires_config": True,
        "env_vars": ["DATA_SOURCE_NAME"],
        "job_name": "postgres",
    },
    "redis_exporter": {
        "display_name": "Redis Exporter",
        "github_repo": "oliver006/redis_exporter",
        "binary_name": "redis_exporter",
        "default_port": 9121,
        "systemd_unit": "redis_exporter.service",
        "requires_config": True,
        "env_vars": ["REDIS_ADDR"],
        "job_name": "redis",
        "asset_version_prefix": "v",
    },
    "elasticsearch_exporter": {
        "display_name": "Elasticsearch Exporter",
        "github_repo": "prometheus-community/elasticsearch_exporter",
        "binary_name": "elasticsearch_exporter",
        "default_port": 9114,
        "systemd_unit": "elasticsearch_exporter.service",
        "requires_config": True,
        "env_vars": ["ES_URI"],
        "job_name": "elasticsearch",
        "exec_extra_args": ["--es.uri=${ES_URI}"],
    },
    "jitsi_jvb": {
        "display_name": "Jitsi Videobridge",
        "binary_name": None,
        "default_port": 8080,
        "systemd_unit": "jitsi-videobridge2.service",
        "requires_config": False,
        "job_name": "jitsi_jvb",
        "builtin": True,
    },
    "ipmi_exporter": {
        "display_name": "IPMI Exporter",
        "github_repo": "prometheus-community/ipmi_exporter",
        "binary_name": "ipmi_exporter",
        "default_port": 9290,
        "systemd_unit": "ipmi_exporter.service",
        "requires_config": False,  # Config auto-generated from host IPMI settings
        "job_name": "ipmi",
        "host_level": True,
        "install_method": "release",
        "config_file_path": "/etc/ipmi_exporter/config.yml",
        "extra_install_deps": ["freeipmi"],
    },
}

# Built-in exporters — these are part of the application itself (no binary to install).
# Enabled by setting environment variables and restarting the service.
BUILTIN_EXPORTERS = {
    "mastodon": {
        "display_name": "Mastodon (Built-in)",
        "default_port": 9394,
        "job_name": "mastodon",
    },
}

# sed pattern that removes all Mastodon prometheus exporter env vars from .env.production,
# including the unprefixed PROMETHEUS_EXPORTER_HOST/PORT used in external mode.
_MASTODON_EXPORTER_SED = (
    "/^MASTODON_PROMETHEUS_EXPORTER_/d; "
    "/^PROMETHEUS_EXPORTER_HOST=/d; "
    "/^PROMETHEUS_EXPORTER_PORT=/d"
)

_SLUG_RE = re.compile(r"[^a-z0-9_-]+")


def _slugify_job_name(text):
    """Turn free-text (e.g. a host name) into a safe Prometheus job_name.

    Prometheus job names are just labels, but free text (spaces, quotes, unicode)
    flowing straight into generated YAML makes the config fragile to edit/diff and,
    for values containing a literal quote, syntactically wrong. Lowercases, replaces
    runs of non [a-z0-9_-] with "_", and trims leading/trailing "_".
    """
    slug = _SLUG_RE.sub("_", str(text).strip().lower()).strip("_")
    return slug or "unnamed"


def _dedupe_job_name(base, used):
    """Return `base`, or `base` with a numeric suffix, that isn't already in `used`.

    Mutates `used` by adding the returned name.
    """
    name = base
    n = 2
    while name in used:
        name = f"{base}_{n}"
        n += 1
    used.add(name)
    return name


def _yaml_single_quote(value):
    """Render `value` as a single-quoted YAML scalar.

    Single-quoted YAML strings support exactly one escape: a doubled quote for a
    literal `'`. Embedded CR/LF are stripped first — YAML line-folding would
    otherwise turn a raw newline in the source into a fold point, and a stray `\\r`
    can trip up strict parsers — so this always yields one safely parseable line
    regardless of what a user typed into the source field (e.g. a BMC password).
    """
    text = str(value).replace("\r", "").replace("\n", " ")
    return "'" + text.replace("'", "''") + "'"


def _write_remote_file(ssh, content, path, mode="600", owner="root", group=None, timeout=15):
    """Write `content` to `path` on the remote host atomically, with no
    world-readable window and without a heredoc (whose terminator a value in
    `content` could accidentally — or maliciously — match and break out of).

    Base64-encodes `content` and pipes it through `install`, which writes the
    destination with the final mode/ownership in one step rather than creating it
    at the shell's default umask and `chmod`ing afterward.

    Returns (success, stderr).
    """
    cmd = _remote_write_cmd(path, content, mode=mode, owner=owner, group=group)
    stdout, stderr, code = ssh.execute_sudo(cmd, timeout=timeout)
    return code == 0, stderr or stdout or ""


def _build_mastodon_env_vars(config=None):
    """Build the dict of env vars to write to .env.production for the Mastodon exporter.

    Config keys (all optional):
        web_detailed_metrics (bool, default True)
        sidekiq_detailed_metrics (bool, default True)
        mode ("external" or "local", default "external")
        host (str, default "0.0.0.0")
        port (int, default 9394)
    """
    config = config or {}
    env = {"MASTODON_PROMETHEUS_EXPORTER_ENABLED": "true"}

    web_detailed = config.get("web_detailed_metrics", True)
    sidekiq_detailed = config.get("sidekiq_detailed_metrics", True)
    env["MASTODON_PROMETHEUS_EXPORTER_WEB_DETAILED_METRICS"] = "true" if web_detailed else "false"
    env["MASTODON_PROMETHEUS_EXPORTER_SIDEKIQ_DETAILED_METRICS"] = "true" if sidekiq_detailed else "false"

    mode = config.get("mode", "external")
    host = config.get("host", "0.0.0.0")
    port = str(config.get("port", 9394))

    if mode == "local":
        env["MASTODON_PROMETHEUS_EXPORTER_LOCAL"] = "true"
        env["MASTODON_PROMETHEUS_EXPORTER_HOST"] = host
        env["MASTODON_PROMETHEUS_EXPORTER_PORT"] = port
    else:
        env["PROMETHEUS_EXPORTER_HOST"] = host
        env["PROMETHEUS_EXPORTER_PORT"] = port

    return env


# Systemd unit name for the external prometheus_exporter collector process.
_MASTODON_COLLECTOR_UNIT = "mastodon-prometheus-collector.service"


def _mastodon_collector_unit(app_dir, host, port):
    """Generate a systemd service unit for the Mastodon prometheus_exporter collector."""
    return f"""[Unit]
Description=Mastodon Prometheus Exporter Collector
After=network.target

[Service]
Type=simple
User=mastodon
WorkingDirectory={app_dir}
Environment=RAILS_ENV=production
ExecStart=/home/mastodon/.rbenv/shims/bundle exec prometheus_exporter -b {host} -p {port}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"""


# ---------------------------------------------------------------------------
# Version check
# ---------------------------------------------------------------------------

def check_exporter_release(exporter_type):
    """Check GitHub for the latest release of an exporter.

    Returns (latest_version, error_string).
    """
    info = KNOWN_EXPORTERS.get(exporter_type)
    if not info:
        return None, f"Unknown exporter type: {exporter_type}"
    if info.get("builtin"):
        return None, f"{info['display_name']} is a builtin exporter (no separate install needed)"

    try:
        url = f"https://api.github.com/repos/{info['github_repo']}/releases/latest"
        req = urllib.request.Request(url, headers={"User-Agent": "mstdnca-proxmox-tool"})
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
            data = json.loads(resp.read().decode())
            tag = data.get("tag_name", "")
        if not tag:
            return None, "No version found"
        # The tag comes from a third party and is interpolated into download
        # URLs, extraction paths, and an `rm -rf` — validate before any of that.
        try:
            _validate_release_tag(tag, f"{exporter_type} release tag")
        except ValueError as e:
            logger.error("Rejected %s release tag: %s", exporter_type, e)
            return None, str(e)
        return tag.lstrip("v"), ""
    except Exception as e:
        logger.error("Failed to check %s releases: %s", exporter_type, e)
        return None, str(e)


_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _render_env_file(config):
    """Render an ``/etc/default/<exporter>`` env file from a config dict.

    systemd's EnvironmentFile parser is line-based, so a newline in a value
    would add an arbitrary extra variable (and, before this, could close the
    heredoc the file used to be written with).  Keys are restricted to the
    shell-variable character set and values are single-quoted after being
    rejected for control characters.  Raises ValueError on a bad key/value.
    """
    lines = []
    for key, value in config.items():
        if not _ENV_KEY_RE.match(str(key)):
            raise ValueError(f"invalid environment variable name: {key!r}")
        _validate_no_control_chars(value, f"value for {key}")
        lines.append(f"{key}={shlex.quote(str(value))}")
    return "\n".join(lines) + "\n"


def _release_asset_urls(info, binary, latest, dl_arch):
    """Return (asset_name, download_url, checksum_url, extract_dir) for a release.

    Every Prometheus-project and prometheus-community exporter publishes a
    ``sha256sums.txt`` next to the tarballs in the same release, so the digest
    can be checked on the target host before anything is unpacked as root.
    """
    vprefix = info.get("asset_version_prefix", "")
    extract_dir = f"{binary}-{vprefix}{latest}.linux-{dl_arch}"
    asset = f"{extract_dir}.tar.gz"
    base = f"https://github.com/{info['github_repo']}/releases/download/v{latest}"
    return asset, f"{base}/{asset}", f"{base}/sha256sums.txt", extract_dir


def detect_exporter_version(guest, exporter_type):
    """Detect the installed exporter version on a guest via SSH.

    Returns (version_string, error_string).
    """
    from models import Credential

    info = KNOWN_EXPORTERS.get(exporter_type)
    if not info:
        return None, f"Unknown exporter type: {exporter_type}"
    if info.get("builtin"):
        return None, f"{info['display_name']} is a builtin exporter"

    credential = guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        return None, "No SSH credential configured"

    has_ip = guest.ip_address and guest.ip_address.lower() not in ("dhcp", "dhcp6", "auto")
    if not has_ip:
        return None, "Guest has no usable IP address"

    try:
        binary = info["binary_name"]
        with SSHClient.from_credential(guest.ip_address, credential) as ssh:
            stdout, stderr, code = ssh.execute_sudo(
                f"/usr/local/bin/{binary} --version 2>&1 | head -1", timeout=10
            )
            if code != 0:
                return None, f"{binary} not found or failed to run"
            match = re.search(r"version\s+([\d.]+)", stdout or "")
            if match:
                return match.group(1), ""
            return None, f"Could not parse version from: {(stdout or '')[:100]}"
    except Exception as e:
        return None, str(e)


# ---------------------------------------------------------------------------
# Systemd unit generation
# ---------------------------------------------------------------------------

def _generate_exporter_systemd_unit(exporter_type, port, env_file=None):
    """Generate a systemd service unit for an exporter."""
    info = KNOWN_EXPORTERS[exporter_type]
    binary = info["binary_name"]
    user = binary  # user matches binary name

    env_line = ""
    if env_file:
        env_line = f"\nEnvironmentFile={env_file}"

    extra_args = ""
    for arg in info.get("exec_extra_args", []):
        extra_args += f" \\\n  {arg}"
    if info.get("config_file_path"):
        extra_args += f" \\\n  --config.file={info['config_file_path']}"
    exec_start = (
        f"ExecStart=/usr/local/bin/{binary} \\\n"
        f"  --web.listen-address=:{port}{extra_args}"
    )

    return f"""[Unit]
Description={info['display_name']}
Documentation=https://prometheus.io/docs/instrumenting/exporters/
Wants=network-online.target
After=network-online.target

[Service]
User={user}
Group={user}
Type=simple{env_line}
{exec_start}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"""


# ---------------------------------------------------------------------------
# Install / Uninstall
# ---------------------------------------------------------------------------

def run_exporter_install(instance_id, log_callback=None):
    """Install an exporter on the target guest via SSH.

    Returns (success, log_lines).
    """
    from models import Credential, ExporterInstance, db

    log = log_callback or (lambda msg: None)
    log_lines = []

    def _log(msg):
        log_lines.append(msg)
        log(msg)

    instance = ExporterInstance.query.get(instance_id)
    if not instance:
        _log("ERROR: Exporter instance not found.")
        return False, log_lines

    info = KNOWN_EXPORTERS.get(instance.exporter_type)
    if not info:
        _log(f"ERROR: Unknown exporter type: {instance.exporter_type}")
        return False, log_lines

    guest = instance.guest
    if not guest:
        _log("ERROR: Guest not found.")
        return False, log_lines

    credential = guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        _log("ERROR: No SSH credential configured for this guest.")
        return False, log_lines

    has_ip = guest.ip_address and guest.ip_address.lower() not in ("dhcp", "dhcp6", "auto")
    if not has_ip:
        _log("ERROR: Guest has no usable IP address.")
        return False, log_lines

    # Get latest version
    _log(f"Checking latest {info['display_name']} version...")
    latest, err = check_exporter_release(instance.exporter_type)
    if not latest:
        _log(f"ERROR: Could not determine latest version: {err}")
        return False, log_lines

    binary = info["binary_name"]
    _log(f"Installing {info['display_name']} v{latest} on {guest.name} ({guest.ip_address})...")

    instance.status = "installing"
    db.session.commit()

    try:
        with SSHClient.from_credential(guest.ip_address, credential) as ssh:
            # Determine architecture
            arch_out, _, _ = ssh.execute_sudo("dpkg --print-architecture", timeout=10)
            arch = (arch_out or "amd64").strip()
            dl_arch = "arm64" if arch == "arm64" else "amd64"

            # Create user
            _log(f"Creating {binary} user...")
            stdout, stderr, code = ssh.execute_sudo(
                f"id {binary} >/dev/null 2>&1 || useradd --system --no-create-home --shell /bin/false {binary}",
                timeout=15,
            )
            _log_cmd_output(_log, stdout, stderr, code)

            # Download, verify the published SHA-256, and extract
            asset, dl_url, sums_url, extract_dir = _release_asset_urls(
                info, binary, latest, dl_arch
            )
            _log(f"Downloading {info['display_name']} v{latest} ({dl_arch})...")
            ok, workdir, err = _fetch_verified_tarball(ssh, _log, dl_url, asset, sums_url)
            if not ok:
                _log(f"ERROR: Failed to download {info['display_name']}: {err}")
                instance.status = "failed"
                db.session.commit()
                return False, log_lines

            # Install binary
            _log("Installing binary...")
            src = shlex.quote(f"{workdir}/{extract_dir}/{binary}")
            stdout, stderr, code = ssh.execute_sudo(
                f"cp {src} /usr/local/bin/ && "
                f"chown {binary}:{binary} /usr/local/bin/{binary}",
                timeout=30,
            )
            _log_cmd_output(_log, stdout, stderr, code)
            if code != 0:
                _log("ERROR: Failed to install binary.")
                _cleanup_workdir(ssh, workdir)
                instance.status = "failed"
                db.session.commit()
                return False, log_lines

            # Write env file if needed
            env_file = None
            if info.get("requires_config") and instance.config:
                env_file = f"/etc/default/{binary}"
                try:
                    env_lines = _render_env_file(instance.config)
                except ValueError as e:
                    _log(f"ERROR: Invalid exporter configuration: {e}")
                    _cleanup_workdir(ssh, workdir)
                    instance.status = "failed"
                    db.session.commit()
                    return False, log_lines
                _log("Writing environment configuration...")
                stdout, stderr, code = ssh.execute_sudo(
                    _remote_write_cmd(env_file, env_lines, mode="600", owner="root"),
                    timeout=15,
                )
                _log_cmd_output(_log, stdout, stderr, code)

            # Create systemd service
            _log("Creating systemd service...")
            service_content = _generate_exporter_systemd_unit(
                instance.exporter_type, instance.port, env_file
            )
            stdout, stderr, code = ssh.execute_sudo(
                _remote_write_cmd(
                    f"/etc/systemd/system/{info['systemd_unit']}",
                    service_content, mode="644", owner="root",
                ),
                timeout=15,
            )
            _log_cmd_output(_log, stdout, stderr, code)
            if code != 0:
                _log("ERROR: Failed to create systemd service.")
                _cleanup_workdir(ssh, workdir)
                instance.status = "failed"
                db.session.commit()
                return False, log_lines

            # Enable and start
            _log(f"Starting {info['display_name']}...")
            stdout, stderr, code = ssh.execute_sudo(
                f"systemctl daemon-reload && systemctl enable {info['systemd_unit']} && "
                f"systemctl start {info['systemd_unit']}",
                timeout=30,
            )
            _log_cmd_output(_log, stdout, stderr, code)
            if code != 0:
                _log(f"ERROR: Failed to start {info['display_name']}.")
                instance.status = "failed"
                db.session.commit()
                return False, log_lines

            # Verify
            time.sleep(2)
            stdout, stderr, code = ssh.execute_sudo(
                f"systemctl is-active {info['systemd_unit']}", timeout=10
            )
            if code != 0 or (stdout or "").strip() != "active":
                _log(f"WARNING: {info['display_name']} may not be running.")

            # Clean up
            _cleanup_workdir(ssh, workdir)

            _log(f"{info['display_name']} v{latest} installed successfully.")

            from datetime import datetime, timezone
            instance.status = "installed"
            instance.version = latest
            instance.installed_at = datetime.now(timezone.utc)
            db.session.commit()

            # Regenerate prometheus.yml — a failed validation/reload here fails the
            # overall install so it isn't silently reported as a success.
            config_ok = _regenerate_prometheus_config(_log)

            return config_ok, log_lines

    except Exception as e:
        _log(f"FATAL ERROR: {e}")
        logger.exception("Exporter install failed for %s", instance.exporter_type)
        instance.status = "failed"
        db.session.commit()
        return False, log_lines


def run_exporter_uninstall(instance_id, log_callback=None):
    """Uninstall an exporter from the target guest via SSH.

    Returns (success, log_lines).
    """
    from models import Credential, ExporterInstance, db

    log = log_callback or (lambda msg: None)
    log_lines = []

    def _log(msg):
        log_lines.append(msg)
        log(msg)

    instance = ExporterInstance.query.get(instance_id)
    if not instance:
        _log("ERROR: Exporter instance not found.")
        return False, log_lines

    info = KNOWN_EXPORTERS.get(instance.exporter_type)
    if not info:
        _log(f"ERROR: Unknown exporter type: {instance.exporter_type}")
        return False, log_lines

    guest = instance.guest
    credential = guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        _log("ERROR: No SSH credential configured.")
        return False, log_lines

    binary = info["binary_name"]
    _log(f"Uninstalling {info['display_name']} from {guest.name}...")

    instance.status = "uninstalling"
    db.session.commit()

    try:
        with SSHClient.from_credential(guest.ip_address, credential) as ssh:
            # Stop and disable
            _log("Stopping service...")
            stdout, stderr, code = ssh.execute_sudo(
                f"systemctl stop {info['systemd_unit']} 2>/dev/null; "
                f"systemctl disable {info['systemd_unit']} 2>/dev/null",
                timeout=30,
            )
            _log_cmd_output(_log, stdout, stderr, code)

            # Remove files
            _log("Removing files...")
            stdout, stderr, code = ssh.execute_sudo(
                f"rm -f /usr/local/bin/{binary} "
                f"/etc/systemd/system/{info['systemd_unit']} "
                f"/etc/default/{binary} && "
                f"systemctl daemon-reload",
                timeout=15,
            )
            _log_cmd_output(_log, stdout, stderr, code)

            _log(f"{info['display_name']} uninstalled successfully.")

            instance.status = "removed"
            db.session.commit()

            # Regenerate prometheus.yml
            config_ok = _regenerate_prometheus_config(_log)

            return config_ok, log_lines

    except Exception as e:
        _log(f"FATAL ERROR: {e}")
        logger.exception("Exporter uninstall failed for %s", instance.exporter_type)
        instance.status = "failed"
        db.session.commit()
        return False, log_lines


# ---------------------------------------------------------------------------
# Host-level exporter install / uninstall
# ---------------------------------------------------------------------------


def _install_host_exporter_release(ssh, info, binary, _log, exporter_type):
    """Install a host exporter from a pre-built GitHub release tarball.

    Returns (success, version_string).
    """
    _log(f"Checking latest {info['display_name']} version...")
    latest, err = check_exporter_release(exporter_type)
    if not latest:
        _log(f"ERROR: Could not determine latest version: {err}")
        return False, None

    # Determine architecture
    arch_out, _, _ = ssh.execute_sudo("dpkg --print-architecture", timeout=10)
    arch = (arch_out or "amd64").strip()
    dl_arch = "arm64" if arch == "arm64" else "amd64"

    asset, dl_url, sums_url, extract_dir = _release_asset_urls(info, binary, latest, dl_arch)
    _log(f"Downloading {info['display_name']} v{latest} ({dl_arch})...")
    ok, workdir, err = _fetch_verified_tarball(ssh, _log, dl_url, asset, sums_url)
    if not ok:
        _log(f"ERROR: Failed to download {info['display_name']}: {err}")
        return False, None

    # Install binary
    _log("Installing binary...")
    src = shlex.quote(f"{workdir}/{extract_dir}/{binary}")
    stdout, stderr, code = ssh.execute_sudo(
        f"cp {src} /usr/local/bin/ && "
        f"chown {binary}:{binary} /usr/local/bin/{binary}",
        timeout=30,
    )
    _log_cmd_output(_log, stdout, stderr, code)
    _cleanup_workdir(ssh, workdir)
    if code != 0:
        _log("ERROR: Failed to install binary.")
        return False, None

    return True, latest


def run_host_exporter_install(instance_id, log_callback=None):
    """Install an exporter on a Proxmox host via SSH.

    Returns (success, log_lines).
    """
    from models import Credential, HostExporterInstance, db

    log = log_callback or (lambda msg: None)
    log_lines = []

    def _log(msg):
        log_lines.append(msg)
        log(msg)

    instance = HostExporterInstance.query.get(instance_id)
    if not instance:
        _log("ERROR: Host exporter instance not found.")
        return False, log_lines

    info = KNOWN_EXPORTERS.get(instance.exporter_type)
    if not info:
        _log(f"ERROR: Unknown exporter type: {instance.exporter_type}")
        return False, log_lines

    host = instance.host
    if not host:
        _log("ERROR: Host not found.")
        return False, log_lines

    credential = host.ssh_credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        _log("ERROR: No SSH credential configured for this host.")
        return False, log_lines

    binary = info["binary_name"]
    _log(f"Installing {info['display_name']} on {host.name} ({host.hostname})...")

    instance.status = "installing"
    db.session.commit()

    try:
        with SSHClient.from_credential(host.hostname, credential) as ssh:
            # Create user
            _log(f"Creating {binary} user...")
            stdout, stderr, code = ssh.execute_sudo(
                f"id {binary} >/dev/null 2>&1 || useradd --system --no-create-home --shell /bin/false {binary}",
                timeout=15,
            )
            _log_cmd_output(_log, stdout, stderr, code)

            # Install system dependencies (e.g. freeipmi for ipmi_exporter)
            extra_deps = info.get("extra_install_deps")
            if extra_deps:
                deps_str = " ".join(extra_deps)
                _log(f"Installing dependencies: {deps_str}...")
                stdout, stderr, code = ssh.execute_sudo(
                    f"apt-get update -qq && apt-get install -y -qq {deps_str} >/dev/null 2>&1",
                    timeout=180,
                )
                _log_cmd_output(_log, stdout, stderr, code)
                if code != 0:
                    _log(f"WARNING: Failed to install dependencies: {deps_str}")

            # Install binary from release tarball
            ok, version = _install_host_exporter_release(ssh, info, binary, _log, instance.exporter_type)

            if not ok:
                instance.status = "failed"
                db.session.commit()
                return False, log_lines

            # Write config.yml if applicable (e.g. IPMI exporter with BMC credentials)
            if info.get("config_file_path"):
                config_path = info["config_file_path"]
                config_dir = config_path.rsplit("/", 1)[0]

                # Build config from host's IPMI credentials
                ipmi_user = host.ipmi_username or "ADMIN"
                ipmi_pass = ""
                if host.ipmi_password:
                    from auth.credential_store import decrypt
                    ipmi_pass = decrypt(host.ipmi_password) or ""

                config_yml = (
                    "modules:\n"
                    "  default:\n"
                    "    collectors:\n"
                    "      - bmc\n"
                    "      - ipmi\n"
                    "      - dcmi\n"
                    f"    user: {_yaml_single_quote(ipmi_user)}\n"
                    f"    pass: {_yaml_single_quote(ipmi_pass)}\n"
                    "    privilege: 'admin'\n"
                    "    driver: 'LAN_2_0'\n"
                )

                _log(f"Writing exporter config to {config_path}...")
                stdout, stderr, code = ssh.execute_sudo(
                    f"mkdir -p {shlex.quote(config_dir)}", timeout=15
                )
                if code != 0:
                    _log_cmd_output(_log, stdout, stderr, code)
                    _log("ERROR: Failed to create exporter config directory.")
                    instance.status = "failed"
                    db.session.commit()
                    return False, log_lines

                ok, err = _write_remote_file(ssh, config_yml, config_path, mode="600", owner=binary)
                if not ok:
                    _log(f"ERROR: Failed to write exporter config file: {err[:200]}")
                    instance.status = "failed"
                    db.session.commit()
                    return False, log_lines

            # Write env file if needed (not used by SMCIPMI but kept for other host exporters)
            env_file = None
            if info.get("requires_config") and instance.config and not info.get("config_file_path"):
                env_file = f"/etc/default/{binary}"
                try:
                    env_lines = _render_env_file(instance.config)
                except ValueError as e:
                    _log(f"ERROR: Invalid exporter configuration: {e}")
                    instance.status = "failed"
                    db.session.commit()
                    return False, log_lines
                _log("Writing environment configuration...")
                stdout, stderr, code = ssh.execute_sudo(
                    _remote_write_cmd(env_file, env_lines, mode="600", owner="root"),
                    timeout=15,
                )
                _log_cmd_output(_log, stdout, stderr, code)

            # Create systemd service
            _log("Creating systemd service...")
            service_content = _generate_exporter_systemd_unit(
                instance.exporter_type, instance.port, env_file
            )
            stdout, stderr, code = ssh.execute_sudo(
                _remote_write_cmd(
                    f"/etc/systemd/system/{info['systemd_unit']}",
                    service_content, mode="644", owner="root",
                ),
                timeout=15,
            )
            _log_cmd_output(_log, stdout, stderr, code)
            if code != 0:
                _log("ERROR: Failed to create systemd service.")
                instance.status = "failed"
                db.session.commit()
                return False, log_lines

            # Enable and start
            _log(f"Starting {info['display_name']}...")
            stdout, stderr, code = ssh.execute_sudo(
                f"systemctl daemon-reload && systemctl enable {info['systemd_unit']} && "
                f"systemctl start {info['systemd_unit']}",
                timeout=30,
            )
            _log_cmd_output(_log, stdout, stderr, code)
            if code != 0:
                _log(f"ERROR: Failed to start {info['display_name']}.")
                instance.status = "failed"
                db.session.commit()
                return False, log_lines

            # Verify
            time.sleep(2)
            stdout, stderr, code = ssh.execute_sudo(
                f"systemctl is-active {info['systemd_unit']}", timeout=10
            )
            if code != 0 or (stdout or "").strip() != "active":
                _log(f"WARNING: {info['display_name']} may not be running.")

            _log(f"{info['display_name']} installed successfully (version: {version}).")

            from datetime import datetime, timezone
            instance.status = "installed"
            instance.version = version
            instance.installed_at = datetime.now(timezone.utc)
            db.session.commit()

            # Regenerate prometheus.yml
            config_ok = _regenerate_prometheus_config(_log)

            return config_ok, log_lines

    except Exception as e:
        _log(f"FATAL ERROR: {e}")
        logger.exception("Host exporter install failed for %s", instance.exporter_type)
        instance.status = "failed"
        db.session.commit()
        return False, log_lines


def run_host_exporter_uninstall(instance_id, log_callback=None):
    """Uninstall an exporter from a Proxmox host via SSH.

    Returns (success, log_lines).
    """
    from models import Credential, HostExporterInstance, db

    log = log_callback or (lambda msg: None)
    log_lines = []

    def _log(msg):
        log_lines.append(msg)
        log(msg)

    instance = HostExporterInstance.query.get(instance_id)
    if not instance:
        _log("ERROR: Host exporter instance not found.")
        return False, log_lines

    info = KNOWN_EXPORTERS.get(instance.exporter_type)
    if not info:
        _log(f"ERROR: Unknown exporter type: {instance.exporter_type}")
        return False, log_lines

    host = instance.host
    credential = host.ssh_credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        _log("ERROR: No SSH credential configured.")
        return False, log_lines

    binary = info["binary_name"]
    _log(f"Uninstalling {info['display_name']} from {host.name}...")

    instance.status = "uninstalling"
    db.session.commit()

    try:
        with SSHClient.from_credential(host.hostname, credential) as ssh:
            # Stop and disable
            _log("Stopping service...")
            stdout, stderr, code = ssh.execute_sudo(
                f"systemctl stop {info['systemd_unit']} 2>/dev/null; "
                f"systemctl disable {info['systemd_unit']} 2>/dev/null",
                timeout=30,
            )
            _log_cmd_output(_log, stdout, stderr, code)

            # Remove files
            _log("Removing files...")
            stdout, stderr, code = ssh.execute_sudo(
                f"rm -f /usr/local/bin/{binary} "
                f"/etc/systemd/system/{info['systemd_unit']} "
                f"/etc/default/{binary} && "
                f"systemctl daemon-reload",
                timeout=15,
            )
            _log_cmd_output(_log, stdout, stderr, code)

            _log(f"{info['display_name']} uninstalled successfully.")

            instance.status = "removed"
            db.session.commit()

            # Regenerate prometheus.yml
            config_ok = _regenerate_prometheus_config(_log)

            return config_ok, log_lines

    except Exception as e:
        _log(f"FATAL ERROR: {e}")
        logger.exception("Host exporter uninstall failed for %s", instance.exporter_type)
        instance.status = "failed"
        db.session.commit()
        return False, log_lines


# ---------------------------------------------------------------------------
# Prometheus config regeneration
# ---------------------------------------------------------------------------

def _regenerate_prometheus_config(_log=None):
    """Regenerate prometheus.yml with every configured scrape target and push it to the
    Prometheus guest.

    This is the SINGLE generator for prometheus.yml — it is also called (instead of a
    local copy) by run_prometheus_install() and run_unpoller_install()/reconfig, so
    installing/reinstalling any one component can no longer wipe out the scrape jobs
    another component added.

    The rendered config is validated with `promtool check config` before it replaces
    the live file, and a validation or reload failure is treated as a failure of this
    function (and, by extension, of whatever install/uninstall operation called it) —
    not merely logged and ignored.

    Returns True if regeneration was skipped (nothing configured yet) or succeeded,
    False if it was attempted and failed.
    """
    from apps.prometheus_app import _generate_prometheus_yml
    from models import Credential, ExporterInstance, Guest, HostExporterInstance, ProxmoxHost, Setting

    _log = _log or (lambda msg: None)

    prom_guest_id = Setting.get("prometheus_guest_id", "")
    if not prom_guest_id:
        _log("Skipping prometheus.yml regeneration: no Prometheus guest configured.")
        return True

    try:
        prom_guest = Guest.query.get(int(prom_guest_id))
    except (TypeError, ValueError):
        _log("ERROR: Invalid Prometheus guest ID.")
        return False

    if not prom_guest:
        _log("ERROR: Prometheus guest not found.")
        return False

    # Build extra scrape configs from installed exporters
    installed = (
        ExporterInstance.query
        .filter(ExporterInstance.status == "installed")  # noqa: E712
        .join(Guest)
        .all()
    )

    # Group by exporter type
    by_type = {}
    for exp in installed:
        ip = exp.guest.ip_address
        if not ip or ip.lower() in ("dhcp", "dhcp6", "auto"):
            continue
        by_type.setdefault(exp.exporter_type, []).append(f"{ip}:{exp.port}")

    # Include host-level exporters
    host_installed = (
        HostExporterInstance.query
        .filter(HostExporterInstance.status == "installed")  # noqa: E712
        .join(ProxmoxHost)
        .all()
    )
    # IPMI exporter uses multi-target pattern (separate handling below)
    ipmi_targets = []
    for exp in host_installed:
        host = exp.host
        if exp.exporter_type == "ipmi_exporter":
            bmc_ip = host.ipmi_address or host.hostname
            ipmi_targets.append((bmc_ip, host.hostname, exp.port, host.name))
        else:
            by_type.setdefault(exp.exporter_type, []).append(f"{host.hostname}:{exp.port}")

    # Include builtin exporters (e.g. JVB) from settings
    if Setting.get("jitsi_prometheus_scrape", "false") == "true":
        jitsi_guest_id = Setting.get("jitsi_guest_id", "")
        if jitsi_guest_id:
            try:
                jitsi_guest = Guest.query.get(int(jitsi_guest_id))
                if jitsi_guest and jitsi_guest.ip_address and jitsi_guest.ip_address.lower() not in (
                    "dhcp", "dhcp6", "auto"
                ):
                    jvb_info = KNOWN_EXPORTERS["jitsi_jvb"]
                    by_type.setdefault("jitsi_jvb", []).append(
                        f"{jitsi_guest.ip_address}:{jvb_info['default_port']}"
                    )
            except (TypeError, ValueError):
                pass

    used_job_names = set()
    extra_configs = ""
    for etype, targets in sorted(by_type.items()):
        info = KNOWN_EXPORTERS.get(etype) or BUILTIN_EXPORTERS.get(etype, {})
        job_name = _dedupe_job_name(info.get("job_name", etype), used_job_names)
        targets_str = ", ".join(f'"{t}"' for t in sorted(targets))
        extra_configs += f"""

  - job_name: "{job_name}"
    static_configs:
      - targets: [{targets_str}]"""

    # IPMI exporter uses multi-target pattern: Prometheus sends the BMC IP
    # as a query param and the exporter connects to it via IPMI/LAN.
    if ipmi_targets:
        # Group by exporter address (host:port) — typically one exporter per host
        for bmc_ip, host_ip, port, host_name in sorted(ipmi_targets):
            job_name = _dedupe_job_name(f"ipmi_{_slugify_job_name(host_name)}", used_job_names)
            extra_configs += f"""

  - job_name: "{job_name}"
    scrape_interval: 60s
    scrape_timeout: 30s
    metrics_path: /ipmi
    params:
      module: ["default"]
    static_configs:
      - targets: ["{bmc_ip}"]
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: "{host_ip}:{port}" """

    # Unpoller (UniFi metrics) — included here so this is the ONLY function that ever
    # writes prometheus.yml; a separate generator in apps/unpoller.py or
    # apps/prometheus_app.py would each overwrite the other's scrape jobs.
    if Setting.get("unpoller_installed", "false") == "true":
        from apps.unpoller import get_unpoller_scrape_config
        if prom_guest.ip_address and prom_guest.ip_address.lower() not in ("dhcp", "dhcp6", "auto"):
            extra_configs += get_unpoller_scrape_config(prom_guest.ip_address)

    # Generate full config
    mstdnca_url = Setting.get("prometheus_mstdnca_metrics_url", "")
    auth_token = Setting.get("prometheus_auth_token", "")
    yml = _generate_prometheus_yml(mstdnca_url, auth_token, extra_configs)

    # Push to Prometheus guest
    credential = prom_guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        _log("ERROR: No SSH credential for Prometheus guest.")
        return False

    return _validate_and_install_prometheus_config(prom_guest, credential, yml, _log)


def _validate_and_install_prometheus_config(prom_guest, credential, yml, _log):
    """Write `yml` to prometheus.yml.new on `prom_guest`, validate it with
    `promtool check config`, and only then move it into place and reload Prometheus.

    A failed check, move, or reload is reported as an ERROR and returns False — the
    live prometheus.yml is left untouched by a failed check, and neither is reported
    to the caller as a success.
    """
    new_path = "/etc/prometheus/prometheus.yml.new"
    live_path = "/etc/prometheus/prometheus.yml"

    try:
        with SSHClient.from_credential(prom_guest.ip_address, credential) as ssh:
            _log("Writing candidate prometheus.yml...")
            ok, err = _write_remote_file(ssh, yml, new_path, mode="644", owner="prometheus")
            if not ok:
                _log(f"ERROR: Failed to write {new_path}: {err[:200]}")
                return False

            _log("Validating prometheus.yml with promtool...")
            check_cmd = (
                'PROMTOOL="/usr/local/bin/promtool"; '
                'command -v "$PROMTOOL" >/dev/null 2>&1 || PROMTOOL="promtool"; '
                f'"$PROMTOOL" check config {new_path}'
            )
            stdout, stderr, code = ssh.execute_sudo(check_cmd, timeout=30)
            if code != 0:
                _log_cmd_output(_log, stdout, stderr, code)
                _log("ERROR: promtool check config failed — prometheus.yml was NOT updated.")
                ssh.execute_sudo(f"rm -f {new_path}", timeout=10)
                return False

            _log("Installing validated prometheus.yml...")
            stdout, stderr, code = ssh.execute_sudo(f"mv {new_path} {live_path}", timeout=15)
            if code != 0:
                _log(f"ERROR: Failed to install validated prometheus.yml: {(stderr or '')[:200]}")
                return False

            _log("Reloading Prometheus configuration...")
            stdout, stderr, code = ssh.execute_sudo("systemctl reload prometheus", timeout=15)
            if code != 0:
                _log(f"ERROR: Prometheus reload failed: {(stderr or '')[:200]}")
                return False

            _log("Prometheus configuration updated successfully.")
            return True
    except Exception as e:
        _log(f"ERROR: Failed to update Prometheus config: {e}")
        return False


# ---------------------------------------------------------------------------
# Built-in exporter management (Mastodon)
# ---------------------------------------------------------------------------

def enable_mastodon_exporter(guest_id, config=None, log_callback=None):
    """Enable Mastodon's built-in Prometheus exporter on a guest.

    SSHes into the Mastodon guest, adds env vars to .env.production,
    restarts Mastodon services, verifies the exporter port responds, creates an
    ExporterInstance record, and regenerates the Prometheus scrape config.
    """
    from datetime import datetime, timezone

    from models import Credential, ExporterInstance, Guest, Setting, db

    _log = log_callback or (lambda msg: None)

    guest = Guest.query.get(guest_id)
    if not guest:
        _log("ERROR: Guest not found.")
        return False

    # Check for existing enabled instance
    existing = ExporterInstance.query.filter_by(
        guest_id=guest_id, exporter_type="mastodon", status="installed"
    ).first()
    if existing:
        _log("Mastodon exporter is already enabled on this guest.")
        return True

    app_dir = Setting.get("mastodon_app_dir", "/home/mastodon/live")
    try:
        _validate_abs_path(app_dir, "Mastodon app_dir")
    except ValueError as e:
        _log(f"ERROR: {e}")
        return False
    env_file = f"{app_dir}/.env.production"
    info = BUILTIN_EXPORTERS["mastodon"]
    env_vars = _build_mastodon_env_vars(config)
    port = int((config or {}).get("port", info["default_port"]))

    # Resolve SSH credential
    credential = guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        _log("ERROR: No SSH credential configured for this guest.")
        return False

    ip = guest.ip_address
    if not ip or ip.lower() in ("dhcp", "dhcp6", "auto"):
        _log("ERROR: Guest has no usable IP address.")
        return False

    mode = (config or {}).get("mode", "external")
    host = (config or {}).get("host", "0.0.0.0")

    try:
        with SSHClient.from_credential(ip, credential) as ssh:
            # Step 1: Remove existing exporter env vars (idempotent)
            _log(f"Updating {env_file} with Prometheus exporter env vars...")
            sed_cmd = f"sed -i '{_MASTODON_EXPORTER_SED}' {shlex.quote(env_file)}"
            stdout, stderr, code = ssh.execute_sudo(sed_cmd, timeout=10)
            if code != 0:
                _log(f"WARNING: sed returned {code}: {(stderr or '')[:200]}")

            # Step 2: Append env vars (base64 pipe — no heredoc terminator to match)
            env_lines = "\n".join(f"{k}={v}" for k, v in env_vars.items()) + "\n"
            stdout, stderr, code = ssh.execute_sudo(
                _remote_write_cmd(env_file, env_lines, append=True), timeout=10
            )
            if code != 0:
                _log(f"ERROR: Failed to append env vars: {(stderr or '')[:200]}")
                return False
            _log("Environment variables added.")

            # Step 3: In external mode, create and start the collector service
            if mode == "external":
                _log("Creating prometheus_exporter collector service...")
                unit_content = _mastodon_collector_unit(app_dir, host, port)
                stdout, stderr, code = ssh.execute_sudo(
                    _remote_write_cmd(
                        f"/etc/systemd/system/{_MASTODON_COLLECTOR_UNIT}",
                        unit_content, mode="644", owner="root",
                    ),
                    timeout=15,
                )
                _log_cmd_output(_log, stdout, stderr, code)
                if code != 0:
                    _log("ERROR: Failed to create collector service.")
                    return False

                _log("Starting collector service...")
                stdout, stderr, code = ssh.execute_sudo(
                    f"systemctl daemon-reload && systemctl enable {_MASTODON_COLLECTOR_UNIT} && "
                    f"systemctl restart {_MASTODON_COLLECTOR_UNIT}",
                    timeout=30,
                )
                _log_cmd_output(_log, stdout, stderr, code)
                if code != 0:
                    _log(f"WARNING: Failed to start collector: {(stderr or '')[:200]}")
                else:
                    _log("Collector service started.")
            else:
                # Local mode: stop collector if it was previously running
                ssh.execute_sudo(
                    f"systemctl stop {_MASTODON_COLLECTOR_UNIT} 2>/dev/null; "
                    f"systemctl disable {_MASTODON_COLLECTOR_UNIT} 2>/dev/null",
                    timeout=15,
                )

            # Step 4: Discover and restart Mastodon services
            _log("Discovering Mastodon services...")
            stdout, stderr, code = ssh.execute(
                "systemctl list-units 'mastodon*' --no-pager --plain --no-legend"
                " | awk '{print $1}'",
                timeout=10,
            )
            units = [u.strip() for u in (stdout or "").splitlines() if u.strip() and ".service" in u]
            # Exclude the collector unit from the restart list
            units = [u for u in units if u != _MASTODON_COLLECTOR_UNIT]
            if not units:
                units = ["mastodon-web.service", "mastodon-sidekiq.service"]
                _log(f"No units discovered, using defaults: {', '.join(units)}")
            else:
                _log(f"Found units: {', '.join(units)}")

            for unit in units:
                _log(f"Restarting {unit}...")
                stdout, stderr, code = ssh.execute_sudo(
                    f"systemctl restart {unit}", timeout=60
                )
                if code != 0:
                    _log(f"WARNING: Failed to restart {unit}: {(stderr or '')[:200]}")
                else:
                    _log(f"  {unit} restarted.")

            # Step 5: Wait briefly and verify port
            _log("Waiting for exporter to start...")
            time.sleep(5)
            stdout, stderr, code = ssh.execute(
                f"curl -sf http://localhost:{port}/metrics | head -5", timeout=10
            )
            if code != 0:
                stdout, stderr, code = ssh.execute(
                    f"wget -qO- http://localhost:{port}/metrics 2>/dev/null | head -5",
                    timeout=10,
                )

            if code == 0 and stdout and stdout.strip():
                _log(f"Exporter responding on port {port}.")
            else:
                _log(f"WARNING: Could not verify exporter on port {port}. "
                     "It may need more time to start, or the Mastodon version "
                     "may not support the prometheus_exporter gem.")

    except Exception as e:
        _log(f"ERROR: SSH operation failed: {e}")
        return False

    # Step 6: Create ExporterInstance record
    # Remove any old pending/failed records first
    ExporterInstance.query.filter_by(
        guest_id=guest_id, exporter_type="mastodon"
    ).filter(ExporterInstance.status != "installed").delete()

    instance = ExporterInstance(
        guest_id=guest_id,
        exporter_type="mastodon",
        port=port,
        config=config,
        status="installed",
        installed_at=datetime.now(timezone.utc),
    )
    db.session.add(instance)
    db.session.commit()
    _log("ExporterInstance record created.")

    # Step 6: Regenerate Prometheus scrape config
    config_ok = _regenerate_prometheus_config(_log)
    if not config_ok:
        _log("WARNING: Mastodon exporter is enabled but the Prometheus scrape config could not be updated.")
        return False

    _log("Mastodon Prometheus exporter enabled successfully.")
    return True


def disable_mastodon_exporter(guest_id, log_callback=None):
    """Disable Mastodon's built-in Prometheus exporter on a guest."""
    from models import Credential, ExporterInstance, Guest, Setting, db

    _log = log_callback or (lambda msg: None)

    guest = Guest.query.get(guest_id)
    if not guest:
        _log("ERROR: Guest not found.")
        return False

    app_dir = Setting.get("mastodon_app_dir", "/home/mastodon/live")
    try:
        _validate_abs_path(app_dir, "Mastodon app_dir")
    except ValueError as e:
        _log(f"ERROR: {e}")
        return False
    env_file = f"{app_dir}/.env.production"

    credential = guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        _log("ERROR: No SSH credential configured for this guest.")
        return False

    ip = guest.ip_address
    if not ip or ip.lower() in ("dhcp", "dhcp6", "auto"):
        _log("ERROR: Guest has no usable IP address.")
        return False

    try:
        with SSHClient.from_credential(ip, credential) as ssh:
            # Step 1: Remove env vars (both MASTODON_PROMETHEUS_EXPORTER_* and PROMETHEUS_EXPORTER_*)
            _log(f"Removing Prometheus exporter env vars from {env_file}...")
            sed_cmd = f"sed -i '{_MASTODON_EXPORTER_SED}' {shlex.quote(env_file)}"
            stdout, stderr, code = ssh.execute_sudo(sed_cmd, timeout=10)
            if code != 0:
                _log(f"WARNING: sed returned {code}: {(stderr or '')[:200]}")
            else:
                _log("Environment variables removed.")

            # Step 2: Stop and remove the collector service (if present)
            _log("Stopping collector service...")
            ssh.execute_sudo(
                f"systemctl stop {_MASTODON_COLLECTOR_UNIT} 2>/dev/null; "
                f"systemctl disable {_MASTODON_COLLECTOR_UNIT} 2>/dev/null; "
                f"rm -f /etc/systemd/system/{_MASTODON_COLLECTOR_UNIT}; "
                f"systemctl daemon-reload",
                timeout=15,
            )

            # Step 3: Discover and restart Mastodon services
            _log("Discovering Mastodon services...")
            stdout, stderr, code = ssh.execute(
                "systemctl list-units 'mastodon*' --no-pager --plain --no-legend"
                " | awk '{print $1}'",
                timeout=10,
            )
            units = [u.strip() for u in (stdout or "").splitlines() if u.strip() and ".service" in u]
            units = [u for u in units if u != _MASTODON_COLLECTOR_UNIT]
            if not units:
                units = ["mastodon-web.service", "mastodon-sidekiq.service"]

            for unit in units:
                _log(f"Restarting {unit}...")
                stdout, stderr, code = ssh.execute_sudo(
                    f"systemctl restart {unit}", timeout=60
                )
                if code != 0:
                    _log(f"WARNING: Failed to restart {unit}: {(stderr or '')[:200]}")
                else:
                    _log(f"  {unit} restarted.")

    except Exception as e:
        _log(f"ERROR: SSH operation failed: {e}")
        return False

    # Step 4: Remove ExporterInstance records
    deleted = ExporterInstance.query.filter_by(
        guest_id=guest_id, exporter_type="mastodon"
    ).delete()
    db.session.commit()
    _log(f"Removed {deleted} ExporterInstance record(s).")

    # Step 4: Regenerate Prometheus scrape config
    config_ok = _regenerate_prometheus_config(_log)
    if not config_ok:
        _log("WARNING: Mastodon exporter is disabled but the Prometheus scrape config could not be updated.")
        return False

    _log("Mastodon Prometheus exporter disabled successfully.")
    return True


def reconfigure_mastodon_exporter(guest_id, config, log_callback=None):
    """Reconfigure the Mastodon Prometheus exporter on a guest that already has it enabled.

    Updates env vars in .env.production, restarts Mastodon services, and updates
    the ExporterInstance record and Prometheus scrape config.
    """
    from models import Credential, ExporterInstance, Guest, Setting, db

    _log = log_callback or (lambda msg: None)

    guest = Guest.query.get(guest_id)
    if not guest:
        _log("ERROR: Guest not found.")
        return False

    instance = ExporterInstance.query.filter_by(
        guest_id=guest_id, exporter_type="mastodon", status="installed"
    ).first()
    if not instance:
        _log("ERROR: Mastodon exporter is not currently enabled on this guest.")
        return False

    app_dir = Setting.get("mastodon_app_dir", "/home/mastodon/live")
    try:
        _validate_abs_path(app_dir, "Mastodon app_dir")
    except ValueError as e:
        _log(f"ERROR: {e}")
        return False
    env_file = f"{app_dir}/.env.production"
    env_vars = _build_mastodon_env_vars(config)
    new_port = int(config.get("port", BUILTIN_EXPORTERS["mastodon"]["default_port"]))
    new_mode = config.get("mode", "external")
    new_host = config.get("host", "0.0.0.0")

    credential = guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        _log("ERROR: No SSH credential configured for this guest.")
        return False

    ip = guest.ip_address
    if not ip or ip.lower() in ("dhcp", "dhcp6", "auto"):
        _log("ERROR: Guest has no usable IP address.")
        return False

    try:
        with SSHClient.from_credential(ip, credential) as ssh:
            # Step 1: Remove old env vars
            _log(f"Updating {env_file} with new Prometheus exporter configuration...")
            sed_cmd = f"sed -i '{_MASTODON_EXPORTER_SED}' {shlex.quote(env_file)}"
            stdout, stderr, code = ssh.execute_sudo(sed_cmd, timeout=10)
            if code != 0:
                _log(f"WARNING: sed returned {code}: {(stderr or '')[:200]}")

            # Step 2: Append new env vars (base64 pipe — no heredoc terminator to match)
            env_lines = "\n".join(f"{k}={v}" for k, v in env_vars.items()) + "\n"
            stdout, stderr, code = ssh.execute_sudo(
                _remote_write_cmd(env_file, env_lines, append=True), timeout=10
            )
            if code != 0:
                _log(f"ERROR: Failed to append env vars: {(stderr or '')[:200]}")
                return False
            _log("Environment variables updated.")

            # Step 3: Update collector service based on mode
            if new_mode == "external":
                _log("Updating collector service...")
                unit_content = _mastodon_collector_unit(app_dir, new_host, new_port)
                ssh.execute_sudo(
                    _remote_write_cmd(
                        f"/etc/systemd/system/{_MASTODON_COLLECTOR_UNIT}",
                        unit_content, mode="644", owner="root",
                    ),
                    timeout=15,
                )
                ssh.execute_sudo(
                    f"systemctl daemon-reload && systemctl enable {_MASTODON_COLLECTOR_UNIT} && "
                    f"systemctl restart {_MASTODON_COLLECTOR_UNIT}",
                    timeout=30,
                )
                _log("Collector service updated.")
            else:
                _log("Stopping collector service (local mode)...")
                ssh.execute_sudo(
                    f"systemctl stop {_MASTODON_COLLECTOR_UNIT} 2>/dev/null; "
                    f"systemctl disable {_MASTODON_COLLECTOR_UNIT} 2>/dev/null; "
                    f"rm -f /etc/systemd/system/{_MASTODON_COLLECTOR_UNIT}; "
                    f"systemctl daemon-reload",
                    timeout=15,
                )

            # Step 4: Restart Mastodon services
            _log("Discovering Mastodon services...")
            stdout, stderr, code = ssh.execute(
                "systemctl list-units 'mastodon*' --no-pager --plain --no-legend"
                " | awk '{print $1}'",
                timeout=10,
            )
            units = [u.strip() for u in (stdout or "").splitlines() if u.strip() and ".service" in u]
            units = [u for u in units if u != _MASTODON_COLLECTOR_UNIT]
            if not units:
                units = ["mastodon-web.service", "mastodon-sidekiq.service"]

            for unit in units:
                _log(f"Restarting {unit}...")
                stdout, stderr, code = ssh.execute_sudo(
                    f"systemctl restart {unit}", timeout=60
                )
                if code != 0:
                    _log(f"WARNING: Failed to restart {unit}: {(stderr or '')[:200]}")
                else:
                    _log(f"  {unit} restarted.")

            # Step 5: Verify port
            _log("Waiting for exporter to start...")
            time.sleep(5)
            stdout, stderr, code = ssh.execute(
                f"curl -sf http://localhost:{new_port}/metrics | head -5", timeout=10
            )
            if code != 0:
                stdout, stderr, code = ssh.execute(
                    f"wget -qO- http://localhost:{new_port}/metrics 2>/dev/null | head -5",
                    timeout=10,
                )
            if code == 0 and stdout and stdout.strip():
                _log(f"Exporter responding on port {new_port}.")
            else:
                _log(f"WARNING: Could not verify exporter on port {new_port}.")

    except Exception as e:
        _log(f"ERROR: SSH operation failed: {e}")
        return False

    # Step 5: Update ExporterInstance record
    instance.config = config
    instance.port = new_port
    db.session.commit()
    _log("ExporterInstance record updated.")

    # Step 6: Regenerate Prometheus scrape config (port may have changed)
    config_ok = _regenerate_prometheus_config(_log)
    if not config_ok:
        _log("WARNING: Mastodon exporter is reconfigured but the Prometheus scrape config could not be updated.")
        return False

    _log("Mastodon Prometheus exporter reconfigured successfully.")
    return True
