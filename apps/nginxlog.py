"""
nginx access-log metrics via prometheus-nginxlog-exporter.

The exporter (github.com/martin-helmich/prometheus-nginxlog-exporter) tails an
nginx access log and turns each line into Prometheus counters/summaries. This
module owns the pieces that are specific to it, so apps/exporters.py only has
to call three hooks from its generic install/uninstall flow:

* :func:`setup_nginx_logging` — add a dedicated, managed access log to nginx
  (``/etc/nginx/conf.d/mstdnca-metrics-log.conf``) in a JSON format the
  exporter's ``json`` parser reads directly, then ``nginx -t`` and reload.
* :func:`render_exporter_config` — the exporter's config file, with the
  relabelling rules that keep label cardinality bounded.
* :func:`teardown_nginx_logging` — undo the nginx side on uninstall.

Privacy: the managed log deliberately has no client address, referrer or
cookie fields. It carries only what the metrics need, so adding it does not
create a second copy of personal data on disk.

Cardinality: Prometheus labels must come from small, fixed sets. Request paths
are collapsed into Mastodon route groups, user agents into a handful of client
classes, and the vhost comes from ``$server_name`` (taken from nginx's own
config, so a client cannot invent new values by sending a forged Host header).
"""

import json
import re
import shlex

from apps.utils import _log_cmd_output, _remote_write_cmd

NGINX_SNIPPET_PATH = "/etc/nginx/conf.d/mstdnca-metrics-log.conf"
METRICS_LOG_PATH = "/var/log/nginx/mstdnca-metrics.log"
CONFIG_DIR = "/etc/prometheus-nginxlog-exporter"
CONFIG_PATH = f"{CONFIG_DIR}/config.yml"
LOG_FORMAT_NAME = "mstdnca_metrics"

# Metric name prefix → nginx_http_response_count_total, nginx_http_response_time_seconds, ...
METRIC_PREFIX = "nginx"

# Fields written by the managed log_format. Keys are the variable names the
# exporter looks for (body_bytes_sent, request_length, request_time and
# upstream_response_time feed its built-in byte/latency metrics).
_LOG_FIELDS = (
    ("request", "$request"),
    ("status", "$status"),
    ("body_bytes_sent", "$body_bytes_sent"),
    ("request_length", "$request_length"),
    ("request_time", "$request_time"),
    ("upstream_response_time", "$mstdnca_upstream_time"),
    ("upstream_cache_status", "$upstream_cache_status"),
    ("http_user_agent", "$http_user_agent"),
    ("server_name", "$server_name"),
)

# Request path → route group, first match wins. Each pattern must match the
# WHOLE path (anchored ^...$): the exporter substitutes only the matched part
# of the value, so an unanchored prefix would leave the rest of the URL in the
# label. Paths include the query string. A path that matches nothing becomes
# "" in the exporter, so the final catch-all maps it to "other" instead.
# Patterns use RE2 syntax (Go regexp) — no lookarounds or backreferences.
ROUTE_GROUPS = (
    (r"^/api/v1/streaming([/?].*)?$", "streaming"),
    (r"^/api/v[0-9]+/timelines/.*$", "api_timelines"),
    (r"^/api/v[0-9]+/notifications([/?].*)?$", "api_notifications"),
    (r"^/api/v[0-9]+/statuses([/?].*)?$", "api_statuses"),
    (r"^/api/v[0-9]+/(accounts|follow_requests|lists|blocks|mutes|domain_blocks)([/?].*)?$", "api_accounts"),
    (r"^/api/v[0-9]+/(search|trends|suggestions|directory)([/?].*)?$", "api_discovery"),
    (r"^/api/v[0-9]+/media([/?].*)?$", "api_media_upload"),
    (r"^/api/v[0-9]+/(instance|custom_emojis)([/?].*)?$", "api_instance"),
    (r"^/api/.*$", "api_other"),
    (r"^/(users/[^/?]+/)?inbox([?].*)?$", "ap_inbox"),
    (r"^/users/[^/?]+/(outbox|followers|following|collections)([/?].*)?$", "ap_collections"),
    (r"^/(\.well-known|nodeinfo)/.*$", "federation_discovery"),
    (r"^/(system|media_proxy)/.*$", "media"),
    (r"^/(packs|assets|emoji|sounds|avatars|headers|ocr)/.*$", "static"),
    (r"^/(oauth|auth)/.*$", "auth"),
    (r"^/(@[^/?]+|users/[^/?]+)([/?].*)?$", "profiles_and_posts"),
    (r"^/(settings|admin|filters|relationships|disputes)([/?].*)?$", "web_settings"),
    (r"^/(web|deck|home|explore|public|about|tags|search|privacy-policy|terms)([/?].*)?$", "web_ui"),
    (r"^/([?].*)?$", "web_ui"),
    (r"^.*$", "other"),
)

# User-Agent → client class, first match wins; same whole-value rule as above.
UA_CLASSES = (
    (r"^-?$", "none"),
    # Fediverse servers. Mastodon's own HTTP client sends "http.rb/x (Mastodon/y; +https://host/)";
    # matching on "http.rb" keeps the official iOS app ("Mastodon/2024.x CFNetwork/...") out of this class.
    (r"^.*(http\.rb/.*Mastodon/|Pleroma|Akkoma|Misskey|Sharkey|Iceshrimp|Firefish|GoToSocial|gotosocial|"
     r"Friendica|Pixelfed|PeerTube|Lemmy|kbin|Mbin|WriteFreely|Hubzilla|BookWyrm|Takahe|Bridgy|"
     r"WordPress/.*ActivityPub|Ghost/.*ActivityPub|snac/|Honk/|microblogpub).*$", "fediverse"),
    # Native and third-party apps — before "bot", because Android apps often carry an okhttp token.
    (r"^.*(Ivory|IceCubes|Ice Cubes|Tusky|Moshidon|Megalodon|Fedilab|Tooot|Toot!|Mona/|Mammoth|Feditext|"
     r"Metatext|Trunks|Pinafore|Semaphore|Sengi|Whalebird|Tokodon|Tuba/|Subway ?Tooter|"
     r"MastodonAndroid|Mastodon/[0-9][^ ]* CFNetwork).*$", "app"),
    # Crawlers, monitors, link-preview fetchers and scripted clients.
    (r"(?i)^.*(bot|crawl|spider|slurp|scrape|preview|monitor|uptime|curl/|wget/|python|go-http-client|"
     r"okhttp|java/|libwww|headless|facebookexternalhit|whatsapp|telegram|slack).*$", "bot"),
    (r"^Mozilla/.*$", "browser"),
    (r"^.*$", "other"),
)

# $upstream_cache_status → cache label. Empty when the location has no proxy cache.
CACHE_CLASSES = (
    (r"^(HIT|MISS|BYPASS|EXPIRED|STALE|UPDATING|REVALIDATED)$", "$1"),
    (r"^-?$", "none"),
    (r"^.*$", "other"),
)

# Latency histogram buckets (seconds). Kept short: every bucket is a series per
# label combination.
HISTOGRAM_BUCKETS = [0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]


def render_nginx_snippet():
    """Return the nginx conf.d snippet that defines and enables the managed log."""
    body = ",".join(f'"{key}":"{var}"' for key, var in _LOG_FIELDS)
    return (
        "# Managed by mstdnca-proxmox-tool — access log read by prometheus-nginxlog-exporter.\n"
        "# Holds no client addresses or referrers; it is removed when the exporter is uninstalled.\n"
        "# Server blocks that set their own access_log do not inherit this one; add the line\n"
        f"#   access_log {METRICS_LOG_PATH} {LOG_FORMAT_NAME};\n"
        "# to those blocks as well.\n"
        # With escape=json an unset variable logs as "" rather than "-". The exporter skips "-" but counts ""
        # as a parse error, and $upstream_response_time is unset whenever nginx serves a file itself.
        "map $upstream_response_time $mstdnca_upstream_time {\n"
        '    ""      "-";\n'
        "    default $upstream_response_time;\n"
        "}\n"
        f"log_format {LOG_FORMAT_NAME} escape=json '{{{body}}}';\n"
        f"access_log {METRICS_LOG_PATH} {LOG_FORMAT_NAME};\n"
    )


def _matches(rules):
    return [{"regexp": pattern, "replacement": replacement} for pattern, replacement in rules]


def render_exporter_config(port):
    """Return the exporter config file for listening on ``port``.

    JSON is valid YAML, and the exporter picks its YAML loader from the ``.yml``
    suffix, so the config is emitted with :func:`json.dumps` — no hand-built
    quoting of the regexes.
    """
    config = {
        "listen": {"port": int(port), "address": "0.0.0.0", "metrics_endpoint": "/metrics"},
        "namespaces": [{
            "name": METRIC_PREFIX,
            "parser": "json",
            "source": {"files": [METRICS_LOG_PATH]},
            "histogram_buckets": HISTOGRAM_BUCKETS,
            "relabel_configs": [
                # The exporter always adds `method` (from $request) and `status`.
                {"target_label": "vhost", "from": "server_name"},
                {"target_label": "route", "from": "request", "split": 2, "matches": _matches(ROUTE_GROUPS)},
                # Counter-only: these would multiply the latency summaries/histograms.
                {"target_label": "client", "from": "http_user_agent", "only_counter": True,
                 "matches": _matches(UA_CLASSES)},
                {"target_label": "cache", "from": "upstream_cache_status", "only_counter": True,
                 "matches": _matches(CACHE_CLASSES)},
            ],
        }],
    }
    return json.dumps(config, indent=2) + "\n"


def classify(rules, value):
    """Apply ``rules`` to ``value`` the way the exporter does (first full match wins).

    Used by tests to check the rule tables; Python's ``re`` and Go's RE2 agree
    on the subset of syntax these patterns use.
    """
    for pattern, replacement in rules:
        if re.match(pattern, value):
            # Go's ReplaceAllString spells group references $1; Python's re.sub uses \\1.
            return re.sub(pattern, re.sub(r"\$(\d)", r"\\\1", replacement), value, count=1)
    return ""


_CONF_HEADER_RE = re.compile(r"^# configuration file (.+):\s*$")
_ACCESS_LOG_RE = re.compile(r"(?:^|[;{}])\s*access_log\s+([^;]+);")


def find_other_access_logs(nginx_t_output):
    """List ``(file, directive)`` for access_log lines outside nginx.conf and our snippet.

    ``nginx -T`` prints every included file under a ``# configuration file X:``
    header. An ``access_log`` in a site file is (almost always) inside a server
    or location block, and nginx does not merge access_log across levels — those
    blocks will not write to the managed log, so the installer warns about them.
    ``access_log off`` is reported too, since it also suppresses inheritance.
    """
    current = ""
    found = []
    for line in (nginx_t_output or "").splitlines():
        header = _CONF_HEADER_RE.match(line)
        if header:
            current = header.group(1).strip()
            continue
        if current in ("/etc/nginx/nginx.conf", NGINX_SNIPPET_PATH):
            continue
        code = line.split("#", 1)[0]
        for m in _ACCESS_LOG_RE.finditer(code):
            directive = m.group(1).strip()
            if METRICS_LOG_PATH not in directive:
                found.append((current, directive))
    return found


def setup_nginx_logging(ssh, _log):
    """Install the managed access log on the guest. Returns True on success.

    nginx is validated with ``nginx -t`` before the reload; if validation fails
    the snippet is removed again so nginx is left exactly as it was.
    """
    stdout, _, code = ssh.execute_sudo("command -v nginx", timeout=10)
    if code != 0 or not (stdout or "").strip():
        _log("ERROR: nginx is not installed on this guest.")
        return False

    stdout, _, _ = ssh.execute_sudo(
        "grep -Rqs 'include[[:space:]]*/etc/nginx/conf.d/\\*\\.conf' /etc/nginx/nginx.conf && echo yes",
        timeout=10,
    )
    if (stdout or "").strip() != "yes":
        _log("ERROR: /etc/nginx/nginx.conf does not include /etc/nginx/conf.d/*.conf; "
             "cannot add the metrics access log automatically.")
        return False

    # Pre-create the log readable by group adm (the exporter runs with
    # SupplementaryGroups=adm). Debian's logrotate recreates nginx logs as
    # www-data:adm 0640, so read access survives rotation.
    log_q = shlex.quote(METRICS_LOG_PATH)
    _log("Creating metrics access log...")
    stdout, stderr, code = ssh.execute_sudo(
        f"owner=root; id www-data >/dev/null 2>&1 && owner=www-data; "
        f"test -e {log_q} || install -m 640 -o \"$owner\" -g adm /dev/null {log_q}",
        timeout=15,
    )
    _log_cmd_output(_log, stdout, stderr, code)
    if code != 0:
        _log("ERROR: Failed to create the metrics access log.")
        return False

    _log(f"Writing {NGINX_SNIPPET_PATH}...")
    stdout, stderr, code = ssh.execute_sudo(
        _remote_write_cmd(NGINX_SNIPPET_PATH, render_nginx_snippet(), mode="644", owner="root"),
        timeout=15,
    )
    _log_cmd_output(_log, stdout, stderr, code)
    if code != 0:
        _log("ERROR: Failed to write the nginx log snippet.")
        return False

    _log("Validating nginx configuration (nginx -t)...")
    stdout, stderr, code = ssh.execute_sudo("nginx -t 2>&1", timeout=30)
    if code != 0:
        _log_cmd_output(_log, stdout, stderr, code, max_chars=1500)
        _log("ERROR: nginx rejected the configuration; removing the snippet.")
        ssh.execute_sudo(f"rm -f {shlex.quote(NGINX_SNIPPET_PATH)}", timeout=15)
        return False

    stdout, stderr, code = ssh.execute_sudo("systemctl reload nginx", timeout=30)
    _log_cmd_output(_log, stdout, stderr, code)
    if code != 0:
        _log("ERROR: Failed to reload nginx.")
        return False

    stdout, _, _ = ssh.execute_sudo("nginx -T 2>/dev/null", timeout=30)
    others = find_other_access_logs(stdout)
    if others:
        _log("WARNING: these access_log directives are set inside server/location blocks, which then do not "
             f"write to the metrics log. Add `access_log {METRICS_LOG_PATH} {LOG_FORMAT_NAME};` next to each:")
        for path, directive in others[:20]:
            _log(f"  {path}: access_log {directive};")
        if len(others) > 20:
            _log(f"  ... and {len(others) - 20} more")
    return True


def write_exporter_config(ssh, port, user, _log):
    """Write the exporter's config file. Returns True on success."""
    _log(f"Writing {CONFIG_PATH}...")
    stdout, stderr, code = ssh.execute_sudo(
        f"install -d -m 755 {shlex.quote(CONFIG_DIR)} && "
        + _remote_write_cmd(CONFIG_PATH, render_exporter_config(port), mode="640", owner="root", group=user),
        timeout=15,
    )
    _log_cmd_output(_log, stdout, stderr, code)
    if code != 0:
        _log("ERROR: Failed to write the exporter configuration.")
        return False
    return True


def teardown_nginx_logging(ssh, _log):
    """Remove the managed log snippet, its log files and the exporter config."""
    _log("Removing nginx metrics access log...")
    stdout, stderr, code = ssh.execute_sudo(
        f"rm -f {shlex.quote(NGINX_SNIPPET_PATH)} && "
        "if command -v nginx >/dev/null 2>&1; then nginx -t 2>&1 && systemctl reload nginx; fi",
        timeout=45,
    )
    _log_cmd_output(_log, stdout, stderr, code)
    if code != 0:
        _log("WARNING: nginx did not reload cleanly after removing the snippet; check `nginx -t`.")
    # Rotated copies too (mstdnca-metrics.log.1, .2.gz, ...).
    ssh.execute_sudo(
        f"rm -f {shlex.quote(METRICS_LOG_PATH)} {shlex.quote(METRICS_LOG_PATH)}.* && "
        f"rm -rf {shlex.quote(CONFIG_DIR)}",
        timeout=15,
    )
    return code == 0
