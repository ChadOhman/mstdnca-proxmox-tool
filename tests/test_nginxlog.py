"""Tests for the nginx access-log exporter (apps/nginxlog.py) and its edge-traffic views."""

import base64
import json
import re
import shlex
import zlib
from unittest.mock import MagicMock, patch

import pytest
import yaml

from apps import nginxlog
from models import ExporterInstance, Guest, GuestService, Setting, db

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeSSH:
    """Records commands; ``responses`` maps a substring to (stdout, stderr, code), first match wins."""

    def __init__(self, responses=None):
        self.responses = responses or []
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def execute_sudo(self, cmd, timeout=None):
        self.calls.append(cmd)
        for substr, result in self.responses:
            if substr in cmd:
                return result
        return ("", "", 0)


def _ok_nginx_responses(extra=None):
    return (extra or []) + [
        ("command -v nginx", ("/usr/sbin/nginx\n", "", 0)),
        ("grep -Rqs", ("yes\n", "", 0)),
    ]


def _decoded_writes(calls):
    """All base64 payloads written by _remote_write_cmd() in ``calls``."""
    out = []
    for cmd in calls:
        for m in re.finditer(r"echo (\S+) \| base64 -d", cmd):
            out.append(base64.b64decode(m.group(1)).decode("utf-8"))
    return out


def _nginxlog_credential():
    """A non-default credential, so these tests never change the default-credential fallback."""
    from auth import credential_store
    from models import Credential

    cred = Credential.query.filter_by(name="test-nginxlog-cred").first()
    if cred is None:
        cred = Credential(name="test-nginxlog-cred", username="root", auth_type="password",
                          encrypted_value=credential_store.encrypt("testpass"), is_default=False)
        db.session.add(cred)
        db.session.commit()
    return cred


def _create_guest(name, ip):
    # Standalone guest (no Proxmox host): creating a host here would leave a row other
    # suites pick up via ProxmoxHost.query.first() / hard-coded host ids.
    guest = Guest(proxmox_host_id=None, vmid=zlib.crc32(name.encode()) % 90000 + 1000, name=name,
                  guest_type="ct", ip_address=ip)
    db.session.add(guest)
    db.session.commit()
    return guest


# ---------------------------------------------------------------------------
# Rule tables
# ---------------------------------------------------------------------------


class TestRuleTables:

    @pytest.mark.parametrize("rules", [nginxlog.ROUTE_GROUPS, nginxlog.UA_CLASSES, nginxlog.CACHE_CLASSES])
    def test_every_pattern_is_anchored_and_compiles(self, rules):
        # The exporter substitutes only the matched part of a value, so an unanchored
        # pattern would leave the remainder of the raw URL/user agent in the label.
        for pattern, _ in rules:
            re.compile(pattern)
            body = pattern[4:] if pattern.startswith("(?i)") else pattern
            assert body.startswith("^") and body.endswith("$"), pattern

    def test_last_rule_is_a_catch_all(self):
        for rules in (nginxlog.ROUTE_GROUPS, nginxlog.UA_CLASSES, nginxlog.CACHE_CLASSES):
            assert rules[-1][0] == "^.*$"

    @pytest.mark.parametrize("path, group", [
        ("/api/v1/streaming?stream=user", "streaming"),
        ("/api/v1/streaming", "streaming"),
        ("/api/v1/timelines/home?limit=20", "api_timelines"),
        ("/api/v2/notifications", "api_notifications"),
        ("/api/v1/notifications/123/dismiss", "api_notifications"),
        ("/api/v1/statuses/1234/context", "api_statuses"),
        ("/api/v1/accounts/verify_credentials", "api_accounts"),
        ("/api/v2/search?q=x", "api_discovery"),
        ("/api/v2/media", "api_media_upload"),
        ("/api/v2/instance", "api_instance"),
        ("/api/v1/markers", "api_other"),
        ("/inbox", "ap_inbox"),
        ("/users/alice/inbox", "ap_inbox"),
        ("/users/alice/outbox?page=true", "ap_collections"),
        ("/.well-known/webfinger?resource=acct:a@b", "federation_discovery"),
        ("/nodeinfo/2.0", "federation_discovery"),
        ("/system/media_attachments/files/1/original/x.png", "media"),
        ("/media_proxy/1/original", "media"),
        ("/packs/js/app.js", "static"),
        ("/emoji/1f600.svg", "static"),
        ("/oauth/token", "auth"),
        ("/auth/sign_in", "auth"),
        ("/@alice", "profiles_and_posts"),
        ("/@alice/109876543210", "profiles_and_posts"),
        ("/users/alice/statuses/1", "profiles_and_posts"),
        ("/users/alice", "profiles_and_posts"),
        ("/settings/profile", "web_settings"),
        ("/admin/reports", "web_settings"),
        ("/web/timelines/home", "web_ui"),
        ("/explore", "web_ui"),
        ("/", "web_ui"),
        ("/?foo=1", "web_ui"),
        ("/wp-login.php", "other"),
        ("/inboxes-are-not-this", "other"),
        ("", "other"),
    ])
    def test_route_groups(self, path, group):
        assert nginxlog.classify(nginxlog.ROUTE_GROUPS, path) == group

    @pytest.mark.parametrize("ua, cls", [
        ("http.rb/5.2.0 (Mastodon/4.3.0; +https://mastodon.example/)", "fediverse"),
        ("Pleroma 2.6.0; https://pl.example <admin@pl.example>", "fediverse"),
        ("Misskey/2024.5.0 (https://mk.example)", "fediverse"),
        ("gotosocial/0.16.0 (+https://gts.example)", "fediverse"),
        ("Tusky/25.2 Android/14", "app"),
        ("Ivory/2.0 (iPhone; iOS 18.0)", "app"),
        ("Mastodon/2024.8 CFNetwork/1568.100.1 Darwin/24.0.0", "app"),
        ("okhttp/4.12.0", "bot"),
        ("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "bot"),
        ("curl/8.5.0", "bot"),
        ("python-requests/2.32", "bot"),
        ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130 Safari/537.36", "browser"),
        ("", "none"),
        ("-", "none"),
        ("SomethingElse/1.0", "other"),
    ])
    def test_user_agent_classes(self, ua, cls):
        assert nginxlog.classify(nginxlog.UA_CLASSES, ua) == cls

    @pytest.mark.parametrize("value, label", [
        ("HIT", "HIT"), ("MISS", "MISS"), ("STALE", "STALE"), ("", "none"), ("-", "none"), ("weird", "other"),
    ])
    def test_cache_classes(self, value, label):
        assert nginxlog.classify(nginxlog.CACHE_CLASSES, value) == label


# ---------------------------------------------------------------------------
# Rendered files
# ---------------------------------------------------------------------------


class TestRenderedFiles:

    def test_snippet_has_no_personal_data_fields(self):
        snippet = nginxlog.render_nginx_snippet()
        for var in ("$remote_addr", "$http_referer", "$http_x_forwarded_for", "$http_cookie", "$remote_user"):
            assert var not in snippet

    def test_snippet_defines_format_map_and_log(self):
        snippet = nginxlog.render_nginx_snippet()
        assert "log_format mstdnca_metrics escape=json" in snippet
        assert "map $upstream_response_time $mstdnca_upstream_time" in snippet
        assert f"access_log {nginxlog.METRICS_LOG_PATH} mstdnca_metrics;" in snippet

    def test_snippet_log_format_is_json_template(self):
        line = next(ln for ln in nginxlog.render_nginx_snippet().splitlines() if ln.startswith("log_format"))
        template = line.split("'", 1)[1].rsplit("'", 1)[0]
        fields = json.loads(template)
        assert fields["request"] == "$request"
        assert fields["upstream_response_time"] == "$mstdnca_upstream_time"
        assert fields["server_name"] == "$server_name"

    def test_exporter_config_is_valid_yaml_with_expected_shape(self):
        cfg = yaml.safe_load(nginxlog.render_exporter_config(4041))
        assert cfg["listen"]["port"] == 4041
        ns = cfg["namespaces"][0]
        assert ns["name"] == "nginx"
        assert ns["parser"] == "json"
        assert ns["source"]["files"] == [nginxlog.METRICS_LOG_PATH]
        relabels = {r["target_label"]: r for r in ns["relabel_configs"]}
        assert set(relabels) == {"vhost", "route", "client", "cache"}
        assert relabels["route"]["from"] == "request" and relabels["route"]["split"] == 2
        # client/cache would multiply latency series, so they stay counter-only
        assert relabels["client"]["only_counter"] is True
        assert relabels["cache"]["only_counter"] is True
        assert "only_counter" not in relabels["route"]
        assert len(relabels["route"]["matches"]) == len(nginxlog.ROUTE_GROUPS)
        assert relabels["route"]["matches"][0] == {"regexp": nginxlog.ROUTE_GROUPS[0][0],
                                                   "replacement": nginxlog.ROUTE_GROUPS[0][1]}


# ---------------------------------------------------------------------------
# nginx -T parsing
# ---------------------------------------------------------------------------


class TestFindOtherAccessLogs:

    def test_reports_site_level_directives_only(self):
        out = (
            "# configuration file /etc/nginx/nginx.conf:\n"
            "http {\n    access_log /var/log/nginx/access.log;\n}\n"
            f"# configuration file {nginxlog.NGINX_SNIPPET_PATH}:\n"
            f"access_log {nginxlog.METRICS_LOG_PATH} mstdnca_metrics;\n"
            "# configuration file /etc/nginx/sites-enabled/mastodon:\n"
            "server {\n"
            "  # access_log /commented/out.log;\n"
            "  access_log /var/log/nginx/mastodon.log combined;\n"
            f"  access_log {nginxlog.METRICS_LOG_PATH} mstdnca_metrics;\n"
            "  location /health { access_log off; return 200; }\n"
            "}\n"
        )
        found = nginxlog.find_other_access_logs(out)
        assert found == [
            ("/etc/nginx/sites-enabled/mastodon", "/var/log/nginx/mastodon.log combined"),
            ("/etc/nginx/sites-enabled/mastodon", "off"),
        ]

    def test_empty_output(self):
        assert nginxlog.find_other_access_logs("") == []
        assert nginxlog.find_other_access_logs(None) == []


# ---------------------------------------------------------------------------
# setup / teardown over SSH
# ---------------------------------------------------------------------------


class TestSetupNginxLogging:

    def test_success_writes_snippet_validates_and_reloads(self):
        ssh = _FakeSSH(_ok_nginx_responses())
        log = []
        assert nginxlog.setup_nginx_logging(ssh, log.append) is True
        joined = "\n".join(ssh.calls)
        assert nginxlog.render_nginx_snippet() in _decoded_writes(ssh.calls)
        assert shlex.quote(nginxlog.NGINX_SNIPPET_PATH) in joined
        # validate before reload, and never reload after a failed validation
        test_idx = next(i for i, c in enumerate(ssh.calls) if c.startswith("nginx -t"))
        reload_idx = next(i for i, c in enumerate(ssh.calls) if c == "systemctl reload nginx")
        assert test_idx < reload_idx
        # log file is pre-created group-readable by adm
        assert any("-g adm" in c and nginxlog.METRICS_LOG_PATH in c for c in ssh.calls)

    def test_nginx_missing(self):
        ssh = _FakeSSH([("command -v nginx", ("", "", 1))])
        log = []
        assert nginxlog.setup_nginx_logging(ssh, log.append) is False
        assert any("not installed" in m for m in log)
        assert not _decoded_writes(ssh.calls)

    def test_conf_d_not_included(self):
        ssh = _FakeSSH([("command -v nginx", ("/usr/sbin/nginx\n", "", 0)), ("grep -Rqs", ("", "", 1))])
        log = []
        assert nginxlog.setup_nginx_logging(ssh, log.append) is False
        assert any("conf.d" in m for m in log)

    def test_failed_validation_removes_snippet_and_skips_reload(self):
        ssh = _FakeSSH(_ok_nginx_responses([("nginx -t", ("emerg: duplicate log_format", "", 1))]))
        log = []
        assert nginxlog.setup_nginx_logging(ssh, log.append) is False
        assert f"rm -f {nginxlog.NGINX_SNIPPET_PATH}" in ssh.calls
        assert "systemctl reload nginx" not in ssh.calls

    def test_warns_about_server_level_access_logs(self):
        t_out = ("# configuration file /etc/nginx/sites-enabled/mastodon:\n"
                 "  access_log /var/log/nginx/mastodon.log;\n")
        ssh = _FakeSSH(_ok_nginx_responses([("nginx -T", (t_out, "", 0))]))
        log = []
        assert nginxlog.setup_nginx_logging(ssh, log.append) is True
        assert any(m.startswith("WARNING") for m in log)
        assert any("/etc/nginx/sites-enabled/mastodon" in m for m in log)

    def test_write_exporter_config(self):
        ssh = _FakeSSH()
        assert nginxlog.write_exporter_config(ssh, 4040, "prometheus-nginxlog-exporter", lambda m: None) is True
        assert nginxlog.render_exporter_config(4040) in _decoded_writes(ssh.calls)
        assert "-g prometheus-nginxlog-exporter" in ssh.calls[0]

    def test_teardown_removes_snippet_logs_and_config(self):
        ssh = _FakeSSH()
        assert nginxlog.teardown_nginx_logging(ssh, lambda m: None) is True
        joined = "\n".join(ssh.calls)
        assert f"rm -f {nginxlog.NGINX_SNIPPET_PATH}" in joined
        assert f"{nginxlog.METRICS_LOG_PATH}.*" in joined
        assert f"rm -rf {nginxlog.CONFIG_DIR}" in joined


# ---------------------------------------------------------------------------
# Exporter registry / install flow
# ---------------------------------------------------------------------------


class TestExporterIntegration:

    def test_registry_entry(self):
        from apps.exporters import KNOWN_EXPORTERS
        info = KNOWN_EXPORTERS["nginxlog_exporter"]
        assert info["binary_name"] == "prometheus-nginxlog-exporter"
        assert info["job_name"] == "nginxlog"
        assert info["setup_hook"] == "nginxlog"
        assert not info.get("host_level") and not info.get("builtin")

    def test_goreleaser_asset_urls(self):
        from apps.exporters import KNOWN_EXPORTERS, _release_asset_urls
        info = KNOWN_EXPORTERS["nginxlog_exporter"]
        asset, url, sums, extract_dir = _release_asset_urls(info, info["binary_name"], "1.11.0", "arm64")
        assert asset == "prometheus-nginxlog-exporter_1.11.0_linux_arm64.tar.gz"
        assert url == ("https://github.com/martin-helmich/prometheus-nginxlog-exporter/releases/download/"
                       "v1.11.0/prometheus-nginxlog-exporter_1.11.0_linux_arm64.tar.gz")
        assert sums.endswith("/v1.11.0/checksums.txt")
        assert extract_dir == ""

    def test_prometheus_style_asset_urls_unchanged(self):
        from apps.exporters import KNOWN_EXPORTERS, _release_asset_urls
        asset, _, sums, extract_dir = _release_asset_urls(
            KNOWN_EXPORTERS["node_exporter"], "node_exporter", "1.8.2", "amd64")
        assert asset == "node_exporter-1.8.2.linux-amd64.tar.gz"
        assert sums.endswith("/sha256sums.txt")
        assert extract_dir == "node_exporter-1.8.2.linux-amd64"

    def test_systemd_unit(self):
        from apps.exporters import _generate_exporter_systemd_unit
        unit = _generate_exporter_systemd_unit("nginxlog_exporter", 4040)
        assert "-config-file=/etc/prometheus-nginxlog-exporter/config.yml" in unit
        assert "--web.listen-address" not in unit
        assert "SupplementaryGroups=adm" in unit
        assert "User=prometheus-nginxlog-exporter" in unit

    def test_config_path_matches_unit(self):
        from apps.exporters import KNOWN_EXPORTERS
        assert f"-config-file={nginxlog.CONFIG_PATH}" in KNOWN_EXPORTERS["nginxlog_exporter"]["exec_args"]

    def _install(self, app, ssh, name, ip):
        from apps.exporters import run_exporter_install

        with app.app_context():
            guest = _create_guest(name, ip)
            guest.credential_id = _nginxlog_credential().id
            exp = ExporterInstance(guest_id=guest.id, exporter_type="nginxlog_exporter", port=4040, status="pending")
            db.session.add(exp)
            db.session.commit()
            exp_id, guest_id = exp.id, guest.id

            with patch("apps.exporters.SSHClient") as MockSSH, \
                 patch("apps.exporters.check_exporter_release", return_value=("1.11.0", "")), \
                 patch("apps.exporters._fetch_verified_tarball", return_value=(True, "/tmp/mstdnca-x", "")), \
                 patch("apps.exporters._regenerate_prometheus_config", return_value=True), \
                 patch("apps.exporters.time.sleep"):
                MockSSH.from_credential.return_value = ssh
                ok, log_lines = run_exporter_install(exp_id)
            status = db.session.get(ExporterInstance, exp_id).status
            db.session.delete(db.session.get(ExporterInstance, exp_id))
            db.session.delete(db.session.get(Guest, guest_id))
            db.session.commit()
        return ok, log_lines, status

    def test_install_runs_hook_and_writes_config(self, app):
        ssh = _FakeSSH(_ok_nginx_responses([("systemctl is-active", ("active\n", "", 0))]))
        ok, _, status = self._install(app, ssh, "nginxlog-install-ok", "10.0.0.231")
        assert ok is True
        assert status == "installed"
        writes = _decoded_writes(ssh.calls)
        assert nginxlog.render_nginx_snippet() in writes
        assert nginxlog.render_exporter_config(4040) in writes
        # binary comes straight from the archive root
        assert any("cp /tmp/mstdnca-x/prometheus-nginxlog-exporter /usr/local/bin/" in c for c in ssh.calls)
        # hook runs before the service is started
        hook_idx = next(i for i, c in enumerate(ssh.calls) if c == "systemctl reload nginx")
        start_idx = next(i for i, c in enumerate(ssh.calls) if "systemctl start" in c)
        assert hook_idx < start_idx

    def test_install_fails_when_nginx_rejects_config(self, app):
        ssh = _FakeSSH(_ok_nginx_responses([("nginx -t", ("emerg", "", 1))]))
        ok, log_lines, status = self._install(app, ssh, "nginxlog-install-bad", "10.0.0.232")
        assert ok is False
        assert status == "failed"
        assert not any("systemctl start" in c for c in ssh.calls)

    def test_uninstall_runs_teardown(self, app):
        from apps.exporters import run_exporter_uninstall

        ssh = _FakeSSH()
        with app.app_context():
            guest = _create_guest("nginxlog-uninstall", "10.0.0.233")
            guest.credential_id = _nginxlog_credential().id
            exp = ExporterInstance(guest_id=guest.id, exporter_type="nginxlog_exporter", port=4040, status="installed")
            db.session.add(exp)
            db.session.commit()
            with patch("apps.exporters.SSHClient") as MockSSH, \
                 patch("apps.exporters._regenerate_prometheus_config", return_value=True):
                MockSSH.from_credential.return_value = ssh
                ok, _ = run_exporter_uninstall(exp.id)
            assert ok is True
            assert any(f"rm -f {nginxlog.NGINX_SNIPPET_PATH}" in c for c in ssh.calls)
            db.session.delete(exp)
            db.session.delete(guest)
            db.session.commit()


# ---------------------------------------------------------------------------
# Prometheus queries
# ---------------------------------------------------------------------------


def _instant(metric, value):
    return {"metric": metric, "value": [1700000000, str(value)]}


def _fake_breakdown(promql):
    if promql.startswith("sum by (vhost)"):
        return [_instant({"vhost": "masto.test"}, 900), _instant({"vhost": "blog.test"}, 100)]
    if "nginx_parse_errors_total" in promql:
        return [_instant({}, 3)]
    if promql.startswith("sum by (route)") and "response_size_bytes" in promql:
        return [_instant({"route": "media"}, 9000), _instant({"route": "ap_inbox"}, 1000)]
    if promql.startswith("sum by (route)") and 'status=~"5.."' in promql:
        return [_instant({"route": "ap_inbox"}, 10)]
    if promql.startswith("sum by (route)") and "time_seconds_sum" in promql:
        return [_instant({"route": "media"}, 3), _instant({"route": "ap_inbox"}, 20)]
    if promql.startswith("sum by (route)") and "time_seconds_count" in promql:
        return [_instant({"route": "media"}, 300), _instant({"route": "ap_inbox"}, 400)]
    if promql.startswith("sum by (route)"):
        return [_instant({"route": "media"}, 300), _instant({"route": "ap_inbox"}, 400), _instant({"route": "x"}, 0)]
    if promql.startswith("sum by (client)"):
        return [_instant({"client": "fediverse"}, 400), _instant({"client": "browser"}, 300)]
    if promql.startswith("sum by (cache)"):
        return [_instant({"cache": "HIT"}, 250), _instant({"cache": "none"}, 450)]
    if promql.startswith("sum by (status)"):
        return [_instant({"status": "200"}, 690), _instant({"status": "500"}, 10)]
    return [_instant({}, 700)]


class TestNginxQueries:

    def _client(self, app):
        with app.app_context():
            Setting.set("prometheus_url", "http://10.0.0.5:9090")
            db.session.commit()
            from clients.prometheus_query import PrometheusQueryClient
            return PrometheusQueryClient()

    def test_selector_escapes_targets_and_vhost(self, app):
        from clients.prometheus_query import PrometheusQueryClient
        sel = PrometheusQueryClient._nginx_selector(["10.0.0.5:4040", "10.0.0.6:4040"], vhost='a"b')
        assert sel == 'instance=~"10\\\\.0\\\\.0\\\\.5:4040|10\\\\.0\\\\.0\\\\.6:4040",vhost="a\\"b"'

    def test_breakdown_defaults_to_busiest_vhost(self, app):
        prom = self._client(app)
        with patch.object(prom, "query", side_effect=_fake_breakdown) as mock_query:
            data = prom.get_nginx_traffic_breakdown(["10.0.0.5:4040"], "day")
        assert data["vhost"] == "masto.test"
        assert [v["vhost"] for v in data["vhosts"]] == ["masto.test", "blog.test"]
        # every query after the vhost listing is scoped to the chosen vhost
        scoped = [c.args[0] for c in mock_query.call_args_list
                  if not c.args[0].startswith("sum by (vhost)") and "parse_errors" not in c.args[0]]
        assert scoped and all('vhost="masto.test"' in q for q in scoped)
        assert all("[86400s]" in c.args[0] for c in mock_query.call_args_list)

        assert data["total_requests"] == 700
        assert data["total_bytes"] == 10000
        assert data["parse_errors"] == 3
        inbox, media = data["routes"]  # sorted by requests, zero-count rows dropped
        assert inbox["route"] == "ap_inbox" and inbox["errors_5xx"] == 10 and inbox["avg_ms"] == 50.0
        assert media["bytes_share"] == 90.0 and media["avg_ms"] == 10.0
        assert data["clients"][0] == {"client": "fediverse", "requests": 400, "share": 57.14}
        assert {r["cache"] for r in data["cache"]} == {"HIT", "none"}

    def test_breakdown_honours_explicit_vhost(self, app):
        prom = self._client(app)
        with patch.object(prom, "query", side_effect=_fake_breakdown) as mock_query:
            data = prom.get_nginx_traffic_breakdown(["10.0.0.5:4040"], "week", vhost="blog.test")
        assert data["vhost"] == "blog.test"
        assert any('vhost="blog.test"' in c.args[0] for c in mock_query.call_args_list)

    def test_snapshot_series_aligned_by_timestamp(self, app):
        """A full-window `or vector(0)` series must not shift a shorter real series in time."""
        prom = self._client(app)

        def fake_range(promql, start, end, step):
            if "or vector(0)" in promql:
                return [{"values": [[100, "0"], [200, "0"], [300, "7"]]}]
            return [{"values": [[300, "41"]]}]

        with patch.object(prom, "query_range", side_effect=fake_range):
            data = prom._run_snapshot_queries({"total": "sum(x)", "errors": "sum(y) or vector(0)"}, 0, 300, 100)
        assert len(data["snapshots"]) == 1
        assert data["snapshots"][0]["total"] == 41.0
        assert data["snapshots"][0]["errors"] == 7.0

    def test_traffic_metrics_series(self, app):
        prom = self._client(app)
        with patch.object(prom, "query_range", return_value=[{"values": [[1700000000, "2.5"]]}]) as mock_range:
            data = prom.get_nginx_traffic_metrics(["10.0.0.5:4040"], "day", vhost="masto.test")
        snap = data["snapshots"][0]
        for key in ("req_rate", "rate_5xx", "bytes_out_rate", "p95_response_time", "p95_upstream_time",
                    "client_fediverse", "client_app", "client_browser", "client_bot", "client_other"):
            assert key in snap
        queries = [c.args[0] for c in mock_range.call_args_list]
        assert all('vhost="masto.test"' in q for q in queries)
        assert any(q.startswith("histogram_quantile(0.95") for q in queries)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


class TestEdgeTrafficRoutes:

    def _setup(self, app, name, ip, service_name="mastodon-web (puma)", with_exporter=True):
        with app.app_context():
            Setting.set("prometheus_enabled", "true")
            Setting.set("prometheus_url", "http://10.0.0.5:9090")
            guest = _create_guest(name, ip)
            svc = GuestService(guest_id=guest.id, service_name=service_name,
                               unit_name="mastodon-web.service", status="running")
            db.session.add(svc)
            exp_id = None
            if with_exporter:
                exp = ExporterInstance(guest_id=guest.id, exporter_type="nginxlog_exporter",
                                       port=4040, status="installed")
                db.session.add(exp)
                db.session.flush()
                exp_id = exp.id
            db.session.commit()
            return svc.id, guest.id, exp_id

    def _cleanup(self, app, svc_id, guest_id, exp_id):
        with app.app_context():
            if exp_id:
                db.session.delete(db.session.get(ExporterInstance, exp_id))
            db.session.delete(db.session.get(GuestService, svc_id))
            db.session.delete(db.session.get(Guest, guest_id))
            db.session.commit()

    def test_not_installed(self, app, auth_client):
        svc_id, guest_id, exp_id = self._setup(app, "edge-none", "10.0.0.241", with_exporter=False)
        try:
            data = auth_client.get(f"/services/{svc_id}/mastodon/edge-traffic-breakdown").get_json()
            assert data["available"] is False
            assert data["not_installed"] is True
        finally:
            self._cleanup(app, svc_id, guest_id, exp_id)

    def test_rejects_sidekiq(self, app, auth_client):
        svc_id, guest_id, exp_id = self._setup(app, "edge-sq", "10.0.0.242", service_name="mastodon-sidekiq",
                                               with_exporter=False)
        try:
            assert auth_client.get(f"/services/{svc_id}/mastodon/edge-traffic").status_code == 400
        finally:
            self._cleanup(app, svc_id, guest_id, exp_id)

    def test_rejects_control_chars_in_vhost(self, app, auth_client):
        svc_id, guest_id, exp_id = self._setup(app, "edge-badvhost", "10.0.0.243")
        try:
            resp = auth_client.get(f"/services/{svc_id}/mastodon/edge-traffic?vhost=a%0Ab")
            assert resp.status_code == 400
        finally:
            self._cleanup(app, svc_id, guest_id, exp_id)

    @patch("clients.prometheus_query.PrometheusQueryClient.query")
    def test_breakdown_with_data(self, mock_query, app, auth_client):
        mock_query.side_effect = _fake_breakdown
        svc_id, guest_id, exp_id = self._setup(app, "edge-data", "10.0.0.244")
        try:
            data = auth_client.get(f"/services/{svc_id}/mastodon/edge-traffic-breakdown?timeframe=week").get_json()
            assert data["available"] is True
            assert data["vhost"] == "masto.test"
            assert all("10\\\\.0\\\\.0\\\\.244:4040" in c.args[0] for c in mock_query.call_args_list)
        finally:
            self._cleanup(app, svc_id, guest_id, exp_id)

    @patch("clients.prometheus_query.PrometheusQueryClient.query_range")
    def test_series_with_data(self, mock_range, app, auth_client):
        mock_range.return_value = [{"values": [[1700000000, "1.0"], [1700000300, "2.0"]]}]
        svc_id, guest_id, exp_id = self._setup(app, "edge-series", "10.0.0.245")
        try:
            data = auth_client.get(f"/services/{svc_id}/mastodon/edge-traffic?vhost=masto.test").get_json()
            assert data["available"] is True
            assert len(data["snapshots"]) == 2
        finally:
            self._cleanup(app, svc_id, guest_id, exp_id)

    def test_targets_respect_guest_access(self, app):
        from routes import services

        with app.app_context():
            guest = _create_guest("edge-scoped", "10.0.0.246")
            exp = ExporterInstance(guest_id=guest.id, exporter_type="nginxlog_exporter", port=4040, status="installed")
            db.session.add(exp)
            db.session.commit()
            try:
                denied = MagicMock()
                denied.may_access_guest.return_value = False
                with patch.object(services, "current_user", denied):
                    assert "10.0.0.246:4040" not in services._nginxlog_targets()
                allowed = MagicMock()
                allowed.may_access_guest.return_value = True
                with patch.object(services, "current_user", allowed):
                    assert "10.0.0.246:4040" in services._nginxlog_targets()
            finally:
                db.session.delete(exp)
                db.session.delete(guest)
                db.session.commit()
