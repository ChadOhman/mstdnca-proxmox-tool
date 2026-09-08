"""
Prometheus HTTP API query client.

Wraps the Prometheus ``/api/v1/query`` and ``/api/v1/query_range`` endpoints
to retrieve metrics data for display in Chart.js charts.  Falls back
gracefully when Prometheus is unreachable.
"""

import logging
import time
import zoneinfo
from datetime import datetime, timezone

import requests

from models import Setting


def _user_tz():
    """Return the current user's ZoneInfo or UTC as fallback."""
    try:
        from flask_login import current_user
        if current_user.is_authenticated and current_user.timezone:
            return zoneinfo.ZoneInfo(current_user.timezone)
    except Exception:
        pass
    return timezone.utc

logger = logging.getLogger(__name__)


def _get_jvb_target():
    """Return 'ip:port' for the JVB Prometheus target if scraping is enabled, else None."""
    from apps.exporters import KNOWN_EXPORTERS
    from models import Guest
    if Setting.get("jitsi_prometheus_scrape", "false") != "true":
        return None
    guest_id = Setting.get("jitsi_guest_id", "")
    if not guest_id:
        return None
    try:
        guest = Guest.query.get(int(guest_id))
    except (TypeError, ValueError):
        return None
    if not guest or not guest.ip_address or guest.ip_address.lower() in ("dhcp", "dhcp6", "auto"):
        return None
    return f"{guest.ip_address}:{KNOWN_EXPORTERS['jitsi_jvb']['default_port']}"


def _get_exporter_target(guest_id, exporter_type):
    """Return 'ip:port' if the guest has an installed exporter of the given type, else None."""
    from models import ExporterInstance, Guest
    instance = ExporterInstance.query.filter_by(
        guest_id=guest_id, exporter_type=exporter_type, status="installed"
    ).first()
    if not instance:
        return None
    guest = Guest.query.get(guest_id)
    if not guest or not guest.ip_address or guest.ip_address.lower() in ("dhcp", "dhcp6", "auto"):
        return None
    return f"{guest.ip_address}:{instance.port}"

# Map friendly timeframe names to (duration_seconds, step_seconds)
_TIMEFRAMES = {
    "hour": (3600, 60),
    "day": (86400, 300),
    "3d": (259200, 900),
    "week": (604800, 1800),
    "month": (2592000, 7200),
    "3mo": (7776000, 21600),
    "year": (31536000, 86400),
    "365d": (31536000, 86400),
}


def escape_label_value(value):
    """Escape a value for safe interpolation into a PromQL string literal.

    PromQL string literals follow Go string-escaping rules: a backslash must
    be escaped first (so it doesn't swallow the next escape), then a double
    quote, then a literal newline. Without this, a value such as
    ``x"} or up{job=~".*`` closes the label matcher early and injects an
    arbitrary additional selector into the query (PromQL injection), which
    can be used to exfiltrate unrelated metrics or craft a query expensive
    enough to DoS the shared Prometheus.
    """
    if value is None:
        return ""
    value = str(value)
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


class PrometheusQueryClient:
    """Thin client around the Prometheus HTTP API."""

    def __init__(self, base_url=None, timeout=10):
        self.base_url = (base_url or Setting.get("prometheus_url", "")).rstrip("/")
        self.timeout = timeout
        if not self.base_url:
            raise ValueError("Prometheus URL is not configured")

    # ----- low-level -----

    def query(self, promql):
        """Execute an instant query and return the raw result list."""
        resp = requests.get(
            f"{self.base_url}/api/v1/query",
            params={"query": promql},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") != "success":
            raise RuntimeError(f"Prometheus query failed: {data.get('error', 'unknown')}")
        return data.get("data", {}).get("result", [])

    def query_range(self, promql, start, end, step):
        """Execute a range query and return the raw result list.

        *start* and *end* are Unix epoch floats; *step* is seconds.
        """
        resp = requests.get(
            f"{self.base_url}/api/v1/query_range",
            params={"query": promql, "start": start, "end": end, "step": step},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") != "success":
            raise RuntimeError(f"Prometheus range query failed: {data.get('error', 'unknown')}")
        return data.get("data", {}).get("result", [])

    def check_connection(self):
        """Return True if Prometheus is reachable, False otherwise."""
        try:
            resp = requests.get(
                f"{self.base_url}/api/v1/status/buildinfo",
                timeout=5,
            )
            return resp.status_code == 200
        except Exception:
            return False

    # ----- Chart.js helpers -----

    def get_guest_rrd(self, vmid, timeframe="day", guest_id=None):
        """Query Prometheus for guest performance metrics and return Chart.js-ready JSON.

        When *guest_id* is provided and a node_exporter is installed on that guest,
        queries standard node_exporter metrics instead of mstdnca_* gauges.
        """
        dur, step = _TIMEFRAMES.get(timeframe, _TIMEFRAMES["day"])
        end = time.time()
        start = end - dur
        rate_interval = f"{max(step * 2, 120)}s"

        # Check for node_exporter
        target = _get_exporter_target(guest_id, "node_exporter") if guest_id else None
        source = "node_exporter" if target else "mstdnca"

        if target:
            inst = f'instance="{escape_label_value(target)}"'
            cpu_data = self._range_single(
                f'100 - (avg(rate(node_cpu_seconds_total{{mode="idle",{inst}}}[{rate_interval}])) * 100)',
                start, end, step,
            )
            mem_used = self._range_single(
                f'node_memory_MemTotal_bytes{{{inst}}} - node_memory_MemAvailable_bytes{{{inst}}}',
                start, end, step,
            )
            mem_total = self._range_single(f'node_memory_MemTotal_bytes{{{inst}}}', start, end, step)
            netin = self._range_single(
                f'sum(rate(node_network_receive_bytes_total{{device!="lo",{inst}}}[{rate_interval}]))',
                start, end, step,
            )
            netout = self._range_single(
                f'sum(rate(node_network_transmit_bytes_total{{device!="lo",{inst}}}[{rate_interval}]))',
                start, end, step,
            )
        else:
            vmid_str = str(vmid)
            cpu_data = self._range_single(f'mstdnca_guest_cpu_usage_percent{{vmid="{escape_label_value(vmid_str)}"}}', start, end, step)
            mem_used = self._range_single(f'mstdnca_guest_memory_used_bytes{{vmid="{escape_label_value(vmid_str)}"}}', start, end, step)
            mem_total = self._range_single(f'mstdnca_guest_memory_total_bytes{{vmid="{escape_label_value(vmid_str)}"}}', start, end, step)
            netin = self._range_single(
                f'mstdnca_guest_network_in_bytes_per_sec{{vmid="{escape_label_value(vmid_str)}"}}', start, end, step,
            )
            netout = self._range_single(
                f'mstdnca_guest_network_out_bytes_per_sec{{vmid="{escape_label_value(vmid_str)}"}}', start, end, step,
            )

        return self._build_guest_result(cpu_data, mem_used, mem_total, netin, netout, source)

    def _build_guest_result(self, cpu_data, mem_used, mem_total, netin, netout, source="mstdnca"):
        """Build Chart.js-ready JSON from raw range query results."""
        timestamps = cpu_data.get("timestamps") or mem_used.get("timestamps") or []
        utz = _user_tz()
        labels = [datetime.fromtimestamp(ts, tz=timezone.utc).astimezone(utz).strftime("%Y-%m-%d %H:%M") for ts in timestamps]

        cpu_vals = cpu_data.get("values", [])
        mem_used_vals = mem_used.get("values", [])
        mem_total_vals = mem_total.get("values", [])
        netin_vals = netin.get("values", [])
        netout_vals = netout.get("values", [])

        mem_total_mb = 0
        mem_percent = []
        mem_used_mb = []
        for i, used in enumerate(mem_used_vals):
            total = mem_total_vals[i] if i < len(mem_total_vals) else None
            if used is not None and total and total > 0:
                mem_used_mb.append(round(used / 1048576, 1))
                mem_percent.append(round(used / total * 100, 2))
                mem_total_mb = round(total / 1048576, 1)
            else:
                mem_used_mb.append(None)
                mem_percent.append(None)

        all_net = [v for v in netin_vals + netout_vals if v is not None]
        max_net = max(all_net, default=0)
        if max_net > 1_000_000:
            net_unit = "Mbps"
            divisor = 125_000
        elif max_net > 1_000:
            net_unit = "KB/s"
            divisor = 1024
        else:
            net_unit = "B/s"
            divisor = 1

        if divisor != 1:
            netin_vals = [round(v / divisor, 2) if v is not None else None for v in netin_vals]
            netout_vals = [round(v / divisor, 2) if v is not None else None for v in netout_vals]

        return {
            "labels": labels,
            "cpu": cpu_vals,
            "mem_percent": mem_percent,
            "mem_used_mb": mem_used_mb,
            "mem_total_mb": mem_total_mb,
            "netin": netin_vals,
            "netout": netout_vals,
            "net_unit": net_unit,
            "source": source,
        }

    def get_host_rrd(self, host_id, timeframe="day"):
        """Query Prometheus for host performance metrics and return Chart.js-ready JSON."""
        dur, step = _TIMEFRAMES.get(timeframe, _TIMEFRAMES["day"])
        end = time.time()
        start = end - dur

        hid = str(host_id)

        cpu_data = self._range_single(f'mstdnca_host_cpu_usage_percent{{host_id="{escape_label_value(hid)}"}}', start, end, step)
        mem_used = self._range_single(f'mstdnca_host_memory_used_bytes{{host_id="{escape_label_value(hid)}"}}', start, end, step)
        mem_total = self._range_single(f'mstdnca_host_memory_total_bytes{{host_id="{escape_label_value(hid)}"}}', start, end, step)
        netin = self._range_single(f'mstdnca_host_network_in_bytes_per_sec{{host_id="{escape_label_value(hid)}"}}', start, end, step)
        netout = self._range_single(f'mstdnca_host_network_out_bytes_per_sec{{host_id="{escape_label_value(hid)}"}}', start, end, step)
        rootfs = self._range_single(f'mstdnca_host_rootfs_used_percent{{host_id="{escape_label_value(hid)}"}}', start, end, step)

        timestamps = cpu_data.get("timestamps") or mem_used.get("timestamps") or []
        utz = _user_tz()
        labels = [datetime.fromtimestamp(ts, tz=timezone.utc).astimezone(utz).strftime("%Y-%m-%d %H:%M") for ts in timestamps]

        cpu_vals = cpu_data.get("values", [])
        mem_used_vals = mem_used.get("values", [])
        mem_total_vals = mem_total.get("values", [])
        netin_vals = netin.get("values", [])
        netout_vals = netout.get("values", [])
        rootfs_vals = rootfs.get("values", [])

        mem_total_mb = 0
        mem_percent = []
        mem_used_mb = []
        for i, used in enumerate(mem_used_vals):
            total = mem_total_vals[i] if i < len(mem_total_vals) else None
            if used is not None and total and total > 0:
                mem_used_mb.append(round(used / 1048576, 1))
                mem_percent.append(round(used / total * 100, 2))
                mem_total_mb = round(total / 1048576, 1)
            else:
                mem_used_mb.append(None)
                mem_percent.append(None)

        all_net = [v for v in netin_vals + netout_vals if v is not None]
        max_net = max(all_net, default=0)
        if max_net > 1_000_000:
            net_unit = "Mbps"
            divisor = 125_000
        elif max_net > 1_000:
            net_unit = "KB/s"
            divisor = 1024
        else:
            net_unit = "B/s"
            divisor = 1

        if divisor != 1:
            netin_vals = [round(v / divisor, 2) if v is not None else None for v in netin_vals]
            netout_vals = [round(v / divisor, 2) if v is not None else None for v in netout_vals]

        return {
            "labels": labels,
            "cpu": cpu_vals,
            "mem_percent": mem_percent,
            "mem_used_mb": mem_used_mb,
            "mem_total_mb": mem_total_mb,
            "netin": netin_vals,
            "netout": netout_vals,
            "net_unit": net_unit,
            "iowait": [],
            "rootfs_percent": rootfs_vals,
        }

    def get_service_metrics_history(self, service_id, metric_names, timeframe="day"):
        """Query Prometheus for service metric history and return as snapshot list.

        Returns {"snapshots": [{metric: value, "captured_at": iso_str}, ...]}
        matching the format of pg_metrics_history/jvb_metrics_history.
        """
        dur, step = _TIMEFRAMES.get(timeframe, _TIMEFRAMES["day"])
        end = time.time()
        start = end - dur

        sid = str(service_id)
        all_series = {}
        timestamps = []

        for metric_name in metric_names:
            result = self._range_single(f'{metric_name}{{service_id="{escape_label_value(sid)}"}}', start, end, step)
            all_series[metric_name] = result.get("values", [])
            if not timestamps and result.get("timestamps"):
                timestamps = result["timestamps"]

        # Build snapshot list matching the SQLite format
        snapshots = []
        for i, ts in enumerate(timestamps):
            snap = {"captured_at": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()}
            for metric_name, values in all_series.items():
                # Use the short name (strip prefix)
                short = metric_name.split("{")[0].replace("mstdnca_", "")
                snap[short] = values[i] if i < len(values) else None
            snapshots.append(snap)

        return {"snapshots": snapshots, "source": "mstdnca"}

    def get_pg_metrics_exporter(self, target, timeframe="day"):
        """Query postgres_exporter metrics and return snapshots matching PG format."""
        dur, step = _TIMEFRAMES.get(timeframe, _TIMEFRAMES["day"])
        end = time.time()
        start = end - dur
        inst = f'instance="{escape_label_value(target)}"'
        rate_interval = f"{max(step * 2, 120)}s"

        queries = {
            "total_connections": f'sum(pg_stat_activity_count{{{inst}}})',
            "active_connections": f'sum(pg_stat_activity_count{{state="active",{inst}}})',
            "cache_hit_ratio": (
                f'sum(rate(pg_stat_database_blks_hit{{{inst}}}[{rate_interval}])) / '
                f'clamp_min(sum(rate(pg_stat_database_blks_hit{{{inst}}}[{rate_interval}])) + '
                f'sum(rate(pg_stat_database_blks_read{{{inst}}}[{rate_interval}])), 1) * 100'
            ),
            "total_commits": f'sum(pg_stat_database_xact_commit{{{inst}}})',
            "total_rollbacks": f'sum(pg_stat_database_xact_rollback{{{inst}}})',
            "lock_waits": f'sum(pg_locks_count{{{inst}}}) or vector(0)',
        }

        return self._run_snapshot_queries(queries, start, end, step, source="postgres_exporter")

    def get_redis_metrics_exporter(self, target, timeframe="day"):
        """Query redis_exporter metrics and return snapshots matching Redis format."""
        dur, step = _TIMEFRAMES.get(timeframe, _TIMEFRAMES["day"])
        end = time.time()
        start = end - dur
        inst = f'instance="{escape_label_value(target)}"'
        rate_interval = f"{max(step * 2, 120)}s"

        queries = {
            "used_memory_bytes": f'redis_memory_used_bytes{{{inst}}}',
            "connected_clients": f'redis_connected_clients{{{inst}}}',
            "ops_per_sec": f'rate(redis_commands_processed_total{{{inst}}}[{rate_interval}])',
            "hit_ratio": (
                f'redis_keyspace_hits_total{{{inst}}} / '
                f'clamp_min(redis_keyspace_hits_total{{{inst}}} + '
                f'redis_keyspace_misses_total{{{inst}}}, 1) * 100'
            ),
            "evicted_keys": f'redis_evicted_keys_total{{{inst}}}',
        }

        return self._run_snapshot_queries(queries, start, end, step, source="redis_exporter")

    def get_es_metrics_exporter(self, target, timeframe="day"):
        """Query elasticsearch_exporter metrics and return snapshots."""
        dur, step = _TIMEFRAMES.get(timeframe, _TIMEFRAMES["day"])
        end = time.time()
        start = end - dur
        inst = f'instance="{escape_label_value(target)}"'

        queries = {
            "cluster_health": f'elasticsearch_cluster_health_status{{{inst}}}',
            "doc_count": f'elasticsearch_indices_docs{{{inst}}}',
            "store_size_bytes": f'elasticsearch_indices_store_size_bytes{{{inst}}}',
            "jvm_heap_used_bytes": f'sum(elasticsearch_jvm_memory_used_bytes{{{inst}}})',
            "jvm_heap_max_bytes": f'sum(elasticsearch_jvm_memory_max_bytes{{{inst}}})',
            "cpu_percent": f'avg(elasticsearch_os_cpu_percent{{{inst}}})',
        }

        return self._run_snapshot_queries(queries, start, end, step, source="elasticsearch_exporter")

    def get_mastodon_metrics(self, target, timeframe="day"):
        """Query Mastodon built-in Prometheus exporter metrics and return snapshots.

        Uses ruby_* prefixed metrics from the prometheus_exporter gem.
        Duration metrics are summaries (not histograms) so we compute averages via sum/count.
        """
        dur, step = _TIMEFRAMES.get(timeframe, _TIMEFRAMES["day"])
        end = time.time()
        start = end - dur
        inst = f'instance="{escape_label_value(target)}"'
        ri = f"{max(step * 2, 120)}s"

        # Helper for summary average: rate(sum) / rate(count)
        def _summary_avg(metric):
            return (
                f'sum(rate({metric}_sum{{{inst}}}[{ri}])) / '
                f'clamp_min(sum(rate({metric}_count{{{inst}}}[{ri}])), 1e-10)'
            )

        queries = {
            # -- Puma / Web --
            "puma_request_rate": f'sum(rate(ruby_http_requests_total{{{inst}}}[{ri}]))',
            "puma_avg_response_time": _summary_avg("ruby_http_request_duration_seconds"),
            "puma_sql_duration": _summary_avg("ruby_http_request_sql_duration_seconds"),
            "puma_redis_duration": _summary_avg("ruby_http_request_redis_duration_seconds"),
            "puma_queue_wait": _summary_avg("ruby_http_request_queue_duration_seconds"),
            "puma_thread_utilization": (
                f'sum(ruby_puma_running_threads{{{inst}}}) / '
                f'clamp_min(sum(ruby_puma_max_threads{{{inst}}}), 1) * 100'
            ),
            "puma_backlog": f'sum(ruby_puma_backlog{{{inst}}})',
            "puma_rss_memory": f'sum(ruby_rss{{{inst}}})',
            # -- Sidekiq --
            "sidekiq_throughput": f'sum(rate(ruby_sidekiq_jobs_total{{{inst}}}[{ri}]))',
            "sidekiq_failure_rate": f'sum(rate(ruby_sidekiq_failed_jobs_total{{{inst}}}[{ri}]))',
            "sidekiq_avg_duration": _summary_avg("ruby_sidekiq_job_duration_seconds"),
            "sidekiq_enqueued": f'sum(ruby_sidekiq_stats_enqueued{{{inst}}})',
            "sidekiq_retry_queue": f'sum(ruby_sidekiq_stats_retry_size{{{inst}}})',
            "sidekiq_dead_queue": f'sum(ruby_sidekiq_stats_dead_size{{{inst}}})',
            # -- ActiveRecord --
            "db_pool_utilization": (
                f'sum(ruby_active_record_connection_pool_busy{{{inst}}}) / '
                f'clamp_min(sum(ruby_active_record_connection_pool_size{{{inst}}}), 1) * 100'
            ),
            "db_pool_waiting": f'sum(ruby_active_record_connection_pool_waiting{{{inst}}})',
            # -- Ruby runtime --
            "ruby_heap_live_slots": f'sum(ruby_heap_live_slots{{{inst}}})',
            "ruby_allocations_rate": f'sum(rate(ruby_allocations{{{inst}}}[{ri}]))',
        }

        return self._run_snapshot_queries(queries, start, end, step, source="mastodon_exporter")

    def get_ipmi_metrics_exporter(self, target, timeframe="day"):
        """Query ipmi_exporter metrics and return snapshots."""
        dur, step = _TIMEFRAMES.get(timeframe, _TIMEFRAMES["day"])
        end = time.time()
        start = end - dur
        inst = f'instance="{escape_label_value(target)}"'

        queries = {
            "power_consumption_watts": f"ipmi_dcmi_power_consumption_watts{{{inst}}}",
            "cpu_temp": f'ipmi_temperature_celsius{{{inst},name=~"CPU.*Temp|Processor.*"}}',
            "system_temp": f'ipmi_temperature_celsius{{{inst},name=~"System.*Temp|Inlet.*|Ambient.*"}}',
            "fan_speed_rpm": f"avg(ipmi_fan_speed_rpm{{{inst}}})",
            "chassis_power_state": f"ipmi_chassis_power_state{{{inst}}}",
        }

        return self._run_snapshot_queries(queries, start, end, step, source="ipmi_exporter")

    def get_jvb_metrics_exporter(self, target, timeframe="day"):
        """Query native JVB Prometheus metrics and return snapshots."""
        dur, step = _TIMEFRAMES.get(timeframe, _TIMEFRAMES["day"])
        end = time.time()
        start = end - dur
        inst = f'instance="{escape_label_value(target)}"'

        queries = {
            "conferences": f"jitsi_jvb_conferences{{{inst}}}",
            "participants": f"jitsi_jvb_participants{{{inst}}}",
            "stress_level": f"jitsi_jvb_stress_level{{{inst}}}",
            "bit_rate_download": f"jitsi_jvb_bit_rate_download{{{inst}}}",
            "bit_rate_upload": f"jitsi_jvb_bit_rate_upload{{{inst}}}",
            "conferences_created_total": f"jitsi_jvb_conferences_created_total{{{inst}}}",
            "participants_total": f"jitsi_jvb_participants_total{{{inst}}}",
            "ice_succeeded_total": f"jitsi_jvb_ice_succeeded_total{{{inst}}}",
            "ice_failed_total": f"jitsi_jvb_ice_failed_total{{{inst}}}",
        }

        return self._run_snapshot_queries(queries, start, end, step, source="jitsi_jvb")

    def _run_snapshot_queries(self, queries, start, end, step, source="exporter"):
        """Run multiple range queries and build a snapshot list."""
        all_series = {}
        timestamps = []

        for short_name, promql in queries.items():
            result = self._range_single(promql, start, end, step)
            all_series[short_name] = result.get("values", [])
            if not timestamps and result.get("timestamps"):
                timestamps = result["timestamps"]

        snapshots = []
        for i, ts in enumerate(timestamps):
            snap = {"captured_at": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()}
            for name, values in all_series.items():
                snap[name] = values[i] if i < len(values) else None
            snapshots.append(snap)

        return {"snapshots": snapshots, "source": source}

    # ----- UniFi -----

    def get_unifi_device_history(self, device_mac, timeframe="day"):
        """Query Prometheus for UniFi device performance metrics over time.

        Returns Chart.js-ready JSON with CPU, memory, client count, TX/RX.
        """
        dur, step = _TIMEFRAMES.get(timeframe, _TIMEFRAMES["day"])
        end = time.time()
        start = end - dur
        mac = device_mac.lower()

        queries = {
            "cpu": f'mstdnca_unifi_device_cpu_percent{{device_mac="{escape_label_value(mac)}"}}',
            "memory": f'mstdnca_unifi_device_memory_percent{{device_mac="{escape_label_value(mac)}"}}',
            "clients": f'mstdnca_unifi_device_clients{{device_mac="{escape_label_value(mac)}"}}',
            "tx_bytes": f'mstdnca_unifi_device_tx_bytes{{device_mac="{escape_label_value(mac)}"}}',
            "rx_bytes": f'mstdnca_unifi_device_rx_bytes{{device_mac="{escape_label_value(mac)}"}}',
            "temperature": f'mstdnca_unifi_device_temperature_celsius{{device_mac="{escape_label_value(mac)}"}}',
        }

        all_series = {}
        timestamps = []
        for name, promql in queries.items():
            result = self._range_single(promql, start, end, step)
            all_series[name] = result.get("values", [])
            if not timestamps and result.get("timestamps"):
                timestamps = result["timestamps"]

        utz = _user_tz()
        labels = [
            datetime.fromtimestamp(ts, tz=timezone.utc).astimezone(utz).strftime("%Y-%m-%d %H:%M")
            for ts in timestamps
        ]

        return {
            "labels": labels,
            "cpu": all_series.get("cpu", []),
            "memory": all_series.get("memory", []),
            "clients": all_series.get("clients", []),
            "tx_bytes": all_series.get("tx_bytes", []),
            "rx_bytes": all_series.get("rx_bytes", []),
            "temperature": all_series.get("temperature", []),
        }

    def get_unifi_site_history(self, site_name, timeframe="day"):
        """Query Prometheus for aggregate UniFi site metrics over time.

        Returns Chart.js-ready JSON with total clients, WAN latency, bandwidth.
        """
        dur, step = _TIMEFRAMES.get(timeframe, _TIMEFRAMES["day"])
        end = time.time()
        start = end - dur

        queries = {
            "clients": f'mstdnca_unifi_client_count{{site_name="{escape_label_value(site_name)}"}}',
            "devices": f'mstdnca_unifi_device_count{{site_name="{escape_label_value(site_name)}"}}',
            "wan_latency": f'mstdnca_unifi_wan_latency_ms{{site_name="{escape_label_value(site_name)}"}}',
            "wan_tx": f'mstdnca_unifi_wan_tx_bytes_per_sec{{site_name="{escape_label_value(site_name)}"}}',
            "wan_rx": f'mstdnca_unifi_wan_rx_bytes_per_sec{{site_name="{escape_label_value(site_name)}"}}',
            "speedtest_dl": f'mstdnca_unifi_speedtest_download_mbps{{site_name="{escape_label_value(site_name)}"}}',
            "speedtest_ul": f'mstdnca_unifi_speedtest_upload_mbps{{site_name="{escape_label_value(site_name)}"}}',
        }

        all_series = {}
        timestamps = []
        for name, promql in queries.items():
            result = self._range_single(promql, start, end, step)
            all_series[name] = result.get("values", [])
            if not timestamps and result.get("timestamps"):
                timestamps = result["timestamps"]

        utz = _user_tz()
        labels = [
            datetime.fromtimestamp(ts, tz=timezone.utc).astimezone(utz).strftime("%Y-%m-%d %H:%M")
            for ts in timestamps
        ]

        return {
            "labels": labels,
            **all_series,
        }

    # ----- Unpoller (enhanced UniFi metrics) -----

    def _unpoller_prefix(self):
        """Return the configured unpoller metric namespace prefix."""
        return Setting.get("unpoller_metric_prefix", "unpoller")

    def check_unpoller_available(self):
        """Return True if unpoller metrics exist in Prometheus."""
        prefix = self._unpoller_prefix()
        try:
            result = self.query(f"{prefix}_site_num_user")
            return len(result) > 0
        except Exception:
            return False

    def get_unpoller_device_history(self, device_name, site_name=None, timeframe="day"):
        """Query unpoller for per-device metrics over time.

        Uses device *name* label since unpoller labels devices by name.
        Falls back to mstdnca metrics if unpoller returns no data.
        """
        dur, step = _TIMEFRAMES.get(timeframe, _TIMEFRAMES["day"])
        end = time.time()
        start = end - dur
        p = self._unpoller_prefix()
        site = site_name or Setting.get("unpoller_site_name", "default")
        lbl = f'site_name="{escape_label_value(site)}",name="{escape_label_value(device_name)}"'

        queries = {
            "cpu": f'{p}_device_system_cpu{{site_name="{escape_label_value(site)}",name="{escape_label_value(device_name)}"}}',
            "memory": f'{p}_device_system_mem{{site_name="{escape_label_value(site)}",name="{escape_label_value(device_name)}"}}',
            "clients": f'{p}_device_num_sta{{site_name="{escape_label_value(site)}",name="{escape_label_value(device_name)}"}}',
            "temperature": f'{p}_device_general_temperature{{site_name="{escape_label_value(site)}",name="{escape_label_value(device_name)}"}}',
            "uptime": f'{p}_device_uptime_seconds{{site_name="{escape_label_value(site)}",name="{escape_label_value(device_name)}"}}',
            "tx_bytes": f'{p}_device_stat_bytes_sent{{{lbl}}}',
            "rx_bytes": f'{p}_device_stat_bytes_received{{{lbl}}}',
        }

        all_series = {}
        timestamps = []
        for name, promql in queries.items():
            result = self._range_single(promql, start, end, step)
            all_series[name] = result.get("values", [])
            if not timestamps and result.get("timestamps"):
                timestamps = result["timestamps"]

        utz = _user_tz()
        labels = [
            datetime.fromtimestamp(ts, tz=timezone.utc).astimezone(utz).strftime("%Y-%m-%d %H:%M")
            for ts in timestamps
        ]

        return {
            "labels": labels,
            "cpu": all_series.get("cpu", []),
            "memory": all_series.get("memory", []),
            "clients": all_series.get("clients", []),
            "tx_bytes": all_series.get("tx_bytes", []),
            "rx_bytes": all_series.get("rx_bytes", []),
            "temperature": all_series.get("temperature", []),
            "uptime": all_series.get("uptime", []),
            "source": "unpoller",
        }

    def get_unpoller_client_history(self, client_mac, site_name=None, timeframe="day"):
        """Query unpoller for per-client metrics over time (signal, satisfaction, TX/RX)."""
        dur, step = _TIMEFRAMES.get(timeframe, _TIMEFRAMES["day"])
        end = time.time()
        start = end - dur
        p = self._unpoller_prefix()
        site = site_name or Setting.get("unpoller_site_name", "default")
        mac = client_mac.lower()
        lbl = f'site_name="{escape_label_value(site)}",mac="{escape_label_value(mac)}"'
        ri = f"{max(step * 2, 120)}s"

        queries = {
            "rssi": f"{p}_client_rssi_db{{{lbl}}}",
            "signal": f"{p}_client_radio_signal_db{{{lbl}}}",
            "satisfaction": f"{p}_client_satisfaction_ratio{{{lbl}}}",
            "noise": f"{p}_client_noise_db{{{lbl}}}",
            "tx_rate": f"rate({p}_client_transmit_bytes_total{{{lbl}}}[{ri}])",
            "rx_rate": f"rate({p}_client_receive_bytes_total{{{lbl}}}[{ri}])",
            "uptime": f"{p}_client_uptime_seconds{{{lbl}}}",
        }

        all_series = {}
        timestamps = []
        for name, promql in queries.items():
            result = self._range_single(promql, start, end, step)
            all_series[name] = result.get("values", [])
            if not timestamps and result.get("timestamps"):
                timestamps = result["timestamps"]

        utz = _user_tz()
        labels = [
            datetime.fromtimestamp(ts, tz=timezone.utc).astimezone(utz).strftime("%Y-%m-%d %H:%M")
            for ts in timestamps
        ]

        return {"labels": labels, **all_series, "source": "unpoller"}

    def get_unpoller_radio_history(self, device_name, radio_name, site_name=None, timeframe="day"):
        """Query unpoller for per-radio metrics over time (channel util, stations, TX power)."""
        dur, step = _TIMEFRAMES.get(timeframe, _TIMEFRAMES["day"])
        end = time.time()
        start = end - dur
        p = self._unpoller_prefix()
        site = site_name or Setting.get("unpoller_site_name", "default")
        lbl = f'site_name="{escape_label_value(site)}",name="{escape_label_value(device_name)}",radio_name="{escape_label_value(radio_name)}"'

        queries = {
            "channel": f"{p}_device_radio_channel{{{lbl}}}",
            "channel_utilization": f"{p}_device_radio_channel_utilization_total_ratio{{{lbl}}}",
            "stations": f"{p}_device_radio_stations{{{lbl}}}",
            "tx_power": f"{p}_device_radio_transmit_power{{{lbl}}}",
        }

        all_series = {}
        timestamps = []
        for name, promql in queries.items():
            result = self._range_single(promql, start, end, step)
            all_series[name] = result.get("values", [])
            if not timestamps and result.get("timestamps"):
                timestamps = result["timestamps"]

        utz = _user_tz()
        labels = [
            datetime.fromtimestamp(ts, tz=timezone.utc).astimezone(utz).strftime("%Y-%m-%d %H:%M")
            for ts in timestamps
        ]

        return {"labels": labels, **all_series, "source": "unpoller"}

    def get_unpoller_site_history(self, site_name=None, timeframe="day"):
        """Query unpoller for site-level metrics over time."""
        dur, step = _TIMEFRAMES.get(timeframe, _TIMEFRAMES["day"])
        end = time.time()
        start = end - dur
        p = self._unpoller_prefix()
        site = site_name or Setting.get("unpoller_site_name", "default")
        lbl = f'site_name="{escape_label_value(site)}"'

        queries = {
            "clients": f"{p}_site_num_user{{{lbl}}}",
            "guests": f"{p}_site_num_guest{{{lbl}}}",
            "devices": f"{p}_site_num_adopted{{{lbl}}}",
            "wan_latency": f"{p}_site_latency_seconds{{{lbl}}}",
            "wan_tx": f"{p}_site_transmit_rate_bytes{{{lbl}}}",
            "wan_rx": f"{p}_site_receive_rate_bytes{{{lbl}}}",
            "speedtest_dl": f"{p}_site_xput_down_rate{{{lbl}}}",
            "speedtest_ul": f"{p}_site_xput_up_rate{{{lbl}}}",
            "aps": f"{p}_site_num_ap{{{lbl}}}",
            "switches": f"{p}_site_num_sw{{{lbl}}}",
            "gateways": f"{p}_site_num_gw{{{lbl}}}",
        }

        all_series = {}
        timestamps = []
        for name, promql in queries.items():
            result = self._range_single(promql, start, end, step)
            all_series[name] = result.get("values", [])
            if not timestamps and result.get("timestamps"):
                timestamps = result["timestamps"]

        utz = _user_tz()
        labels = [
            datetime.fromtimestamp(ts, tz=timezone.utc).astimezone(utz).strftime("%Y-%m-%d %H:%M")
            for ts in timestamps
        ]

        return {"labels": labels, **all_series, "source": "unpoller"}

    def get_unpoller_wan_history(self, site_name=None, timeframe="day"):
        """Query unpoller for WAN-specific metrics over time."""
        dur, step = _TIMEFRAMES.get(timeframe, _TIMEFRAMES["day"])
        end = time.time()
        start = end - dur
        p = self._unpoller_prefix()
        site = site_name or Setting.get("unpoller_site_name", "default")
        lbl = f'site_name="{escape_label_value(site)}"'

        queries = {
            "latency": f"{p}_site_latency_seconds{{{lbl}}}",
            "wan_tx_rate": f"{p}_site_transmit_rate_bytes{{{lbl}}}",
            "wan_rx_rate": f"{p}_site_receive_rate_bytes{{{lbl}}}",
            "speedtest_download": f"{p}_site_xput_down_rate{{{lbl}}}",
            "speedtest_upload": f"{p}_site_xput_up_rate{{{lbl}}}",
            "speedtest_ping": f"{p}_site_speedtest_ping{{{lbl}}}",
            "internet_drops": f"{p}_site_intenet_drops_total{{{lbl}}}",
        }

        all_series = {}
        timestamps = []
        for name, promql in queries.items():
            result = self._range_single(promql, start, end, step)
            all_series[name] = result.get("values", [])
            if not timestamps and result.get("timestamps"):
                timestamps = result["timestamps"]

        utz = _user_tz()
        labels = [
            datetime.fromtimestamp(ts, tz=timezone.utc).astimezone(utz).strftime("%Y-%m-%d %H:%M")
            for ts in timestamps
        ]

        return {"labels": labels, **all_series, "source": "unpoller"}

    def get_unpoller_dpi_history(self, site_name=None, timeframe="day"):
        """Query unpoller for DPI category breakdown over time."""
        dur, step = _TIMEFRAMES.get(timeframe, _TIMEFRAMES["day"])
        end = time.time()
        start = end - dur
        p = self._unpoller_prefix()
        site = site_name or Setting.get("unpoller_site_name", "default")
        ri = f"{max(step * 2, 120)}s"

        # Query all DPI categories at once — unpoller labels by category
        rx_query = f'rate({p}_site_dpi_receive_bytes{{site_name="{escape_label_value(site)}"}}[{ri}])'
        tx_query = f'rate({p}_site_dpi_transmit_bytes{{site_name="{escape_label_value(site)}"}}[{ri}])'

        try:
            rx_results = self.query_range(rx_query, start, end, step)
            tx_results = self.query_range(tx_query, start, end, step)
        except Exception:
            logger.debug("Unpoller DPI query failed", exc_info=True)
            return {"labels": [], "categories": [], "source": "unpoller"}

        # Build per-category series
        categories = {}
        timestamps = []
        for series in rx_results + tx_results:
            cat = series.get("metric", {}).get("category", "unknown")
            if cat not in categories:
                categories[cat] = {"rx": [], "tx": []}
            values_raw = series.get("values", [])
            if not timestamps and values_raw:
                timestamps = [float(v[0]) for v in values_raw]
            parsed = []
            for _, val in values_raw:
                try:
                    parsed.append(round(float(val), 2))
                except (TypeError, ValueError):
                    parsed.append(0)
            # Determine if this is RX or TX based on which query set it came from
            if series in rx_results:
                categories[cat]["rx"] = parsed
            else:
                categories[cat]["tx"] = parsed

        utz = _user_tz()
        labels = [
            datetime.fromtimestamp(ts, tz=timezone.utc).astimezone(utz).strftime("%Y-%m-%d %H:%M")
            for ts in timestamps
        ]

        return {"labels": labels, "categories": categories, "source": "unpoller"}

    # ----- internal -----

    def _range_single(self, promql, start, end, step):
        """Run a range query expecting a single time series and return timestamps + values."""
        try:
            results = self.query_range(promql, start, end, step)
        except Exception:
            logger.debug("Prometheus range query failed for %s", promql, exc_info=True)
            return {"timestamps": [], "values": []}

        if not results:
            return {"timestamps": [], "values": []}

        # Take the first matching series
        values_raw = results[0].get("values", [])
        timestamps = []
        values = []
        for ts, val in values_raw:
            timestamps.append(float(ts))
            try:
                values.append(round(float(val), 2))
            except (TypeError, ValueError):
                values.append(None)

        return {"timestamps": timestamps, "values": values}
