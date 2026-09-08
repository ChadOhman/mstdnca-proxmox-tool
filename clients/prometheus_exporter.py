"""
Prometheus metrics exporter for mstdnca-proxmox-tool.

Maintains a thread-safe in-memory metrics registry using the prometheus_client
library.  Scheduled jobs call update_*() functions after each collection cycle
to refresh gauge values.  The registry is exposed via a /metrics endpoint
(see routes/prometheus_metrics.py).

Uses a custom CollectorRegistry to avoid conflicts with the default global
registry and any future WSGI middleware.

Metric lifecycle
-----------------
Several collection loops (host, guest, service, APT) call their update_*()
function once per entity from a shared refresh cycle in core/scheduler.py, so
this module has no explicit "cycle complete" signal from the caller. To avoid
exporting stale series forever for deleted/renamed guests, hosts, or services,
each of these groups is tracked by ``_prune_cycle()``: a gap of more than
``_CYCLE_GAP_SECONDS`` between calls for the same group is treated as the
boundary between one full refresh and the next, and any label combination not
touched during the cycle that just finished is removed from its collectors.

UniFi device/health metrics are different: the caller already passes the full
current list on every call, so those are pruned by direct set-difference
against the previous call's labels for that site — no timing heuristic needed.
"""

import logging
import threading
import time

from prometheus_client import CollectorRegistry, Gauge, Info, generate_latest

logger = logging.getLogger(__name__)

# Custom registry — isolated from the default global one
registry = CollectorRegistry()

_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Host metrics (labels: host_id, host_name, host_type)
# ---------------------------------------------------------------------------
HOST_CPU = Gauge("mstdnca_host_cpu_usage_percent", "Host CPU usage percentage",
                 ["host_id", "host_name", "host_type"], registry=registry)
HOST_MEM_USED = Gauge("mstdnca_host_memory_used_bytes", "Host memory used in bytes",
                      ["host_id", "host_name", "host_type"], registry=registry)
HOST_MEM_TOTAL = Gauge("mstdnca_host_memory_total_bytes", "Host memory total in bytes",
                       ["host_id", "host_name", "host_type"], registry=registry)
HOST_ROOTFS = Gauge("mstdnca_host_rootfs_used_percent", "Host rootfs usage percentage",
                    ["host_id", "host_name", "host_type"], registry=registry)
HOST_UPTIME = Gauge("mstdnca_host_uptime_seconds", "Host uptime in seconds",
                    ["host_id", "host_name", "host_type"], registry=registry)

_HOST_COLLECTORS = [HOST_CPU, HOST_MEM_USED, HOST_MEM_TOTAL, HOST_ROOTFS, HOST_UPTIME]

# ---------------------------------------------------------------------------
# Guest metrics (labels: guest_id, guest_name, guest_type, host_name, vmid)
# ---------------------------------------------------------------------------
GUEST_CPU = Gauge("mstdnca_guest_cpu_usage_percent", "Guest CPU usage percentage",
                  ["guest_id", "guest_name", "guest_type", "host_name", "vmid"], registry=registry)
GUEST_MEM_USED = Gauge("mstdnca_guest_memory_used_bytes", "Guest memory used in bytes",
                       ["guest_id", "guest_name", "guest_type", "host_name", "vmid"], registry=registry)
GUEST_MEM_TOTAL = Gauge("mstdnca_guest_memory_total_bytes", "Guest memory total in bytes",
                        ["guest_id", "guest_name", "guest_type", "host_name", "vmid"], registry=registry)
GUEST_NET_IN = Gauge("mstdnca_guest_network_in_bytes_per_sec", "Guest network inbound bytes/sec",
                     ["guest_id", "guest_name", "guest_type", "host_name", "vmid"], registry=registry)
GUEST_NET_OUT = Gauge("mstdnca_guest_network_out_bytes_per_sec", "Guest network outbound bytes/sec",
                      ["guest_id", "guest_name", "guest_type", "host_name", "vmid"], registry=registry)
GUEST_POWER = Gauge("mstdnca_guest_power_state", "Guest power state (1=running, 0=stopped)",
                    ["guest_id", "guest_name", "guest_type", "host_name", "vmid"], registry=registry)

_GUEST_COLLECTORS = [GUEST_CPU, GUEST_MEM_USED, GUEST_MEM_TOTAL, GUEST_NET_IN, GUEST_NET_OUT, GUEST_POWER]

# ---------------------------------------------------------------------------
# Service health (labels: service_id, service_name, guest_name, unit_name)
# ---------------------------------------------------------------------------
SVC_UP = Gauge("mstdnca_service_up", "Service status (1=running, 0=not running)",
               ["service_id", "service_name", "guest_name", "unit_name"], registry=registry)
SVC_MEMORY = Gauge("mstdnca_service_memory_bytes", "Service memory usage in bytes",
                   ["service_id", "service_name", "guest_name", "unit_name"], registry=registry)

_SERVICE_COLLECTORS = [SVC_UP, SVC_MEMORY]

# ---------------------------------------------------------------------------
# PostgreSQL (labels: service_id, guest_name)
# ---------------------------------------------------------------------------
PG_CONNECTIONS = Gauge("mstdnca_pg_connections_total", "PostgreSQL total connections",
                       ["service_id", "guest_name"], registry=registry)
PG_CONNECTIONS_ACTIVE = Gauge("mstdnca_pg_connections_active", "PostgreSQL active connections",
                              ["service_id", "guest_name"], registry=registry)
PG_CACHE_HIT = Gauge("mstdnca_pg_cache_hit_ratio", "PostgreSQL cache hit ratio",
                      ["service_id", "guest_name"], registry=registry)
PG_COMMITS = Gauge("mstdnca_pg_commits_total", "PostgreSQL total commits",
                   ["service_id", "guest_name"], registry=registry)
PG_ROLLBACKS = Gauge("mstdnca_pg_rollbacks_total", "PostgreSQL total rollbacks",
                     ["service_id", "guest_name"], registry=registry)
PG_LOCK_WAITS = Gauge("mstdnca_pg_lock_waits", "PostgreSQL lock waits",
                      ["service_id", "guest_name"], registry=registry)

# ---------------------------------------------------------------------------
# Redis (labels: service_id, guest_name)
# ---------------------------------------------------------------------------
REDIS_MEM = Gauge("mstdnca_redis_memory_used_bytes", "Redis memory used in bytes",
                  ["service_id", "guest_name"], registry=registry)
REDIS_CLIENTS = Gauge("mstdnca_redis_connected_clients", "Redis connected clients",
                      ["service_id", "guest_name"], registry=registry)
REDIS_OPS = Gauge("mstdnca_redis_ops_per_sec", "Redis operations per second",
                  ["service_id", "guest_name"], registry=registry)
REDIS_HIT_RATIO = Gauge("mstdnca_redis_hit_ratio", "Redis cache hit ratio",
                        ["service_id", "guest_name"], registry=registry)
REDIS_EVICTED = Gauge("mstdnca_redis_evicted_keys_total", "Redis evicted keys total",
                      ["service_id", "guest_name"], registry=registry)

# ---------------------------------------------------------------------------
# Elasticsearch (labels: service_id, guest_name)
# ---------------------------------------------------------------------------
ES_HEALTH = Gauge("mstdnca_es_cluster_health", "Elasticsearch cluster health (0=red, 1=yellow, 2=green)",
                  ["service_id", "guest_name"], registry=registry)
ES_DOC_COUNT = Gauge("mstdnca_es_doc_count", "Elasticsearch document count",
                     ["service_id", "guest_name"], registry=registry)
ES_STORE_SIZE = Gauge("mstdnca_es_store_size_bytes", "Elasticsearch store size in bytes",
                      ["service_id", "guest_name"], registry=registry)
ES_JVM_HEAP_USED = Gauge("mstdnca_es_jvm_heap_used_bytes", "Elasticsearch JVM heap used",
                         ["service_id", "guest_name"], registry=registry)
ES_JVM_HEAP_MAX = Gauge("mstdnca_es_jvm_heap_max_bytes", "Elasticsearch JVM heap max",
                        ["service_id", "guest_name"], registry=registry)
ES_CPU = Gauge("mstdnca_es_cpu_percent", "Elasticsearch CPU usage",
               ["service_id", "guest_name"], registry=registry)

# ---------------------------------------------------------------------------
# Jitsi Videobridge (labels: service_id, guest_name)
# ---------------------------------------------------------------------------
JITSI_CONFERENCES = Gauge("mstdnca_jitsi_conferences", "Active Jitsi conferences",
                          ["service_id", "guest_name"], registry=registry)
JITSI_PARTICIPANTS = Gauge("mstdnca_jitsi_participants", "Total Jitsi participants",
                           ["service_id", "guest_name"], registry=registry)
JITSI_STRESS = Gauge("mstdnca_jitsi_stress_level", "Jitsi Videobridge stress level",
                     ["service_id", "guest_name"], registry=registry)
JITSI_BITRATE_DL = Gauge("mstdnca_jitsi_bitrate_download_bps", "Jitsi download bitrate",
                         ["service_id", "guest_name"], registry=registry)

# ---------------------------------------------------------------------------
# Prometheus server (labels: service_id, guest_name)
# ---------------------------------------------------------------------------
PROM_TARGETS_UP = Gauge("mstdnca_prometheus_targets_up", "Prometheus scrape targets that are up",
                        ["service_id", "guest_name"], registry=registry)
PROM_TARGETS_DOWN = Gauge("mstdnca_prometheus_targets_down", "Prometheus scrape targets that are down",
                          ["service_id", "guest_name"], registry=registry)
PROM_STORAGE = Gauge("mstdnca_prometheus_storage_bytes", "Prometheus TSDB storage size in bytes",
                     ["service_id", "guest_name"], registry=registry)
PROM_HEAD_SERIES = Gauge("mstdnca_prometheus_head_series", "Prometheus TSDB head series count",
                         ["service_id", "guest_name"], registry=registry)

# ---------------------------------------------------------------------------
# UniFi — aggregate (labels: site_name)
# ---------------------------------------------------------------------------
UNIFI_DEVICES = Gauge("mstdnca_unifi_device_count", "UniFi managed device count",
                      ["site_name"], registry=registry)
UNIFI_CLIENTS = Gauge("mstdnca_unifi_client_count", "UniFi connected client count",
                      ["site_name"], registry=registry)

# ---------------------------------------------------------------------------
# UniFi — per-device (labels: site_name, device_mac, device_name, device_type)
# ---------------------------------------------------------------------------
_UNIFI_DEV_LABELS = ["site_name", "device_mac", "device_name", "device_type"]
UNIFI_DEV_CPU = Gauge("mstdnca_unifi_device_cpu_percent", "UniFi device CPU utilization",
                      _UNIFI_DEV_LABELS, registry=registry)
UNIFI_DEV_MEM = Gauge("mstdnca_unifi_device_memory_percent", "UniFi device memory utilization",
                      _UNIFI_DEV_LABELS, registry=registry)
UNIFI_DEV_UPTIME = Gauge("mstdnca_unifi_device_uptime_seconds", "UniFi device uptime",
                         _UNIFI_DEV_LABELS, registry=registry)
UNIFI_DEV_TEMP = Gauge("mstdnca_unifi_device_temperature_celsius", "UniFi device temperature",
                       _UNIFI_DEV_LABELS, registry=registry)
UNIFI_DEV_LOAD1 = Gauge("mstdnca_unifi_device_load_avg_1", "UniFi device 1-min load average",
                        _UNIFI_DEV_LABELS, registry=registry)
UNIFI_DEV_CLIENTS = Gauge("mstdnca_unifi_device_clients", "UniFi device connected clients",
                          _UNIFI_DEV_LABELS, registry=registry)
UNIFI_DEV_TX = Gauge("mstdnca_unifi_device_tx_bytes", "UniFi device TX bytes",
                     _UNIFI_DEV_LABELS, registry=registry)
UNIFI_DEV_RX = Gauge("mstdnca_unifi_device_rx_bytes", "UniFi device RX bytes",
                     _UNIFI_DEV_LABELS, registry=registry)
UNIFI_DEV_UPLINK_SPEED = Gauge("mstdnca_unifi_device_uplink_speed_mbps", "UniFi device uplink speed",
                               _UNIFI_DEV_LABELS, registry=registry)

_UNIFI_DEV_COLLECTORS = [
    UNIFI_DEV_CPU, UNIFI_DEV_MEM, UNIFI_DEV_UPTIME, UNIFI_DEV_TEMP,
    UNIFI_DEV_LOAD1, UNIFI_DEV_CLIENTS, UNIFI_DEV_TX, UNIFI_DEV_RX, UNIFI_DEV_UPLINK_SPEED,
]

# ---------------------------------------------------------------------------
# UniFi — per-AP radio (labels: site_name, device_mac, device_name, radio)
# ---------------------------------------------------------------------------
_UNIFI_RADIO_LABELS = ["site_name", "device_mac", "device_name", "radio"]
UNIFI_RADIO_CHANNEL = Gauge("mstdnca_unifi_radio_channel", "UniFi AP radio channel",
                            _UNIFI_RADIO_LABELS, registry=registry)
UNIFI_RADIO_CU = Gauge("mstdnca_unifi_radio_channel_utilization", "UniFi AP channel utilization %",
                       _UNIFI_RADIO_LABELS, registry=registry)
UNIFI_RADIO_CLIENTS = Gauge("mstdnca_unifi_radio_clients", "UniFi AP radio clients",
                            _UNIFI_RADIO_LABELS, registry=registry)
UNIFI_RADIO_TX_POWER = Gauge("mstdnca_unifi_radio_tx_power", "UniFi AP radio TX power",
                             _UNIFI_RADIO_LABELS, registry=registry)

_UNIFI_RADIO_COLLECTORS = [UNIFI_RADIO_CHANNEL, UNIFI_RADIO_CU, UNIFI_RADIO_CLIENTS, UNIFI_RADIO_TX_POWER]

# ---------------------------------------------------------------------------
# UniFi — site health (labels: site_name, subsystem)
# ---------------------------------------------------------------------------
_UNIFI_HEALTH_LABELS = ["site_name", "subsystem"]
UNIFI_HEALTH_STATUS = Gauge("mstdnca_unifi_health_status",
                            "UniFi subsystem health (0=unknown, 1=ok, 2=warn, 3=error)",
                            _UNIFI_HEALTH_LABELS, registry=registry)

# UniFi — WAN metrics (labels: site_name)
UNIFI_WAN_LATENCY = Gauge("mstdnca_unifi_wan_latency_ms", "UniFi WAN latency (ms)",
                          ["site_name"], registry=registry)
UNIFI_WAN_TX_RATE = Gauge("mstdnca_unifi_wan_tx_bytes_per_sec", "UniFi WAN TX bytes/sec",
                          ["site_name"], registry=registry)
UNIFI_WAN_RX_RATE = Gauge("mstdnca_unifi_wan_rx_bytes_per_sec", "UniFi WAN RX bytes/sec",
                          ["site_name"], registry=registry)
UNIFI_WAN_UPTIME = Gauge("mstdnca_unifi_wan_uptime_seconds", "UniFi WAN uptime",
                         ["site_name"], registry=registry)
UNIFI_SPEEDTEST_DL = Gauge("mstdnca_unifi_speedtest_download_mbps", "UniFi last speedtest download",
                           ["site_name"], registry=registry)
UNIFI_SPEEDTEST_UL = Gauge("mstdnca_unifi_speedtest_upload_mbps", "UniFi last speedtest upload",
                           ["site_name"], registry=registry)

_UNIFI_WAN_COLLECTORS = [
    UNIFI_WAN_LATENCY, UNIFI_WAN_TX_RATE, UNIFI_WAN_RX_RATE, UNIFI_WAN_UPTIME,
    UNIFI_SPEEDTEST_DL, UNIFI_SPEEDTEST_UL,
]

# ---------------------------------------------------------------------------
# APT updates (labels: guest_id, guest_name)
# ---------------------------------------------------------------------------
APT_PENDING = Gauge("mstdnca_guest_pending_updates", "Pending APT updates",
                    ["guest_id", "guest_name"], registry=registry)
APT_SECURITY = Gauge("mstdnca_guest_security_updates", "Pending security updates",
                     ["guest_id", "guest_name"], registry=registry)
APT_REBOOT = Gauge("mstdnca_guest_reboot_required", "Reboot required (1=yes, 0=no)",
                   ["guest_id", "guest_name"], registry=registry)

_APT_COLLECTORS = [APT_PENDING, APT_SECURITY, APT_REBOOT]

# ---------------------------------------------------------------------------
# Application version info (labels: app_name)
# ---------------------------------------------------------------------------
APP_UPDATE = Gauge("mstdnca_app_update_available", "Application update available (1=yes, 0=no)",
                   ["app_name"], registry=registry)
APP_INFO = Info("mstdnca_app", "Application version information",
                ["app_name"], registry=registry)


# ---------------------------------------------------------------------------
# Metric lifecycle helpers
# ---------------------------------------------------------------------------

# Gap between calls for the same group that marks the boundary between one
# full refresh cycle and the next (see module docstring). Comfortably shorter
# than the scheduler's collection interval (default 60s) while still long
# enough to cover a full per-entity loop.
_CYCLE_GAP_SECONDS = 30

# group_name -> {"cycle_start": monotonic ts, "last_call": monotonic ts, "seen": {label_tuple: ts}}
_cycle_state = {}

# site_name -> set of label tuples currently exported, for groups whose caller
# already supplies the full current list on every call.
_unifi_device_labels = {}
_unifi_radio_labels = {}
_unifi_health_labels = {}
_unifi_wan_present = {}


def _remove_labels(collectors, label_tuple):
    """Remove `label_tuple` from every collector in `collectors`, ignoring collectors
    that never had a series for it."""
    for collector in collectors:
        try:
            collector.remove(*label_tuple)
        except KeyError:
            pass


def _prune_cycle(group, label_tuple, collectors):
    """Record `label_tuple` as refreshed in `group`'s current cycle.

    If the gap since the last call to this group exceeds `_CYCLE_GAP_SECONDS`, the
    previous cycle is considered finished: any label combination not touched during
    it is removed from `collectors`. Must be called with `_lock` held.
    """
    now = time.monotonic()
    state = _cycle_state.setdefault(group, {"cycle_start": now, "last_call": now, "seen": {}})
    if now - state["last_call"] > _CYCLE_GAP_SECONDS:
        cycle_start = state["cycle_start"]
        stale = [lbl for lbl, ts in state["seen"].items() if ts < cycle_start]
        for lbl in stale:
            _remove_labels(collectors, lbl)
            del state["seen"][lbl]
        state["cycle_start"] = now
    state["last_call"] = now
    state["seen"][label_tuple] = now


# ---------------------------------------------------------------------------
# Update functions — called from scheduler/scanner after each collection
# ---------------------------------------------------------------------------

def update_host_metrics(host_id, host_name, host_type, status):
    """Update host metrics from Proxmox node status dict."""
    labels = [str(host_id), host_name, host_type]
    with _lock:
        try:
            _prune_cycle("host", tuple(labels), _HOST_COLLECTORS)

            cpu = status.get("cpu")
            if cpu is not None:
                HOST_CPU.labels(*labels).set(round(cpu * 100, 2))

            mem_used = status.get("memory", {}).get("used")
            mem_total = status.get("memory", {}).get("total")
            if mem_used is not None:
                HOST_MEM_USED.labels(*labels).set(mem_used)
            if mem_total is not None:
                HOST_MEM_TOTAL.labels(*labels).set(mem_total)

            rootfs = status.get("rootfs", {})
            if rootfs.get("total"):
                pct = round(rootfs["used"] / rootfs["total"] * 100, 2)
                HOST_ROOTFS.labels(*labels).set(pct)

            uptime = status.get("uptime")
            if uptime is not None:
                HOST_UPTIME.labels(*labels).set(uptime)
        except Exception:
            logger.debug("Failed to update host metrics for %s", host_name, exc_info=True)


def update_guest_metrics(guest_id, guest_name, guest_type, host_name, vmid, status):
    """Update guest metrics from Proxmox guest status or RRD data."""
    labels = [str(guest_id), guest_name, guest_type, host_name, str(vmid)]
    with _lock:
        try:
            _prune_cycle("guest", tuple(labels), _GUEST_COLLECTORS)

            cpu = status.get("cpu")
            maxcpu = status.get("maxcpu", 1) or 1
            if cpu is not None:
                GUEST_CPU.labels(*labels).set(round(cpu / maxcpu * 100, 2))

            mem = status.get("mem")
            maxmem = status.get("maxmem")
            if mem is not None:
                GUEST_MEM_USED.labels(*labels).set(mem)
            if maxmem is not None:
                GUEST_MEM_TOTAL.labels(*labels).set(maxmem)

            netin = status.get("netin")
            netout = status.get("netout")
            if netin is not None:
                GUEST_NET_IN.labels(*labels).set(netin)
            if netout is not None:
                GUEST_NET_OUT.labels(*labels).set(netout)

            power = status.get("status", "unknown")
            GUEST_POWER.labels(*labels).set(1 if power == "running" else 0)
        except Exception:
            logger.debug("Failed to update guest metrics for %s", guest_name, exc_info=True)


def update_service_health(service_id, service_name, guest_name, unit_name, status, memory_bytes=None):
    """Update service health gauge from health check results."""
    labels = [str(service_id), service_name, guest_name, unit_name]
    with _lock:
        try:
            _prune_cycle("service", tuple(labels), _SERVICE_COLLECTORS)

            running = 1 if status in ("running", "active") else 0
            SVC_UP.labels(*labels).set(running)
            if memory_bytes is not None:
                SVC_MEMORY.labels(*labels).set(memory_bytes)
        except Exception:
            logger.debug("Failed to update service health for %s", service_name, exc_info=True)


def update_pg_metrics(service_id, guest_name, data):
    """Update PostgreSQL metrics from stats dict."""
    labels = [str(service_id), guest_name]
    with _lock:
        try:
            if data.get("total_connections") is not None:
                PG_CONNECTIONS.labels(*labels).set(_to_num(data["total_connections"]))
            if data.get("active_queries") is not None:
                PG_CONNECTIONS_ACTIVE.labels(*labels).set(_to_num(data["active_queries"]))
            if data.get("cache_hit_ratio") is not None:
                ratio = str(data["cache_hit_ratio"]).rstrip("%")
                PG_CACHE_HIT.labels(*labels).set(_to_num(ratio))
            if data.get("total_commits") is not None:
                PG_COMMITS.labels(*labels).set(_to_num(data["total_commits"]))
            if data.get("total_rollbacks") is not None:
                PG_ROLLBACKS.labels(*labels).set(_to_num(data["total_rollbacks"]))
            if data.get("lock_waits") is not None:
                PG_LOCK_WAITS.labels(*labels).set(_to_num(data["lock_waits"]))
        except Exception:
            logger.debug("Failed to update PG metrics for service %s", service_id, exc_info=True)


def update_redis_metrics(service_id, guest_name, data):
    """Update Redis metrics from stats dict."""
    labels = [str(service_id), guest_name]
    with _lock:
        try:
            if data.get("used_memory") is not None:
                REDIS_MEM.labels(*labels).set(_to_num(data["used_memory"]))
            if data.get("connected_clients") is not None:
                REDIS_CLIENTS.labels(*labels).set(_to_num(data["connected_clients"]))
            if data.get("ops_per_sec") is not None:
                REDIS_OPS.labels(*labels).set(_to_num(data["ops_per_sec"]))
            if data.get("hit_ratio") is not None:
                ratio = str(data["hit_ratio"]).rstrip("%")
                REDIS_HIT_RATIO.labels(*labels).set(_to_num(ratio))
            if data.get("evicted_keys") is not None:
                REDIS_EVICTED.labels(*labels).set(_to_num(data["evicted_keys"]))
        except Exception:
            logger.debug("Failed to update Redis metrics for service %s", service_id, exc_info=True)


def update_es_metrics(service_id, guest_name, data):
    """Update Elasticsearch metrics from stats dict."""
    labels = [str(service_id), guest_name]
    with _lock:
        try:
            health_map = {"green": 2, "yellow": 1, "red": 0}
            health = data.get("cluster_health", "")
            if health in health_map:
                ES_HEALTH.labels(*labels).set(health_map[health])
            if data.get("doc_count") is not None:
                ES_DOC_COUNT.labels(*labels).set(_to_num(data["doc_count"]))
            if data.get("store_size_bytes") is not None:
                ES_STORE_SIZE.labels(*labels).set(_to_num(data["store_size_bytes"]))
            if data.get("jvm_heap_used") is not None:
                ES_JVM_HEAP_USED.labels(*labels).set(_to_num(data["jvm_heap_used"]))
            if data.get("jvm_heap_max") is not None:
                ES_JVM_HEAP_MAX.labels(*labels).set(_to_num(data["jvm_heap_max"]))
            if data.get("cpu_percent") is not None:
                ES_CPU.labels(*labels).set(_to_num(data["cpu_percent"]))
        except Exception:
            logger.debug("Failed to update ES metrics for service %s", service_id, exc_info=True)


def update_jitsi_metrics(service_id, guest_name, data):
    """Update Jitsi Videobridge metrics from stats dict."""
    labels = [str(service_id), guest_name]
    with _lock:
        try:
            if data.get("conferences") is not None:
                JITSI_CONFERENCES.labels(*labels).set(_to_num(data["conferences"]))
            if data.get("participants") is not None:
                JITSI_PARTICIPANTS.labels(*labels).set(_to_num(data["participants"]))
            if data.get("stress_level") is not None:
                JITSI_STRESS.labels(*labels).set(_to_num(data["stress_level"]))
            if data.get("bit_rate_download") is not None:
                JITSI_BITRATE_DL.labels(*labels).set(_to_num(data["bit_rate_download"]))
        except Exception:
            logger.debug("Failed to update Jitsi metrics for service %s", service_id, exc_info=True)


def update_prometheus_metrics(service_id, guest_name, data):
    """Update Prometheus server metrics from stats dict."""
    labels = [str(service_id), guest_name]
    with _lock:
        try:
            if data.get("targets_up") is not None:
                PROM_TARGETS_UP.labels(*labels).set(_to_num(data["targets_up"]))
            if data.get("targets_down") is not None:
                PROM_TARGETS_DOWN.labels(*labels).set(_to_num(data["targets_down"]))
            if data.get("storage_bytes") is not None:
                PROM_STORAGE.labels(*labels).set(_to_num(data["storage_bytes"]))
            if data.get("head_series") is not None:
                PROM_HEAD_SERIES.labels(*labels).set(_to_num(data["head_series"]))
        except Exception:
            logger.debug("Failed to update Prometheus metrics for service %s", service_id, exc_info=True)


def update_unifi_metrics(site_name, device_count=None, client_count=None):
    """Update UniFi aggregate metrics."""
    with _lock:
        try:
            if device_count is not None:
                UNIFI_DEVICES.labels(site_name).set(device_count)
            if client_count is not None:
                UNIFI_CLIENTS.labels(site_name).set(client_count)
        except Exception:
            logger.debug("Failed to update UniFi metrics", exc_info=True)


def update_unifi_device_metrics(site_name, devices):
    """Update per-device and per-radio UniFi metrics.

    `devices` is the full current device list for `site_name` on every call, so
    any device/radio label combination previously exported for this site but not
    present this time is removed (deleted/renamed devices stop being exported).
    """
    with _lock:
        try:
            new_device_labels = set()
            new_radio_labels = set()

            for d in devices:
                labels = (site_name, d.get("mac", ""), d.get("name", ""), d.get("type", ""))
                new_device_labels.add(labels)
                cpu = d.get("cpu")
                if cpu is not None:
                    UNIFI_DEV_CPU.labels(*labels).set(cpu)
                mem = d.get("mem")
                if mem is not None:
                    UNIFI_DEV_MEM.labels(*labels).set(mem)
                uptime = d.get("uptime")
                if uptime:
                    UNIFI_DEV_UPTIME.labels(*labels).set(uptime)
                temp = d.get("temperature")
                if temp is not None:
                    UNIFI_DEV_TEMP.labels(*labels).set(temp)
                load1 = d.get("loadavg_1")
                if load1 is not None:
                    UNIFI_DEV_LOAD1.labels(*labels).set(load1)
                num_sta = d.get("num_sta")
                if num_sta is not None:
                    UNIFI_DEV_CLIENTS.labels(*labels).set(num_sta)

                uplink = d.get("uplink", {})
                if uplink.get("tx_bytes"):
                    UNIFI_DEV_TX.labels(*labels).set(uplink["tx_bytes"])
                if uplink.get("rx_bytes"):
                    UNIFI_DEV_RX.labels(*labels).set(uplink["rx_bytes"])
                if uplink.get("speed"):
                    UNIFI_DEV_UPLINK_SPEED.labels(*labels).set(uplink["speed"])

                # Per-radio metrics
                for r in d.get("radio_table", []):
                    radio_name = r.get("name") or r.get("radio", "unknown")
                    rlabels = (site_name, d.get("mac", ""), d.get("name", ""), radio_name)
                    new_radio_labels.add(rlabels)
                    if r.get("channel"):
                        UNIFI_RADIO_CHANNEL.labels(*rlabels).set(r["channel"])
                    if r.get("cu_total") is not None:
                        UNIFI_RADIO_CU.labels(*rlabels).set(r["cu_total"])
                    if r.get("num_sta") is not None:
                        UNIFI_RADIO_CLIENTS.labels(*rlabels).set(r["num_sta"])
                    if r.get("tx_power"):
                        UNIFI_RADIO_TX_POWER.labels(*rlabels).set(r["tx_power"])

            stale_devices = _unifi_device_labels.get(site_name, set()) - new_device_labels
            for lbl in stale_devices:
                _remove_labels(_UNIFI_DEV_COLLECTORS, lbl)
            _unifi_device_labels[site_name] = new_device_labels

            stale_radios = _unifi_radio_labels.get(site_name, set()) - new_radio_labels
            for lbl in stale_radios:
                _remove_labels(_UNIFI_RADIO_COLLECTORS, lbl)
            _unifi_radio_labels[site_name] = new_radio_labels
        except Exception:
            logger.debug("Failed to update UniFi device metrics", exc_info=True)


def update_unifi_health_metrics(site_name, health_data):
    """Update UniFi site health and WAN metrics.

    `health_data` is the full current subsystem list for `site_name` on every call,
    so subsystems (and WAN metrics, when the "wan" subsystem disappears) that were
    previously exported but are no longer present are removed.
    """
    _HEALTH_MAP = {"ok": 1, "warning": 2, "error": 3}
    with _lock:
        try:
            new_health_labels = set()
            wan_present = False

            for subsystem in health_data:
                name = subsystem.get("subsystem", "")
                if not name:
                    continue
                labels = (site_name, name)
                new_health_labels.add(labels)
                status = subsystem.get("status", "unknown")
                UNIFI_HEALTH_STATUS.labels(*labels).set(_HEALTH_MAP.get(status, 0))

                # WAN-specific metrics
                if name == "wan":
                    wan_present = True
                    latency = subsystem.get("latency")
                    if latency is not None:
                        UNIFI_WAN_LATENCY.labels(site_name).set(_to_num(latency))
                    tx_rate = subsystem.get("tx_bytes-r")
                    if tx_rate is not None:
                        UNIFI_WAN_TX_RATE.labels(site_name).set(_to_num(tx_rate))
                    rx_rate = subsystem.get("rx_bytes-r")
                    if rx_rate is not None:
                        UNIFI_WAN_RX_RATE.labels(site_name).set(_to_num(rx_rate))
                    wan_uptime = subsystem.get("uptime")
                    if wan_uptime is not None:
                        UNIFI_WAN_UPTIME.labels(site_name).set(_to_num(wan_uptime))
                    speedtest_dl = subsystem.get("speedtest_lastrun_download")
                    if speedtest_dl is not None:
                        UNIFI_SPEEDTEST_DL.labels(site_name).set(_to_num(speedtest_dl))
                    speedtest_ul = subsystem.get("speedtest_lastrun_upload")
                    if speedtest_ul is not None:
                        UNIFI_SPEEDTEST_UL.labels(site_name).set(_to_num(speedtest_ul))

            stale_health = _unifi_health_labels.get(site_name, set()) - new_health_labels
            for lbl in stale_health:
                _remove_labels([UNIFI_HEALTH_STATUS], lbl)
            _unifi_health_labels[site_name] = new_health_labels

            if _unifi_wan_present.get(site_name, False) and not wan_present:
                _remove_labels(_UNIFI_WAN_COLLECTORS, (site_name,))
            _unifi_wan_present[site_name] = wan_present
        except Exception:
            logger.debug("Failed to update UniFi health metrics", exc_info=True)


def update_apt_metrics(guest_id, guest_name, pending, security, reboot_required):
    """Update APT update metrics for a guest."""
    labels = [str(guest_id), guest_name]
    with _lock:
        try:
            _prune_cycle("apt", tuple(labels), _APT_COLLECTORS)

            APT_PENDING.labels(*labels).set(pending)
            APT_SECURITY.labels(*labels).set(security)
            APT_REBOOT.labels(*labels).set(1 if reboot_required else 0)
        except Exception:
            logger.debug("Failed to update APT metrics for guest %s", guest_name, exc_info=True)


def update_app_version_info(app_name, current_version="", latest_version="", update_available=False):
    """Update application version info metrics."""
    with _lock:
        try:
            APP_UPDATE.labels(app_name).set(1 if update_available else 0)
            APP_INFO.labels(app_name).info({
                "current_version": current_version,
                "latest_version": latest_version,
            })
        except Exception:
            logger.debug("Failed to update app version info for %s", app_name, exc_info=True)


def get_metrics():
    """Generate the Prometheus text exposition format for the custom registry."""
    return generate_latest(registry)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _to_num(val):
    """Safely convert a value to a number, returning 0 on failure."""
    if val is None:
        return 0
    try:
        return float(val)
    except (TypeError, ValueError):
        return 0
