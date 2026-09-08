import json
import logging
import queue
import re
import shlex
import threading
from datetime import datetime, timedelta, timezone

from flask import Blueprint, Response, flash, jsonify, redirect, render_template, request, stream_with_context, url_for
from flask_login import current_user, login_required
from sqlalchemy import func

from auth.audit import log_action
from core.scanner import (
    check_service_statuses,
    get_service_logs,
    get_service_stats,
    lt_install_package,
    lt_list_available,
    lt_list_installed,
    lt_update_all_packages,
    lt_update_packages_stream,
    service_action,
    sidekiq_clear_dead,
    sidekiq_clear_retry,
    sidekiq_delete_job,
    sidekiq_list_jobs,
    sidekiq_retry_dead,
    sidekiq_retry_job,
    sidekiq_retry_retry,
)
from models import AuditLog, Guest, GuestService, ServiceMetricSnapshot, Tag, db

logger = logging.getLogger(__name__)

# Allowlist for PostgreSQL database names: letters, digits, underscores only (max 63 chars).
# Prevents command injection in shell commands that embed the database name.
_PG_DB_NAME_RE = re.compile(r'^[A-Za-z0-9_]{1,63}$')

bp = Blueprint("services", __name__)


@bp.before_request
@login_required
def _require_login():
    if not current_user.can_view_services:
        flash("You don't have permission to view services.", "error")
        return redirect(url_for("dashboard.index"))


@bp.route("/")
def index():
    service_filter = request.args.get("service", "")
    query = GuestService.query.join(Guest).filter(Guest.enabled == True)

    # Filter by user's tag-based access (non-admin users only see services
    # on guests they have tag access to)
    if not current_user.is_admin:
        user_tag_ids = [t.id for t in current_user.allowed_tags]
        if user_tag_ids:
            query = query.filter(Guest.tags.any(Tag.id.in_(user_tag_ids)))
        else:
            query = query.filter(False)  # no tags = no access

    if service_filter:
        query = query.filter(GuestService.service_name == service_filter)
    services = query.order_by(Guest.name, GuestService.service_name).all()

    service_types = sorted(set(s.service_name for s in GuestService.query.all()))
    return render_template("services.html", services=services,
                           service_types=service_types, current_filter=service_filter)


@bp.route("/<int:service_id>/<action>", methods=["POST"])
def control(service_id, action):
    if not current_user.can_edit_services:
        flash("You don't have permission to control services.", "error")
        return redirect(url_for("services.index"))
    if action not in ("start", "stop", "restart"):
        flash("Invalid action.", "error")
        return redirect(url_for("services.index"))

    svc = GuestService.query.get_or_404(service_id)
    guest = svc.guest

    ok, msg = service_action(guest, svc, action)
    if ok:
        log_action("service_control", "guest", resource_id=guest.id, resource_name=guest.name,
                   details={"service": svc.service_name, "action": action})
        db.session.commit()
        flash(f"{action.capitalize()} sent for {svc.service_name} on {guest.name}.", "success")
    else:
        flash(f"Failed to {action} {svc.service_name} on {guest.name}: {msg}", "error")

    referrer = request.referrer
    if referrer and f"/guests/{guest.id}" in referrer:
        from urllib.parse import urlparse
        parsed = urlparse(referrer)
        if not parsed.netloc or parsed.netloc == request.host:
            return redirect(url_for("guests.detail", guest_id=guest.id))
    return redirect(url_for("services.index"))


@bp.route("/<int:service_id>/logs", methods=["POST"])
def logs(service_id):
    svc = GuestService.query.get_or_404(service_id)
    guest = svc.guest
    log_text = get_service_logs(guest, svc)
    return jsonify({"logs": log_text, "service": svc.service_name, "guest": guest.name})


@bp.route("/refresh", methods=["POST"])
def refresh_all():
    if not current_user.can_edit_services:
        flash("You don't have permission to refresh service statuses.", "error")
        return redirect(url_for("services.index"))
    guests = Guest.query.filter(Guest.enabled == True, Guest.services.any()).all()
    checked = 0
    for guest in guests:
        try:
            check_service_statuses(guest)
            checked += 1
        except Exception as e:
            logger.warning(f"Service status check failed for {guest.name}: {e}")
    flash(f"Service statuses refreshed for {checked} guest(s).", "success")

    referrer = request.referrer
    if referrer and "/guests/" in referrer:
        from urllib.parse import urlparse
        parsed = urlparse(referrer)
        # Only redirect to same-host paths to prevent open redirect
        if not parsed.netloc or parsed.netloc == request.host:
            return redirect(parsed.path)
    return redirect(url_for("services.index"))


@bp.route("/<int:guest_id>/assign", methods=["POST"])
def assign(guest_id):
    if not current_user.can_edit_services:
        flash("You don't have permission to assign services.", "error")
        return redirect(url_for("guests.detail", guest_id=guest_id))
    guest = Guest.query.get_or_404(guest_id)
    service_key = request.form.get("service_key", "").strip()

    if service_key not in GuestService.KNOWN_SERVICES:
        flash("Unknown service type.", "error")
        return redirect(url_for("guests.detail", guest_id=guest.id))

    existing = GuestService.query.filter_by(guest_id=guest.id, service_name=service_key).first()
    if existing:
        flash(f"{existing.service_name} is already assigned to {guest.name}.", "warning")
        return redirect(url_for("guests.detail", guest_id=guest.id))

    display_name, unit_name, default_port = GuestService.KNOWN_SERVICES[service_key]
    svc = GuestService(
        guest_id=guest.id,
        service_name=service_key,
        unit_name=unit_name,
        port=default_port,
        auto_detected=False,
    )
    db.session.add(svc)
    log_action("service_assign", "guest", resource_id=guest.id, resource_name=guest.name,
               details={"service": service_key})
    db.session.commit()

    flash(f"{display_name} assigned to {guest.name}.", "success")
    return redirect(url_for("guests.detail", guest_id=guest.id))


@bp.route("/<int:service_id>/remove", methods=["POST"])
def remove(service_id):
    if not current_user.can_edit_services:
        flash("You don't have permission to remove services.", "error")
        return redirect(url_for("services.index"))
    svc = GuestService.query.get_or_404(service_id)
    guest_id = svc.guest_id
    name = svc.service_name
    log_action("service_remove", "guest", resource_id=guest_id, resource_name=svc.guest.name,
               details={"service": name})
    db.session.delete(svc)
    db.session.commit()
    flash(f"Service '{name}' removed.", "warning")

    referrer = request.referrer
    if referrer and f"/guests/{guest_id}" in referrer:
        from urllib.parse import urlparse
        parsed = urlparse(referrer)
        if not parsed.netloc or parsed.netloc == request.host:
            return redirect(url_for("guests.detail", guest_id=guest_id))
    return redirect(url_for("services.index"))


@bp.route("/<int:service_id>/detail")
def detail(service_id):
    svc = GuestService.query.get_or_404(service_id)
    guest = svc.guest
    stats = get_service_stats(guest, svc)
    log_text = get_service_logs(guest, svc, lines=30)
    cutoff = datetime.now(timezone.utc) - timedelta(days=7)
    recent_logs = (AuditLog.query
                   .filter(AuditLog.resource_type == "guest",
                           AuditLog.resource_id == guest.id,
                           AuditLog.timestamp >= cutoff,
                           func.json_extract(AuditLog.details, "$.service") == svc.service_name)
                   .order_by(AuditLog.timestamp.desc())
                   .limit(25).all())
    return render_template("service_detail.html", service=svc, guest=guest, stats=stats, logs=log_text,
                           recent_logs=recent_logs)


@bp.route("/<int:service_id>/sidekiq/clear-dead", methods=["POST"])
def sidekiq_clear_dead_queue(service_id):
    if not current_user.can_edit_services:
        return jsonify({"ok": False, "message": "Permission denied."}), 403
    svc = GuestService.query.get_or_404(service_id)
    if svc.service_name != "sidekiq":
        return jsonify({"ok": False, "message": "Not a Sidekiq service"}), 400
    guest = svc.guest
    ok, msg = sidekiq_clear_dead(guest, svc)
    if ok:
        log_action("sidekiq_clear_dead", "guest", resource_id=guest.id, resource_name=guest.name,
                   details={"service": svc.service_name, "result": msg})
        db.session.commit()
    return jsonify({"ok": ok, "message": msg})


@bp.route("/<int:service_id>/sidekiq/retry-dead", methods=["POST"])
def sidekiq_retry_dead_queue(service_id):
    if not current_user.can_edit_services:
        return jsonify({"ok": False, "message": "Permission denied."}), 403
    svc = GuestService.query.get_or_404(service_id)
    if svc.service_name != "sidekiq":
        return jsonify({"ok": False, "message": "Not a Sidekiq service"}), 400
    guest = svc.guest
    ok, msg = sidekiq_retry_dead(guest, svc)
    if ok:
        log_action("sidekiq_retry_dead", "guest", resource_id=guest.id, resource_name=guest.name,
                   details={"service": svc.service_name, "result": msg})
        db.session.commit()
    return jsonify({"ok": ok, "message": msg})


@bp.route("/<int:service_id>/sidekiq/clear-retry", methods=["POST"])
def sidekiq_clear_retry_queue(service_id):
    if not current_user.can_edit_services:
        return jsonify({"ok": False, "message": "Permission denied."}), 403
    svc = GuestService.query.get_or_404(service_id)
    if svc.service_name != "sidekiq":
        return jsonify({"ok": False, "message": "Not a Sidekiq service"}), 400
    guest = svc.guest
    ok, msg = sidekiq_clear_retry(guest, svc)
    if ok:
        log_action("sidekiq_clear_retry", "guest", resource_id=guest.id, resource_name=guest.name,
                   details={"service": svc.service_name, "result": msg})
        db.session.commit()
    return jsonify({"ok": ok, "message": msg})


@bp.route("/<int:service_id>/sidekiq/retry-retry", methods=["POST"])
def sidekiq_retry_retry_queue(service_id):
    if not current_user.can_edit_services:
        return jsonify({"ok": False, "message": "Permission denied."}), 403
    svc = GuestService.query.get_or_404(service_id)
    if svc.service_name != "sidekiq":
        return jsonify({"ok": False, "message": "Not a Sidekiq service"}), 400
    guest = svc.guest
    ok, msg = sidekiq_retry_retry(guest, svc)
    if ok:
        log_action("sidekiq_retry_retry", "guest", resource_id=guest.id, resource_name=guest.name,
                   details={"service": svc.service_name, "result": msg})
        db.session.commit()
    return jsonify({"ok": ok, "message": msg})


@bp.route("/<int:service_id>/sidekiq/<queue_type>/jobs")
def sidekiq_jobs(service_id, queue_type):
    if queue_type not in ("dead", "retry", "schedule"):
        return jsonify({"error": "Invalid queue type"}), 400
    svc = GuestService.query.get_or_404(service_id)
    if svc.service_name != "sidekiq":
        return jsonify({"error": "Not a Sidekiq service"}), 400
    guest = svc.guest
    try:
        offset = max(0, int(request.args.get("offset", 0)))
        limit = min(100, max(1, int(request.args.get("limit", 25))))
    except (ValueError, TypeError):
        offset, limit = 0, 25
    jobs, total, err = sidekiq_list_jobs(guest, svc, queue_type, offset=offset, limit=limit)
    if err:
        return jsonify({"error": err}), 500
    return jsonify({"jobs": jobs, "total": total, "offset": offset, "limit": limit})


@bp.route("/<int:service_id>/sidekiq/<queue_type>/jobs/<jid>/delete", methods=["POST"])
def sidekiq_delete_job_route(service_id, queue_type, jid):
    if not current_user.can_edit_services:
        return jsonify({"ok": False, "message": "Permission denied."}), 403
    if queue_type not in ("dead", "retry", "schedule"):
        return jsonify({"ok": False, "message": "Invalid queue type"}), 400
    svc = GuestService.query.get_or_404(service_id)
    if svc.service_name != "sidekiq":
        return jsonify({"ok": False, "message": "Not a Sidekiq service"}), 400
    guest = svc.guest
    ok, msg = sidekiq_delete_job(guest, svc, queue_type, jid)
    if ok:
        log_action("sidekiq_delete_job", "guest", resource_id=guest.id, resource_name=guest.name,
                   details={"service": svc.service_name, "queue_type": queue_type, "jid": jid})
        db.session.commit()
    return jsonify({"ok": ok, "message": msg})


@bp.route("/<int:service_id>/sidekiq/<queue_type>/jobs/<jid>/retry", methods=["POST"])
def sidekiq_retry_job_route(service_id, queue_type, jid):
    if not current_user.can_edit_services:
        return jsonify({"ok": False, "message": "Permission denied."}), 403
    if queue_type not in ("dead", "retry", "schedule"):
        return jsonify({"ok": False, "message": "Invalid queue type"}), 400
    svc = GuestService.query.get_or_404(service_id)
    if svc.service_name != "sidekiq":
        return jsonify({"ok": False, "message": "Not a Sidekiq service"}), 400
    guest = svc.guest
    ok, msg = sidekiq_retry_job(guest, svc, queue_type, jid)
    if ok:
        log_action("sidekiq_retry_job", "guest", resource_id=guest.id, resource_name=guest.name,
                   details={"service": svc.service_name, "queue_type": queue_type, "jid": jid})
        db.session.commit()
    return jsonify({"ok": ok, "message": msg})


@bp.route("/<int:service_id>/pg/kill-query/<int:pid>", methods=["POST"])
def pg_kill_query(service_id, pid):
    if not current_user.can_edit_services:
        return jsonify({"ok": False, "message": "Permission denied."}), 403
    svc = GuestService.query.get_or_404(service_id)
    if svc.service_name != "postgresql":
        return jsonify({"ok": False, "message": "Not a PostgreSQL service"}), 400
    guest = svc.guest
    from core.scanner import _execute_command
    stdout, error = _execute_command(
        guest,
        f"sudo -u postgres psql -t -A -c \"SELECT pg_terminate_backend({pid})\" 2>&1",
        timeout=10,
        sudo=True,
    )
    if error:
        return jsonify({"ok": False, "message": f"SSH error: {error[:200]}"})
    result = (stdout or "").strip()
    if result == "t":
        log_action("pg_kill_query", "guest", resource_id=guest.id, resource_name=guest.name,
                   details={"service": svc.service_name, "pid": pid})
        db.session.commit()
        return jsonify({"ok": True, "message": f"Backend {pid} terminated."})
    if result == "f":
        return jsonify({"ok": False, "message": f"Backend {pid} not found (already finished?)."})
    return jsonify({"ok": False, "message": f"Unexpected result: {(result or error or '')[:100]}"})


def _safe_int(v):
    try:
        return int(v) if v is not None else None
    except (TypeError, ValueError):
        return None


def _safe_float(v):
    try:
        return float(v) if v is not None else None
    except (TypeError, ValueError):
        return None


def _analyze_pg_plan(plan_json: list) -> list[dict]:
    """Walk a PostgreSQL EXPLAIN (FORMAT JSON) plan tree and apply pgplan-style performance rules.

    Returns a list of findings: [{"severity": str, "rule": str, "message": str, "recommendation": str}, ...]
    Severity values: "critical" | "warning" | "info"
    """
    _JOIN_TYPES = {"Hash Join", "Merge Join", "Nested Loop"}

    def _walk_node(node: dict, findings: list, seen: set, in_join: bool = False) -> None:
        if not isinstance(node, dict):
            return
        node_type = node.get("Node Type", "")
        relation = node.get("Relation Name", "")
        actual_rows = node.get("Actual Rows", 0) or 0
        actual_loops = node.get("Actual Loops", 1) or 1
        plan_rows = node.get("Plan Rows", 0) or 0
        plan_width = node.get("Plan Width", 0) or 0

        # seq_scan_in_join: Seq Scan inside a join on a large table
        if node_type == "Seq Scan" and in_join and actual_rows > 10_000:
            key = ("seq_scan_in_join", relation)
            if key not in seen:
                seen.add(key)
                findings.append({
                    "severity": "critical",
                    "rule": "seq_scan_in_join",
                    "message": f"Sequential scan on \"{relation}\" ({actual_rows:,} rows) inside a join.",
                    "recommendation": "Add an index on the join column(s) used against this table.",
                })

        # sort_spill_to_disk: Sort node spilling to disk
        if node_type == "Sort":
            sort_method = node.get("Sort Method", "")
            if "disk" in sort_method.lower():
                key = ("sort_spill_to_disk", relation)
                if key not in seen:
                    seen.add(key)
                    space_kb = node.get("Sort Space Used", 0) or 0
                    findings.append({
                        "severity": "critical",
                        "rule": "sort_spill_to_disk",
                        "message": f"Sort spilled to disk ({sort_method}, {space_kb:,} kB used).",
                        "recommendation": "Increase work_mem to allow in-memory sorts for this query.",
                    })

        # hash_spill_to_disk: Hash node using multiple batches
        if node_type == "Hash":
            hash_batches = node.get("Hash Batches", 1) or 1
            if hash_batches > 1:
                key = ("hash_spill_to_disk", relation)
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "severity": "warning",
                        "rule": "hash_spill_to_disk",
                        "message": f"Hash join used {hash_batches} batches — spilled to disk.",
                        "recommendation": "Increase work_mem to allow the hash table to fit in memory.",
                    })

        # temp_blocks_usage: Any node reading/writing temp blocks
        temp_read = node.get("Temp Read Blocks", 0) or 0
        temp_written = node.get("Temp Written Blocks", 0) or 0
        if temp_read > 0 or temp_written > 0:
            key = ("temp_blocks_usage", node_type)
            if key not in seen:
                seen.add(key)
                findings.append({
                    "severity": "warning",
                    "rule": "temp_blocks_usage",
                    "message": f"Temporary I/O detected: {temp_read:,} blocks read, {temp_written:,} blocks written in {node_type}.",
                    "recommendation": "Increase work_mem or restructure the query to reduce temporary disk usage.",
                })

        # nested_loop_high_loops: Nested loop with many iterations and significant time
        if node_type == "Nested Loop":
            total_time = (node.get("Actual Total Time", 0) or 0) * actual_loops
            if actual_loops > 1000 and total_time > 5000:
                key = ("nested_loop_high_loops", "")
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "severity": "warning",
                        "rule": "nested_loop_high_loops",
                        "message": f"Nested loop executed {actual_loops:,} times with {total_time:,.0f} ms total time.",
                        "recommendation": "Consider rewriting as a hash join or merge join, or add an index on the inner table.",
                    })

        # correlated_subplan_loops: Subquery scanned many times
        if "Subquery" in node_type and actual_loops > 100:
            key = ("correlated_subplan_loops", relation)
            if key not in seen:
                seen.add(key)
                findings.append({
                    "severity": "warning",
                    "rule": "correlated_subplan_loops",
                    "message": f"Subquery executed {actual_loops:,} times — likely a correlated subquery.",
                    "recommendation": "Rewrite as a JOIN or use a CTE to avoid repeated subquery execution.",
                })

        # bitmap_heap_recheck: Bitmap Heap Scan with all lossy pages (work_mem pressure)
        if node_type == "Bitmap Heap Scan":
            lossy = node.get("Lossy Heap Blocks", 0) or 0
            exact = node.get("Exact Heap Blocks", 0) or 0
            if lossy > 0 and exact == 0:
                key = ("bitmap_heap_recheck", relation)
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "severity": "warning",
                        "rule": "bitmap_heap_recheck",
                        "message": f"Bitmap heap scan on \"{relation}\" used {lossy:,} lossy pages — all rows rechecked.",
                        "recommendation": "Increase work_mem so the bitmap fits in memory and avoids lossy storage.",
                    })

        # index_low_selectivity: Index scan removing more rows than it returns
        if node_type.endswith("Index Scan") or node_type == "Index Only Scan":
            rows_removed = node.get("Rows Removed by Filter", 0) or 0
            if rows_removed > actual_rows and actual_rows > 0:
                fraction = rows_removed / (rows_removed + actual_rows)
                if fraction > 0.5:
                    key = ("index_low_selectivity", relation)
                    if key not in seen:
                        seen.add(key)
                        findings.append({
                            "severity": "info",
                            "rule": "index_low_selectivity",
                            "message": (
                                f"Index scan on \"{relation}\" removed {rows_removed:,} rows, "
                                f"returning only {actual_rows:,} ({fraction:.0%} filtered out)."
                            ),
                            "recommendation": "Consider a partial or composite index to improve selectivity.",
                        })

        # worker_mismatch: Fewer parallel workers launched than planned
        workers_planned = node.get("Workers Planned", 0) or 0
        workers_launched = node.get("Workers Launched")
        if workers_planned > 0 and workers_launched is not None and workers_launched < workers_planned:
            key = ("worker_mismatch", node_type)
            if key not in seen:
                seen.add(key)
                findings.append({
                    "severity": "warning",
                    "rule": "worker_mismatch",
                    "message": f"Only {workers_launched} of {workers_planned} planned parallel workers launched.",
                    "recommendation": "Check max_worker_processes, max_parallel_workers, and system CPU availability.",
                })

        # wide_rows: Large rows being processed in quantity
        if plan_width > 2000 and actual_rows > 1000:
            key = ("wide_rows", relation or node_type)
            if key not in seen:
                seen.add(key)
                findings.append({
                    "severity": "info",
                    "rule": "wide_rows",
                    "message": f"Node producing {actual_rows:,} rows of {plan_width} bytes each ({plan_rows * plan_width / 1024 / 1024:.1f} MB estimated).",
                    "recommendation": "Select only required columns to reduce row width and memory pressure.",
                })

        # Recurse into child plans; propagate in_join flag for join node children
        child_in_join = in_join or (node_type in _JOIN_TYPES)
        for child in node.get("Plans", []):
            _walk_node(child, findings, seen, in_join=child_in_join)

    try:
        if not isinstance(plan_json, list) or not plan_json:
            raise ValueError("plan_json must be a non-empty list")
        findings: list[dict] = []
        seen: set[tuple] = set()
        for top in plan_json:
            root = top.get("Plan") if isinstance(top, dict) else None
            if root:
                _walk_node(root, findings, seen, in_join=False)
        return findings
    except Exception:  # noqa: BLE001
        return [{"severity": "info", "rule": "parse_error", "message": "Could not parse plan JSON.", "recommendation": "Check that EXPLAIN (FORMAT JSON) executed successfully."}]


def _pg_guard(service_id):
    """Return (svc, guest) or raise 404. Also checks service type."""
    svc = GuestService.query.get_or_404(service_id)
    if svc.service_name != "postgresql":
        return None, None
    return svc, svc.guest


@bp.route("/<int:service_id>/pg/vacuum", methods=["POST"])
def pg_vacuum(service_id):
    if not current_user.can_edit_services:
        return jsonify({"ok": False, "message": "Permission denied."}), 403
    svc, guest = _pg_guard(service_id)
    if svc is None:
        return jsonify({"ok": False, "message": "Not a PostgreSQL service"}), 400
    data = request.get_json(silent=True) or {}
    database = (data.get("database") or "").strip()
    analyze = bool(data.get("analyze", False))
    verbose = bool(data.get("verbose", False))
    if not database:
        return jsonify({"ok": False, "message": "database is required"}), 400
    if not _PG_DB_NAME_RE.match(database):
        return jsonify({"ok": False, "message": "Invalid database name."}), 400
    from core.scanner import _execute_command
    options = ["VERBOSE"] if verbose else []
    if analyze:
        options.append("ANALYZE")
    verb = "VACUUM " + " ".join(options) if options else "VACUUM"
    stdout, error = _execute_command(
        guest,
        f"sudo -u postgres psql -d {database} -c \"{verb}\" 2>&1",
        timeout=120,
        sudo=True,
    )
    if error:
        return jsonify({"ok": False, "message": f"SSH error: {error[:300]}"})
    log_action("pg_vacuum", "guest", resource_id=guest.id, resource_name=guest.name,
               details={"service": svc.service_name, "database": database, "analyze": analyze, "verbose": verbose})
    db.session.commit()
    output = (stdout or "").strip() or f"{verb} completed."
    return jsonify({"ok": True, "message": output})


@bp.route("/<int:service_id>/pg/explain", methods=["POST"])
def pg_explain(service_id):
    if not current_user.can_edit_services:
        return jsonify({"ok": False, "message": "Permission denied."}), 403
    svc, guest = _pg_guard(service_id)
    if svc is None:
        return jsonify({"ok": False, "message": "Not a PostgreSQL service"}), 400
    data = request.get_json(silent=True) or {}
    database = (data.get("database") or "").strip()
    query = (data.get("query") or "").strip()
    if not database or not query:
        return jsonify({"ok": False, "message": "database and query are required"}), 400
    if not _PG_DB_NAME_RE.match(database):
        return jsonify({"ok": False, "message": "Invalid database name."}), 400
    import uuid

    from core.scanner import _execute_command
    tmpfile = f"/tmp/.pg_explain_{uuid.uuid4().hex[:12]}.sql"  # nosec B108 — remote SSH path, not a local temp file
    # Use shlex.quote() to safely shell-quote the SQL content; single quotes in the shell
    # prevent all metacharacter expansion (backticks, $(), semicolons, etc.).
    safe_content = shlex.quote(f"EXPLAIN {query}")
    _, write_err = _execute_command(
        guest,
        f"printf %s {safe_content} > {tmpfile}",
        timeout=10,
    )
    if write_err:
        return jsonify({"ok": False, "message": f"Could not write temp file: {write_err[:200]}"})
    stdout, error = _execute_command(
        guest,
        f"sudo -u postgres psql -d {database} -f {tmpfile} 2>&1; rm -f {tmpfile}",
        timeout=60,
        sudo=True,
    )
    if error:
        _execute_command(guest, f"rm -f {tmpfile}", timeout=5)
        return jsonify({"ok": False, "message": f"SSH error: {error[:300]}"})
    log_action("pg_explain", "guest", resource_id=guest.id, resource_name=guest.name,
               details={"service": svc.service_name, "database": database})
    db.session.commit()
    return jsonify({"ok": True, "plan": (stdout or "").strip()})


@bp.route("/<int:service_id>/pg/roles")
def pg_roles(service_id):
    svc, guest = _pg_guard(service_id)
    if svc is None:
        return jsonify({"error": "Not a PostgreSQL service"}), 400
    from core.scanner import _execute_command
    stdout, error = _execute_command(
        guest,
        "sudo -u postgres psql -t -A -c \""
        "SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolcanlogin, rolreplication, rolconnlimit "
        "FROM pg_roles ORDER BY rolname"
        "\" 2>/dev/null",
        timeout=10,
        sudo=True,
    )
    if error:
        return jsonify({"error": error[:200]}), 500
    roles = []
    for line in (stdout or "").strip().split("\n"):
        parts = line.strip().split("|")
        if len(parts) == 7:
            roles.append({
                "name": parts[0],
                "superuser": parts[1] == "t",
                "create_role": parts[2] == "t",
                "create_db": parts[3] == "t",
                "can_login": parts[4] == "t",
                "replication": parts[5] == "t",
                "conn_limit": parts[6],
            })
    return jsonify({"roles": roles})


@bp.route("/<int:service_id>/pg/settings")
def pg_settings(service_id):
    svc, guest = _pg_guard(service_id)
    if svc is None:
        return jsonify({"error": "Not a PostgreSQL service"}), 400
    from core.scanner import _execute_command
    # Fetch a curated set of important settings
    names = (
        "max_connections,shared_buffers,work_mem,maintenance_work_mem,"
        "effective_cache_size,wal_level,max_wal_size,checkpoint_completion_target,"
        "log_min_duration_statement,autovacuum,autovacuum_vacuum_scale_factor,"
        "autovacuum_analyze_scale_factor,random_page_cost,effective_io_concurrency,"
        "max_worker_processes,max_parallel_workers"
    )
    stdout, error = _execute_command(
        guest,
        f"sudo -u postgres psql -t -A -c \""  # noqa: S608 — query built from hardcoded literals only, no user input
        f"SELECT name, setting, unit, short_desc FROM pg_settings "
        f"WHERE name = ANY(ARRAY[{','.join(repr(n) for n in names.split(','))}]) "
        f"ORDER BY name"
        f"\" 2>/dev/null",
        timeout=10,
        sudo=True,
    )
    if error:
        return jsonify({"error": error[:200]}), 500
    settings = []
    for line in (stdout or "").strip().split("\n"):
        parts = line.strip().split("|", 3)
        if len(parts) == 4:
            settings.append({
                "name": parts[0],
                "setting": parts[1],
                "unit": parts[2],
                "description": parts[3],
            })
    return jsonify({"settings": settings})


@bp.route("/<int:service_id>/pg/analyze-plan", methods=["POST"])
def pg_analyze_plan(service_id):
    """Run EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) on the remote host and return plan analysis findings."""
    if not current_user.can_edit_services:
        return jsonify({"ok": False, "message": "Permission denied."}), 403
    svc, guest = _pg_guard(service_id)
    if svc is None:
        return jsonify({"ok": False, "message": "Not a PostgreSQL service"}), 400
    data = request.get_json(silent=True) or {}
    database = (data.get("database") or "").strip()
    query = (data.get("query") or "").strip()
    if not database or not query:
        return jsonify({"ok": False, "message": "database and query are required"}), 400
    if not _PG_DB_NAME_RE.match(database):
        return jsonify({"ok": False, "message": "Invalid database name."}), 400

    import uuid

    from core.scanner import _execute_command

    tmpfile = f"/tmp/.pg_analyze_{uuid.uuid4().hex[:12]}.sql"  # nosec B108 — remote SSH path, not local
    safe_content = shlex.quote(f"EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) {query}")
    _, write_err = _execute_command(guest, f"printf %s {safe_content} > {tmpfile}", timeout=10)
    if write_err:
        return jsonify({"ok": False, "message": f"Could not write temp file: {write_err[:200]}"})

    stdout, error = _execute_command(
        guest,
        f"sudo -u postgres psql -d {database} -t -A -f {tmpfile} 2>&1; rm -f {tmpfile}",
        timeout=120,
        sudo=True,
    )
    if error:
        _execute_command(guest, f"rm -f {tmpfile}", timeout=5)
        return jsonify({"ok": False, "message": f"SSH error: {error[:300]}"})

    raw = (stdout or "").strip()
    try:
        plan_json = json.loads(raw)
    except (json.JSONDecodeError, TypeError, ValueError):
        return jsonify({"ok": False, "message": f"Could not parse plan JSON: {raw[:300]}"}), 400

    findings = _analyze_pg_plan(plan_json)

    query_time_ms = None
    try:
        query_time_ms = plan_json[0]["Plan"]["Actual Total Time"]
    except (IndexError, KeyError, TypeError):
        pass

    log_action(
        "pg_analyze_plan", "guest",
        resource_id=guest.id, resource_name=guest.name,
        details={
            "service": svc.service_name,
            "database": database,
            "findings_count": len(findings),
            "critical": sum(1 for f in findings if f["severity"] == "critical"),
        },
    )
    db.session.commit()
    return jsonify({"ok": True, "findings": findings, "plan_json": raw, "query_time_ms": query_time_ms})


@bp.route("/<int:service_id>/pg/metrics-history")
def pg_metrics_history(service_id):
    from models import Setting

    svc = GuestService.query.get_or_404(service_id)
    if svc.service_name != "postgresql":
        return jsonify({"error": "Not a PostgreSQL service"}), 400

    # Try Prometheus first if enabled
    timeframe = request.args.get("timeframe", "day")
    if Setting.get("prometheus_enabled", "false") == "true" and Setting.get("prometheus_url", ""):
        try:
            from clients.prometheus_query import PrometheusQueryClient, _get_exporter_target
            prom = PrometheusQueryClient()

            # Prefer postgres_exporter if installed on this guest
            pg_target = _get_exporter_target(svc.guest_id, "postgres_exporter")
            if pg_target:
                data = prom.get_pg_metrics_exporter(pg_target, timeframe)
            else:
                pg_metrics = [
                    "mstdnca_pg_connections_total",
                    "mstdnca_pg_cache_hit_ratio",
                    "mstdnca_pg_connections_active",
                    "mstdnca_pg_lock_waits",
                    "mstdnca_pg_commits_total",
                    "mstdnca_pg_rollbacks_total",
                ]
                data = prom.get_service_metrics_history(svc.id, pg_metrics, timeframe)
                # Rename keys to match the SQLite snapshot format the chart JS expects
                _pg_key_map = {
                    "pg_connections_total": "total_connections",
                    "pg_cache_hit_ratio": "cache_hit_ratio",
                    "pg_connections_active": "active_connections",
                    "pg_lock_waits": "lock_waits",
                    "pg_commits_total": "total_commits",
                    "pg_rollbacks_total": "total_rollbacks",
                }
                for snap in data.get("snapshots", []):
                    for old_key, new_key in _pg_key_map.items():
                        if old_key in snap:
                            snap[new_key] = snap.pop(old_key)

            if data and data.get("snapshots"):
                return jsonify(data)
        except Exception:
            logger.debug("Prometheus query failed for PG metrics history, falling back to SQLite")

    # Fall back to SQLite
    limit = min(int(request.args.get("limit", 144)), 288)  # default 12h at 5-min
    rows = (
        ServiceMetricSnapshot.query
        .filter_by(service_id=svc.id)
        .order_by(ServiceMetricSnapshot.captured_at.asc())
        .limit(limit)
        .all()
    )
    result = []
    for row in rows:
        try:
            d = json.loads(row.data or "{}")
        except (json.JSONDecodeError, TypeError):
            d = {}
        d["captured_at"] = row.captured_at.isoformat()
        result.append(d)
    return jsonify({"snapshots": result, "source": "sqlite"})


@bp.route("/<int:service_id>/redis/metrics-history")
def redis_metrics_history(service_id):
    from models import Setting

    svc = GuestService.query.get_or_404(service_id)
    if svc.service_name != "redis":
        return jsonify({"error": "Not a Redis service"}), 400

    timeframe = request.args.get("timeframe", "day")
    if Setting.get("prometheus_enabled", "false") == "true" and Setting.get("prometheus_url", ""):
        try:
            from clients.prometheus_query import PrometheusQueryClient, _get_exporter_target
            prom = PrometheusQueryClient()

            # Try redis_exporter first, then mstdnca_redis_* gauges
            redis_target = _get_exporter_target(svc.guest_id, "redis_exporter")
            data = None
            if redis_target:
                logger.debug("Querying redis_exporter at %s for service %s", redis_target, svc.id)
                data = prom.get_redis_metrics_exporter(redis_target, timeframe)

            if not data or not data.get("snapshots"):
                logger.debug("redis_exporter returned no data (target=%s), trying mstdnca_redis_* metrics", redis_target)
                redis_metrics = [
                    "mstdnca_redis_memory_used_bytes",
                    "mstdnca_redis_connected_clients",
                    "mstdnca_redis_ops_per_sec",
                    "mstdnca_redis_hit_ratio",
                    "mstdnca_redis_evicted_keys_total",
                ]
                data = prom.get_service_metrics_history(svc.id, redis_metrics, timeframe)
                # Rename keys to match chart-friendly names
                _redis_key_map = {
                    "redis_memory_used_bytes": "used_memory_bytes",
                    "redis_connected_clients": "connected_clients",
                    "redis_ops_per_sec": "ops_per_sec",
                    "redis_hit_ratio": "hit_ratio",
                    "redis_evicted_keys_total": "evicted_keys",
                }
                for snap in data.get("snapshots", []):
                    for old_key, new_key in _redis_key_map.items():
                        if old_key in snap:
                            snap[new_key] = snap.pop(old_key)

            if data and data.get("snapshots"):
                return jsonify(data)
        except Exception:
            logger.debug("Prometheus query failed for Redis metrics history, falling back to SQLite", exc_info=True)

    # Fall back to SQLite
    limit = min(int(request.args.get("limit", 144)), 288)
    rows = (
        ServiceMetricSnapshot.query
        .filter_by(service_id=svc.id)
        .order_by(ServiceMetricSnapshot.captured_at.asc())
        .limit(limit)
        .all()
    )
    result = []
    for row in rows:
        try:
            d = json.loads(row.data or "{}")
        except (json.JSONDecodeError, TypeError):
            d = {}
        d["captured_at"] = row.captured_at.isoformat()
        result.append(d)
    return jsonify({"snapshots": result, "source": "sqlite"})


@bp.route("/<int:service_id>/es/metrics-history")
def es_metrics_history(service_id):
    from models import Setting

    svc = GuestService.query.get_or_404(service_id)
    if svc.service_name != "elasticsearch":
        return jsonify({"error": "Not an Elasticsearch service"}), 400

    timeframe = request.args.get("timeframe", "day")
    if Setting.get("prometheus_enabled", "false") == "true" and Setting.get("prometheus_url", ""):
        try:
            from clients.prometheus_query import PrometheusQueryClient, _get_exporter_target
            prom = PrometheusQueryClient()

            # Try elasticsearch_exporter first, then mstdnca_es_* gauges
            es_target = _get_exporter_target(svc.guest_id, "elasticsearch_exporter")
            data = None
            if es_target:
                logger.debug("Querying elasticsearch_exporter at %s for service %s", es_target, svc.id)
                data = prom.get_es_metrics_exporter(es_target, timeframe)

            if not data or not data.get("snapshots"):
                logger.debug("elasticsearch_exporter returned no data (target=%s), trying mstdnca_es_* metrics", es_target)
                es_metrics = [
                    "mstdnca_es_cluster_health",
                    "mstdnca_es_doc_count",
                    "mstdnca_es_store_size_bytes",
                    "mstdnca_es_jvm_heap_used_bytes",
                    "mstdnca_es_jvm_heap_max_bytes",
                    "mstdnca_es_cpu_percent",
                ]
                data = prom.get_service_metrics_history(svc.id, es_metrics, timeframe)
                _es_key_map = {
                    "es_cluster_health": "cluster_health",
                    "es_doc_count": "doc_count",
                    "es_store_size_bytes": "store_size_bytes",
                    "es_jvm_heap_used_bytes": "jvm_heap_used_bytes",
                    "es_jvm_heap_max_bytes": "jvm_heap_max_bytes",
                    "es_cpu_percent": "cpu_percent",
                }
                for snap in data.get("snapshots", []):
                    for old_key, new_key in _es_key_map.items():
                        if old_key in snap:
                            snap[new_key] = snap.pop(old_key)

            if data and data.get("snapshots"):
                return jsonify(data)
        except Exception:
            logger.debug("Prometheus query failed for ES metrics history, falling back to SQLite", exc_info=True)

    # Fall back to SQLite
    limit = min(int(request.args.get("limit", 144)), 288)
    rows = (
        ServiceMetricSnapshot.query
        .filter_by(service_id=svc.id)
        .order_by(ServiceMetricSnapshot.captured_at.asc())
        .limit(limit)
        .all()
    )
    result = []
    for row in rows:
        try:
            d = json.loads(row.data or "{}")
        except (json.JSONDecodeError, TypeError):
            d = {}
        d["captured_at"] = row.captured_at.isoformat()
        result.append(d)
    return jsonify({"snapshots": result, "source": "sqlite"})


@bp.route("/<int:service_id>/mastodon/metrics-history")
def mastodon_metrics_history(service_id):
    from models import Setting

    svc = GuestService.query.get_or_404(service_id)
    # Accept both puma (mastodon-web) and sidekiq services
    if not any(name in svc.service_name for name in ("mastodon", "puma", "sidekiq")):
        return jsonify({"error": "Not a Mastodon service"}), 400

    timeframe = request.args.get("timeframe", "day")
    if Setting.get("prometheus_enabled", "false") == "true" and Setting.get("prometheus_url", ""):
        try:
            from clients.prometheus_query import PrometheusQueryClient, _get_exporter_target
            prom = PrometheusQueryClient()
            mastodon_target = _get_exporter_target(svc.guest_id, "mastodon")
            if mastodon_target:
                data = prom.get_mastodon_metrics(mastodon_target, timeframe)
                if data and data.get("snapshots"):
                    return jsonify(data)
        except Exception:
            logger.debug("Prometheus query failed for Mastodon metrics history")

    return jsonify({"snapshots": [], "source": "none"})


def save_service_snapshot(svc, data):
    """Persist a metric snapshot for services that support historical charts."""
    snapshot_data = None
    stype = svc.service_name

    if stype == "postgresql" and data.get("type") == "postgresql":
        snapshot_data = {
            "total_connections": _safe_int(data.get("total_connections")),
            "cache_hit_ratio": _safe_float(str(data.get("cache_hit_ratio", "")).rstrip("%")),
            "active_queries": _safe_int(data.get("active_queries")),
            "lock_waits": data.get("lock_waits", 0),
            "total_commits": _safe_int(data.get("total_commits")),
            "total_rollbacks": _safe_int(data.get("total_rollbacks")),
        }
    elif stype == "jitsi-videobridge2" and not data.get("rest_api_disabled"):
        snapshot_data = {
            "conferences": data.get("conferences", 0),
            "participants": data.get("participants", 0),
            "stress_level": data.get("stress_level", 0),
            "bit_rate_download": data.get("bit_rate_download", 0),
        }
    elif stype == "redis" and data.get("type") == "redis":
        hit_ratio_raw = data.get("hit_ratio", "N/A")
        if isinstance(hit_ratio_raw, str):
            hit_ratio_raw = hit_ratio_raw.rstrip("%")
        snapshot_data = {
            "used_memory_bytes": _safe_int(data.get("used_memory_bytes")),
            "connected_clients": _safe_int(data.get("connected_clients")),
            "ops_per_sec": _safe_int(data.get("ops_per_sec")),
            "hit_ratio": _safe_float(str(hit_ratio_raw)),
            "evicted_keys": _safe_int(data.get("evicted_keys")),
        }

    if snapshot_data is None:
        return

    try:
        snap = ServiceMetricSnapshot(
            service_id=svc.id,
            captured_at=datetime.now(timezone.utc),
            data=json.dumps(snapshot_data),
        )
        db.session.add(snap)
        # Prune: keep most recent 288 rows per service (~24h at 5-min intervals)
        old_ids = (
            db.session.query(ServiceMetricSnapshot.id)
            .filter_by(service_id=svc.id)
            .order_by(ServiceMetricSnapshot.captured_at.desc())
            .offset(288)
            .all()
        )
        if old_ids:
            ServiceMetricSnapshot.query.filter(
                ServiceMetricSnapshot.id.in_([r[0] for r in old_ids])
            ).delete(synchronize_session=False)
        db.session.commit()
    except Exception:
        db.session.rollback()
        logger.exception("Failed to save metric snapshot for service %s", svc.id)


@bp.route("/<int:service_id>/stats")
def stats(service_id):
    svc = GuestService.query.get_or_404(service_id)
    guest = svc.guest
    data = get_service_stats(guest, svc)

    save_service_snapshot(svc, data)

    # Feed Prometheus exporter with service-specific metrics
    _update_prometheus_service_stats(svc, guest, data)

    return jsonify(data)


def _update_prometheus_service_stats(svc, guest, data):
    """Push service stats to the Prometheus exporter."""
    try:
        if svc.service_name == "postgresql" and data.get("type") == "postgresql":
            from clients.prometheus_exporter import update_pg_metrics
            update_pg_metrics(svc.id, guest.name, data)
        elif svc.service_name == "redis" and data.get("type") == "redis":
            from clients.prometheus_exporter import update_redis_metrics
            update_redis_metrics(svc.id, guest.name, data)
        elif svc.service_name == "elasticsearch" and data.get("type") == "elasticsearch":
            from clients.prometheus_exporter import update_es_metrics
            update_es_metrics(svc.id, guest.name, data)
        elif svc.service_name == "jitsi-videobridge2" and not data.get("rest_api_disabled"):
            from clients.prometheus_exporter import update_jitsi_metrics
            update_jitsi_metrics(svc.id, guest.name, data)
        elif svc.service_name == "prometheus" and not data.get("prom_api_disabled"):
            from clients.prometheus_exporter import update_prometheus_metrics
            update_prometheus_metrics(svc.id, guest.name, data)
    except Exception:
        logger.debug("Failed to update Prometheus metrics for service %s", svc.id, exc_info=True)


@bp.route("/<int:service_id>/jvb/metrics-history")
def jvb_metrics_history(service_id):
    from models import Setting

    svc = GuestService.query.get_or_404(service_id)
    if svc.service_name != "jitsi-videobridge2":
        return jsonify({"error": "Not a Jitsi Videobridge service"}), 400

    # Try native JVB Prometheus metrics first (scraped directly from JVB /metrics)
    timeframe = request.args.get("timeframe", "day")
    if Setting.get("prometheus_enabled", "false") == "true" and Setting.get("prometheus_url", ""):
        try:
            from clients.prometheus_query import PrometheusQueryClient, _get_jvb_target
            jvb_target = _get_jvb_target()
            if jvb_target:
                prom = PrometheusQueryClient()
                data = prom.get_jvb_metrics_exporter(jvb_target, timeframe)
                if data and data.get("snapshots"):
                    return jsonify(data)
        except Exception:
            logger.debug("Native JVB Prometheus query failed, trying mstdnca gauges")

        # Fall back to mstdnca gauges
        try:
            from clients.prometheus_query import PrometheusQueryClient
            prom = PrometheusQueryClient()
            jvb_metrics = [
                "mstdnca_jitsi_conferences",
                "mstdnca_jitsi_participants",
                "mstdnca_jitsi_stress_level",
                "mstdnca_jitsi_bitrate_download_bps",
            ]
            data = prom.get_service_metrics_history(svc.id, jvb_metrics, timeframe)
            if data and data.get("snapshots"):
                return jsonify(data)
        except Exception:
            logger.debug("Prometheus query failed for JVB metrics history, falling back to SQLite")

    # Fall back to SQLite
    limit = min(int(request.args.get("limit", 144)), 288)
    rows = (
        ServiceMetricSnapshot.query
        .filter_by(service_id=svc.id)
        .order_by(ServiceMetricSnapshot.captured_at.asc())
        .limit(limit)
        .all()
    )
    result = []
    for row in rows:
        try:
            d = json.loads(row.data or "{}")
        except (json.JSONDecodeError, TypeError):
            d = {}
        d["captured_at"] = row.captured_at.isoformat()
        result.append(d)
    return jsonify({"snapshots": result, "source": "sqlite"})


@bp.route("/<int:service_id>/libretranslate/packages")
def lt_packages(service_id):
    svc = GuestService.query.get_or_404(service_id)
    if svc.service_name != "libretranslate":
        return jsonify({"error": "Not a LibreTranslate service"}), 400
    guest = svc.guest
    pkg_type = request.args.get("type", "installed")
    if pkg_type == "available":
        packages, err = lt_list_available(guest, svc)
    else:
        packages, err = lt_list_installed(guest, svc)
    if err:
        return jsonify({"error": err}), 500
    return jsonify({"packages": packages, "type": pkg_type})


@bp.route("/<int:service_id>/libretranslate/install", methods=["POST"])
def lt_install(service_id):
    if not current_user.can_edit_services:
        return jsonify({"ok": False, "message": "Permission denied."}), 403
    svc = GuestService.query.get_or_404(service_id)
    if svc.service_name != "libretranslate":
        return jsonify({"ok": False, "message": "Not a LibreTranslate service"}), 400
    guest = svc.guest
    data = request.get_json(silent=True) or {}
    from_code = data.get("from_code", "")
    to_code = data.get("to_code", "")
    ok, msg = lt_install_package(guest, svc, from_code, to_code)
    if ok:
        log_action("lt_install_package", "guest", resource_id=guest.id, resource_name=guest.name,
                   details={"service": svc.service_name, "from": from_code, "to": to_code})
        db.session.commit()
    return jsonify({"ok": ok, "message": msg})


@bp.route("/<int:service_id>/libretranslate/update", methods=["POST"])
def lt_update(service_id):
    if not current_user.can_edit_services:
        return jsonify({"ok": False, "message": "Permission denied."}), 403
    svc = GuestService.query.get_or_404(service_id)
    if svc.service_name != "libretranslate":
        return jsonify({"ok": False, "message": "Not a LibreTranslate service"}), 400
    guest = svc.guest
    ok, msg, count = lt_update_all_packages(guest, svc)
    if ok:
        log_action("lt_update_packages", "guest", resource_id=guest.id, resource_name=guest.name,
                   details={"service": svc.service_name, "updated": count})
        db.session.commit()
    return jsonify({"ok": ok, "message": msg, "count": count})


@bp.route("/<int:service_id>/libretranslate/update-stream", methods=["POST"])
def lt_update_stream(service_id):
    from flask import current_app
    if not current_user.can_edit_services:
        return jsonify({"ok": False, "message": "Permission denied."}), 403
    svc = GuestService.query.get_or_404(service_id)
    if svc.service_name != "libretranslate":
        return jsonify({"ok": False, "message": "Not a LibreTranslate service"}), 400
    guest = svc.guest
    guest_id = guest.id
    guest_name = guest.name
    svc_name = svc.service_name
    svc_id = svc.id

    msg_queue = queue.Queue()
    app = current_app._get_current_object()

    def run():
        # Push a fresh app context so the background thread gets its own
        # SQLAlchemy session and can safely reload the SQLAlchemy objects.
        try:
            with app.app_context():
                fresh_guest = Guest.query.get(guest_id)
                fresh_svc = GuestService.query.get(svc_id)
                if fresh_guest and fresh_svc:
                    lt_update_packages_stream(fresh_guest, fresh_svc, msg_queue.put)
                else:
                    msg_queue.put(json.dumps({"type": "result", "ok": False,
                                             "updated": 0, "message": "Service not found"}))
        except Exception as exc:
            msg_queue.put(json.dumps({"type": "result", "ok": False,
                                     "updated": 0, "message": str(exc)}))
        finally:
            msg_queue.put(None)  # sentinel — always sent so generator never blocks forever

    threading.Thread(target=run, daemon=True).start()

    def generate():
        result = None
        while True:
            item = msg_queue.get()
            if item is None:
                break
            yield f"data: {item}\n\n"
            try:
                data = json.loads(item)
                if data.get("type") == "result":
                    result = data
            except Exception:
                pass
        if result and result.get("ok"):
            log_action("lt_update_packages", "guest", resource_id=guest_id, resource_name=guest_name,
                       details={"service": svc_name, "updated": result.get("updated", 0)})
            db.session.commit()

    return Response(
        stream_with_context(generate()),
        content_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ---------------------------------------------------------------------------
# Prometheus management routes
# ---------------------------------------------------------------------------

def _prom_guard(service_id):
    """Return (svc, guest) or (None, None). Also checks service type."""
    svc = GuestService.query.get_or_404(service_id)
    if svc.service_name != "prometheus":
        return None, None
    return svc, svc.guest


def _prom_api(guest, port, path, method="GET", timeout=10):
    """Fetch a Prometheus API endpoint on the guest via SSH."""
    from core.scanner import _execute_command
    url = f"http://localhost:{port}{path}"
    if method == "POST":
        cmd = f"(curl -sf -X POST '{url}' 2>/dev/null || wget -qO- --post-data='' '{url}' 2>/dev/null)"
    else:
        cmd = f"(curl -sf '{url}' 2>/dev/null || wget -qO- '{url}' 2>/dev/null)"
    stdout, error = _execute_command(guest, cmd, timeout=timeout)
    if error:
        return None, f"SSH error: {error[:200]}"
    return (stdout or "").strip(), None


@bp.route("/<int:service_id>/prometheus/config")
def prom_config(service_id):
    svc, guest = _prom_guard(service_id)
    if svc is None:
        return jsonify({"error": "Not a Prometheus service"}), 400
    port = svc.port or 9090
    out, err = _prom_api(guest, port, "/api/v1/status/config")
    if err:
        return jsonify({"error": err}), 500
    if not out:
        return jsonify({"error": "No response from Prometheus API"}), 502
    try:
        data = json.loads(out)
        yaml_text = data.get("data", {}).get("yaml", "")
        return jsonify({"config": yaml_text})
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON from Prometheus"}), 502


@bp.route("/<int:service_id>/prometheus/flags")
def prom_flags(service_id):
    svc, guest = _prom_guard(service_id)
    if svc is None:
        return jsonify({"error": "Not a Prometheus service"}), 400
    port = svc.port or 9090
    out, err = _prom_api(guest, port, "/api/v1/status/flags")
    if err:
        return jsonify({"error": err}), 500
    if not out:
        return jsonify({"error": "No response from Prometheus API"}), 502
    try:
        data = json.loads(out)
        return jsonify({"flags": data.get("data", {})})
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON from Prometheus"}), 502


@bp.route("/<int:service_id>/prometheus/rules")
def prom_rules(service_id):
    svc, guest = _prom_guard(service_id)
    if svc is None:
        return jsonify({"error": "Not a Prometheus service"}), 400
    port = svc.port or 9090

    # Fetch rules
    groups = []
    out, err = _prom_api(guest, port, "/api/v1/rules")
    if not err and out:
        try:
            data = json.loads(out)
            groups = data.get("data", {}).get("groups", [])
        except json.JSONDecodeError:
            pass

    # Fetch active alerts
    alerts = []
    out, err = _prom_api(guest, port, "/api/v1/alerts")
    if not err and out:
        try:
            data = json.loads(out)
            alerts = data.get("data", {}).get("alerts", [])
        except json.JSONDecodeError:
            pass

    return jsonify({"groups": groups, "alerts": alerts})


@bp.route("/<int:service_id>/prometheus/reload", methods=["POST"])
def prom_reload(service_id):
    if not current_user.can_edit_services:
        return jsonify({"ok": False, "message": "Permission denied."}), 403
    svc, guest = _prom_guard(service_id)
    if svc is None:
        return jsonify({"ok": False, "message": "Not a Prometheus service"}), 400
    port = svc.port or 9090

    # Check lifecycle API is enabled
    out, err = _prom_api(guest, port, "/api/v1/status/flags")
    if err:
        return jsonify({"ok": False, "message": f"Cannot check flags: {err}"})
    try:
        flags = json.loads(out).get("data", {})
    except (json.JSONDecodeError, TypeError):
        flags = {}
    if flags.get("web.enable-lifecycle", "false") != "true":
        return jsonify({"ok": False, "message": "Lifecycle API not enabled. Start Prometheus with --web.enable-lifecycle."})

    out, err = _prom_api(guest, port, "/-/reload", method="POST")
    if err:
        return jsonify({"ok": False, "message": err})

    log_action("prom_reload_config", "guest", resource_id=guest.id, resource_name=guest.name,
               details={"service": svc.service_name})
    db.session.commit()
    return jsonify({"ok": True, "message": "Configuration reloaded successfully."})


@bp.route("/<int:service_id>/prometheus/reconfigure", methods=["POST"])
def prom_reconfigure(service_id):
    """Regenerate prometheus.yml from all installed exporters and reload."""
    if not current_user.can_edit_services:
        return jsonify({"ok": False, "message": "Permission denied."}), 403
    svc, guest = _prom_guard(service_id)
    if svc is None:
        return jsonify({"ok": False, "message": "Not a Prometheus service"}), 400

    from apps.exporters import _regenerate_prometheus_config

    messages = []

    def _log(msg):
        messages.append(msg)

    _regenerate_prometheus_config(_log)

    log_action("prom_reconfigure", "guest", resource_id=guest.id, resource_name=guest.name,
               details={"service": svc.service_name})
    db.session.commit()

    # Check if any error occurred
    has_error = any("ERROR" in m for m in messages)
    return jsonify({
        "ok": not has_error,
        "message": "\n".join(messages) if messages else "Prometheus configuration regenerated.",
    })


@bp.route("/<int:service_id>/prometheus/snapshot", methods=["POST"])
def prom_snapshot(service_id):
    if not current_user.can_edit_services:
        return jsonify({"ok": False, "message": "Permission denied."}), 403
    svc, guest = _prom_guard(service_id)
    if svc is None:
        return jsonify({"ok": False, "message": "Not a Prometheus service"}), 400
    port = svc.port or 9090

    # Check admin API is enabled
    out, err = _prom_api(guest, port, "/api/v1/status/flags")
    if err:
        return jsonify({"ok": False, "message": f"Cannot check flags: {err}"})
    try:
        flags = json.loads(out).get("data", {})
    except (json.JSONDecodeError, TypeError):
        flags = {}
    if flags.get("web.enable-admin-api", "false") != "true":
        return jsonify({"ok": False, "message": "Admin API not enabled. Start Prometheus with --web.enable-admin-api."})

    out, err = _prom_api(guest, port, "/api/v1/admin/tsdb/snapshot", method="POST", timeout=60)
    if err:
        return jsonify({"ok": False, "message": err})

    snapshot_name = ""
    if out:
        try:
            snapshot_name = json.loads(out).get("data", {}).get("name", "")
        except json.JSONDecodeError:
            pass

    log_action("prom_snapshot", "guest", resource_id=guest.id, resource_name=guest.name,
               details={"service": svc.service_name, "snapshot": snapshot_name})
    db.session.commit()
    return jsonify({"ok": True, "message": f"Snapshot created: {snapshot_name}" if snapshot_name else "Snapshot created."})
