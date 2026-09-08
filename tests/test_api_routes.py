"""Tests for API routes in routes/api.py that operate purely on DB state.

Covers endpoints that do not require Proxmox / SSH connectivity:
- /api/apply/<id>/status        — job status JSON (no job -> safe empty response)
- /api/apply/<id>/cancel        — POST cancel (no job -> error JSON, no SSH)
- /api/scan/<id>                — POST starts a backgrounded scan (no sync SSH)
- /api/scan/<id>/status         — scan job status JSON (no job -> safe empty response)
- /api/scan-all                 — POST starts a backgrounded bulk scan
- /api/scan-all/progress        — bulk-scan progress page
- /api/scan-all/status          — bulk-scan status JSON
- /api/task/<id>/<type>/status  — proxmox job status JSON
- /api/task/<id>/<type>/cancel  — POST cancel (no job -> error JSON, no SSH)
- /api/collab/presence          — POST heartbeat (uses in-process collab_hub)
- /api/collab/terminal-sessions — GET (DB-only guest lookup)
- /api/collab/cursor            — GET cursor update (in-process cursor_hub)
- /api/collab/cursors           — GET cursors for a page
- Authorization: unauthenticated requests redirect / return 401/302
"""
import time
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import patch

from models import Guest, UpdatePackage, db
from routes.api import (
    ProxmoxJob,
    ScanJob,
    UpdateJob,
    _bulk_scan,
    _bulk_scan_lock,
    _proxmox_jobs,
    _scan_jobs,
    _update_jobs,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_guest(app, name, guest_type="ct", **kwargs):
    """Create and persist a Guest; return its id."""
    with app.app_context():
        g = Guest(name=name, guest_type=guest_type, enabled=True, **kwargs)
        db.session.add(g)
        db.session.commit()
        return g.id


def _delete_guest(app, guest_id):
    with app.app_context():
        g = Guest.query.get(guest_id)
        if g:
            db.session.delete(g)
            db.session.commit()


# ---------------------------------------------------------------------------
# Authentication guard tests
# ---------------------------------------------------------------------------

class TestUnauthenticated:
    """All API endpoints must require authentication."""

    def test_update_status_unauthenticated(self, client):
        resp = client.get("/api/apply/1/status", follow_redirects=False)
        assert resp.status_code in (302, 401)

    def test_update_cancel_unauthenticated(self, client):
        resp = client.post("/api/apply/1/cancel", follow_redirects=False)
        assert resp.status_code in (302, 401)

    def test_task_status_unauthenticated(self, client):
        resp = client.get("/api/task/1/backup/status", follow_redirects=False)
        assert resp.status_code in (302, 401)

    def test_task_cancel_unauthenticated(self, client):
        resp = client.post("/api/task/1/backup/cancel", follow_redirects=False)
        assert resp.status_code in (302, 401)

    def test_collab_presence_unauthenticated(self, client):
        resp = client.post(
            "/api/collab/presence",
            json={"page": "/"},
            follow_redirects=False,
        )
        assert resp.status_code in (302, 401)

    def test_collab_terminal_sessions_unauthenticated(self, client):
        resp = client.get("/api/collab/terminal-sessions", follow_redirects=False)
        assert resp.status_code in (302, 401)

    def test_collab_cursor_unauthenticated(self, client):
        resp = client.get(
            "/api/collab/cursor?x_pct=0.5&y_pct=0.5",
            follow_redirects=False,
        )
        assert resp.status_code in (302, 401)

    def test_collab_cursors_unauthenticated(self, client):
        resp = client.get(
            "/api/collab/cursors?page=/",
            follow_redirects=False,
        )
        assert resp.status_code in (302, 401)

    def test_unauthenticated_redirects_to_login(self, client):
        """Redirect destination should contain /login."""
        resp = client.get("/api/apply/1/status", follow_redirects=False)
        if resp.status_code == 302:
            assert "/login" in resp.headers["Location"]


# ---------------------------------------------------------------------------
# /api/apply/<guest_id>/status
# ---------------------------------------------------------------------------

class TestUpdateStatus:
    """GET /api/apply/<guest_id>/status"""

    def test_returns_200_for_existing_guest(self, app, auth_client):
        guest_id = _make_guest(app, "_api-status-basic")
        try:
            resp = auth_client.get(f"/api/apply/{guest_id}/status")
            assert resp.status_code == 200
        finally:
            _delete_guest(app, guest_id)

    def test_returns_json_content_type(self, app, auth_client):
        guest_id = _make_guest(app, "_api-status-ct")
        try:
            resp = auth_client.get(f"/api/apply/{guest_id}/status")
            assert resp.content_type.startswith("application/json")
        finally:
            _delete_guest(app, guest_id)

    def test_no_job_returns_running_false(self, app, auth_client):
        """When no update job exists the endpoint returns running=False with empty log."""
        guest_id = _make_guest(app, "_api-status-no-job")
        try:
            resp = auth_client.get(f"/api/apply/{guest_id}/status")
            data = resp.get_json()
            assert data["running"] is False
            assert data["log"] == ""
            assert data["success"] is None
        finally:
            _delete_guest(app, guest_id)

    def test_active_job_fields_present(self, app, auth_client):
        """When a job exists the dict contains all expected keys."""
        guest_id = _make_guest(app, "_api-status-active-job")
        job = UpdateJob(guest_id, "_api-status-active-job")
        job.append("Installing...\n")
        _update_jobs[guest_id] = job
        try:
            resp = auth_client.get(f"/api/apply/{guest_id}/status")
            data = resp.get_json()
            assert "running" in data
            assert "log" in data
            assert "success" in data
            assert "cancelled" in data
            assert "started_at" in data
            assert "Installing..." in data["log"]
        finally:
            _update_jobs.pop(guest_id, None)
            _delete_guest(app, guest_id)

    def test_active_job_running_true(self, app, auth_client):
        guest_id = _make_guest(app, "_api-status-running-flag")
        job = UpdateJob(guest_id, "_api-status-running-flag")
        _update_jobs[guest_id] = job
        try:
            resp = auth_client.get(f"/api/apply/{guest_id}/status")
            data = resp.get_json()
            assert data["running"] is True
        finally:
            _update_jobs.pop(guest_id, None)
            _delete_guest(app, guest_id)

    def test_finished_job_success_true(self, app, auth_client):
        guest_id = _make_guest(app, "_api-status-finished")
        job = UpdateJob(guest_id, "_api-status-finished")
        job.finish(True)
        _update_jobs[guest_id] = job
        try:
            resp = auth_client.get(f"/api/apply/{guest_id}/status")
            data = resp.get_json()
            assert data["running"] is False
            assert data["success"] is True
        finally:
            _update_jobs.pop(guest_id, None)
            _delete_guest(app, guest_id)

    def test_finished_job_success_false(self, app, auth_client):
        guest_id = _make_guest(app, "_api-status-failed")
        job = UpdateJob(guest_id, "_api-status-failed")
        job.finish(False)
        _update_jobs[guest_id] = job
        try:
            resp = auth_client.get(f"/api/apply/{guest_id}/status")
            data = resp.get_json()
            assert data["running"] is False
            assert data["success"] is False
        finally:
            _update_jobs.pop(guest_id, None)
            _delete_guest(app, guest_id)

    def test_cancelled_job_flag(self, app, auth_client):
        guest_id = _make_guest(app, "_api-status-cancelled")
        job = UpdateJob(guest_id, "_api-status-cancelled")
        job.cancel_requested = True
        job.finish(False)
        _update_jobs[guest_id] = job
        try:
            resp = auth_client.get(f"/api/apply/{guest_id}/status")
            data = resp.get_json()
            assert data["cancelled"] is True
        finally:
            _update_jobs.pop(guest_id, None)
            _delete_guest(app, guest_id)

    def test_reboot_required_flag_propagated(self, app, auth_client):
        guest_id = _make_guest(app, "_api-status-reboot")
        job = UpdateJob(guest_id, "_api-status-reboot")
        job.reboot_required = True
        _update_jobs[guest_id] = job
        try:
            resp = auth_client.get(f"/api/apply/{guest_id}/status")
            data = resp.get_json()
            assert data["reboot_required"] is True
        finally:
            _update_jobs.pop(guest_id, None)
            _delete_guest(app, guest_id)

    def test_nonexistent_guest_returns_404(self, auth_client):
        resp = auth_client.get("/api/apply/999999/status")
        assert resp.status_code == 404

    def test_started_at_is_iso_format(self, app, auth_client):
        guest_id = _make_guest(app, "_api-status-iso-ts")
        job = UpdateJob(guest_id, "_api-status-iso-ts")
        _update_jobs[guest_id] = job
        try:
            resp = auth_client.get(f"/api/apply/{guest_id}/status")
            data = resp.get_json()
            # Should not raise — ISO 8601 format
            datetime.fromisoformat(data["started_at"])
        finally:
            _update_jobs.pop(guest_id, None)
            _delete_guest(app, guest_id)


# ---------------------------------------------------------------------------
# /api/apply/<guest_id>/cancel
# ---------------------------------------------------------------------------

class TestUpdateCancel:
    """POST /api/apply/<guest_id>/cancel"""

    def test_no_active_job_returns_ok_false(self, app, auth_client):
        guest_id = _make_guest(app, "_api-cancel-no-job")
        try:
            resp = auth_client.post(f"/api/apply/{guest_id}/cancel")
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["ok"] is False
            assert "No active job" in data["error"]
        finally:
            _delete_guest(app, guest_id)

    def test_cancel_sets_cancel_requested(self, app, auth_client):
        guest_id = _make_guest(app, "_api-cancel-active")
        job = UpdateJob(guest_id, "_api-cancel-active")
        _update_jobs[guest_id] = job
        try:
            resp = auth_client.post(f"/api/apply/{guest_id}/cancel")
            data = resp.get_json()
            assert data["ok"] is True
            assert job.cancel_requested is True
        finally:
            _update_jobs.pop(guest_id, None)
            _delete_guest(app, guest_id)

    def test_cancel_already_finished_job_returns_ok_false(self, app, auth_client):
        guest_id = _make_guest(app, "_api-cancel-done")
        job = UpdateJob(guest_id, "_api-cancel-done")
        job.finish(True)
        _update_jobs[guest_id] = job
        try:
            resp = auth_client.post(f"/api/apply/{guest_id}/cancel")
            data = resp.get_json()
            assert data["ok"] is False
        finally:
            _update_jobs.pop(guest_id, None)
            _delete_guest(app, guest_id)

    def test_cancel_nonexistent_guest_returns_404(self, auth_client):
        resp = auth_client.post("/api/apply/999999/cancel")
        assert resp.status_code == 404

    def test_cancel_returns_json(self, app, auth_client):
        guest_id = _make_guest(app, "_api-cancel-json")
        try:
            resp = auth_client.post(f"/api/apply/{guest_id}/cancel")
            assert resp.content_type.startswith("application/json")
        finally:
            _delete_guest(app, guest_id)


def _wait_until(predicate, timeout=15.0, interval=0.02):
    """Poll `predicate()` until it returns truthy or `timeout` elapses."""
    deadline = time.monotonic() + timeout
    result = predicate()
    while not result and time.monotonic() < deadline:
        time.sleep(interval)
        result = predicate()
    return result


# ---------------------------------------------------------------------------
# /api/scan/<guest_id> and /api/scan/<guest_id>/status
#
# scan_single() no longer scans synchronously in the request thread (a scan
# can be slow enough to exceed a front-door timeout) -- it now starts a
# background job, same pattern as /api/apply/<id>. These tests patch
# routes.api.scan_guest so no real SSH/Proxmox call happens.
# ---------------------------------------------------------------------------

class TestScanSingle:
    def test_post_redirects_and_does_not_block(self, app, auth_client):
        guest_id = _make_guest(app, "_api-scan-single-redirect")
        fake_result = SimpleNamespace(status="success", total_updates=3,
                                       security_updates=1, error_message=None)
        try:
            with patch("routes.api.scan_guest", return_value=fake_result):
                resp = auth_client.post(f"/api/scan/{guest_id}", follow_redirects=False)
            assert resp.status_code == 302
        finally:
            _wait_until(lambda: not (_scan_jobs.get(guest_id) and _scan_jobs[guest_id].running))
            _scan_jobs.pop(guest_id, None)
            _delete_guest(app, guest_id)

    def test_background_job_records_success_result(self, app, auth_client):
        guest_id = _make_guest(app, "_api-scan-single-result")
        fake_result = SimpleNamespace(status="success", total_updates=5,
                                       security_updates=2, error_message=None)
        try:
            with patch("routes.api.scan_guest", return_value=fake_result):
                auth_client.post(f"/api/scan/{guest_id}", follow_redirects=False)
                # Keep the patch active until the background thread (which
                # calls routes.api.scan_guest asynchronously) has finished --
                # otherwise the patch is reverted before the thread gets to it.
                assert _wait_until(lambda: not (_scan_jobs.get(guest_id) and _scan_jobs[guest_id].running))

            job = _scan_jobs[guest_id]
            assert job.success is True
            assert job.total_updates == 5
            assert job.security_updates == 2
        finally:
            _scan_jobs.pop(guest_id, None)
            _delete_guest(app, guest_id)

    def test_already_running_does_not_start_a_second_job(self, app, auth_client):
        guest_id = _make_guest(app, "_api-scan-single-already-running")
        existing_job = ScanJob(guest_id, "_api-scan-single-already-running")
        _scan_jobs[guest_id] = existing_job
        try:
            with patch("routes.api.scan_guest") as mock_scan:
                resp = auth_client.post(f"/api/scan/{guest_id}", follow_redirects=True)
            assert b"already running" in resp.data
            mock_scan.assert_not_called()
            assert _scan_jobs[guest_id] is existing_job
        finally:
            _scan_jobs.pop(guest_id, None)
            _delete_guest(app, guest_id)

    def test_nonexistent_guest_returns_404(self, auth_client):
        resp = auth_client.post("/api/scan/999999")
        assert resp.status_code == 404


class TestScanStatus:
    """GET /api/scan/<guest_id>/status"""

    def test_no_job_returns_running_false(self, app, auth_client):
        guest_id = _make_guest(app, "_api-scan-status-none")
        try:
            resp = auth_client.get(f"/api/scan/{guest_id}/status")
            assert resp.status_code == 200
            assert resp.content_type.startswith("application/json")
            data = resp.get_json()
            assert data["running"] is False
            assert data["success"] is None
        finally:
            _delete_guest(app, guest_id)

    def test_active_job_running_true(self, app, auth_client):
        guest_id = _make_guest(app, "_api-scan-status-active")
        _scan_jobs[guest_id] = ScanJob(guest_id, "_api-scan-status-active")
        try:
            resp = auth_client.get(f"/api/scan/{guest_id}/status")
            data = resp.get_json()
            assert data["running"] is True
            assert data["guest_id"] == guest_id
        finally:
            _scan_jobs.pop(guest_id, None)
            _delete_guest(app, guest_id)

    def test_finished_job_reports_totals(self, app, auth_client):
        guest_id = _make_guest(app, "_api-scan-status-done")
        job = ScanJob(guest_id, "_api-scan-status-done")
        job.finish(SimpleNamespace(status="success", total_updates=7, security_updates=1, error_message=None))
        _scan_jobs[guest_id] = job
        try:
            resp = auth_client.get(f"/api/scan/{guest_id}/status")
            data = resp.get_json()
            assert data["running"] is False
            assert data["success"] is True
            assert data["total_updates"] == 7
            assert data["security_updates"] == 1
        finally:
            _scan_jobs.pop(guest_id, None)
            _delete_guest(app, guest_id)

    def test_failed_job_reports_error_message(self, app, auth_client):
        guest_id = _make_guest(app, "_api-scan-status-failed")
        job = ScanJob(guest_id, "_api-scan-status-failed")
        job.finish(SimpleNamespace(status="error", total_updates=0, security_updates=0,
                                    error_message="SSH connection failed"))
        _scan_jobs[guest_id] = job
        try:
            resp = auth_client.get(f"/api/scan/{guest_id}/status")
            data = resp.get_json()
            assert data["success"] is False
            assert data["error_message"] == "SSH connection failed"
        finally:
            _scan_jobs.pop(guest_id, None)
            _delete_guest(app, guest_id)

    def test_nonexistent_guest_returns_404(self, auth_client):
        resp = auth_client.get("/api/scan/999999/status")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# /api/scan-all, /api/scan-all/progress, /api/scan-all/status
# ---------------------------------------------------------------------------

class TestScanAll:
    def _reset_bulk_scan(self):
        with _bulk_scan_lock:
            _bulk_scan["running"] = False
            _bulk_scan["started_at"] = None
            _bulk_scan["total"] = 0
            _bulk_scan["done"] = 0
            _bulk_scan["items"] = []

    def test_no_targets_flashes_info_and_redirects_to_dashboard(self, app, auth_client):
        self._reset_bulk_scan()
        resp = auth_client.post("/api/scan-all", follow_redirects=True)
        assert resp.status_code == 200
        assert b"No running guests" in resp.data

    def test_starts_background_bulk_scan_and_redirects_to_progress(self, app, auth_client):
        self._reset_bulk_scan()
        guest_id = _make_guest(app, "_api-scan-all-target", power_state="running",
                                status="updates-available")
        fake_result = SimpleNamespace(status="success", total_updates=2,
                                       security_updates=0, error_message=None)
        try:
            with patch("routes.api.scan_guest", return_value=fake_result), \
                 patch("routes.api.send_update_notification"):
                resp = auth_client.post("/api/scan-all", follow_redirects=False)
                assert resp.status_code == 302
                assert "/api/scan-all/progress" in resp.headers["Location"]

                # Keep the patches active until the background thread (which
                # calls these asynchronously) has finished.
                assert _wait_until(lambda: not _bulk_scan["running"])

            with _bulk_scan_lock:
                items = list(_bulk_scan["items"])
                assert _bulk_scan["done"] == _bulk_scan["total"] == 1
            assert items[0]["guest_id"] == guest_id
            assert items[0]["state"] == "success"
        finally:
            self._reset_bulk_scan()
            _delete_guest(app, guest_id)

    def test_already_running_redirects_to_progress_without_restarting(self, app, auth_client):
        self._reset_bulk_scan()
        with _bulk_scan_lock:
            _bulk_scan["running"] = True
        try:
            with patch("routes.api.scan_guest") as mock_scan:
                resp = auth_client.post("/api/scan-all", follow_redirects=False)
            assert resp.status_code == 302
            assert "/api/scan-all/progress" in resp.headers["Location"]
            mock_scan.assert_not_called()
        finally:
            self._reset_bulk_scan()

    def test_progress_page_renders(self, auth_client):
        resp = auth_client.get("/api/scan-all/progress")
        assert resp.status_code == 200

    def test_status_endpoint_returns_json_shape(self, auth_client):
        self._reset_bulk_scan()
        resp = auth_client.get("/api/scan-all/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["running"] is False
        assert data["items"] == []


# ---------------------------------------------------------------------------
# /api/task/<guest_id>/<job_type>/status
# ---------------------------------------------------------------------------

class TestTaskStatus:
    """GET /api/task/<guest_id>/<job_type>/status"""

    def test_no_task_returns_running_false(self, app, auth_client):
        guest_id = _make_guest(app, "_api-task-status-nojob")
        try:
            resp = auth_client.get(f"/api/task/{guest_id}/backup/status")
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["running"] is False
            assert data["log"] == ""
            assert data["success"] is None
        finally:
            _delete_guest(app, guest_id)

    def test_active_task_fields_present(self, app, auth_client):
        guest_id = _make_guest(app, "_api-task-status-active")
        job_key = f"backup:{guest_id}"
        job = ProxmoxJob(
            guest_id=guest_id,
            guest_name="_api-task-status-active",
            job_type="backup",
            upid="UPID:pvetest:001:backup",
            node="pve1",
            host_model=None,
        )
        job.append("Backing up...\n")
        _proxmox_jobs[job_key] = job
        try:
            resp = auth_client.get(f"/api/task/{guest_id}/backup/status")
            data = resp.get_json()
            assert "running" in data
            assert "log" in data
            assert "success" in data
            assert "job_type" in data
            assert "label" in data
            assert "started_at" in data
            assert "Backing up..." in data["log"]
            assert data["job_type"] == "backup"
        finally:
            _proxmox_jobs.pop(job_key, None)
            _delete_guest(app, guest_id)

    def test_task_label_human_readable(self, app, auth_client):
        guest_id = _make_guest(app, "_api-task-label")
        job_key = f"snapshot:{guest_id}"
        job = ProxmoxJob(
            guest_id=guest_id,
            guest_name="_api-task-label",
            job_type="snapshot",
            upid="UPID:test",
            node="pve1",
            host_model=None,
        )
        _proxmox_jobs[job_key] = job
        try:
            resp = auth_client.get(f"/api/task/{guest_id}/snapshot/status")
            data = resp.get_json()
            assert data["label"] == "Creating Snapshot"
        finally:
            _proxmox_jobs.pop(job_key, None)
            _delete_guest(app, guest_id)

    def test_all_job_types_return_200(self, app, auth_client):
        """All four supported job types should be accessible and return 200."""
        job_types = ["backup", "snapshot", "snapshot_delete", "rollback"]
        guest_id = _make_guest(app, "_api-task-types")
        try:
            for jt in job_types:
                resp = auth_client.get(f"/api/task/{guest_id}/{jt}/status")
                assert resp.status_code == 200, f"Expected 200 for job_type={jt}"
        finally:
            _delete_guest(app, guest_id)

    def test_task_status_nonexistent_guest(self, auth_client):
        resp = auth_client.get("/api/task/999999/backup/status")
        assert resp.status_code == 404

    def test_task_returns_json(self, app, auth_client):
        guest_id = _make_guest(app, "_api-task-ctype")
        try:
            resp = auth_client.get(f"/api/task/{guest_id}/backup/status")
            assert resp.content_type.startswith("application/json")
        finally:
            _delete_guest(app, guest_id)

    def test_finished_task_success_true(self, app, auth_client):
        guest_id = _make_guest(app, "_api-task-done-ok")
        job_key = f"backup:{guest_id}"
        job = ProxmoxJob(
            guest_id=guest_id,
            guest_name="_api-task-done-ok",
            job_type="backup",
            upid="UPID:test",
            node="pve1",
            host_model=None,
        )
        job.finish(True)
        _proxmox_jobs[job_key] = job
        try:
            resp = auth_client.get(f"/api/task/{guest_id}/backup/status")
            data = resp.get_json()
            assert data["running"] is False
            assert data["success"] is True
        finally:
            _proxmox_jobs.pop(job_key, None)
            _delete_guest(app, guest_id)


# ---------------------------------------------------------------------------
# /api/task/<guest_id>/<job_type>/cancel
# ---------------------------------------------------------------------------

class TestTaskCancel:
    """POST /api/task/<guest_id>/<job_type>/cancel"""

    def test_no_active_job_returns_ok_false(self, app, auth_client):
        guest_id = _make_guest(app, "_api-task-cancel-nojob")
        try:
            resp = auth_client.post(f"/api/task/{guest_id}/backup/cancel")
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["ok"] is False
            assert "No active job" in data["error"]
        finally:
            _delete_guest(app, guest_id)

    def test_cancel_nonexistent_guest_returns_404(self, auth_client):
        resp = auth_client.post("/api/task/999999/backup/cancel")
        assert resp.status_code == 404

    def test_cancel_returns_json(self, app, auth_client):
        guest_id = _make_guest(app, "_api-task-cancel-ctype")
        try:
            resp = auth_client.post(f"/api/task/{guest_id}/backup/cancel")
            assert resp.content_type.startswith("application/json")
        finally:
            _delete_guest(app, guest_id)

    def test_already_finished_job_returns_ok_false(self, app, auth_client):
        guest_id = _make_guest(app, "_api-task-cancel-finished")
        job_key = f"backup:{guest_id}"
        job = ProxmoxJob(
            guest_id=guest_id,
            guest_name="_api-task-cancel-finished",
            job_type="backup",
            upid="UPID:test",
            node="pve1",
            host_model=None,
        )
        job.finish(True)
        _proxmox_jobs[job_key] = job
        try:
            resp = auth_client.post(f"/api/task/{guest_id}/backup/cancel")
            data = resp.get_json()
            assert data["ok"] is False
        finally:
            _proxmox_jobs.pop(job_key, None)
            _delete_guest(app, guest_id)


# ---------------------------------------------------------------------------
# /api/collab/presence
# ---------------------------------------------------------------------------

class TestCollabPresence:
    """POST /api/collab/presence — heartbeat endpoint."""

    def test_presence_returns_200(self, auth_client):
        resp = auth_client.post(
            "/api/collab/presence",
            json={"page": "/guests/"},
        )
        assert resp.status_code == 200

    def test_presence_returns_ok_true(self, auth_client):
        resp = auth_client.post(
            "/api/collab/presence",
            json={"page": "/guests/"},
        )
        data = resp.get_json()
        assert data["ok"] is True

    def test_presence_returns_json(self, auth_client):
        resp = auth_client.post(
            "/api/collab/presence",
            json={"page": "/"},
        )
        assert resp.content_type.startswith("application/json")

    def test_presence_with_empty_body(self, auth_client):
        """Sending no JSON body should still succeed (page defaults to '/')."""
        resp = auth_client.post(
            "/api/collab/presence",
            data="",
            content_type="application/json",
        )
        # Should not crash — collab_hub.update_presence handles None gracefully
        assert resp.status_code == 200

    def test_presence_with_following_field(self, auth_client):
        resp = auth_client.post(
            "/api/collab/presence",
            json={"page": "/guests/", "following": "otheruser"},
        )
        data = resp.get_json()
        assert data["ok"] is True

    def test_presence_following_null_allowed(self, auth_client):
        resp = auth_client.post(
            "/api/collab/presence",
            json={"page": "/", "following": None},
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# /api/collab/terminal-sessions
# ---------------------------------------------------------------------------

class TestCollabTerminalSessions:
    """GET /api/collab/terminal-sessions"""

    def test_returns_200(self, auth_client):
        resp = auth_client.get("/api/collab/terminal-sessions")
        assert resp.status_code == 200

    def test_returns_json(self, auth_client):
        resp = auth_client.get("/api/collab/terminal-sessions")
        assert resp.content_type.startswith("application/json")

    def test_returns_sessions_key(self, auth_client):
        resp = auth_client.get("/api/collab/terminal-sessions")
        data = resp.get_json()
        assert "sessions" in data

    def test_sessions_is_list(self, auth_client):
        resp = auth_client.get("/api/collab/terminal-sessions")
        data = resp.get_json()
        assert isinstance(data["sessions"], list)

    def test_sessions_empty_when_no_active_terminals(self, auth_client):
        """With no active SSH terminal sessions the list should be empty."""
        resp = auth_client.get("/api/collab/terminal-sessions")
        data = resp.get_json()
        # In tests there are no real WebSocket connections so the registry is empty.
        assert data["sessions"] == []


# ---------------------------------------------------------------------------
# /api/collab/cursor  and  /api/collab/cursors
# ---------------------------------------------------------------------------

class TestCollabCursor:
    """GET /api/collab/cursor — cursor position update."""

    def test_cursor_update_valid_params(self, auth_client):
        resp = auth_client.get("/api/collab/cursor?x_pct=0.25&y_pct=0.75&page=/guests/")
        assert resp.status_code == 200

    def test_cursor_update_returns_ok_true(self, auth_client):
        resp = auth_client.get("/api/collab/cursor?x_pct=0.5&y_pct=0.5")
        data = resp.get_json()
        assert data["ok"] is True

    def test_cursor_update_missing_x_returns_400(self, auth_client):
        resp = auth_client.get("/api/collab/cursor?y_pct=0.5")
        assert resp.status_code == 400

    def test_cursor_update_missing_y_returns_400(self, auth_client):
        resp = auth_client.get("/api/collab/cursor?x_pct=0.5")
        assert resp.status_code == 400

    def test_cursor_update_missing_both_returns_400(self, auth_client):
        resp = auth_client.get("/api/collab/cursor")
        assert resp.status_code == 400

    def test_cursor_update_non_numeric_x_returns_400(self, auth_client):
        resp = auth_client.get("/api/collab/cursor?x_pct=abc&y_pct=0.5")
        assert resp.status_code == 400

    def test_cursor_update_returns_json(self, auth_client):
        resp = auth_client.get("/api/collab/cursor?x_pct=0.1&y_pct=0.1")
        assert resp.content_type.startswith("application/json")

    def test_cursor_update_with_color(self, auth_client):
        resp = auth_client.get("/api/collab/cursor?x_pct=0.3&y_pct=0.3&color=%23ff0000")
        assert resp.status_code == 200


class TestCollabCursors:
    """GET /api/collab/cursors — retrieve cursor positions for a page."""

    def test_returns_200(self, auth_client):
        resp = auth_client.get("/api/collab/cursors?page=/")
        assert resp.status_code == 200

    def test_returns_json(self, auth_client):
        resp = auth_client.get("/api/collab/cursors?page=/")
        assert resp.content_type.startswith("application/json")

    def test_returns_cursors_key(self, auth_client):
        resp = auth_client.get("/api/collab/cursors?page=/guests/")
        data = resp.get_json()
        assert "cursors" in data

    def test_cursors_is_list(self, auth_client):
        resp = auth_client.get("/api/collab/cursors?page=/")
        data = resp.get_json()
        assert isinstance(data["cursors"], list)

    def test_cursors_excludes_own_user(self, auth_client):
        """A user's own cursor should not appear in their own cursor list."""
        # First record the admin cursor position
        auth_client.get("/api/collab/cursor?x_pct=0.5&y_pct=0.5&page=/test/page")
        # Then retrieve cursors for the same page — admin should be excluded
        resp = auth_client.get("/api/collab/cursors?page=/test/page")
        data = resp.get_json()
        for cursor in data["cursors"]:
            assert cursor.get("username") != "admin"

    def test_no_page_param_defaults_gracefully(self, auth_client):
        """Omitting the page query param should not crash the endpoint."""
        resp = auth_client.get("/api/collab/cursors")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# UpdateJob unit tests (no HTTP layer)
# ---------------------------------------------------------------------------

class TestUpdateJobModel:
    """Direct unit tests for the UpdateJob class."""

    def test_initial_state(self):
        job = UpdateJob(42, "myguest")
        d = job.to_dict()
        assert d["guest_id"] == 42
        assert d["guest_name"] == "myguest"
        assert d["running"] is True
        assert d["success"] is None
        assert d["cancelled"] is False
        assert d["reboot_required"] is False
        assert d["log"] == ""

    def test_append_accumulates(self):
        job = UpdateJob(1, "g")
        job.append("line1\n")
        job.append("line2\n")
        assert "line1\n" in job.to_dict()["log"]
        assert "line2\n" in job.to_dict()["log"]

    def test_finish_success(self):
        job = UpdateJob(1, "g")
        job.finish(True)
        d = job.to_dict()
        assert d["running"] is False
        assert d["success"] is True
        assert d["cancelled"] is False

    def test_finish_failure(self):
        job = UpdateJob(1, "g")
        job.finish(False)
        d = job.to_dict()
        assert d["running"] is False
        assert d["success"] is False

    def test_cancel_marks_cancelled_on_finish(self):
        job = UpdateJob(1, "g")
        job.cancel_requested = True
        job.finish(False)
        assert job.to_dict()["cancelled"] is True

    def test_cancel_not_set_without_cancel_request(self):
        job = UpdateJob(1, "g")
        job.finish(False)
        assert job.to_dict()["cancelled"] is False

    def test_started_at_is_datetime(self):
        job = UpdateJob(1, "g")
        assert isinstance(job.started_at, datetime)

    def test_to_dict_started_at_iso(self):
        job = UpdateJob(1, "g")
        ts = job.to_dict()["started_at"]
        # Must parse without error
        datetime.fromisoformat(ts)


# ---------------------------------------------------------------------------
# ProxmoxJob unit tests (no HTTP layer)
# ---------------------------------------------------------------------------

class TestProxmoxJobModel:
    """Direct unit tests for the ProxmoxJob class."""

    def _make_job(self, job_type="backup"):
        return ProxmoxJob(
            guest_id=10,
            guest_name="pve-guest",
            job_type=job_type,
            upid="UPID:node1:001:backup",
            node="node1",
            host_model=None,
        )

    def test_initial_state(self):
        job = self._make_job()
        d = job.to_dict()
        assert d["guest_id"] == 10
        assert d["guest_name"] == "pve-guest"
        assert d["job_type"] == "backup"
        assert d["running"] is True
        assert d["success"] is None
        assert d["cancelled"] is False
        assert d["log"] == ""

    def test_label_backup(self):
        job = self._make_job("backup")
        assert job.label == "Creating Backup"

    def test_label_snapshot(self):
        job = self._make_job("snapshot")
        assert job.label == "Creating Snapshot"

    def test_label_snapshot_delete(self):
        job = self._make_job("snapshot_delete")
        assert job.label == "Deleting Snapshot"

    def test_label_rollback(self):
        job = self._make_job("rollback")
        assert job.label == "Rolling Back"

    def test_label_unknown_falls_back_to_type(self):
        job = self._make_job("custom_op")
        assert job.label == "custom_op"

    def test_append_log(self):
        job = self._make_job()
        job.append("Task started\n")
        assert "Task started" in job.to_dict()["log"]

    def test_finish_success(self):
        job = self._make_job()
        job.finish(True)
        d = job.to_dict()
        assert d["running"] is False
        assert d["success"] is True

    def test_cancelled_on_cancel_request(self):
        job = self._make_job()
        job.cancel_requested = True
        job.finish(False)
        assert job.to_dict()["cancelled"] is True

    def test_to_dict_contains_label(self):
        job = self._make_job("rollback")
        d = job.to_dict()
        assert "label" in d
        assert d["label"] == "Rolling Back"

    def test_started_at_iso_parseable(self):
        job = self._make_job()
        ts = job.to_dict()["started_at"]
        datetime.fromisoformat(ts)


# ---------------------------------------------------------------------------
# Guest fixtures — DB model integrity used by API endpoints
# ---------------------------------------------------------------------------

class TestGuestModelForApiRoutes:
    """Verify Guest and UpdatePackage records behave as API endpoints expect."""

    def test_guest_pending_updates_empty_by_default(self, app):
        with app.app_context():
            g = Guest(name="_api-model-pending", guest_type="vm")
            db.session.add(g)
            db.session.commit()
            assert g.pending_updates() == []
            db.session.delete(g)
            db.session.commit()

    def test_guest_pending_updates_counts_pending_only(self, app):
        with app.app_context():
            g = Guest(name="_api-model-pkgs", guest_type="vm")
            db.session.add(g)
            db.session.flush()
            db.session.add(UpdatePackage(
                guest_id=g.id, package_name="libc6",
                status="pending", severity="critical",
            ))
            db.session.add(UpdatePackage(
                guest_id=g.id, package_name="curl",
                status="applied", severity="normal",
            ))
            db.session.commit()

            assert len(g.pending_updates()) == 1
            assert g.pending_updates()[0].package_name == "libc6"

            db.session.delete(g)
            db.session.commit()

    def test_update_package_requires_reboot_kernel(self, app):
        with app.app_context():
            g = Guest(name="_api-model-reboot-pkg", guest_type="ct")
            db.session.add(g)
            db.session.flush()
            pkg = UpdatePackage(
                guest_id=g.id, package_name="linux-image-6.1.0-amd64",
                status="pending", severity="normal",
            )
            db.session.add(pkg)
            db.session.commit()

            assert pkg.requires_reboot is True

            db.session.delete(g)
            db.session.commit()

    def test_update_package_no_reboot_for_curl(self, app):
        with app.app_context():
            g = Guest(name="_api-model-no-reboot-pkg", guest_type="ct")
            db.session.add(g)
            db.session.flush()
            pkg = UpdatePackage(
                guest_id=g.id, package_name="curl",
                status="pending", severity="normal",
            )
            db.session.add(pkg)
            db.session.commit()

            assert pkg.requires_reboot is False

            db.session.delete(g)
            db.session.commit()
