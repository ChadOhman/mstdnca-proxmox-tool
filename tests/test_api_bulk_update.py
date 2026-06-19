"""Tests for bulk guest updates — POST /api/apply-all and aggregate status.

Coverage is split the same way as the host bulk tests: the route populates
``_bulk_update["items"]`` synchronously before spawning the (stubbed) orchestrator
thread, so target selection + permissions are tested via HTTP; the orchestrator
itself is tested by calling ``_run_bulk_update`` directly with the per-guest
``_run_update_background`` worker stubbed (no real SSH).
"""
import routes.api as api_mod
from models import AuditLog, Guest, Role, Tag, UpdatePackage, User, db
from routes.api import UpdateJob, _bulk_update, _bulk_update_lock, _update_jobs


def _reset_bulk():
    with _bulk_update_lock:
        _bulk_update["running"] = False
        _bulk_update["started_at"] = None
        _bulk_update["total"] = 0
        _bulk_update["done"] = 0
        _bulk_update["items"] = []


def _make_guest(app, name, status="updates-available", power_state="running",
                pending=1, tag_names=None):
    with app.app_context():
        g = Guest(name=name, guest_type="ct", enabled=True,
                  status=status, power_state=power_state)
        for tname in (tag_names or []):
            tag = Tag.query.filter_by(name=tname).first() or Tag(name=tname)
            g.tags.append(tag)
        db.session.add(g)
        db.session.flush()
        for i in range(pending):
            db.session.add(UpdatePackage(guest_id=g.id, package_name=f"pkg{i}",
                                         status="pending", severity="normal"))
        db.session.commit()
        return g.id


def _cleanup_guests(app, *guest_ids):
    with app.app_context():
        for gid in guest_ids:
            g = Guest.query.get(gid)
            if g:
                for t in list(g.tags):
                    g.tags.remove(t)
                db.session.delete(g)
        db.session.commit()


# ---------------------------------------------------------------------------
# Permission gate (guards the #76 family: tag read access != apply rights)
# ---------------------------------------------------------------------------

class TestApplyAllPermission:
    def test_requires_can_update(self, app, client):
        with app.app_context():
            viewer = Role.query.filter_by(name="viewer").first()
            assert viewer.can_update is False  # guard
            u = User(username="_bulk_guest_viewer", display_name="V", role_id=viewer.id)
            u.set_password("ViewerPass123!")
            db.session.add(u)
            db.session.commit()
        _reset_bulk()
        client.post("/login", data={"username": "_bulk_guest_viewer", "password": "ViewerPass123!"})
        try:
            resp = client.post("/api/apply-all", follow_redirects=False)
            assert resp.status_code == 302
            with _bulk_update_lock:
                assert _bulk_update["running"] is False
                assert _bulk_update["items"] == []
        finally:
            with app.app_context():
                User.query.filter_by(username="_bulk_guest_viewer").delete()
                db.session.commit()
            _reset_bulk()

    def test_unauthenticated_redirects(self, client):
        resp = client.post("/api/apply-all", follow_redirects=False)
        assert resp.status_code in (302, 401)


# ---------------------------------------------------------------------------
# Target selection
# ---------------------------------------------------------------------------

class TestApplyAllTargetSelection:
    def test_targets_only_eligible_guests(self, app, auth_client, monkeypatch):
        g_ok = _make_guest(app, "_bulk-g-ok", status="updates-available",
                           power_state="running", pending=2)
        g_utd = _make_guest(app, "_bulk-g-utd", status="up-to-date",
                            power_state="running", pending=0)
        g_stopped = _make_guest(app, "_bulk-g-stopped", status="updates-available",
                                power_state="stopped", pending=2)
        g_nopkg = _make_guest(app, "_bulk-g-nopkg", status="updates-available",
                              power_state="running", pending=0)
        _reset_bulk()
        monkeypatch.setattr(api_mod, "_run_bulk_update", lambda *a, **k: None)
        try:
            resp = auth_client.post("/api/apply-all", data={"dist_upgrade": "0"},
                                    follow_redirects=False)
            assert resp.status_code == 302
            assert "/api/apply-all/progress" in resp.headers["Location"]
            with _bulk_update_lock:
                names = {i["name"] for i in _bulk_update["items"]}
                assert names == {"_bulk-g-ok"}  # only running + updates-available + has pending pkgs
                assert _bulk_update["total"] == 1
            with app.app_context():
                assert AuditLog.query.filter_by(action="guest_update_all").count() >= 1
                # per-guest audit row written too (parity with single apply)
                assert AuditLog.query.filter_by(
                    action="guest_update", resource_name="_bulk-g-ok").count() >= 1
        finally:
            _cleanup_guests(app, g_ok, g_utd, g_stopped, g_nopkg)
            _reset_bulk()

    def test_no_eligible_guests_redirects_to_guests(self, app, auth_client, monkeypatch):
        g = _make_guest(app, "_bulk-g-none", status="up-to-date",
                        power_state="running", pending=0)
        _reset_bulk()
        monkeypatch.setattr(api_mod, "_run_bulk_update", lambda *a, **k: None)
        try:
            resp = auth_client.post("/api/apply-all", follow_redirects=False)
            assert resp.status_code == 302
            assert resp.headers["Location"].endswith("/guests/")
            with _bulk_update_lock:
                assert _bulk_update["running"] is False
        finally:
            _cleanup_guests(app, g)
            _reset_bulk()

    def test_dist_upgrade_flag_forwarded(self, app, auth_client, monkeypatch):
        g = _make_guest(app, "_bulk-g-dist", pending=1)
        _reset_bulk()
        captured = {}

        def fake_orch(app_, guest_ids, dist_upgrade, enforce_snapshot):
            captured["dist_upgrade"] = dist_upgrade
            captured["guest_ids"] = list(guest_ids)
        monkeypatch.setattr(api_mod, "_run_bulk_update", fake_orch)
        try:
            auth_client.post("/api/apply-all", data={"dist_upgrade": "1"}, follow_redirects=False)
            assert captured["dist_upgrade"] is True
            assert g in captured["guest_ids"]
        finally:
            _cleanup_guests(app, g)
            _reset_bulk()


# ---------------------------------------------------------------------------
# Orchestrator (_run_bulk_update called directly, _run_update_background stubbed)
# ---------------------------------------------------------------------------

class TestBulkUpdateOrchestrator:
    def _seed_items(self, items, total):
        with _bulk_update_lock:
            _bulk_update["running"] = True
            _bulk_update["total"] = total
            _bulk_update["done"] = 0
            _bulk_update["items"] = items

    def test_runs_each_guest_and_marks_success(self, app, monkeypatch):
        g1 = _make_guest(app, "_bulk-orch-g1", pending=1)
        g2 = _make_guest(app, "_bulk-orch-g2", pending=1)

        def fake_bg(app_, gid, dist):
            job = _update_jobs.get(gid)
            if job:
                job.finish(True)
        monkeypatch.setattr(api_mod, "_run_update_background", fake_bg)

        _reset_bulk()
        self._seed_items([
            {"guest_id": g1, "name": "_bulk-orch-g1", "state": "pending", "reason": None},
            {"guest_id": g2, "name": "_bulk-orch-g2", "state": "pending", "reason": None},
        ], total=2)
        try:
            api_mod._run_bulk_update(app, [g1, g2], False, False)
            with _bulk_update_lock:
                assert _bulk_update["running"] is False
                assert _bulk_update["done"] == 2
                assert all(i["state"] == "success" for i in _bulk_update["items"])
        finally:
            _update_jobs.pop(g1, None)
            _update_jobs.pop(g2, None)
            _cleanup_guests(app, g1, g2)
            _reset_bulk()

    def test_one_failure_does_not_abort_batch(self, app, monkeypatch):
        g1 = _make_guest(app, "_bulk-orch-gf1", pending=1)
        g2 = _make_guest(app, "_bulk-orch-gf2", pending=1)

        def fake_bg(app_, gid, dist):
            if gid == g1:
                raise RuntimeError("boom")
            job = _update_jobs.get(gid)
            if job:
                job.finish(True)
        monkeypatch.setattr(api_mod, "_run_update_background", fake_bg)

        _reset_bulk()
        self._seed_items([
            {"guest_id": g1, "name": "_bulk-orch-gf1", "state": "pending", "reason": None},
            {"guest_id": g2, "name": "_bulk-orch-gf2", "state": "pending", "reason": None},
        ], total=2)
        try:
            api_mod._run_bulk_update(app, [g1, g2], False, False)
            with _bulk_update_lock:
                by_id = {i["guest_id"]: i for i in _bulk_update["items"]}
                assert by_id[g1]["state"] == "failed"
                assert by_id[g2]["state"] == "success"
                assert _bulk_update["done"] == 2
                assert _bulk_update["running"] is False
        finally:
            _update_jobs.pop(g1, None)
            _update_jobs.pop(g2, None)
            _cleanup_guests(app, g1, g2)
            _reset_bulk()

    def test_skips_already_running_guest(self, app, monkeypatch):
        g1 = _make_guest(app, "_bulk-orch-gr1", pending=1)
        _update_jobs[g1] = UpdateJob(g1, "_bulk-orch-gr1")  # running=True by default
        calls = []
        monkeypatch.setattr(api_mod, "_run_update_background", lambda *a, **k: calls.append(1))

        _reset_bulk()
        self._seed_items(
            [{"guest_id": g1, "name": "_bulk-orch-gr1", "state": "pending", "reason": None}],
            total=1,
        )
        try:
            api_mod._run_bulk_update(app, [g1], False, False)
            with _bulk_update_lock:
                item = _bulk_update["items"][0]
                assert item["state"] == "skipped"
                assert "already running" in (item["reason"] or "")
            assert calls == []
        finally:
            _update_jobs.pop(g1, None)
            _cleanup_guests(app, g1)
            _reset_bulk()

    def test_snapshot_failure_skips_guest(self, app, monkeypatch):
        g1 = _make_guest(app, "_bulk-orch-snap", pending=1)
        monkeypatch.setattr("routes.guests.guest_requires_snapshot", lambda g: True)
        monkeypatch.setattr("routes.guests.auto_snapshot_if_needed", lambda g: (False, "no node"))
        bg_calls = []
        monkeypatch.setattr(api_mod, "_run_update_background", lambda *a, **k: bg_calls.append(1))

        _reset_bulk()
        self._seed_items(
            [{"guest_id": g1, "name": "_bulk-orch-snap", "state": "pending", "reason": None}],
            total=1,
        )
        try:
            api_mod._run_bulk_update(app, [g1], False, True)  # enforce_snapshot=True
            with _bulk_update_lock:
                item = _bulk_update["items"][0]
                assert item["state"] == "skipped"
                assert "Snapshot" in (item["reason"] or "")
            assert bg_calls == []
        finally:
            _update_jobs.pop(g1, None)
            _cleanup_guests(app, g1)
            _reset_bulk()


# ---------------------------------------------------------------------------
# Aggregate status / progress page
# ---------------------------------------------------------------------------

class TestApplyAllStatus:
    def test_status_returns_aggregate_shape(self, auth_client):
        _reset_bulk()
        running_job = UpdateJob(8555, "running-guest")
        running_job.append("installing...\n")
        _update_jobs[8555] = running_job
        done_job = UpdateJob(8444, "done-guest")
        done_job.append("ok\n")
        done_job.finish(True)
        _update_jobs[8444] = done_job
        with _bulk_update_lock:
            _bulk_update["running"] = True
            _bulk_update["total"] = 2
            _bulk_update["done"] = 1
            _bulk_update["items"] = [
                {"guest_id": 8444, "name": "done-guest", "state": "success", "reason": None},
                {"guest_id": 8555, "name": "running-guest", "state": "running", "reason": None},
            ]
        try:
            resp = auth_client.get("/api/apply-all/status")
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["total"] == 2
            assert data["done"] == 1
            assert data["running"] is True
            by_name = {i["name"]: i for i in data["items"]}
            assert by_name["running-guest"]["state"] == "running"
            assert "installing" in by_name["running-guest"]["log"]
            assert by_name["done-guest"]["state"] == "success"
        finally:
            _update_jobs.pop(8444, None)
            _update_jobs.pop(8555, None)
            _reset_bulk()

    def test_status_forbidden_for_viewer(self, app, client):
        with app.app_context():
            viewer = Role.query.filter_by(name="viewer").first()
            u = User(username="_bulk_status_viewer", display_name="V", role_id=viewer.id)
            u.set_password("ViewerPass123!")
            db.session.add(u)
            db.session.commit()
        client.post("/login", data={"username": "_bulk_status_viewer", "password": "ViewerPass123!"})
        try:
            resp = client.get("/api/apply-all/status")
            assert resp.status_code == 403
        finally:
            with app.app_context():
                User.query.filter_by(username="_bulk_status_viewer").delete()
                db.session.commit()

    def test_progress_page_renders(self, auth_client):
        resp = auth_client.get("/api/apply-all/progress")
        assert resp.status_code == 200
        assert b"Updating All Guests" in resp.data
