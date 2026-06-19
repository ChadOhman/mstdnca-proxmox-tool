"""Tests for bulk host updates — POST /hosts/updates/apply-all and aggregate status.

The orchestrator runs in a background thread in production, but the test DB is an
in-memory SQLite (one connection per thread), so a background thread would see an
empty database. We therefore split the coverage:

  * target SELECTION + permissions are tested via the route, which populates
    ``_bulk_apply["items"]`` synchronously in the request context BEFORE spawning
    the thread (the thread target ``_run_bulk_apply`` is stubbed to a no-op);
  * the ORCHESTRATOR is tested by calling ``_run_bulk_apply`` directly (same
    thread, same DB connection) with the per-host ``_run_apply`` worker stubbed,
    so no real SSH happens.
"""
import routes.hosts as hosts_mod
from auth.credential_store import encrypt
from models import AuditLog, Credential, HostUpdatePackage, ProxmoxHost, Role, User, db
from routes.hosts import _apply_jobs, _apply_lock, _bulk_apply, _bulk_apply_lock


def _reset_bulk():
    with _bulk_apply_lock:
        _bulk_apply["running"] = False
        _bulk_apply["started_at"] = None
        _bulk_apply["total"] = 0
        _bulk_apply["done"] = 0
        _bulk_apply["items"] = []


def _make_credential(app, name="_bulk-host-cred"):
    with app.app_context():
        c = Credential(name=name, username="root", auth_type="password",
                       encrypted_value=encrypt("test-only-pw"))
        db.session.add(c)
        db.session.commit()
        return c.id


def _make_host(app, name, host_type="pve", ssh_credential_id=None, pending=0):
    with app.app_context():
        h = ProxmoxHost(name=name, hostname="10.0.0.9", host_type=host_type,
                        auth_type="token", username="root@pam",
                        ssh_credential_id=ssh_credential_id)
        db.session.add(h)
        db.session.flush()
        for i in range(pending):
            db.session.add(HostUpdatePackage(host_id=h.id, package_name=f"pkg{i}",
                                             status="pending", severity="normal"))
        db.session.commit()
        return h.id


def _cleanup_hosts(app, *host_ids):
    with app.app_context():
        for hid in host_ids:
            h = ProxmoxHost.query.get(hid)
            if h:
                db.session.delete(h)
        db.session.commit()


# ---------------------------------------------------------------------------
# Permission gate
# ---------------------------------------------------------------------------

class TestApplyAllPermission:
    def test_requires_can_manage_hosts(self, app, client):
        with app.app_context():
            viewer = Role.query.filter_by(name="viewer").first()
            assert viewer.can_manage_hosts is False  # guard
            u = User(username="_bulk_host_viewer", display_name="V", role_id=viewer.id)
            u.set_password("ViewerPass123!")
            db.session.add(u)
            db.session.commit()
        _reset_bulk()
        client.post("/login", data={"username": "_bulk_host_viewer", "password": "ViewerPass123!"})
        try:
            resp = client.post("/hosts/updates/apply-all", follow_redirects=False)
            assert resp.status_code == 302
            with _bulk_apply_lock:
                assert _bulk_apply["running"] is False
                assert _bulk_apply["items"] == []
        finally:
            with app.app_context():
                User.query.filter_by(username="_bulk_host_viewer").delete()
                db.session.commit()
            _reset_bulk()

    def test_unauthenticated_redirects(self, client):
        resp = client.post("/hosts/updates/apply-all", follow_redirects=False)
        assert resp.status_code in (302, 401)


# ---------------------------------------------------------------------------
# Target selection (route populates _bulk_apply synchronously)
# ---------------------------------------------------------------------------

class TestApplyAllTargetSelection:
    def test_targets_only_pending_pve_hosts(self, app, auth_client, monkeypatch):
        cred_id = _make_credential(app)
        h_pending = _make_host(app, "_bulk-pve-pending", ssh_credential_id=cred_id, pending=2)
        h_clean = _make_host(app, "_bulk-pve-clean", ssh_credential_id=cred_id, pending=0)
        h_pbs = _make_host(app, "_bulk-pbs-pending", host_type="pbs",
                           ssh_credential_id=cred_id, pending=2)
        _reset_bulk()
        # Stub orchestrator so the spawned thread is a no-op (avoids cross-thread DB).
        monkeypatch.setattr(hosts_mod, "_run_bulk_apply", lambda *a, **k: None)
        try:
            resp = auth_client.post("/hosts/updates/apply-all", follow_redirects=False)
            assert resp.status_code == 302
            assert "/hosts/updates/apply-all/progress" in resp.headers["Location"]
            with _bulk_apply_lock:
                names = {i["name"] for i in _bulk_apply["items"]}
                assert names == {"_bulk-pve-pending"}  # PBS + clean excluded
                assert _bulk_apply["total"] == 1
            with app.app_context():
                assert AuditLog.query.filter_by(action="host_update_all").count() >= 1
        finally:
            _cleanup_hosts(app, h_pending, h_clean, h_pbs)
            _reset_bulk()

    def test_no_pending_hosts_redirects_to_index(self, app, auth_client, monkeypatch):
        h_clean = _make_host(app, "_bulk-none-clean", pending=0)
        _reset_bulk()
        monkeypatch.setattr(hosts_mod, "_run_bulk_apply", lambda *a, **k: None)
        try:
            resp = auth_client.post("/hosts/updates/apply-all", follow_redirects=False)
            assert resp.status_code == 302
            assert resp.headers["Location"].endswith("/hosts/")
            with _bulk_apply_lock:
                assert _bulk_apply["running"] is False  # never started
        finally:
            _cleanup_hosts(app, h_clean)
            _reset_bulk()

    def test_concurrent_run_blocked(self, app, auth_client, monkeypatch):
        cred_id = _make_credential(app, "_bulk-host-cred-busy")
        h = _make_host(app, "_bulk-busy", ssh_credential_id=cred_id, pending=1)
        _reset_bulk()
        with _bulk_apply_lock:
            _bulk_apply["running"] = True  # pretend a run is already in flight
        monkeypatch.setattr(hosts_mod, "_run_bulk_apply", lambda *a, **k: None)
        try:
            resp = auth_client.post("/hosts/updates/apply-all", follow_redirects=False)
            assert resp.status_code == 302
            assert "/hosts/updates/apply-all/progress" in resp.headers["Location"]
            # Items were not replaced by a second run.
            with _bulk_apply_lock:
                assert _bulk_apply["items"] == []
        finally:
            _cleanup_hosts(app, h)
            _reset_bulk()


# ---------------------------------------------------------------------------
# Orchestrator (_run_bulk_apply called directly, _run_apply stubbed)
# ---------------------------------------------------------------------------

class TestBulkApplyOrchestrator:
    def _seed_items(self, items, total):
        with _bulk_apply_lock:
            _bulk_apply["running"] = True
            _bulk_apply["total"] = total
            _bulk_apply["done"] = 0
            _bulk_apply["items"] = items

    def test_runs_each_host_and_marks_success(self, app, monkeypatch):
        cred_id = _make_credential(app, "_bulk-orch-cred")
        h1 = _make_host(app, "_bulk-orch-1", ssh_credential_id=cred_id, pending=1)
        h2 = _make_host(app, "_bulk-orch-2", ssh_credential_id=cred_id, pending=1)

        def fake_run_apply(host_id, hostname, cred, app_ctx):
            with _apply_lock:
                _apply_jobs[host_id]["running"] = False
                _apply_jobs[host_id]["success"] = True
        monkeypatch.setattr(hosts_mod, "_run_apply", fake_run_apply)

        _reset_bulk()
        self._seed_items([
            {"host_id": h1, "name": "_bulk-orch-1", "state": "pending", "reason": None},
            {"host_id": h2, "name": "_bulk-orch-2", "state": "pending", "reason": None},
        ], total=2)
        try:
            hosts_mod._run_bulk_apply(app)
            with _bulk_apply_lock:
                assert _bulk_apply["running"] is False
                assert _bulk_apply["done"] == 2
                assert all(i["state"] == "success" for i in _bulk_apply["items"])
        finally:
            _apply_jobs.pop(h1, None)
            _apply_jobs.pop(h2, None)
            _cleanup_hosts(app, h1, h2)
            _reset_bulk()

    def test_skips_host_without_ssh_credential(self, app, monkeypatch):
        h = _make_host(app, "_bulk-orch-nossh", ssh_credential_id=None, pending=1)
        called = []
        monkeypatch.setattr(hosts_mod, "_run_apply", lambda *a, **k: called.append(1))

        _reset_bulk()
        self._seed_items(
            [{"host_id": h, "name": "_bulk-orch-nossh", "state": "pending", "reason": None}],
            total=1,
        )
        try:
            hosts_mod._run_bulk_apply(app)
            with _bulk_apply_lock:
                item = _bulk_apply["items"][0]
                assert item["state"] == "skipped"
                assert "SSH" in (item["reason"] or "")
                assert _bulk_apply["done"] == 1
            assert called == []  # _run_apply never invoked for a credential-less host
        finally:
            _cleanup_hosts(app, h)
            _reset_bulk()

    def test_one_failure_does_not_abort_batch(self, app, monkeypatch):
        cred_id = _make_credential(app, "_bulk-orch-fail-cred")
        h1 = _make_host(app, "_bulk-orch-fail-1", ssh_credential_id=cred_id, pending=1)
        h2 = _make_host(app, "_bulk-orch-fail-2", ssh_credential_id=cred_id, pending=1)

        def fake_run_apply(host_id, hostname, cred, app_ctx):
            if host_id == h1:
                raise RuntimeError("boom")
            with _apply_lock:
                _apply_jobs[host_id]["running"] = False
                _apply_jobs[host_id]["success"] = True
        monkeypatch.setattr(hosts_mod, "_run_apply", fake_run_apply)

        _reset_bulk()
        self._seed_items([
            {"host_id": h1, "name": "_bulk-orch-fail-1", "state": "pending", "reason": None},
            {"host_id": h2, "name": "_bulk-orch-fail-2", "state": "pending", "reason": None},
        ], total=2)
        try:
            hosts_mod._run_bulk_apply(app)
            with _bulk_apply_lock:
                by_id = {i["host_id"]: i for i in _bulk_apply["items"]}
                assert by_id[h1]["state"] == "failed"
                assert by_id[h2]["state"] == "success"
                assert _bulk_apply["done"] == 2
                assert _bulk_apply["running"] is False
        finally:
            _apply_jobs.pop(h1, None)
            _apply_jobs.pop(h2, None)
            _cleanup_hosts(app, h1, h2)
            _reset_bulk()


# ---------------------------------------------------------------------------
# Aggregate status / progress page
# ---------------------------------------------------------------------------

class TestApplyAllStatus:
    def test_status_returns_aggregate_shape(self, auth_client):
        _reset_bulk()
        with _bulk_apply_lock:
            _bulk_apply["running"] = True
            _bulk_apply["total"] = 2
            _bulk_apply["done"] = 1
            _bulk_apply["items"] = [
                {"host_id": 9111, "name": "a", "state": "success", "reason": None},
                {"host_id": 9222, "name": "b", "state": "running", "reason": None},
            ]
        with _apply_lock:
            _apply_jobs[9111] = {"log": ["done\n"], "running": False, "success": True, "cancelled": False}
            _apply_jobs[9222] = {"log": ["working\n"], "running": True, "success": None, "cancelled": False}
        try:
            resp = auth_client.get("/hosts/updates/apply-all/status")
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["total"] == 2
            assert data["done"] == 1
            assert data["running"] is True
            by_name = {i["name"]: i for i in data["items"]}
            assert by_name["a"]["state"] == "success"
            assert "done" in by_name["a"]["log"]
            assert by_name["b"]["state"] == "running"
            assert "working" in by_name["b"]["log"]
        finally:
            _apply_jobs.pop(9111, None)
            _apply_jobs.pop(9222, None)
            _reset_bulk()

    def test_progress_page_renders(self, auth_client):
        resp = auth_client.get("/hosts/updates/apply-all/progress")
        assert resp.status_code == 200
        assert b"Updating All Hosts" in resp.data
