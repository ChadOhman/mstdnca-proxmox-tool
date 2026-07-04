"""Tests for the update-history / trends feature.

Covers:
  - core.update_history.record_update_history (the shared instrumentation
    helper used by every apply code path)
  - History recorded by the interactive apply path (routes.api._run_update_background)
  - History recorded by the scheduled auto-update path (core.scheduler._run_auto_updates)
  - The /trends page: rendering with data, rendering with an empty DB, and
    permission/tag-scoping behavior
  - The chronically-behind ranking logic in core.update_trends
"""
from datetime import datetime, timedelta, timezone

import routes.api as api_mod
from models import Guest, MaintenanceWindow, Role, Tag, UpdateHistory, UpdatePackage, User, db


def _make_guest(app, name, **kwargs):
    with app.app_context():
        g = Guest(name=name, guest_type="ct", enabled=True, **kwargs)
        db.session.add(g)
        db.session.commit()
        return g.id


def _cleanup(app, *ids_by_model):
    """ids_by_model: list of (Model, id) tuples to delete, in order given."""
    with app.app_context():
        for model, obj_id in ids_by_model:
            obj = model.query.get(obj_id)
            if obj:
                db.session.delete(obj)
        db.session.commit()


class TestRecordUpdateHistory:
    """Unit tests for core.update_history.record_update_history."""

    def test_creates_row_with_counts_and_summary(self, app):
        gid = _make_guest(app, "_uh-basic")
        try:
            with app.app_context():
                from core.update_history import record_update_history

                guest = Guest.query.get(gid)
                pkgs = [
                    UpdatePackage(guest_id=gid, package_name="curl", severity="normal", status="pending"),
                    UpdatePackage(guest_id=gid, package_name="openssl", severity="critical", status="pending"),
                ]
                db.session.add_all(pkgs)
                db.session.flush()

                record_update_history(guest, pkgs, initiated_by="admin")
                db.session.commit()

                rows = UpdateHistory.query.filter_by(guest_id=gid).all()
                assert len(rows) == 1
                row = rows[0]
                assert row.package_count == 2
                assert row.security_count == 1
                assert "curl" in row.packages_summary
                assert "openssl" in row.packages_summary
                assert row.initiated_by == "admin"
        finally:
            _cleanup(app, (Guest, gid))

    def test_initiated_by_defaults_to_none(self, app):
        gid = _make_guest(app, "_uh-noinit")
        try:
            with app.app_context():
                from core.update_history import record_update_history

                guest = Guest.query.get(gid)
                pkg = UpdatePackage(guest_id=gid, package_name="vim", severity="normal", status="pending")
                db.session.add(pkg)
                db.session.flush()

                record_update_history(guest, [pkg])
                db.session.commit()

                row = UpdateHistory.query.filter_by(guest_id=gid).first()
                assert row.initiated_by is None
        finally:
            _cleanup(app, (Guest, gid))

    def test_empty_package_list_records_zero_counts(self, app):
        gid = _make_guest(app, "_uh-empty")
        try:
            with app.app_context():
                from core.update_history import record_update_history

                guest = Guest.query.get(gid)
                record_update_history(guest, [], initiated_by="scheduler")
                db.session.commit()

                row = UpdateHistory.query.filter_by(guest_id=gid).first()
                assert row.package_count == 0
                assert row.security_count == 0
                assert row.packages_summary is None
        finally:
            _cleanup(app, (Guest, gid))


class TestInteractiveApplyRecordsHistory:
    """routes.api._run_update_background (SSH path) writes an UpdateHistory row."""

    def _make_credentialed_guest(self, app, name):
        from models import Credential
        with app.app_context():
            cred = Credential(name="_uh-cred", username="root", auth_type="password",
                               encrypted_value="unused", is_default=False)
            db.session.add(cred)
            db.session.flush()
            g = Guest(name=name, guest_type="ct", enabled=True, ip_address="10.0.0.50",
                       connection_method="ssh", credential_id=cred.id)
            db.session.add(g)
            db.session.flush()
            pkg = UpdatePackage(guest_id=g.id, package_name="nginx", severity="critical", status="pending")
            db.session.add(pkg)
            db.session.commit()
            return g.id, cred.id

    def test_ssh_apply_records_history_with_initiated_by(self, app, monkeypatch):
        guest_id, cred_id = self._make_credentialed_guest(app, "_uh-ssh-guest")

        class FakeSSH:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def execute_sudo_streaming(self, cmd, callback, timeout=None, stop_fn=None):
                return 0

            def execute_sudo(self, cmd, timeout=None):
                return ("no", "", 0)

        monkeypatch.setattr(
            "clients.ssh_client.SSHClient.from_credential",
            classmethod(lambda cls, host, cred, port=22: FakeSSH()),
        )

        with app.app_context():
            job = api_mod.UpdateJob(guest_id, "_uh-ssh-guest")
            api_mod._update_jobs[guest_id] = job

        try:
            api_mod._run_update_background(app, guest_id, dist_upgrade=False, initiated_by="alice")

            with app.app_context():
                job = api_mod._update_jobs.get(guest_id)
                assert job.success is True

                rows = UpdateHistory.query.filter_by(guest_id=guest_id).all()
                assert len(rows) == 1
                assert rows[0].package_count == 1
                assert rows[0].security_count == 1
                assert rows[0].initiated_by == "alice"
                assert "nginx" in rows[0].packages_summary
        finally:
            api_mod._update_jobs.pop(guest_id, None)
            _cleanup(app, (Guest, guest_id), (__import__("models").Credential, cred_id))

    def test_ssh_apply_without_initiated_by_records_none(self, app, monkeypatch):
        guest_id, cred_id = self._make_credentialed_guest(app, "_uh-ssh-guest2")

        class FakeSSH:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def execute_sudo_streaming(self, cmd, callback, timeout=None, stop_fn=None):
                return 0

            def execute_sudo(self, cmd, timeout=None):
                return ("no", "", 0)

        monkeypatch.setattr(
            "clients.ssh_client.SSHClient.from_credential",
            classmethod(lambda cls, host, cred, port=22: FakeSSH()),
        )

        with app.app_context():
            job = api_mod.UpdateJob(guest_id, "_uh-ssh-guest2")
            api_mod._update_jobs[guest_id] = job

        try:
            api_mod._run_update_background(app, guest_id, dist_upgrade=False)

            with app.app_context():
                rows = UpdateHistory.query.filter_by(guest_id=guest_id).all()
                assert len(rows) == 1
                assert rows[0].initiated_by is None
        finally:
            api_mod._update_jobs.pop(guest_id, None)
            _cleanup(app, (Guest, guest_id), (__import__("models").Credential, cred_id))


class TestScheduledAutoUpdateRecordsHistory:
    """core.scheduler._run_auto_updates writes an UpdateHistory row with initiated_by='scheduler'."""

    def _make_due_guest(self, app, name):
        with app.app_context():
            window = MaintenanceWindow(
                name="_uh-window", day_of_week="daily",
                start_time="00:00", end_time="23:59",
                update_type="upgrade", enabled=True,
            )
            db.session.add(window)
            db.session.flush()
            g = Guest(name=name, guest_type="ct", enabled=True, auto_update=True,
                      maintenance_window_id=window.id, status="updates-available")
            db.session.add(g)
            db.session.flush()
            pkg = UpdatePackage(guest_id=g.id, package_name="python3", severity="normal", status="pending")
            db.session.add(pkg)
            db.session.commit()
            return g.id, window.id

    def test_auto_update_records_history(self, app, monkeypatch):
        guest_id, window_id = self._make_due_guest(app, "_uh-auto-guest")

        monkeypatch.setattr("core.scanner.apply_updates", lambda guest, dist_upgrade=False: (True, "ok"))
        monkeypatch.setattr("core.notifier.send_updates_applied_notification", lambda results: None)

        try:
            with app.app_context():
                from core.scheduler import _run_auto_updates
                _run_auto_updates(app)

            with app.app_context():
                rows = UpdateHistory.query.filter_by(guest_id=guest_id).all()
                assert len(rows) == 1
                assert rows[0].initiated_by == "scheduler"
                assert rows[0].package_count == 1
        finally:
            _cleanup(app, (Guest, guest_id), (MaintenanceWindow, window_id))

    def test_auto_update_failure_does_not_record_history(self, app, monkeypatch):
        guest_id, window_id = self._make_due_guest(app, "_uh-auto-fail")

        monkeypatch.setattr("core.scanner.apply_updates", lambda guest, dist_upgrade=False: (False, "boom"))
        monkeypatch.setattr("core.notifier.send_updates_applied_notification", lambda results: None)

        try:
            with app.app_context():
                from core.scheduler import _run_auto_updates
                _run_auto_updates(app)

            with app.app_context():
                assert UpdateHistory.query.filter_by(guest_id=guest_id).count() == 0
        finally:
            _cleanup(app, (Guest, guest_id), (MaintenanceWindow, window_id))


class TestTrendsRoutePermission:
    def test_unauthenticated_redirects_to_login(self, client):
        resp = client.get("/trends/", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_authenticated_admin_sees_page(self, auth_client):
        resp = auth_client.get("/trends/")
        assert resp.status_code == 200
        assert b"Update History" in resp.data

    def test_viewer_without_tags_sees_empty_state(self, app, client):
        with app.app_context():
            viewer = Role.query.filter_by(name="viewer").first()
            u = User(username="_uh_viewer_notag", display_name="V", role_id=viewer.id)
            u.set_password("ViewerPass123!")
            db.session.add(u)
            db.session.commit()
        client.post("/login", data={"username": "_uh_viewer_notag", "password": "ViewerPass123!"})
        try:
            resp = client.get("/trends/")
            assert resp.status_code == 200
            # No accessible guests -> no chronically-behind rows, no crash.
            assert b"Choose a guest" in resp.data or b"No guests with pending updates" in resp.data
        finally:
            with app.app_context():
                User.query.filter_by(username="_uh_viewer_notag").delete()
                db.session.commit()

    def test_tag_scoped_user_only_sees_own_guest_history(self, app, client):
        with app.app_context():
            tag = Tag.query.filter_by(name="_uh_tag").first() or Tag(name="_uh_tag")
            db.session.add(tag)
            db.session.flush()
            g_in = Guest(name="_uh-tagged-in", guest_type="ct", enabled=True)
            g_in.tags.append(tag)
            g_out = Guest(name="_uh-tagged-out", guest_type="ct", enabled=True)
            db.session.add_all([g_in, g_out])
            db.session.flush()
            gid_in, gid_out = g_in.id, g_out.id
            db.session.add(UpdateHistory(guest_id=gid_in, package_count=3, security_count=0,
                                          initiated_by="tester"))
            db.session.add(UpdateHistory(guest_id=gid_out, package_count=9, security_count=0,
                                          initiated_by="tester"))
            db.session.commit()

            viewer = Role.query.filter_by(name="viewer").first()
            u = User(username="_uh_tagscoped", display_name="V", role_id=viewer.id)
            u.set_password("ViewerPass123!")
            u.allowed_tags.append(tag)
            db.session.add(u)
            db.session.commit()

        client.post("/login", data={"username": "_uh_tagscoped", "password": "ViewerPass123!"})
        try:
            resp = client.get(f"/trends/?guest_id={gid_in}")
            assert resp.status_code == 200
            assert b"_uh-tagged-in" in resp.data

            resp2 = client.get(f"/trends/?guest_id={gid_out}")
            assert resp2.status_code == 200
            # Guest select dropdown should not offer the out-of-scope guest.
            assert b"_uh-tagged-out" not in resp2.data
        finally:
            with app.app_context():
                User.query.filter_by(username="_uh_tagscoped").delete()
                UpdateHistory.query.filter(UpdateHistory.guest_id.in_([gid_in, gid_out])).delete(
                    synchronize_session=False
                )
                Guest.query.filter(Guest.id.in_([gid_in, gid_out])).delete(synchronize_session=False)
                db.session.commit()


class TestTrendsRouteRendering:
    def test_renders_with_no_history_at_all(self, auth_client):
        # No guarantee the shared in-memory DB is empty, but the page must not
        # error out when a guest has zero UpdateHistory rows.
        resp = auth_client.get("/trends/")
        assert resp.status_code == 200

    def test_renders_weekly_chart_when_history_exists(self, app, auth_client):
        gid = _make_guest(app, "_uh-chart-guest")
        try:
            with app.app_context():
                db.session.add(UpdateHistory(
                    guest_id=gid, package_count=5, security_count=2,
                    applied_at=datetime.now(timezone.utc) - timedelta(days=3),
                    initiated_by="admin",
                ))
                db.session.commit()

            resp = auth_client.get("/trends/")
            assert resp.status_code == 200
            assert b"chartWeekly" in resp.data
        finally:
            _cleanup(app, (Guest, gid))

    def test_per_guest_history_section_shows_entries(self, app, auth_client):
        gid = _make_guest(app, "_uh-perguest")
        try:
            with app.app_context():
                db.session.add(UpdateHistory(
                    guest_id=gid, package_count=4, security_count=1,
                    packages_summary="libssl, curl, nginx, python3",
                    initiated_by="bob",
                ))
                db.session.commit()

            resp = auth_client.get(f"/trends/?guest_id={gid}")
            assert resp.status_code == 200
            assert b"_uh-perguest" in resp.data
            assert b"bob" in resp.data
            assert b"libssl" in resp.data
        finally:
            _cleanup(app, (Guest, gid))

    def test_guest_detail_links_to_history(self, app, auth_client):
        gid = _make_guest(app, "_uh-detail-link")
        try:
            resp = auth_client.get(f"/guests/{gid}")
            assert resp.status_code == 200
            assert f"/trends/?guest_id={gid}".encode() in resp.data
        finally:
            _cleanup(app, (Guest, gid))


class TestChronicallyBehindRanking:
    def test_ranks_by_oldest_pending_first(self, app):
        with app.app_context():
            g_old = Guest(name="_uh-behind-old", guest_type="ct", enabled=True)
            g_new = Guest(name="_uh-behind-new", guest_type="ct", enabled=True)
            db.session.add_all([g_old, g_new])
            db.session.flush()
            gid_old, gid_new = g_old.id, g_new.id

            db.session.add(UpdatePackage(
                guest_id=gid_old, package_name="old-pkg", severity="normal", status="pending",
                discovered_at=datetime.now(timezone.utc) - timedelta(days=45),
            ))
            db.session.add(UpdatePackage(
                guest_id=gid_new, package_name="new-pkg", severity="critical", status="pending",
                discovered_at=datetime.now(timezone.utc) - timedelta(days=2),
            ))
            db.session.commit()

        try:
            with app.app_context():
                from core.update_trends import chronically_behind

                guests = Guest.query.filter(Guest.id.in_([gid_old, gid_new])).all()
                ranked = chronically_behind(guests)

                assert len(ranked) == 2
                assert ranked[0]["guest"].id == gid_old
                assert ranked[0]["oldest_pending_days"] >= 44
                assert ranked[1]["guest"].id == gid_new
                assert ranked[1]["pending_security_count"] == 1
        finally:
            _cleanup(app, (Guest, gid_old), (Guest, gid_new))

    def test_excludes_guests_with_no_pending_updates(self, app):
        gid = _make_guest(app, "_uh-behind-clean")
        try:
            with app.app_context():
                from core.update_trends import chronically_behind

                guests = Guest.query.filter(Guest.id == gid).all()
                ranked = chronically_behind(guests)
                assert ranked == []
        finally:
            _cleanup(app, (Guest, gid))

    def test_days_since_last_update_uses_history(self, app):
        with app.app_context():
            g = Guest(name="_uh-behind-hist", guest_type="ct", enabled=True)
            db.session.add(g)
            db.session.flush()
            gid = g.id
            db.session.add(UpdatePackage(
                guest_id=gid, package_name="pkg", severity="normal", status="pending",
                discovered_at=datetime.now(timezone.utc) - timedelta(days=5),
            ))
            db.session.add(UpdateHistory(
                guest_id=gid, package_count=1, security_count=0,
                applied_at=datetime.now(timezone.utc) - timedelta(days=20),
            ))
            db.session.commit()

        try:
            with app.app_context():
                from core.update_trends import chronically_behind

                guests = Guest.query.filter(Guest.id == gid).all()
                ranked = chronically_behind(guests)
                assert len(ranked) == 1
                assert ranked[0]["days_since_last_update"] >= 19
        finally:
            _cleanup(app, (Guest, gid))

    def test_never_updated_guest_has_none_days_since(self, app):
        with app.app_context():
            g = Guest(name="_uh-behind-never", guest_type="ct", enabled=True)
            db.session.add(g)
            db.session.flush()
            gid = g.id
            db.session.add(UpdatePackage(
                guest_id=gid, package_name="pkg", severity="normal", status="pending",
            ))
            db.session.commit()

        try:
            with app.app_context():
                from core.update_trends import chronically_behind

                guests = Guest.query.filter(Guest.id == gid).all()
                ranked = chronically_behind(guests)
                assert ranked[0]["days_since_last_update"] is None
        finally:
            _cleanup(app, (Guest, gid))


class TestWeeklyApplySeries:
    def test_empty_guest_ids_returns_zero_filled_buckets(self, app):
        with app.app_context():
            from core.update_trends import weekly_apply_series

            series = weekly_apply_series([], days=14)
            assert len(series) >= 2
            assert all(b["total"] == 0 and b["security"] == 0 for b in series)

    def test_buckets_totals_by_week(self, app):
        gid = _make_guest(app, "_uh-series-guest")
        try:
            with app.app_context():
                from core.update_trends import weekly_apply_series

                db.session.add(UpdateHistory(
                    guest_id=gid, package_count=3, security_count=1,
                    applied_at=datetime.now(timezone.utc) - timedelta(days=1),
                ))
                db.session.commit()

                series = weekly_apply_series([gid], days=90)
                total = sum(b["total"] for b in series)
                security = sum(b["security"] for b in series)
                assert total == 3
                assert security == 1
        finally:
            _cleanup(app, (Guest, gid))
