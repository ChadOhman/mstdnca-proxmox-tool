"""Tests for maintenance schedule routes."""
import pytest

from models import MaintenanceWindow, db

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def window(app):
    """Seed a single MaintenanceWindow row; clean up after the test."""
    win_id = None
    with app.app_context():
        w = MaintenanceWindow(
            name="_test-window",
            day_of_week="sunday",
            start_time="02:00",
            end_time="05:00",
            update_type="upgrade",
            enabled=True,
        )
        db.session.add(w)
        db.session.commit()
        win_id = w.id

    yield win_id

    with app.app_context():
        w = MaintenanceWindow.query.get(win_id)
        if w:
            db.session.delete(w)
            db.session.commit()


# ---------------------------------------------------------------------------
# Route: GET /schedules/
# ---------------------------------------------------------------------------


class TestSchedulesIndex:
    def test_returns_200(self, auth_client):
        resp = auth_client.get("/schedules/")
        assert resp.status_code == 200

    def test_unauthenticated_redirects_to_login(self, client):
        resp = client.get("/schedules/", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_lists_existing_schedules(self, auth_client, window, app):
        with app.app_context():
            w = MaintenanceWindow.query.get(window)
            win_name = w.name

        resp = auth_client.get("/schedules/")
        assert resp.status_code == 200
        assert win_name.encode() in resp.data


# ---------------------------------------------------------------------------
# Route: POST /schedules/add
# ---------------------------------------------------------------------------


class TestScheduleAdd:
    def test_add_happy_path_creates_window(self, app, auth_client):
        win_id = None
        try:
            resp = auth_client.post(
                "/schedules/add",
                data={
                    "name": "_test-add-window",
                    "day_of_week": "monday",
                    "start_time": "03:00",
                    "end_time": "04:00",
                    "update_type": "upgrade",
                },
                follow_redirects=False,
            )
            assert resp.status_code == 302

            with app.app_context():
                w = MaintenanceWindow.query.filter_by(name="_test-add-window").first()
                assert w is not None
                assert w.day_of_week == "monday"
                assert w.start_time == "03:00"
                assert w.end_time == "04:00"
                assert w.update_type == "upgrade"
                assert w.enabled is True
                win_id = w.id
        finally:
            if win_id is not None:
                with app.app_context():
                    w = MaintenanceWindow.query.get(win_id)
                    if w:
                        db.session.delete(w)
                        db.session.commit()

    def test_add_uses_default_values(self, app, auth_client):
        """Omitting optional fields falls back to route defaults."""
        win_id = None
        try:
            resp = auth_client.post(
                "/schedules/add",
                data={"name": "_test-add-defaults"},
                follow_redirects=False,
            )
            assert resp.status_code == 302

            with app.app_context():
                w = MaintenanceWindow.query.filter_by(name="_test-add-defaults").first()
                assert w is not None
                assert w.day_of_week == "sunday"
                assert w.start_time == "02:00"
                assert w.end_time == "05:00"
                assert w.update_type == "upgrade"
                win_id = w.id
        finally:
            if win_id is not None:
                with app.app_context():
                    w = MaintenanceWindow.query.get(win_id)
                    if w:
                        db.session.delete(w)
                        db.session.commit()

    def test_add_missing_name_redirects_without_creating(self, app, auth_client):
        resp = auth_client.post(
            "/schedules/add",
            data={
                "name": "",
                "day_of_week": "friday",
                "start_time": "01:00",
                "end_time": "02:00",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302
        with app.app_context():
            assert MaintenanceWindow.query.filter_by(name="").count() == 0


# ---------------------------------------------------------------------------
# Route: POST /schedules/<id>/toggle
# ---------------------------------------------------------------------------


class TestScheduleToggle:
    def test_toggle_enabled_to_disabled(self, app, auth_client, window):
        resp = auth_client.post(
            f"/schedules/{window}/toggle",
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            w = MaintenanceWindow.query.get(window)
            assert w.enabled is False

    def test_toggle_disabled_to_enabled(self, app, auth_client, window):
        # First toggle: enabled -> disabled
        auth_client.post(f"/schedules/{window}/toggle", follow_redirects=False)
        # Second toggle: disabled -> enabled
        resp = auth_client.post(
            f"/schedules/{window}/toggle",
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            w = MaintenanceWindow.query.get(window)
            assert w.enabled is True

    def test_toggle_nonexistent_returns_404(self, auth_client):
        resp = auth_client.post("/schedules/999999/toggle")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Route: POST /schedules/<id>/delete
# ---------------------------------------------------------------------------


class TestScheduleDelete:
    def test_delete_removes_row(self, app, auth_client, window):
        resp = auth_client.post(
            f"/schedules/{window}/delete",
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            assert MaintenanceWindow.query.get(window) is None

    def test_delete_nonexistent_returns_404(self, auth_client):
        resp = auth_client.post("/schedules/999999/delete")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Issue #126 — day/time validation on POST /schedules/add
# ---------------------------------------------------------------------------


class TestScheduleAddValidation:
    def _post(self, auth_client, **overrides):
        data = {
            "name": "_test-validate",
            "day_of_week": "monday",
            "start_time": "03:00",
            "end_time": "04:00",
            "update_type": "upgrade",
        }
        data.update(overrides)
        return auth_client.post("/schedules/add", data=data, follow_redirects=True)

    def _assert_not_created(self, app, resp, needle):
        assert resp.status_code == 200
        assert needle in resp.get_data(as_text=True)
        with app.app_context():
            assert MaintenanceWindow.query.filter_by(name="_test-validate").count() == 0

    @pytest.mark.parametrize("bad_time", ["3:00", "25:00", "03:60", "morning", "", "0300"])
    def test_bad_start_time_rejected(self, app, auth_client, bad_time):
        resp = self._post(auth_client, start_time=bad_time)
        self._assert_not_created(app, resp, "HH:MM")

    @pytest.mark.parametrize("bad_time", ["4:00", "24:01", "later"])
    def test_bad_end_time_rejected(self, app, auth_client, bad_time):
        resp = self._post(auth_client, end_time=bad_time)
        self._assert_not_created(app, resp, "HH:MM")

    @pytest.mark.parametrize("bad_day", ["someday", "mon", "", "0"])
    def test_bad_day_rejected(self, app, auth_client, bad_day):
        resp = self._post(auth_client, day_of_week=bad_day)
        self._assert_not_created(app, resp, "weekday")

    def test_day_is_normalised_to_lowercase(self, app, auth_client):
        win_id = None
        try:
            resp = self._post(auth_client, day_of_week="Sunday")
            assert resp.status_code == 200
            with app.app_context():
                w = MaintenanceWindow.query.filter_by(name="_test-validate").first()
                assert w is not None
                assert w.day_of_week == "sunday"
                win_id = w.id
        finally:
            if win_id is not None:
                with app.app_context():
                    w = MaintenanceWindow.query.get(win_id)
                    if w:
                        db.session.delete(w)
                        db.session.commit()

    def test_midnight_spanning_window_is_accepted(self, app, auth_client):
        win_id = None
        try:
            self._post(auth_client, start_time="23:00", end_time="02:00", day_of_week="daily")
            with app.app_context():
                w = MaintenanceWindow.query.filter_by(name="_test-validate").first()
                assert w is not None
                assert (w.start_time, w.end_time) == ("23:00", "02:00")
                win_id = w.id
        finally:
            if win_id is not None:
                with app.app_context():
                    w = MaintenanceWindow.query.get(win_id)
                    if w:
                        db.session.delete(w)
                        db.session.commit()
