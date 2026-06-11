"""Authorization tests for API status/cancel endpoints."""
from models import Guest, Role, Tag, User, db
from routes.api import ProxmoxJob, UpdateJob, _proxmox_jobs, _update_jobs


def _login(client, username, password):
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=False,
    )


class TestApiAuthorization:
    def test_update_status_denies_inaccessible_guest(self, app, client):
        with app.app_context():
            viewer_role = Role.query.filter_by(name="viewer").first()
            user = User(username="api_viewer_status", display_name="API Viewer", role_id=viewer_role.id)
            user.set_password("ViewerPass123!")
            guest = Guest(name="_api-authz-status", guest_type="ct", enabled=True)
            db.session.add_all([user, guest])
            db.session.commit()
            guest_id = guest.id

        _update_jobs[guest_id] = UpdateJob(guest_id, "_api-authz-status")
        _login(client, "api_viewer_status", "ViewerPass123!")

        resp = client.get(f"/api/apply/{guest_id}/status")
        assert resp.status_code == 403
        assert resp.get_json()["error"] == "forbidden"

        with app.app_context():
            User.query.filter_by(username="api_viewer_status").delete()
            Guest.query.filter_by(id=guest_id).delete()
            db.session.commit()
        _update_jobs.pop(guest_id, None)

    def test_update_cancel_denies_inaccessible_guest(self, app, client):
        with app.app_context():
            viewer_role = Role.query.filter_by(name="viewer").first()
            user = User(username="api_viewer_cancel", display_name="API Viewer", role_id=viewer_role.id)
            user.set_password("ViewerPass123!")
            guest = Guest(name="_api-authz-cancel", guest_type="ct", enabled=True)
            db.session.add_all([user, guest])
            db.session.commit()
            guest_id = guest.id

        _update_jobs[guest_id] = UpdateJob(guest_id, "_api-authz-cancel")
        _login(client, "api_viewer_cancel", "ViewerPass123!")

        resp = client.post(f"/api/apply/{guest_id}/cancel")
        assert resp.status_code == 403
        payload = resp.get_json()
        assert payload["ok"] is False
        assert payload["error"] == "forbidden"

        with app.app_context():
            User.query.filter_by(username="api_viewer_cancel").delete()
            Guest.query.filter_by(id=guest_id).delete()
            db.session.commit()
        _update_jobs.pop(guest_id, None)

    def test_task_status_denies_inaccessible_guest(self, app, client):
        with app.app_context():
            viewer_role = Role.query.filter_by(name="viewer").first()
            user = User(username="api_viewer_task_status", display_name="API Viewer", role_id=viewer_role.id)
            user.set_password("ViewerPass123!")
            guest = Guest(name="_api-task-status", guest_type="ct", enabled=True)
            db.session.add_all([user, guest])
            db.session.commit()
            guest_id = guest.id

        job_key = f"backup:{guest_id}"
        _proxmox_jobs[job_key] = ProxmoxJob(
            guest_id=guest_id,
            guest_name="_api-task-status",
            job_type="backup",
            upid="UPID:test",
            node="node1",
            host_model=None,
        )
        _login(client, "api_viewer_task_status", "ViewerPass123!")

        resp = client.get(f"/api/task/{guest_id}/backup/status")
        assert resp.status_code == 403
        assert resp.get_json()["error"] == "forbidden"

        with app.app_context():
            User.query.filter_by(username="api_viewer_task_status").delete()
            Guest.query.filter_by(id=guest_id).delete()
            db.session.commit()
        _proxmox_jobs.pop(job_key, None)

    def test_task_cancel_denies_inaccessible_guest(self, app, client):
        with app.app_context():
            viewer_role = Role.query.filter_by(name="viewer").first()
            user = User(username="api_viewer_task_cancel", display_name="API Viewer", role_id=viewer_role.id)
            user.set_password("ViewerPass123!")
            guest = Guest(name="_api-task-cancel", guest_type="ct", enabled=True)
            db.session.add_all([user, guest])
            db.session.commit()
            guest_id = guest.id

        job_key = f"backup:{guest_id}"
        _proxmox_jobs[job_key] = ProxmoxJob(
            guest_id=guest_id,
            guest_name="_api-task-cancel",
            job_type="backup",
            upid="UPID:test",
            node="node1",
            host_model=None,
        )
        _login(client, "api_viewer_task_cancel", "ViewerPass123!")

        resp = client.post(f"/api/task/{guest_id}/backup/cancel")
        assert resp.status_code == 403
        payload = resp.get_json()
        assert payload["ok"] is False
        assert payload["error"] == "forbidden"

        with app.app_context():
            User.query.filter_by(username="api_viewer_task_cancel").delete()
            Guest.query.filter_by(id=guest_id).delete()
            db.session.commit()
        _proxmox_jobs.pop(job_key, None)

    def test_update_status_allows_admin(self, app, auth_client):
        with app.app_context():
            guest = Guest(name="_api-authz-status-ok", guest_type="ct", enabled=True)
            db.session.add(guest)
            db.session.commit()
            guest_id = guest.id

        resp = auth_client.get(f"/api/apply/{guest_id}/status")
        assert resp.status_code == 200

        with app.app_context():
            Guest.query.filter_by(id=guest_id).delete()
            db.session.commit()

    def test_update_cancel_allows_admin(self, app, auth_client):
        with app.app_context():
            guest = Guest(name="_api-authz-cancel-ok", guest_type="ct", enabled=True)
            db.session.add(guest)
            db.session.commit()
            guest_id = guest.id

        resp = auth_client.post(f"/api/apply/{guest_id}/cancel")
        assert resp.status_code == 200  # reaches handler (no active job), not 403

        with app.app_context():
            Guest.query.filter_by(id=guest_id).delete()
            db.session.commit()

    def test_task_status_allows_admin(self, app, auth_client):
        with app.app_context():
            guest = Guest(name="_api-task-status-ok", guest_type="ct", enabled=True)
            db.session.add(guest)
            db.session.commit()
            guest_id = guest.id

        resp = auth_client.get(f"/api/task/{guest_id}/backup/status")
        assert resp.status_code == 200

        with app.app_context():
            Guest.query.filter_by(id=guest_id).delete()
            db.session.commit()

    def test_task_cancel_allows_admin(self, app, auth_client):
        with app.app_context():
            guest = Guest(name="_api-task-cancel-ok", guest_type="ct", enabled=True)
            db.session.add(guest)
            db.session.commit()
            guest_id = guest.id

        resp = auth_client.post(f"/api/task/{guest_id}/backup/cancel")
        assert resp.status_code == 200  # reaches handler (no active job), not 403

        with app.app_context():
            Guest.query.filter_by(id=guest_id).delete()
            db.session.commit()


class TestApplyUpdatePermission:
    """POST /api/apply must require the can_update permission, not just
    tag-based read access to the guest (issue #76)."""

    def test_apply_denied_for_tagged_viewer_without_can_update(self, app, client):
        with app.app_context():
            viewer_role = Role.query.filter_by(name="viewer").first()
            assert viewer_role.can_update is False  # guard: viewer is read-only
            user = User(username="api_apply_viewer", display_name="Apply Viewer",
                        role_id=viewer_role.id)
            user.set_password("ViewerPass123!")
            tag = Tag(name="_apply-authz-tag", color="#123456")
            guest = Guest(name="_api-apply-authz", guest_type="ct", enabled=True)
            guest.tags.append(tag)
            user.allowed_tags.append(tag)
            db.session.add_all([user, tag, guest])
            db.session.commit()
            guest_id = guest.id
            # Sanity: the viewer DOES have read access, so only can_update blocks them.
            assert user.can_access_guest(guest) is True

        _login(client, "api_apply_viewer", "ViewerPass123!")

        resp = client.post(f"/api/apply/{guest_id}", data={"dist_upgrade": "0"})
        # Redirected away (not allowed to start the update)...
        assert resp.status_code == 302
        # ...and crucially no background update job was created.
        assert guest_id not in _update_jobs

        with app.app_context():
            guest = Guest.query.get(guest_id)
            for t in list(guest.tags):
                guest.tags.remove(t)
            u = User.query.filter_by(username="api_apply_viewer").first()
            for t in list(u.allowed_tags):
                u.allowed_tags.remove(t)
            db.session.commit()
            User.query.filter_by(username="api_apply_viewer").delete()
            Guest.query.filter_by(id=guest_id).delete()
            Tag.query.filter_by(name="_apply-authz-tag").delete()
            db.session.commit()
        _update_jobs.pop(guest_id, None)
