"""Tests for Jibri recording/streaming routes and backend logic."""


# ---------------------------------------------------------------------------
# Route tests — authentication
# ---------------------------------------------------------------------------


class TestJibriRouteAuth:
    """Jibri routes require authentication and can_update permission."""

    def test_manage_page_unauthenticated(self, client):
        resp = client.get("/jibri/manage", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers.get("Location", "")

    def test_save_unauthenticated(self, client):
        resp = client.post("/jibri/save", follow_redirects=False)
        assert resp.status_code == 302

    def test_preflight_unauthenticated(self, client):
        resp = client.post("/jibri/preflight", follow_redirects=False)
        assert resp.status_code == 302

    def test_preflight_status_unauthenticated(self, client):
        resp = client.get("/jibri/preflight/status", follow_redirects=False)
        assert resp.status_code == 302

    def test_install_unauthenticated(self, client):
        resp = client.post("/jibri/install", follow_redirects=False)
        assert resp.status_code == 302

    def test_install_status_unauthenticated(self, client):
        resp = client.get("/jibri/install/status", follow_redirects=False)
        assert resp.status_code == 302

    def test_configure_jitsi_unauthenticated(self, client):
        resp = client.post("/jibri/configure-jitsi", follow_redirects=False)
        assert resp.status_code == 302

    def test_configure_jitsi_status_unauthenticated(self, client):
        resp = client.get("/jibri/configure-jitsi/status", follow_redirects=False)
        assert resp.status_code == 302

    def test_configure_smb_unauthenticated(self, client):
        resp = client.post("/jibri/configure-smb", follow_redirects=False)
        assert resp.status_code == 302

    def test_configure_smb_status_unauthenticated(self, client):
        resp = client.get("/jibri/configure-smb/status", follow_redirects=False)
        assert resp.status_code == 302

    def test_status_unauthenticated(self, client):
        resp = client.get("/jibri/status", follow_redirects=False)
        assert resp.status_code == 302

    def test_record_start_unauthenticated(self, client):
        resp = client.post("/jibri/record/start", follow_redirects=False)
        assert resp.status_code == 302

    def test_record_stop_unauthenticated(self, client):
        resp = client.post("/jibri/record/stop", follow_redirects=False)
        assert resp.status_code == 302

    def test_stream_start_unauthenticated(self, client):
        resp = client.post("/jibri/stream/start", follow_redirects=False)
        assert resp.status_code == 302

    def test_stream_stop_unauthenticated(self, client):
        resp = client.post("/jibri/stream/stop", follow_redirects=False)
        assert resp.status_code == 302

    def test_recordings_unauthenticated(self, client):
        resp = client.get("/jibri/recordings", follow_redirects=False)
        assert resp.status_code == 302

    def test_recordings_delete_unauthenticated(self, client):
        resp = client.post("/jibri/recordings/delete", follow_redirects=False)
        assert resp.status_code == 302


# ---------------------------------------------------------------------------
# Route tests — viewer denied
# ---------------------------------------------------------------------------


class TestJibriRouteViewer:
    """Viewer users (can_update=False) should be denied access."""

    def test_viewer_denied_manage_page(self, app, client):
        from models import Role, User, db

        with app.app_context():
            viewer_role = Role.query.filter_by(name="viewer").first()
            user = User(
                username="_jibri_test_viewer",
                display_name="Jibri Viewer",
                role_id=viewer_role.id,
            )
            user.set_password("ViewerPass123!")
            db.session.add(user)
            db.session.commit()

        try:
            client.post(
                "/login",
                data={"username": "_jibri_test_viewer", "password": "ViewerPass123!"},
                follow_redirects=False,
            )
            resp = client.get("/jibri/manage", follow_redirects=False)
            assert resp.status_code == 302
            location = resp.headers.get("Location", "")
            assert "/jibri" not in location
        finally:
            with app.app_context():
                User.query.filter_by(username="_jibri_test_viewer").delete()
                db.session.commit()


# ---------------------------------------------------------------------------
# Route tests — authenticated admin
# ---------------------------------------------------------------------------


class TestJibriRouteAuthed:
    """Admin users (can_update=True) can access Jibri routes."""

    def test_manage_page_loads(self, auth_client):
        resp = auth_client.get("/jibri/manage")
        assert resp.status_code == 200
        assert b"Jibri" in resp.data

    def test_preflight_status_returns_json(self, auth_client):
        resp = auth_client.get("/jibri/preflight/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "running" in data
        assert "success" in data
        assert "log" in data

    def test_install_status_returns_json(self, auth_client):
        resp = auth_client.get("/jibri/install/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "running" in data
        assert "success" in data
        assert "log" in data

    def test_configure_status_returns_json(self, auth_client):
        resp = auth_client.get("/jibri/configure-jitsi/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "running" in data
        assert "success" in data
        assert "log" in data

    def test_smb_status_returns_json(self, auth_client):
        resp = auth_client.get("/jibri/configure-smb/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "running" in data
        assert "success" in data
        assert "log" in data

    def test_jibri_status_returns_json(self, auth_client):
        resp = auth_client.get("/jibri/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "status" in data
        assert "service" in data

    def test_recordings_returns_json(self, auth_client):
        resp = auth_client.get("/jibri/recordings")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "recordings" in data

    def test_save_persists_settings(self, app, auth_client):
        from models import Setting

        resp = auth_client.post(
            "/jibri/save",
            data={
                "jibri_guest_id": "42",
                "jibri_recording_dir": "/mnt/recordings",
                "jibri_protection_type": "backup",
                "jibri_backup_storage": "local-zfs",
                "jibri_backup_mode": "suspend",
                "jibri_smb_share": "//nas/recordings",
                "jibri_smb_username": "jibri_user",
                "jibri_smb_password": "test-only-not-real",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            assert Setting.get("jibri_guest_id") == "42"
            assert Setting.get("jibri_recording_dir") == "/mnt/recordings"
            assert Setting.get("jibri_protection_type") == "backup"
            assert Setting.get("jibri_backup_storage") == "local-zfs"
            assert Setting.get("jibri_backup_mode") == "suspend"
            assert Setting.get("jibri_smb_share") == "//nas/recordings"
            assert Setting.get("jibri_smb_username") == "jibri_user"
            assert Setting.get("jibri_smb_password") == "test-only-not-real"

    def test_save_validates_protection_type(self, app, auth_client):
        from models import Setting

        auth_client.post(
            "/jibri/save",
            data={"jibri_protection_type": "invalid"},
            follow_redirects=False,
        )
        with app.app_context():
            assert Setting.get("jibri_protection_type") == "snapshot"

    def test_save_validates_backup_mode(self, app, auth_client):
        from models import Setting

        auth_client.post(
            "/jibri/save",
            data={
                "jibri_backup_mode": "invalid",
                "jibri_protection_type": "backup",
            },
            follow_redirects=False,
        )
        with app.app_context():
            assert Setting.get("jibri_backup_mode") == "snapshot"

    def test_save_preserves_existing_smb_password(self, app, auth_client):
        """When no password is provided in the form, existing password is kept."""
        from models import Setting

        with app.app_context():
            Setting.set("jibri_smb_password", "test-only-existing")

        auth_client.post(
            "/jibri/save",
            data={
                "jibri_smb_share": "//nas/share",
                "jibri_smb_username": "user",
                "jibri_smb_password": "",  # blank = keep existing
            },
            follow_redirects=False,
        )
        with app.app_context():
            assert Setting.get("jibri_smb_password") == "test-only-existing"

    def test_save_default_recording_dir(self, app, auth_client):
        """Empty recording dir falls back to default."""
        from models import Setting

        auth_client.post(
            "/jibri/save",
            data={"jibri_recording_dir": ""},
            follow_redirects=False,
        )
        with app.app_context():
            assert Setting.get("jibri_recording_dir") == "/srv/recordings"

    def test_record_start_no_room(self, auth_client):
        """Start recording without room name should flash warning."""
        resp = auth_client.post(
            "/jibri/record/start",
            data={"room_name": ""},
            follow_redirects=False,
        )
        assert resp.status_code == 302

    def test_stream_start_no_room(self, auth_client):
        """Start streaming without room name should flash warning."""
        resp = auth_client.post(
            "/jibri/stream/start",
            data={"room_name": "", "rtmp_url": "rtmp://example.com/live"},
            follow_redirects=False,
        )
        assert resp.status_code == 302

    def test_stream_start_no_rtmp(self, auth_client):
        """Start streaming without RTMP URL should flash warning."""
        resp = auth_client.post(
            "/jibri/stream/start",
            data={"room_name": "test-room", "rtmp_url": ""},
            follow_redirects=False,
        )
        assert resp.status_code == 302

    def test_recordings_delete_no_filename(self, auth_client):
        """Delete recording without filename should flash warning."""
        resp = auth_client.post(
            "/jibri/recordings/delete",
            data={"filename": ""},
            follow_redirects=False,
        )
        assert resp.status_code == 302

    def test_configure_jitsi_not_installed(self, app, auth_client):
        """Cannot configure Jitsi server if Jibri not installed."""
        from models import Setting

        with app.app_context():
            Setting.set("jibri_installed", "false")
        resp = auth_client.post("/jibri/configure-jitsi", follow_redirects=False)
        assert resp.status_code == 302

    def test_configure_smb_not_installed(self, app, auth_client):
        """Cannot configure SMB if Jibri not installed."""
        from models import Setting

        with app.app_context():
            Setting.set("jibri_installed", "false")
        resp = auth_client.post("/jibri/configure-smb", follow_redirects=False)
        assert resp.status_code == 302


# ---------------------------------------------------------------------------
# Applications index
# ---------------------------------------------------------------------------


class TestApplicationsIndexJibri:
    """Jibri appears on the applications index page."""

    def test_jibri_card_present(self, auth_client):
        resp = auth_client.get("/applications/")
        assert resp.status_code == 200
        assert b"Jibri" in resp.data
        assert b"/jibri/manage" in resp.data


# ---------------------------------------------------------------------------
# Backend logic — preflight
# ---------------------------------------------------------------------------


class TestJibriPreflight:
    """Unit tests for Jibri pre-flight validation."""

    def test_preflight_fails_no_guest(self, app):
        from apps.jibri import run_jibri_preflight
        from models import Setting

        with app.app_context():
            Setting.set("jibri_guest_id", "")
            Setting.set("jitsi_installed", "true")
            Setting.set("jitsi_hostname", "meet.example.com")

            ok, log_output = run_jibri_preflight()
            assert not ok
            assert "not set" in log_output

    def test_preflight_fails_jitsi_not_installed(self, app):
        from apps.jibri import run_jibri_preflight
        from models import Setting

        with app.app_context():
            Setting.set("jibri_guest_id", "99")
            Setting.set("jitsi_installed", "false")
            Setting.set("jitsi_hostname", "meet.example.com")

            ok, log_output = run_jibri_preflight()
            assert not ok
            assert "Jitsi must be installed" in log_output

    def test_preflight_fails_no_jitsi_hostname(self, app):
        from apps.jibri import run_jibri_preflight
        from models import Setting

        with app.app_context():
            Setting.set("jibri_guest_id", "99")
            Setting.set("jitsi_installed", "true")
            Setting.set("jitsi_hostname", "")

            ok, log_output = run_jibri_preflight()
            assert not ok
            assert "hostname" in log_output.lower()

    def test_preflight_fails_guest_not_found(self, app):
        from apps.jibri import run_jibri_preflight
        from models import Setting

        with app.app_context():
            Setting.set("jibri_guest_id", "99999")
            Setting.set("jitsi_installed", "true")
            Setting.set("jitsi_hostname", "meet.example.com")

            ok, log_output = run_jibri_preflight()
            assert not ok
            assert "not found" in log_output


# ---------------------------------------------------------------------------
# Backend logic — recording management
# ---------------------------------------------------------------------------


class TestJibriRecordingManagement:
    """Unit tests for recording file operations."""

    def test_delete_recording_path_traversal(self, app):
        from apps.jibri import delete_recording
        from models import Setting

        with app.app_context():
            Setting.set("jibri_installed", "true")
            Setting.set("jibri_guest_id", "99")

            ok, msg = delete_recording("../../etc/passwd")
            assert not ok
            assert "Invalid" in msg

    def test_delete_recording_absolute_path(self, app):
        from apps.jibri import delete_recording
        from models import Setting

        with app.app_context():
            Setting.set("jibri_installed", "true")
            Setting.set("jibri_guest_id", "99")

            ok, msg = delete_recording("/etc/passwd")
            assert not ok
            assert "Invalid" in msg

    def test_delete_recording_empty_filename(self, app):
        from apps.jibri import delete_recording

        with app.app_context():
            ok, msg = delete_recording("")
            assert not ok
            assert "required" in msg.lower()

    def test_list_recordings_not_installed(self, app):
        from apps.jibri import list_recordings
        from models import Setting

        with app.app_context():
            Setting.set("jibri_installed", "false")

            recordings, error = list_recordings()
            assert recordings == []
            assert "not installed" in error.lower()


# ---------------------------------------------------------------------------
# Backend logic — recording/streaming control
# ---------------------------------------------------------------------------


class TestJibriRecordingControl:
    """Unit tests for start/stop recording."""

    def test_start_recording_not_installed(self, app):
        from apps.jibri import start_recording
        from models import Setting

        with app.app_context():
            Setting.set("jibri_installed", "false")

            ok, msg = start_recording("test-room")
            assert not ok
            assert "not installed" in msg.lower()

    def test_start_recording_not_enabled(self, app):
        from apps.jibri import start_recording
        from models import Setting

        with app.app_context():
            Setting.set("jibri_installed", "true")
            Setting.set("jibri_enabled", "false")

            ok, msg = start_recording("test-room")
            assert not ok
            assert "not enabled" in msg.lower()

    def test_start_recording_empty_room(self, app):
        from apps.jibri import start_recording
        from models import Setting

        with app.app_context():
            Setting.set("jibri_installed", "true")
            Setting.set("jibri_enabled", "true")

            ok, msg = start_recording("")
            assert not ok
            assert "required" in msg.lower()

    def test_stop_recording_not_installed(self, app):
        from apps.jibri import stop_recording
        from models import Setting

        with app.app_context():
            Setting.set("jibri_installed", "false")

            ok, msg = stop_recording()
            assert not ok
            assert "not installed" in msg.lower()


class TestJibriStreamingControl:
    """Unit tests for start/stop streaming."""

    def test_start_streaming_not_installed(self, app):
        from apps.jibri import start_streaming
        from models import Setting

        with app.app_context():
            Setting.set("jibri_installed", "false")

            ok, msg = start_streaming("test-room", "rtmp://example.com/live", "key123")
            assert not ok
            assert "not installed" in msg.lower()

    def test_start_streaming_empty_room(self, app):
        from apps.jibri import start_streaming
        from models import Setting

        with app.app_context():
            Setting.set("jibri_installed", "true")
            Setting.set("jibri_enabled", "true")

            ok, msg = start_streaming("", "rtmp://example.com/live", "key123")
            assert not ok
            assert "required" in msg.lower()

    def test_start_streaming_empty_rtmp(self, app):
        from apps.jibri import start_streaming
        from models import Setting

        with app.app_context():
            Setting.set("jibri_installed", "true")
            Setting.set("jibri_enabled", "true")

            ok, msg = start_streaming("test-room", "", "key123")
            assert not ok
            assert "required" in msg.lower()


# ---------------------------------------------------------------------------
# Backend logic — SMB configuration
# ---------------------------------------------------------------------------


class TestJibriSMBConfig:
    """Unit tests for SMB mount configuration."""

    def test_smb_not_installed(self, app):
        from apps.jibri import configure_smb_mount
        from models import Setting

        with app.app_context():
            Setting.set("jibri_installed", "false")

            ok, msg = configure_smb_mount()
            assert not ok
            assert "installed" in msg.lower()

    def test_smb_no_share_path(self, app):
        from apps.jibri import configure_smb_mount
        from models import Setting

        with app.app_context():
            Setting.set("jibri_installed", "true")
            Setting.set("jibri_guest_id", "99")
            Setting.set("jibri_smb_share", "")

            ok, msg = configure_smb_mount()
            assert not ok
            assert "not configured" in msg.lower()

    def test_smb_invalid_share_path(self, app):
        from apps.jibri import configure_smb_mount
        from models import Setting

        with app.app_context():
            Setting.set("jibri_installed", "true")
            Setting.set("jibri_guest_id", "99")
            Setting.set("jibri_smb_share", "not-a-valid-path")

            ok, msg = configure_smb_mount()
            assert not ok
            assert "Invalid" in msg

    def test_smb_no_username(self, app):
        from apps.jibri import configure_smb_mount
        from models import Setting

        with app.app_context():
            Setting.set("jibri_installed", "true")
            Setting.set("jibri_guest_id", "99")
            Setting.set("jibri_smb_share", "//nas/recordings")
            Setting.set("jibri_smb_username", "")

            ok, msg = configure_smb_mount()
            assert not ok
            assert "username" in msg.lower()


# ---------------------------------------------------------------------------
# Backend logic — Jibri status
# ---------------------------------------------------------------------------


class TestJibriStatus:
    """Unit tests for Jibri status check."""

    def test_status_not_installed(self, app):
        from apps.jibri import check_jibri_status
        from models import Setting

        with app.app_context():
            Setting.set("jibri_installed", "false")

            result = check_jibri_status()
            assert result["service"] == "not_installed"
            assert result["status"] == "unhealthy"

    def test_status_no_guest_id(self, app):
        from apps.jibri import check_jibri_status
        from models import Setting

        with app.app_context():
            Setting.set("jibri_installed", "true")
            Setting.set("jibri_guest_id", "")

            result = check_jibri_status()
            assert result["status"] == "unhealthy"


# ---------------------------------------------------------------------------
# Backend logic — install validation
# ---------------------------------------------------------------------------


class TestJibriInstallValidation:
    """Unit tests for install input validation (before SSH)."""

    def test_install_no_guest(self, app):
        from apps.jibri import run_jibri_install
        from models import Setting

        with app.app_context():
            Setting.set("jibri_guest_id", "")

            ok, msg = run_jibri_install()
            assert not ok
            assert "not configured" in msg.lower()

    def test_install_no_jitsi_hostname(self, app):
        from apps.jibri import run_jibri_install
        from models import Guest, Setting, db

        with app.app_context():
            # Create a VM guest
            guest = Guest(name="test-jibri-vm", vmid=200, guest_type="vm", enabled=True)
            db.session.add(guest)
            db.session.commit()
            Setting.set("jibri_guest_id", str(guest.id))
            Setting.set("jitsi_installed", "true")
            Setting.set("jitsi_hostname", "")

            ok, msg = run_jibri_install()
            assert not ok
            assert "hostname" in msg.lower()

            # Cleanup
            db.session.delete(guest)
            db.session.commit()

    def test_install_lxc_rejected(self, app):
        from apps.jibri import run_jibri_install
        from models import Guest, Setting, db

        with app.app_context():
            # Create an LXC guest
            guest = Guest(name="test-jibri-lxc", vmid=201, guest_type="lxc", enabled=True)
            db.session.add(guest)
            db.session.commit()
            Setting.set("jibri_guest_id", str(guest.id))
            Setting.set("jitsi_installed", "true")
            Setting.set("jitsi_hostname", "meet.example.com")

            ok, msg = run_jibri_install()
            assert not ok
            assert "VM" in msg

            # Cleanup
            db.session.delete(guest)
            db.session.commit()

    def test_install_jitsi_not_installed(self, app):
        from apps.jibri import run_jibri_install
        from models import Guest, Setting, db

        with app.app_context():
            guest = Guest(name="test-jibri-vm2", vmid=202, guest_type="vm", enabled=True)
            db.session.add(guest)
            db.session.commit()
            Setting.set("jibri_guest_id", str(guest.id))
            Setting.set("jitsi_installed", "false")
            Setting.set("jitsi_hostname", "meet.example.com")

            ok, msg = run_jibri_install()
            assert not ok
            assert "Jitsi" in msg

            # Cleanup
            db.session.delete(guest)
            db.session.commit()


# ---------------------------------------------------------------------------
# Backend logic — Jitsi server configure validation
# ---------------------------------------------------------------------------


class TestJibriJitsiConfigureValidation:
    """Unit tests for Jitsi server configuration validation."""

    def test_configure_jitsi_not_installed(self, app):
        from apps.jibri import run_jibri_jitsi_configure
        from models import Setting

        with app.app_context():
            Setting.set("jitsi_installed", "false")

            ok, msg = run_jibri_jitsi_configure()
            assert not ok
            assert "Jitsi" in msg

    def test_configure_jibri_not_installed(self, app):
        from apps.jibri import run_jibri_jitsi_configure
        from models import Setting

        with app.app_context():
            Setting.set("jitsi_installed", "true")
            Setting.set("jibri_installed", "false")

            ok, msg = run_jibri_jitsi_configure()
            assert not ok
            assert "Jibri" in msg

    def test_configure_no_xmpp_credentials(self, app):
        from apps.jibri import run_jibri_jitsi_configure
        from models import Setting

        with app.app_context():
            Setting.set("jitsi_installed", "true")
            Setting.set("jibri_installed", "true")
            Setting.set("jitsi_hostname", "meet.example.com")
            Setting.set("jibri_xmpp_password", "")
            Setting.set("jibri_recorder_password", "")

            ok, msg = run_jibri_jitsi_configure()
            assert not ok
            assert "credentials" in msg.lower()
