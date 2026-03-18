"""Tests for guest list route and status filters."""
import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from models import Guest, ProxmoxHost, Setting, Tag, UpdatePackage, db

_NOW = datetime.now(timezone.utc)


@pytest.fixture()
def filter_guests(app):
    """Seed a set of guests covering every filter case, clean up after."""
    ids = []
    with app.app_context():
        guests = [
            Guest(name="_filter-updates", guest_type="ct", status="updates-available", last_scan=_NOW),
            Guest(name="_filter-error", guest_type="ct", status="error", last_scan=_NOW),
            Guest(name="_filter-reboot", guest_type="ct", status="up-to-date", reboot_required=True, last_scan=_NOW),
            Guest(name="_filter-uptodate", guest_type="ct", status="up-to-date", last_scan=_NOW),
            Guest(name="_filter-never-scanned", guest_type="ct"),  # last_scan stays None
        ]
        for g in guests:
            db.session.add(g)
        db.session.flush()

        # Add a critical-severity pending package to the updates guest so
        # ?filter=security also matches it.
        sec_guest = next(g for g in guests if g.name == "_filter-updates")
        db.session.add(UpdatePackage(
            guest_id=sec_guest.id,
            package_name="libc6",
            severity="critical",
            status="pending",
        ))
        db.session.commit()
        ids = [g.id for g in guests]

    yield

    with app.app_context():
        for gid in ids:
            g = Guest.query.get(gid)
            if g:
                db.session.delete(g)
        db.session.commit()


class TestGuestList:
    def test_guest_list_returns_200(self, auth_client):
        resp = auth_client.get("/guests/")
        assert resp.status_code == 200

    def test_guest_list_unauthenticated_redirects(self, client):
        resp = client.get("/guests/", follow_redirects=False)
        assert resp.status_code == 302

    def test_unknown_filter_shows_all(self, auth_client, filter_guests):
        resp = auth_client.get("/guests/?filter=bogus_value")
        assert resp.status_code == 200

    def test_filter_updates(self, auth_client, filter_guests):
        resp = auth_client.get("/guests/?filter=updates")
        assert resp.status_code == 200
        assert b"_filter-updates" in resp.data
        assert b"_filter-uptodate" not in resp.data
        assert b"_filter-never-scanned" not in resp.data

    def test_filter_security(self, auth_client, filter_guests):
        resp = auth_client.get("/guests/?filter=security")
        assert resp.status_code == 200
        assert b"_filter-updates" in resp.data
        assert b"_filter-uptodate" not in resp.data

    def test_filter_reboot(self, auth_client, filter_guests):
        resp = auth_client.get("/guests/?filter=reboot")
        assert resp.status_code == 200
        assert b"_filter-reboot" in resp.data
        assert b"_filter-uptodate" not in resp.data

    def test_filter_never_scanned(self, auth_client, filter_guests):
        resp = auth_client.get("/guests/?filter=never_scanned")
        assert resp.status_code == 200
        assert b"_filter-never-scanned" in resp.data
        assert b"_filter-updates" not in resp.data

    def test_filter_error(self, auth_client, filter_guests):
        resp = auth_client.get("/guests/?filter=error")
        assert resp.status_code == 200
        assert b"_filter-error" in resp.data
        assert b"_filter-uptodate" not in resp.data

    def test_filter_up_to_date(self, auth_client, filter_guests):
        resp = auth_client.get("/guests/?filter=up_to_date")
        assert resp.status_code == 200
        assert b"_filter-uptodate" in resp.data
        assert b"_filter-updates" not in resp.data

    def test_active_filter_badge_shown(self, auth_client, filter_guests):
        """When a filter is active, the template shows the filter label."""
        resp = auth_client.get("/guests/?filter=updates")
        assert b"Pending Updates" in resp.data
        # There should be a way to clear the filter (link back to /guests/)
        assert b"/guests/" in resp.data


class TestGetTagBackupDefaults:
    """Tests for _get_tag_backup_defaults helper in routes/guests.py."""

    def test_returns_empty_when_no_setting(self, app):
        from routes.guests import _get_tag_backup_defaults
        with app.app_context():
            guest = Guest(name="test-guest", guest_type="ct")
            db.session.add(guest)
            db.session.commit()
            assert _get_tag_backup_defaults(guest) == {}

    def test_returns_override_for_matching_tag(self, app):
        from routes.guests import _get_tag_backup_defaults
        with app.app_context():
            tag = Tag(name="production", color="#ff0000")
            guest = Guest(name="prod-guest", guest_type="ct")
            guest.tags.append(tag)
            db.session.add_all([tag, guest])
            db.session.commit()

            overrides = {"production": {"storage": "pbs-prod", "mode": "snapshot"}}
            Setting.set("backup_tag_defaults", json.dumps(overrides))

            result = _get_tag_backup_defaults(guest)
            assert result["storage"] == "pbs-prod"
            assert result["mode"] == "snapshot"

    def test_returns_first_matching_tag(self, app):
        from routes.guests import _get_tag_backup_defaults
        with app.app_context():
            tag1 = Tag(name="alpha", color="#aaa")
            tag2 = Tag(name="beta", color="#bbb")
            guest = Guest(name="multi-tag-guest", guest_type="ct")
            guest.tags.extend([tag1, tag2])
            db.session.add_all([tag1, tag2, guest])
            db.session.commit()

            overrides = {
                "alpha": {"storage": "storage-a"},
                "beta": {"storage": "storage-b"},
            }
            Setting.set("backup_tag_defaults", json.dumps(overrides))

            result = _get_tag_backup_defaults(guest)
            assert result["storage"] == "storage-a"

    def test_returns_empty_when_no_tag_matches(self, app):
        from routes.guests import _get_tag_backup_defaults
        with app.app_context():
            tag = Tag(name="staging", color="#ccc")
            guest = Guest(name="staging-guest", guest_type="ct")
            guest.tags.append(tag)
            db.session.add_all([tag, guest])
            db.session.commit()

            overrides = {"production": {"storage": "pbs-prod"}}
            Setting.set("backup_tag_defaults", json.dumps(overrides))

            assert _get_tag_backup_defaults(guest) == {}

    def test_handles_invalid_json(self, app):
        from routes.guests import _get_tag_backup_defaults
        with app.app_context():
            guest = Guest(name="bad-json-guest", guest_type="ct")
            db.session.add(guest)
            db.session.commit()

            Setting.set("backup_tag_defaults", "not-valid-json{")
            assert _get_tag_backup_defaults(guest) == {}


class TestSaveBackupDefaults:
    """Tests for the per-guest backup defaults save endpoint."""

    def _make_guest(self, app):
        with app.app_context():
            guest = Guest(name="_backup-defaults-test", guest_type="ct")
            db.session.add(guest)
            db.session.commit()
            return guest.id

    def test_save_backup_defaults(self, app, auth_client):
        gid = self._make_guest(app)
        resp = auth_client.post(
            f"/guests/{gid}/backup-defaults",
            data={"backup_storage": "pbs-prod", "backup_mode": "snapshot", "backup_compress": "zstd"},
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            guest = Guest.query.get(gid)
            assert guest.backup_storage == "pbs-prod"
            assert guest.backup_mode == "snapshot"
            assert guest.backup_compress == "zstd"

    def test_save_empty_clears_defaults(self, app, auth_client):
        gid = self._make_guest(app)
        with app.app_context():
            guest = Guest.query.get(gid)
            guest.backup_storage = "old-storage"
            guest.backup_mode = "stop"
            db.session.commit()

        resp = auth_client.post(
            f"/guests/{gid}/backup-defaults",
            data={"backup_storage": "", "backup_mode": "", "backup_compress": ""},
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            guest = Guest.query.get(gid)
            assert guest.backup_storage is None
            assert guest.backup_mode is None
            assert guest.backup_compress is None

    def test_guest_defaults_override_tag_defaults(self, app):
        """Per-guest defaults should take priority over tag defaults in the fallback chain."""
        with app.app_context():
            tag = Tag(name="override-test-tag", color="#000")
            guest = Guest(name="override-test-guest", guest_type="ct",
                         backup_storage="guest-storage", backup_mode="stop")
            guest.tags.append(tag)
            db.session.add_all([tag, guest])
            db.session.commit()

            overrides = {"override-test-tag": {"storage": "tag-storage", "mode": "snapshot", "compress": "lzo"}}
            Setting.set("backup_tag_defaults", json.dumps(overrides))

            # Per-guest storage and mode should win; compress inherits from tag
            from routes.guests import _get_tag_backup_defaults
            tag_cfg = _get_tag_backup_defaults(guest)
            storage = guest.backup_storage or tag_cfg.get("storage", "")
            mode = guest.backup_mode or tag_cfg.get("mode", "")
            compress = guest.backup_compress or tag_cfg.get("compress", "")

            assert storage == "guest-storage"
            assert mode == "stop"
            assert compress == "lzo"  # inherited from tag


class TestPowerAction:
    """Tests for the guest power action route."""

    @patch("routes.guests.ProxmoxClient")
    def test_reboot_clears_reboot_required(self, mock_client_cls, app, auth_client):
        """Rebooting a guest should clear reboot_required flag."""
        with app.app_context():
            host = ProxmoxHost(name="test-only-node", hostname="test-only-pve.local", host_type="pve")
            db.session.add(host)
            db.session.flush()
            guest = Guest(
                name="_power-reboot-test",
                guest_type="ct",
                vmid=100,
                proxmox_host_id=host.id,
                reboot_required=True,
            )
            db.session.add(guest)
            db.session.commit()
            guest_id = guest.id

        mock_instance = MagicMock()
        mock_instance.reboot_guest.return_value = (True, "Reboot sent")
        mock_instance.find_guest_node.return_value = None
        mock_client_cls.return_value = mock_instance

        resp = auth_client.post(f"/guests/{guest_id}/power/reboot", follow_redirects=False)
        assert resp.status_code == 302

        with app.app_context():
            guest = Guest.query.get(guest_id)
            assert guest.reboot_required is False

            # Cleanup
            db.session.delete(guest)
            host = ProxmoxHost.query.filter_by(name="test-only-node").first()
            if host:
                db.session.delete(host)
            db.session.commit()
