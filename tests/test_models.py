"""Unit tests for model helpers."""
import pytest

from models import Guest, HostUpdatePackage, ProxmoxHost, PushWebhook, Setting, UpdatePackage, db


@pytest.fixture()
def guest_with_updates(app):
    """Guest with a mix of pending and applied packages, one of which is critical."""
    with app.app_context():
        g = Guest(name="_test-model-guest", guest_type="ct")
        db.session.add(g)
        db.session.flush()

        pkgs = [
            UpdatePackage(guest_id=g.id, package_name="pkg-normal-pending",
                          severity="normal", status="pending"),
            UpdatePackage(guest_id=g.id, package_name="pkg-critical-pending",
                          severity="critical", status="pending"),
            UpdatePackage(guest_id=g.id, package_name="pkg-normal-applied",
                          severity="normal", status="applied"),
        ]
        db.session.add_all(pkgs)
        db.session.commit()
        gid = g.id

    yield gid

    with app.app_context():
        g = Guest.query.get(gid)
        if g:
            db.session.delete(g)
            db.session.commit()


class TestGuestHelpers:
    def test_pending_updates_count(self, app, guest_with_updates):
        with app.app_context():
            g = Guest.query.get(guest_with_updates)
            assert len(g.pending_updates()) == 2

    def test_pending_updates_excludes_applied(self, app, guest_with_updates):
        with app.app_context():
            g = Guest.query.get(guest_with_updates)
            assert all(u.status == "pending" for u in g.pending_updates())

    def test_security_updates_count(self, app, guest_with_updates):
        with app.app_context():
            g = Guest.query.get(guest_with_updates)
            assert len(g.security_updates()) == 1

    def test_security_updates_are_critical(self, app, guest_with_updates):
        with app.app_context():
            g = Guest.query.get(guest_with_updates)
            assert all(u.severity == "critical" for u in g.security_updates())

    def test_no_updates(self, app):
        with app.app_context():
            g = Guest(name="_test-empty-guest", guest_type="vm")
            db.session.add(g)
            db.session.commit()
            assert g.pending_updates() == []
            assert g.security_updates() == []
            db.session.delete(g)
            db.session.commit()


class TestSettingModel:
    def test_get_returns_default_when_absent(self, app):
        with app.app_context():
            val = Setting.get("_nonexistent_key_xyz_", "mydefault")
            assert val == "mydefault"

    def test_get_returns_none_default_when_absent(self, app):
        with app.app_context():
            val = Setting.get("_nonexistent_key_xyz_")
            assert val is None

    def test_set_and_get(self, app):
        with app.app_context():
            Setting.set("_test_key_", "hello")
            assert Setting.get("_test_key_") == "hello"
            s = Setting.query.filter_by(key="_test_key_").first()
            db.session.delete(s)
            db.session.commit()

    def test_set_overwrites(self, app):
        with app.app_context():
            Setting.set("_test_overwrite_", "first")
            Setting.set("_test_overwrite_", "second")
            assert Setting.get("_test_overwrite_") == "second"
            s = Setting.query.filter_by(key="_test_overwrite_").first()
            db.session.delete(s)
            db.session.commit()


class TestHostUpdatePackageModel:
    def test_create_host_update_package(self, app):
        with app.app_context():
            host = ProxmoxHost(name="pve1", hostname="pve1.local", host_type="pve")
            db.session.add(host)
            db.session.commit()

            pkg = HostUpdatePackage(
                host_id=host.id,
                package_name="linux-image-6.1",
                current_version="6.1.0-1",
                available_version="6.1.0-2",
                severity="critical",
                status="pending",
            )
            db.session.add(pkg)
            db.session.commit()

            assert pkg.id is not None
            assert pkg.host_id == host.id
            assert pkg.package_name == "linux-image-6.1"
            assert pkg.severity == "critical"
            assert pkg.status == "pending"
            assert pkg.applied_at is None

    def test_pending_updates_method(self, app):
        with app.app_context():
            host = ProxmoxHost(name="pve2", hostname="pve2.local", host_type="pve")
            db.session.add(host)
            db.session.commit()

            pkg1 = HostUpdatePackage(host_id=host.id, package_name="curl", status="pending", severity="normal")
            pkg2 = HostUpdatePackage(host_id=host.id, package_name="vim", status="applied", severity="normal")
            pkg3 = HostUpdatePackage(host_id=host.id, package_name="openssl", status="pending", severity="critical")
            db.session.add_all([pkg1, pkg2, pkg3])
            db.session.commit()

            pending = host.pending_updates()
            assert len(pending) == 2
            assert all(p.status == "pending" for p in pending)

    def test_security_updates_method(self, app):
        with app.app_context():
            host = ProxmoxHost(name="pve3", hostname="pve3.local", host_type="pve")
            db.session.add(host)
            db.session.commit()

            pkg1 = HostUpdatePackage(host_id=host.id, package_name="curl", status="pending", severity="normal")
            pkg2 = HostUpdatePackage(host_id=host.id, package_name="openssl", status="pending", severity="critical")
            db.session.add_all([pkg1, pkg2])
            db.session.commit()

            sec = host.security_updates()
            assert len(sec) == 1
            assert sec[0].package_name == "openssl"

    def test_cascade_delete(self, app):
        with app.app_context():
            host = ProxmoxHost(name="pve-del", hostname="pve-del.local", host_type="pve")
            db.session.add(host)
            db.session.commit()

            pkg = HostUpdatePackage(host_id=host.id, package_name="curl", status="pending", severity="normal")
            db.session.add(pkg)
            db.session.commit()
            pkg_id = pkg.id

            db.session.delete(host)
            db.session.commit()

            assert HostUpdatePackage.query.get(pkg_id) is None


class TestPushWebhookValidEvents:
    def test_service_failed_is_valid_event(self):
        assert "service_failed" in PushWebhook.VALID_EVENTS

    def test_service_recovered_is_valid_event(self):
        assert "service_recovered" in PushWebhook.VALID_EVENTS

    def test_service_down_still_valid_for_backwards_compat(self):
        assert "service_down" in PushWebhook.VALID_EVENTS
