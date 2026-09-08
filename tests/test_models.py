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


# ---------------------------------------------------------------------------
# Delete cascades (issue #127)
# ---------------------------------------------------------------------------


class TestDeleteCascades:
    def test_deleting_host_removes_its_exporter_instances(self, app):
        """host_exporter_instances.host_id is NOT NULL -- the delete must cascade."""
        from models import HostExporterInstance

        with app.app_context():
            host = ProxmoxHost(name="_casc-exporter-host", hostname="10.9.0.1", host_type="pve")
            db.session.add(host)
            db.session.commit()

            inst = HostExporterInstance(host_id=host.id, exporter_type="ipmi_exporter", port=9290)
            db.session.add(inst)
            db.session.commit()
            inst_id = inst.id

            db.session.delete(host)
            db.session.commit()  # used to raise IntegrityError

            assert HostExporterInstance.query.get(inst_id) is None

    def test_deleting_tag_removes_its_unifi_networks(self, app):
        from models import Tag, TagUnifiNetwork

        with app.app_context():
            tag = Tag(name="_casc-unifi-tag")
            db.session.add(tag)
            db.session.commit()
            tag_id = tag.id

            db.session.add(TagUnifiNetwork(tag_id=tag_id, network_name="LAN"))
            db.session.commit()

            db.session.delete(tag)
            db.session.commit()

            assert TagUnifiNetwork.query.filter_by(tag_id=tag_id).count() == 0

    def test_deleting_host_removes_its_metric_snapshots(self, app):
        from models import HostMetricSnapshot

        with app.app_context():
            host = ProxmoxHost(name="_casc-metric-host", hostname="10.9.0.2", host_type="pve")
            db.session.add(host)
            db.session.commit()
            host_id = host.id

            db.session.add(HostMetricSnapshot(host_id=host_id, data="{}"))
            db.session.commit()

            db.session.delete(ProxmoxHost.query.get(host_id))
            db.session.commit()

            assert HostMetricSnapshot.query.filter_by(host_id=host_id).count() == 0

    def test_deleting_guest_removes_service_metric_snapshots(self, app):
        from models import GuestService, ServiceMetricSnapshot

        with app.app_context():
            guest = Guest(name="_casc-svc-guest", guest_type="ct")
            db.session.add(guest)
            db.session.commit()

            svc = GuestService(guest_id=guest.id, service_name="postgresql",
                               unit_name="postgresql.service")
            db.session.add(svc)
            db.session.commit()
            svc_id = svc.id

            db.session.add(ServiceMetricSnapshot(service_id=svc_id, data="{}"))
            db.session.commit()

            db.session.delete(guest)
            db.session.commit()

            assert ServiceMetricSnapshot.query.filter_by(service_id=svc_id).count() == 0

    def test_deleting_guest_removes_update_history(self, app):
        from models import UpdateHistory

        with app.app_context():
            guest = Guest(name="_casc-history-guest", guest_type="ct")
            db.session.add(guest)
            db.session.commit()
            guest_id = guest.id

            db.session.add(UpdateHistory(guest_id=guest_id, package_count=3))
            db.session.commit()

            db.session.delete(Guest.query.get(guest_id))
            db.session.commit()

            assert UpdateHistory.query.filter_by(guest_id=guest_id).count() == 0


class TestSqliteForeignKeysAreEnforced:
    def test_dangling_foreign_key_is_rejected(self, app):
        from sqlalchemy.exc import IntegrityError

        with app.app_context():
            db.session.add(Guest(name="_fk-dangling", guest_type="ct", credential_id=987654))
            with pytest.raises(IntegrityError):
                db.session.commit()
            db.session.rollback()


class TestGuestVmidUniqueness:
    def test_same_host_and_vmid_is_rejected(self, app):
        from sqlalchemy.exc import IntegrityError

        with app.app_context():
            host = ProxmoxHost(name="_uniq-vmid-host", hostname="10.9.0.3", host_type="pve")
            db.session.add(host)
            db.session.commit()
            host_id = host.id

            db.session.add(Guest(name="_uniq-a", guest_type="ct", proxmox_host_id=host_id, vmid=4242))
            db.session.commit()

            db.session.add(Guest(name="_uniq-b", guest_type="ct", proxmox_host_id=host_id, vmid=4242))
            with pytest.raises(IntegrityError):
                db.session.commit()
            db.session.rollback()

            db.session.delete(ProxmoxHost.query.get(host_id))
            db.session.commit()

    def test_guests_without_a_vmid_are_not_constrained(self, app):
        """The index is partial (vmid IS NOT NULL), so VMID-less rows stack up."""
        with app.app_context():
            host = ProxmoxHost(name="_uniq-novmid-host", hostname="10.9.0.4", host_type="pve")
            db.session.add(host)
            db.session.commit()
            host_id = host.id

            db.session.add_all([
                Guest(name="_uniq-novmid-a", guest_type="ct", proxmox_host_id=host_id),
                Guest(name="_uniq-novmid-b", guest_type="ct", proxmox_host_id=host_id),
            ])
            db.session.commit()  # must not raise

            assert Guest.query.filter_by(proxmox_host_id=host_id).count() == 2

            db.session.delete(ProxmoxHost.query.get(host_id))
            db.session.commit()


class TestSettingSetUpsert:
    def test_creates_then_updates_a_key(self, app):
        with app.app_context():
            Setting.set("_upsert-key", "first")
            assert Setting.get("_upsert-key") == "first"

            Setting.set("_upsert-key", "second")
            assert Setting.get("_upsert-key") == "second"
            assert Setting.query.filter_by(key="_upsert-key").count() == 1

    def test_row_inserted_behind_the_session_is_updated_not_duplicated(self, app):
        """Simulates the check-then-act race: the row appears after the SELECT."""
        with app.app_context():
            Setting.query.filter_by(key="_upsert-race").delete()
            db.session.commit()

            # Write the row via raw SQL so the identity map has never seen it.
            db.session.execute(
                db.text("INSERT INTO settings (key, value) VALUES ('_upsert-race', 'from-other-writer')")
            )
            db.session.commit()
            db.session.expunge_all()

            Setting.set("_upsert-race", "mine")

            assert Setting.query.filter_by(key="_upsert-race").count() == 1
            assert Setting.get("_upsert-race") == "mine"

    def test_returns_the_persisted_row(self, app):
        with app.app_context():
            row = Setting.set("_upsert-return", "value")
            assert row is not None
            assert row.key == "_upsert-return"
            assert row.value == "value"
