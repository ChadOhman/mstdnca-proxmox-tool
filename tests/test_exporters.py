"""Tests for the Prometheus exporter management system."""

from unittest.mock import MagicMock, patch

from models import Credential, ExporterInstance, Guest, HostExporterInstance, ProxmoxHost, Setting, db

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_host(app):
    """Create a minimal host for guest FK."""
    host = ProxmoxHost.query.first()
    if host:
        return host
    host = ProxmoxHost(
        name="pve-test",
        hostname="10.0.0.1",
        host_type="pve",
    )
    db.session.add(host)
    db.session.commit()
    return host


def _create_guest(app, name="test-guest", ip="10.0.0.50", with_credential=False):
    """Create a minimal guest for exporter tests.

    (proxmox_host_id, vmid) is unique, and the app fixture is session-scoped,
    so each call takes the next free VMID on the host instead of a fixed one.
    """
    host = _create_host(app)
    credential_id = None
    if with_credential:
        cred = _get_or_create_credential()
        credential_id = cred.id
    highest = (
        db.session.query(db.func.max(Guest.vmid))
        .filter(Guest.proxmox_host_id == host.id)
        .scalar()
    )
    guest = Guest(
        name=name,
        vmid=max(highest or 0, 99) + 1,
        guest_type="lxc",
        proxmox_host_id=host.id,
        ip_address=ip,
        credential_id=credential_id,
    )
    db.session.add(guest)
    db.session.commit()
    return guest


def _get_or_create_credential():
    """Get or create a test credential for SSH tests."""
    from auth import credential_store
    cred = Credential.query.filter_by(name="test-exporter-cred").first()
    if cred:
        return cred
    cred = Credential(
        name="test-exporter-cred",
        username="root",
        auth_type="password",
        encrypted_value=credential_store.encrypt("testpass"),
        is_default=True,
    )
    db.session.add(cred)
    db.session.commit()
    return cred


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------

class TestExporterModel:

    def test_create_exporter_instance(self, app):
        with app.app_context():
            guest = _create_guest(app, name="exp-model-test", ip="10.0.0.60")
            exp = ExporterInstance(
                guest_id=guest.id,
                exporter_type="node_exporter",
                port=9100,
                status="pending",
            )
            db.session.add(exp)
            db.session.commit()

            fetched = ExporterInstance.query.filter_by(guest_id=guest.id).first()
            assert fetched is not None
            assert fetched.exporter_type == "node_exporter"
            assert fetched.port == 9100
            assert fetched.status == "pending"
            assert fetched.version is None

            db.session.delete(exp)
            db.session.delete(guest)
            db.session.commit()

    def test_guest_exporters_relationship(self, app):
        with app.app_context():
            guest = _create_guest(app, name="exp-rel-test", ip="10.0.0.61")
            exp = ExporterInstance(
                guest_id=guest.id,
                exporter_type="node_exporter",
                port=9100,
            )
            db.session.add(exp)
            db.session.commit()

            assert len(guest.exporters) == 1
            assert guest.exporters[0].exporter_type == "node_exporter"

            db.session.delete(exp)
            db.session.delete(guest)
            db.session.commit()

    def test_cascade_delete_with_guest(self, app):
        with app.app_context():
            guest = _create_guest(app, name="exp-cascade-test", ip="10.0.0.62")
            exp = ExporterInstance(
                guest_id=guest.id,
                exporter_type="node_exporter",
                port=9100,
            )
            db.session.add(exp)
            db.session.commit()
            exp_id = exp.id

            db.session.delete(guest)
            db.session.commit()

            assert ExporterInstance.query.get(exp_id) is None


# ---------------------------------------------------------------------------
# Logic tests (apps/exporters.py)
# ---------------------------------------------------------------------------

class TestExporterLogic:

    def test_known_exporters_registry(self):
        from apps.exporters import KNOWN_EXPORTERS
        assert "node_exporter" in KNOWN_EXPORTERS
        assert "postgres_exporter" in KNOWN_EXPORTERS
        assert "redis_exporter" in KNOWN_EXPORTERS
        assert "elasticsearch_exporter" in KNOWN_EXPORTERS
        assert KNOWN_EXPORTERS["node_exporter"]["default_port"] == 9100

    def test_systemd_unit_generation(self):
        from apps.exporters import _generate_exporter_systemd_unit
        unit = _generate_exporter_systemd_unit("node_exporter", 9100)
        assert "ExecStart=/usr/local/bin/node_exporter" in unit
        assert ":9100" in unit
        assert "User=node_exporter" in unit
        assert "[Install]" in unit

    def test_systemd_unit_with_env_file(self):
        from apps.exporters import _generate_exporter_systemd_unit
        unit = _generate_exporter_systemd_unit("postgres_exporter", 9187, env_file="/etc/default/postgres_exporter")
        assert "EnvironmentFile=/etc/default/postgres_exporter" in unit
        assert ":9187" in unit

    def test_elasticsearch_exporter_registry(self):
        from apps.exporters import KNOWN_EXPORTERS
        info = KNOWN_EXPORTERS["elasticsearch_exporter"]
        assert info["display_name"] == "Elasticsearch Exporter"
        assert info["github_repo"] == "prometheus-community/elasticsearch_exporter"
        assert info["binary_name"] == "elasticsearch_exporter"
        assert info["default_port"] == 9114
        assert info["systemd_unit"] == "elasticsearch_exporter.service"
        assert info["requires_config"] is True
        assert "ES_URI" in info["env_vars"]
        assert info["job_name"] == "elasticsearch"

    def test_elasticsearch_systemd_unit_includes_es_uri_flag(self):
        from apps.exporters import _generate_exporter_systemd_unit
        unit = _generate_exporter_systemd_unit(
            "elasticsearch_exporter", 9114, env_file="/etc/default/elasticsearch_exporter"
        )
        assert "ExecStart=/usr/local/bin/elasticsearch_exporter" in unit
        assert ":9114" in unit
        assert "--es.uri=${ES_URI}" in unit
        assert "EnvironmentFile=/etc/default/elasticsearch_exporter" in unit
        assert "User=elasticsearch_exporter" in unit

    def test_systemd_unit_without_extra_args(self):
        """Verify that exporters without exec_extra_args still work normally."""
        from apps.exporters import _generate_exporter_systemd_unit
        unit = _generate_exporter_systemd_unit("node_exporter", 9100)
        assert "--es.uri" not in unit
        assert "ExecStart=/usr/local/bin/node_exporter" in unit

    def test_check_exporter_release_unknown_type(self):
        from apps.exporters import check_exporter_release
        version, err = check_exporter_release("unknown_exporter")
        assert version is None
        assert "Unknown exporter type" in err

    def test_detect_exporter_version_unknown_type(self, app):
        from apps.exporters import detect_exporter_version
        with app.app_context():
            guest = _create_guest(app, name="exp-ver-test", ip="10.0.0.63")
            version, err = detect_exporter_version(guest, "unknown_exporter")
            assert version is None
            assert "Unknown exporter type" in err

            db.session.delete(guest)
            db.session.commit()

    def test_detect_exporter_version_no_credential(self, app):
        from apps.exporters import detect_exporter_version
        with app.app_context():
            guest = _create_guest(app, name="exp-nocred-test", ip="10.0.0.64")
            version, err = detect_exporter_version(guest, "node_exporter")
            assert version is None
            assert "credential" in err.lower()

            db.session.delete(guest)
            db.session.commit()


# ---------------------------------------------------------------------------
# Prometheus YML generation tests
# ---------------------------------------------------------------------------

class TestPrometheusYmlGeneration:

    def test_yml_without_extra_configs(self):
        from apps.prometheus_app import _generate_prometheus_yml
        yml = _generate_prometheus_yml("10.0.0.10:5000")
        assert 'job_name: "prometheus"' in yml
        assert 'job_name: "mstdnca"' in yml
        assert "10.0.0.10:5000" in yml

    def test_yml_with_extra_configs(self):
        from apps.prometheus_app import _generate_prometheus_yml
        extra = """

  - job_name: "node"
    static_configs:
      - targets: ["10.0.0.50:9100"]"""
        yml = _generate_prometheus_yml("10.0.0.10:5000", extra_scrape_configs=extra)
        assert 'job_name: "node"' in yml
        assert "10.0.0.50:9100" in yml

    def test_yml_with_auth_token(self):
        from apps.prometheus_app import _generate_prometheus_yml
        yml = _generate_prometheus_yml("10.0.0.10:5000", auth_token="test-only-secret123")
        assert "Bearer" in yml
        assert "test-only-secret123" in yml

    def test_yml_without_mstdnca_url(self):
        from apps.prometheus_app import _generate_prometheus_yml
        yml = _generate_prometheus_yml("")
        assert 'job_name: "prometheus"' in yml
        assert "mstdnca" not in yml


# ---------------------------------------------------------------------------
# Route tests
# ---------------------------------------------------------------------------

class TestExporterRoutes:

    def test_exporters_list_requires_auth(self, client):
        resp = client.get("/prometheus/exporters")
        assert resp.status_code in (302, 401)

    def test_exporters_list(self, auth_client):
        resp = auth_client.get("/prometheus/exporters")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "exporters" in data

    def test_exporter_add_invalid_type(self, auth_client):
        resp = auth_client.post("/prometheus/exporters/add", data={
            "guest_id": "1",
            "exporter_type": "invalid_exporter",
            "port": "9100",
        }, follow_redirects=False)
        assert resp.status_code in (302, 303)

    def test_exporter_add_missing_guest(self, auth_client):
        resp = auth_client.post("/prometheus/exporters/add", data={
            "guest_id": "",
            "exporter_type": "node_exporter",
            "port": "9100",
        }, follow_redirects=False)
        assert resp.status_code in (302, 303)

    def test_exporter_add_success(self, auth_client, app):
        with app.app_context():
            guest = _create_guest(app, name="exp-route-add", ip="10.0.0.70")
            guest_id = guest.id

        resp = auth_client.post("/prometheus/exporters/add", data={
            "guest_id": str(guest_id),
            "exporter_type": "node_exporter",
            "port": "9100",
        }, follow_redirects=False)
        assert resp.status_code in (302, 303)

        with app.app_context():
            exp = ExporterInstance.query.filter_by(guest_id=guest_id).first()
            assert exp is not None
            assert exp.exporter_type == "node_exporter"
            assert exp.port == 9100
            assert exp.status == "pending"

            db.session.delete(exp)
            guest = Guest.query.get(guest_id)
            if guest:
                db.session.delete(guest)
            db.session.commit()

    def test_exporter_add_duplicate(self, auth_client, app):
        with app.app_context():
            guest = _create_guest(app, name="exp-route-dup", ip="10.0.0.71")
            exp = ExporterInstance(
                guest_id=guest.id,
                exporter_type="node_exporter",
                port=9100,
                status="pending",
            )
            db.session.add(exp)
            db.session.commit()
            guest_id = guest.id

        resp = auth_client.post("/prometheus/exporters/add", data={
            "guest_id": str(guest_id),
            "exporter_type": "node_exporter",
            "port": "9100",
        }, follow_redirects=False)
        assert resp.status_code in (302, 303)

        with app.app_context():
            count = ExporterInstance.query.filter_by(
                guest_id=guest_id, exporter_type="node_exporter"
            ).count()
            assert count == 1

            for e in ExporterInstance.query.filter_by(guest_id=guest_id).all():
                db.session.delete(e)
            guest = Guest.query.get(guest_id)
            if guest:
                db.session.delete(guest)
            db.session.commit()

    def test_exporter_delete_pending(self, auth_client, app):
        with app.app_context():
            guest = _create_guest(app, name="exp-route-del", ip="10.0.0.72")
            exp = ExporterInstance(
                guest_id=guest.id,
                exporter_type="node_exporter",
                port=9100,
                status="pending",
            )
            db.session.add(exp)
            db.session.commit()
            exp_id = exp.id
            guest_id = guest.id

        resp = auth_client.post(f"/prometheus/exporters/{exp_id}/delete", follow_redirects=False)
        assert resp.status_code in (302, 303)

        with app.app_context():
            assert ExporterInstance.query.get(exp_id) is None
            guest = Guest.query.get(guest_id)
            if guest:
                db.session.delete(guest)
                db.session.commit()

    def test_exporter_delete_installed_blocked(self, auth_client, app):
        with app.app_context():
            guest = _create_guest(app, name="exp-route-deli", ip="10.0.0.73")
            exp = ExporterInstance(
                guest_id=guest.id,
                exporter_type="node_exporter",
                port=9100,
                status="installed",
            )
            db.session.add(exp)
            db.session.commit()
            exp_id = exp.id
            guest_id = guest.id

        resp = auth_client.post(f"/prometheus/exporters/{exp_id}/delete", follow_redirects=False)
        assert resp.status_code in (302, 303)

        with app.app_context():
            # Should NOT be deleted
            assert ExporterInstance.query.get(exp_id) is not None

            for e in ExporterInstance.query.filter_by(guest_id=guest_id).all():
                db.session.delete(e)
            guest = Guest.query.get(guest_id)
            if guest:
                db.session.delete(guest)
            db.session.commit()

    def test_exporter_install_status(self, auth_client):
        resp = auth_client.get("/prometheus/exporters/install/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "running" in data
        assert "log" in data

    def test_exporter_uninstall_status(self, auth_client):
        resp = auth_client.get("/prometheus/exporters/uninstall/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "running" in data
        assert "log" in data

    def test_exporter_install_conflict(self, auth_client, app):
        """Test that install returns 409 when another operation is running."""
        from routes import prometheus_app as route_mod
        with app.app_context():
            guest = _create_guest(app, name="exp-route-conflict", ip="10.0.0.74")
            exp = ExporterInstance(
                guest_id=guest.id,
                exporter_type="node_exporter",
                port=9100,
                status="pending",
            )
            db.session.add(exp)
            db.session.commit()
            exp_id = exp.id
            guest_id = guest.id

        route_mod._exporter_install_job["running"] = True
        try:
            resp = auth_client.post(f"/prometheus/exporters/{exp_id}/install")
            assert resp.status_code == 409
        finally:
            route_mod._exporter_install_job["running"] = False

        with app.app_context():
            for e in ExporterInstance.query.filter_by(guest_id=guest_id).all():
                db.session.delete(e)
            guest = Guest.query.get(guest_id)
            if guest:
                db.session.delete(guest)
            db.session.commit()

    def test_exporter_delete_not_found(self, auth_client):
        resp = auth_client.post("/prometheus/exporters/99999/delete")
        assert resp.status_code == 404

    def test_exporter_add_with_config(self, auth_client, app):
        with app.app_context():
            guest = _create_guest(app, name="exp-route-cfg", ip="10.0.0.80")
            guest_id = guest.id

        resp = auth_client.post("/prometheus/exporters/add", data={
            "guest_id": str(guest_id),
            "exporter_type": "postgres_exporter",
            "port": "9187",
            "config_DATA_SOURCE_NAME": "postgresql://user:pass@localhost/db?sslmode=disable",
        }, follow_redirects=False)
        assert resp.status_code in (302, 303)

        with app.app_context():
            exp = ExporterInstance.query.filter_by(guest_id=guest_id).first()
            assert exp is not None
            assert exp.exporter_type == "postgres_exporter"
            assert exp.config is not None
            assert exp.config["DATA_SOURCE_NAME"] == "postgresql://user:pass@localhost/db?sslmode=disable"

            db.session.delete(exp)
            guest = Guest.query.get(guest_id)
            if guest:
                db.session.delete(guest)
            db.session.commit()

    def test_exporter_add_without_config(self, auth_client, app):
        """Exporters that don't require config should have config=None."""
        with app.app_context():
            guest = _create_guest(app, name="exp-route-nocfg", ip="10.0.0.81")
            guest_id = guest.id

        resp = auth_client.post("/prometheus/exporters/add", data={
            "guest_id": str(guest_id),
            "exporter_type": "node_exporter",
            "port": "9100",
        }, follow_redirects=False)
        assert resp.status_code in (302, 303)

        with app.app_context():
            exp = ExporterInstance.query.filter_by(guest_id=guest_id).first()
            assert exp is not None
            assert exp.config is None

            db.session.delete(exp)
            guest = Guest.query.get(guest_id)
            if guest:
                db.session.delete(guest)
            db.session.commit()

    def test_exporter_update_config(self, auth_client, app):
        with app.app_context():
            guest = _create_guest(app, name="exp-route-ucfg", ip="10.0.0.82")
            exp = ExporterInstance(
                guest_id=guest.id,
                exporter_type="redis_exporter",
                port=9121,
                status="pending",
            )
            db.session.add(exp)
            db.session.commit()
            exp_id = exp.id
            guest_id = guest.id

        resp = auth_client.post(f"/prometheus/exporters/{exp_id}/config", data={
            "config_REDIS_ADDR": "redis://localhost:6379",
        }, follow_redirects=False)
        assert resp.status_code in (302, 303)

        with app.app_context():
            exp = ExporterInstance.query.get(exp_id)
            assert exp.config is not None
            assert exp.config["REDIS_ADDR"] == "redis://localhost:6379"

            db.session.delete(exp)
            guest = Guest.query.get(guest_id)
            if guest:
                db.session.delete(guest)
            db.session.commit()

    def test_exporter_update_config_installed_blocked(self, auth_client, app):
        with app.app_context():
            guest = _create_guest(app, name="exp-route-ucfgi", ip="10.0.0.83")
            exp = ExporterInstance(
                guest_id=guest.id,
                exporter_type="postgres_exporter",
                port=9187,
                status="installed",
                config={"DATA_SOURCE_NAME": "old"},
            )
            db.session.add(exp)
            db.session.commit()
            exp_id = exp.id
            guest_id = guest.id

        resp = auth_client.post(f"/prometheus/exporters/{exp_id}/config", data={
            "config_DATA_SOURCE_NAME": "new",
        }, follow_redirects=False)
        assert resp.status_code in (302, 303)

        with app.app_context():
            exp = ExporterInstance.query.get(exp_id)
            # Config should NOT be changed
            assert exp.config["DATA_SOURCE_NAME"] == "old"

            db.session.delete(exp)
            guest = Guest.query.get(guest_id)
            if guest:
                db.session.delete(guest)
            db.session.commit()

    def test_exporter_update_config_no_config_required(self, auth_client, app):
        with app.app_context():
            guest = _create_guest(app, name="exp-route-ucfgn", ip="10.0.0.84")
            exp = ExporterInstance(
                guest_id=guest.id,
                exporter_type="node_exporter",
                port=9100,
                status="pending",
            )
            db.session.add(exp)
            db.session.commit()
            exp_id = exp.id
            guest_id = guest.id

        resp = auth_client.post(f"/prometheus/exporters/{exp_id}/config", data={}, follow_redirects=False)
        assert resp.status_code in (302, 303)

        with app.app_context():
            db.session.delete(ExporterInstance.query.get(exp_id))
            guest = Guest.query.get(guest_id)
            if guest:
                db.session.delete(guest)
            db.session.commit()


# ---------------------------------------------------------------------------
# Exporter target resolution tests
# ---------------------------------------------------------------------------

class TestExporterTargetResolution:

    def test_get_exporter_target_installed(self, app):
        from clients.prometheus_query import _get_exporter_target
        with app.app_context():
            guest = _create_guest(app, name="exp-target-ok", ip="10.0.0.90")
            exp = ExporterInstance(
                guest_id=guest.id, exporter_type="node_exporter",
                port=9100, status="installed",
            )
            db.session.add(exp)
            db.session.commit()

            target = _get_exporter_target(guest.id, "node_exporter")
            assert target == "10.0.0.90:9100"

            db.session.delete(exp)
            db.session.delete(guest)
            db.session.commit()

    def test_get_exporter_target_not_installed(self, app):
        from clients.prometheus_query import _get_exporter_target
        with app.app_context():
            guest = _create_guest(app, name="exp-target-none", ip="10.0.0.91")
            target = _get_exporter_target(guest.id, "node_exporter")
            assert target is None

            db.session.delete(guest)
            db.session.commit()

    def test_get_exporter_target_pending(self, app):
        from clients.prometheus_query import _get_exporter_target
        with app.app_context():
            guest = _create_guest(app, name="exp-target-pend", ip="10.0.0.92")
            exp = ExporterInstance(
                guest_id=guest.id, exporter_type="node_exporter",
                port=9100, status="pending",
            )
            db.session.add(exp)
            db.session.commit()

            target = _get_exporter_target(guest.id, "node_exporter")
            assert target is None

            db.session.delete(exp)
            db.session.delete(guest)
            db.session.commit()

    def test_get_exporter_target_dhcp_ip(self, app):
        from clients.prometheus_query import _get_exporter_target
        with app.app_context():
            guest = _create_guest(app, name="exp-target-dhcp", ip="dhcp")
            exp = ExporterInstance(
                guest_id=guest.id, exporter_type="node_exporter",
                port=9100, status="installed",
            )
            db.session.add(exp)
            db.session.commit()

            target = _get_exporter_target(guest.id, "node_exporter")
            assert target is None

            db.session.delete(exp)
            db.session.delete(guest)
            db.session.commit()


# ---------------------------------------------------------------------------
# Exporter-aware query method tests
# ---------------------------------------------------------------------------

class TestExporterAwareQueries:

    @patch("clients.prometheus_query.requests.get")
    def test_get_guest_rrd_uses_node_exporter(self, mock_get, app):
        from clients.prometheus_query import PrometheusQueryClient

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "success",
            "data": {"resultType": "matrix", "result": [{
                "metric": {},
                "values": [[1000, "50.0"], [1060, "55.0"]],
            }]},
        }
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        with app.app_context():
            guest = _create_guest(app, name="exp-query-node", ip="10.0.0.93")
            exp = ExporterInstance(
                guest_id=guest.id, exporter_type="node_exporter",
                port=9100, status="installed",
            )
            db.session.add(exp)
            db.session.commit()

            client = PrometheusQueryClient(base_url="http://localhost:9090")
            result = client.get_guest_rrd(100, "hour", guest_id=guest.id)
            assert result["source"] == "node_exporter"
            assert len(result["labels"]) > 0

            # Verify node_exporter queries were used (check the query param)
            all_urls_and_params = str(mock_get.call_args_list)
            assert "node_cpu_seconds_total" in all_urls_and_params

            db.session.delete(exp)
            db.session.delete(guest)
            db.session.commit()

    @patch("clients.prometheus_query.requests.get")
    def test_get_guest_rrd_falls_back_to_mstdnca(self, mock_get, app):
        from clients.prometheus_query import PrometheusQueryClient

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "success",
            "data": {"resultType": "matrix", "result": [{
                "metric": {},
                "values": [[1000, "42.0"]],
            }]},
        }
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        with app.app_context():
            guest = _create_guest(app, name="exp-query-fallback", ip="10.0.0.94")
            # No exporter installed

            client = PrometheusQueryClient(base_url="http://localhost:9090")
            result = client.get_guest_rrd(100, "hour", guest_id=guest.id)
            assert result["source"] == "mstdnca"

            all_urls_and_params = str(mock_get.call_args_list)
            assert "mstdnca_guest_cpu_usage_percent" in all_urls_and_params

            db.session.delete(guest)
            db.session.commit()

    @patch("clients.prometheus_query.requests.get")
    def test_get_guest_rrd_without_guest_id(self, mock_get, app):
        from clients.prometheus_query import PrometheusQueryClient

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "success",
            "data": {"resultType": "matrix", "result": []},
        }
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        with app.app_context():
            client = PrometheusQueryClient(base_url="http://localhost:9090")
            result = client.get_guest_rrd(100, "hour")
            assert result["source"] == "mstdnca"

    @patch("clients.prometheus_query.requests.get")
    def test_get_pg_metrics_exporter(self, mock_get, app):
        from clients.prometheus_query import PrometheusQueryClient

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "success",
            "data": {"resultType": "matrix", "result": [{
                "metric": {},
                "values": [[1000, "10.0"], [1060, "12.0"]],
            }]},
        }
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        with app.app_context():
            client = PrometheusQueryClient(base_url="http://localhost:9090")
            result = client.get_pg_metrics_exporter("10.0.0.50:9187", "hour")
            assert result["source"] == "postgres_exporter"
            assert len(result["snapshots"]) > 0
            snap = result["snapshots"][0]
            assert "total_connections" in snap
            assert "captured_at" in snap

    @patch("clients.prometheus_query.requests.get")
    def test_get_redis_metrics_exporter(self, mock_get, app):
        from clients.prometheus_query import PrometheusQueryClient

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "success",
            "data": {"resultType": "matrix", "result": [{
                "metric": {},
                "values": [[1000, "5000000.0"]],
            }]},
        }
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        with app.app_context():
            client = PrometheusQueryClient(base_url="http://localhost:9090")
            result = client.get_redis_metrics_exporter("10.0.0.50:9121", "hour")
            assert result["source"] == "redis_exporter"
            assert len(result["snapshots"]) > 0
            snap = result["snapshots"][0]
            assert "used_memory_bytes" in snap

    @patch("clients.prometheus_query.requests.get")
    def test_get_es_metrics_exporter(self, mock_get, app):
        from clients.prometheus_query import PrometheusQueryClient

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "success",
            "data": {"resultType": "matrix", "result": [{
                "metric": {},
                "values": [[1000, "1.0"], [1060, "1.0"]],
            }]},
        }
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        with app.app_context():
            client = PrometheusQueryClient(base_url="http://localhost:9090")
            result = client.get_es_metrics_exporter("10.0.0.50:9114", "hour")
            assert result["source"] == "elasticsearch_exporter"
            assert len(result["snapshots"]) > 0
            snap = result["snapshots"][0]
            assert "cluster_health" in snap
            assert "captured_at" in snap


# ---------------------------------------------------------------------------
# Elasticsearch metrics history route tests
# ---------------------------------------------------------------------------

class TestEsMetricsHistoryRoute:

    def test_es_metrics_history_wrong_service_type(self, app, auth_client):
        from models import GuestService
        with app.app_context():
            guest = _create_guest(app, name="es-route-wrong", ip="10.0.0.95")
            svc = GuestService(
                guest_id=guest.id, service_name="redis",
                unit_name="redis-server.service", port=6379,
            )
            db.session.add(svc)
            db.session.commit()
            svc_id = svc.id

        resp = auth_client.get(f"/services/{svc_id}/es/metrics-history")
        assert resp.status_code == 400

    def test_es_metrics_history_sqlite_fallback(self, app, auth_client):
        from models import GuestService
        with app.app_context():
            guest = _create_guest(app, name="es-route-sqlite", ip="10.0.0.96")
            svc = GuestService(
                guest_id=guest.id, service_name="elasticsearch",
                unit_name="elasticsearch.service", port=9200,
            )
            db.session.add(svc)
            db.session.commit()
            svc_id = svc.id

        resp = auth_client.get(f"/services/{svc_id}/es/metrics-history")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "snapshots" in data
        assert data["source"] == "sqlite"

    @patch("clients.prometheus_query.requests.get")
    def test_es_metrics_history_prometheus(self, mock_get, app, auth_client):
        from models import GuestService, Setting
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "success",
            "data": {"resultType": "matrix", "result": [{
                "metric": {},
                "values": [[1000, "2.0"], [1060, "2.0"]],
            }]},
        }
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        with app.app_context():
            Setting.set("prometheus_enabled", "true")
            Setting.set("prometheus_url", "http://localhost:9090")
            db.session.commit()

            guest = _create_guest(app, name="es-route-prom", ip="10.0.0.97")
            svc = GuestService(
                guest_id=guest.id, service_name="elasticsearch",
                unit_name="elasticsearch.service", port=9200,
            )
            db.session.add(svc)
            db.session.commit()
            svc_id = svc.id

        resp = auth_client.get(f"/services/{svc_id}/es/metrics-history?timeframe=hour")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "snapshots" in data
        assert len(data["snapshots"]) > 0

        with app.app_context():
            Setting.set("prometheus_enabled", "false")
            Setting.set("prometheus_url", "")
            db.session.commit()


# ---------------------------------------------------------------------------
# Mastodon built-in exporter tests
# ---------------------------------------------------------------------------

class TestBuildMastodonEnvVars:

    def test_default_config(self):
        from apps.exporters import _build_mastodon_env_vars

        env = _build_mastodon_env_vars()
        assert env["MASTODON_PROMETHEUS_EXPORTER_ENABLED"] == "true"
        assert env["MASTODON_PROMETHEUS_EXPORTER_WEB_DETAILED_METRICS"] == "true"
        assert env["MASTODON_PROMETHEUS_EXPORTER_SIDEKIQ_DETAILED_METRICS"] == "true"
        # External mode by default
        assert env["PROMETHEUS_EXPORTER_HOST"] == "0.0.0.0"
        assert env["PROMETHEUS_EXPORTER_PORT"] == "9394"
        # Should NOT have local mode vars
        assert "MASTODON_PROMETHEUS_EXPORTER_LOCAL" not in env
        assert "MASTODON_PROMETHEUS_EXPORTER_HOST" not in env
        assert "MASTODON_PROMETHEUS_EXPORTER_PORT" not in env

    def test_empty_config(self):
        from apps.exporters import _build_mastodon_env_vars

        env = _build_mastodon_env_vars({})
        assert env["MASTODON_PROMETHEUS_EXPORTER_ENABLED"] == "true"
        assert env["MASTODON_PROMETHEUS_EXPORTER_WEB_DETAILED_METRICS"] == "true"
        assert env["MASTODON_PROMETHEUS_EXPORTER_SIDEKIQ_DETAILED_METRICS"] == "true"

    def test_web_detailed_disabled(self):
        from apps.exporters import _build_mastodon_env_vars

        env = _build_mastodon_env_vars({"web_detailed_metrics": False})
        assert env["MASTODON_PROMETHEUS_EXPORTER_WEB_DETAILED_METRICS"] == "false"
        assert env["MASTODON_PROMETHEUS_EXPORTER_SIDEKIQ_DETAILED_METRICS"] == "true"

    def test_sidekiq_detailed_disabled(self):
        from apps.exporters import _build_mastodon_env_vars

        env = _build_mastodon_env_vars({"sidekiq_detailed_metrics": False})
        assert env["MASTODON_PROMETHEUS_EXPORTER_WEB_DETAILED_METRICS"] == "true"
        assert env["MASTODON_PROMETHEUS_EXPORTER_SIDEKIQ_DETAILED_METRICS"] == "false"

    def test_local_mode(self):
        from apps.exporters import _build_mastodon_env_vars

        env = _build_mastodon_env_vars({"mode": "local"})
        assert env["MASTODON_PROMETHEUS_EXPORTER_LOCAL"] == "true"
        assert env["MASTODON_PROMETHEUS_EXPORTER_HOST"] == "0.0.0.0"
        assert env["MASTODON_PROMETHEUS_EXPORTER_PORT"] == "9394"
        # Should NOT have external mode vars
        assert "PROMETHEUS_EXPORTER_HOST" not in env
        assert "PROMETHEUS_EXPORTER_PORT" not in env

    def test_local_mode_custom_host_port(self):
        from apps.exporters import _build_mastodon_env_vars

        env = _build_mastodon_env_vars({"mode": "local", "host": "127.0.0.1", "port": 9500})
        assert env["MASTODON_PROMETHEUS_EXPORTER_HOST"] == "127.0.0.1"
        assert env["MASTODON_PROMETHEUS_EXPORTER_PORT"] == "9500"

    def test_external_mode_custom_port(self):
        from apps.exporters import _build_mastodon_env_vars

        env = _build_mastodon_env_vars({"mode": "external", "port": 9500})
        assert env["PROMETHEUS_EXPORTER_PORT"] == "9500"
        assert env["PROMETHEUS_EXPORTER_HOST"] == "0.0.0.0"

    def test_external_mode_custom_host(self):
        from apps.exporters import _build_mastodon_env_vars

        env = _build_mastodon_env_vars({"host": "10.0.0.5"})
        assert env["PROMETHEUS_EXPORTER_HOST"] == "10.0.0.5"


class TestBuiltinExporterRegistry:

    def test_mastodon_in_registry(self):
        from apps.exporters import BUILTIN_EXPORTERS

        assert "mastodon" in BUILTIN_EXPORTERS
        info = BUILTIN_EXPORTERS["mastodon"]
        assert info["default_port"] == 9394
        assert info["job_name"] == "mastodon"
        assert info["display_name"] == "Mastodon (Built-in)"

    def test_regenerate_config_looks_up_builtin(self, app):
        """BUILTIN_EXPORTERS are checked during prometheus.yml regeneration."""
        from apps.exporters import BUILTIN_EXPORTERS, KNOWN_EXPORTERS

        # mastodon is in BUILTIN but not KNOWN
        assert "mastodon" not in KNOWN_EXPORTERS
        assert "mastodon" in BUILTIN_EXPORTERS


class TestEnableMastodonExporter:

    def test_guest_not_found(self, app):
        from apps.exporters import enable_mastodon_exporter

        with app.app_context():
            log = []
            result = enable_mastodon_exporter(99999, log_callback=log.append)
            assert result is False
            assert any("Guest not found" in m for m in log)

    def test_no_credential(self, app):
        from apps.exporters import enable_mastodon_exporter

        with app.app_context():
            # Guest without credential, and no default credential exists
            guest = _create_guest(app, name="masto-nocred", ip="10.0.0.80")
            # Ensure no default credential
            Credential.query.filter_by(is_default=True).update({"is_default": False})
            db.session.commit()

            log = []
            result = enable_mastodon_exporter(guest.id, log_callback=log.append)
            assert result is False
            assert any("No SSH credential" in m for m in log)

            db.session.delete(guest)
            db.session.commit()

    def test_no_ip(self, app):
        from apps.exporters import enable_mastodon_exporter

        with app.app_context():
            guest = _create_guest(app, name="masto-noip", ip="dhcp", with_credential=True)
            log = []
            result = enable_mastodon_exporter(guest.id, log_callback=log.append)
            assert result is False
            assert any("no usable IP" in m for m in log)

            db.session.delete(guest)
            db.session.commit()

    def test_already_enabled(self, app):
        from apps.exporters import enable_mastodon_exporter

        with app.app_context():
            guest = _create_guest(app, name="masto-already", ip="10.0.0.81")
            exp = ExporterInstance(
                guest_id=guest.id,
                exporter_type="mastodon",
                port=9394,
                status="installed",
            )
            db.session.add(exp)
            db.session.commit()

            log = []
            result = enable_mastodon_exporter(guest.id, log_callback=log.append)
            assert result is True
            assert any("already enabled" in m for m in log)

            db.session.delete(exp)
            db.session.delete(guest)
            db.session.commit()

    @patch("apps.exporters.SSHClient")
    def test_enable_success_default_config(self, MockSSH, app):
        from apps.exporters import enable_mastodon_exporter

        mock_ssh = MagicMock()
        mock_ssh.execute_sudo.return_value = ("", "", 0)
        mock_ssh.execute.return_value = ("mastodon-web.service\nmastodon-sidekiq.service\n", "", 0)
        mock_ssh.__enter__ = MagicMock(return_value=mock_ssh)
        mock_ssh.__exit__ = MagicMock(return_value=False)
        MockSSH.from_credential.return_value = mock_ssh

        with app.app_context():
            guest = _create_guest(app, name="masto-enable-ok", ip="10.0.0.82", with_credential=True)
            log = []
            with patch("apps.exporters._regenerate_prometheus_config"):
                result = enable_mastodon_exporter(guest.id, log_callback=log.append)

            assert result is True
            exp = ExporterInstance.query.filter_by(
                guest_id=guest.id, exporter_type="mastodon", status="installed"
            ).first()
            assert exp is not None
            assert exp.port == 9394

            db.session.delete(exp)
            db.session.delete(guest)
            db.session.commit()

    @patch("apps.exporters.SSHClient")
    def test_enable_with_custom_config(self, MockSSH, app):
        from apps.exporters import enable_mastodon_exporter

        mock_ssh = MagicMock()
        mock_ssh.execute_sudo.return_value = ("", "", 0)
        mock_ssh.execute.return_value = ("mastodon-web.service\n", "", 0)
        mock_ssh.__enter__ = MagicMock(return_value=mock_ssh)
        mock_ssh.__exit__ = MagicMock(return_value=False)
        MockSSH.from_credential.return_value = mock_ssh

        config = {
            "web_detailed_metrics": False,
            "sidekiq_detailed_metrics": True,
            "mode": "local",
            "host": "0.0.0.0",
            "port": 9500,
        }

        with app.app_context():
            guest = _create_guest(app, name="masto-enable-cfg", ip="10.0.0.83", with_credential=True)
            log = []
            with patch("apps.exporters._regenerate_prometheus_config"):
                result = enable_mastodon_exporter(guest.id, config=config, log_callback=log.append)

            assert result is True
            exp = ExporterInstance.query.filter_by(
                guest_id=guest.id, exporter_type="mastodon", status="installed"
            ).first()
            assert exp is not None
            assert exp.port == 9500
            assert exp.config == config

            db.session.delete(exp)
            db.session.delete(guest)
            db.session.commit()


class TestDisableMastodonExporter:

    def test_guest_not_found(self, app):
        from apps.exporters import disable_mastodon_exporter

        with app.app_context():
            log = []
            result = disable_mastodon_exporter(99999, log_callback=log.append)
            assert result is False
            assert any("Guest not found" in m for m in log)

    @patch("apps.exporters.SSHClient")
    def test_disable_success(self, MockSSH, app):
        from apps.exporters import disable_mastodon_exporter

        mock_ssh = MagicMock()
        mock_ssh.execute_sudo.return_value = ("", "", 0)
        mock_ssh.execute.return_value = ("mastodon-web.service\n", "", 0)
        mock_ssh.__enter__ = MagicMock(return_value=mock_ssh)
        mock_ssh.__exit__ = MagicMock(return_value=False)
        MockSSH.from_credential.return_value = mock_ssh

        with app.app_context():
            guest = _create_guest(app, name="masto-disable-ok", ip="10.0.0.84", with_credential=True)
            exp = ExporterInstance(
                guest_id=guest.id,
                exporter_type="mastodon",
                port=9394,
                status="installed",
            )
            db.session.add(exp)
            db.session.commit()

            log = []
            with patch("apps.exporters._regenerate_prometheus_config"):
                result = disable_mastodon_exporter(guest.id, log_callback=log.append)

            assert result is True
            remaining = ExporterInstance.query.filter_by(
                guest_id=guest.id, exporter_type="mastodon"
            ).count()
            assert remaining == 0

            db.session.delete(guest)
            db.session.commit()

    @patch("apps.exporters.SSHClient")
    def test_disable_sed_removes_unprefixed_vars(self, MockSSH, app):
        """Verify the sed command also removes PROMETHEUS_EXPORTER_HOST/PORT."""
        from apps.exporters import disable_mastodon_exporter

        mock_ssh = MagicMock()
        mock_ssh.execute_sudo.return_value = ("", "", 0)
        mock_ssh.execute.return_value = ("mastodon-web.service\n", "", 0)
        mock_ssh.__enter__ = MagicMock(return_value=mock_ssh)
        mock_ssh.__exit__ = MagicMock(return_value=False)
        MockSSH.from_credential.return_value = mock_ssh

        with app.app_context():
            guest = _create_guest(app, name="masto-disable-sed", ip="10.0.0.85", with_credential=True)
            exp = ExporterInstance(
                guest_id=guest.id,
                exporter_type="mastodon",
                port=9394,
                status="installed",
            )
            db.session.add(exp)
            db.session.commit()

            with patch("apps.exporters._regenerate_prometheus_config"):
                disable_mastodon_exporter(guest.id)

            # Verify sed was called with the pattern that catches unprefixed vars
            sed_calls = [
                str(call) for call in mock_ssh.execute_sudo.call_args_list
                if "sed" in str(call)
            ]
            assert len(sed_calls) > 0
            assert "PROMETHEUS_EXPORTER_HOST" in sed_calls[0]
            assert "PROMETHEUS_EXPORTER_PORT" in sed_calls[0]

            db.session.delete(guest)
            db.session.commit()


class TestReconfigureMastodonExporter:

    def test_guest_not_found(self, app):
        from apps.exporters import reconfigure_mastodon_exporter

        with app.app_context():
            log = []
            result = reconfigure_mastodon_exporter(99999, {}, log_callback=log.append)
            assert result is False
            assert any("Guest not found" in m for m in log)

    def test_not_enabled(self, app):
        from apps.exporters import reconfigure_mastodon_exporter

        with app.app_context():
            guest = _create_guest(app, name="masto-reconf-none", ip="10.0.0.86")
            log = []
            result = reconfigure_mastodon_exporter(guest.id, {}, log_callback=log.append)
            assert result is False
            assert any("not currently enabled" in m for m in log)

            db.session.delete(guest)
            db.session.commit()

    @patch("apps.exporters.SSHClient")
    def test_reconfigure_success(self, MockSSH, app):
        from apps.exporters import reconfigure_mastodon_exporter

        mock_ssh = MagicMock()
        mock_ssh.execute_sudo.return_value = ("", "", 0)
        mock_ssh.execute.return_value = ("mastodon-web.service\n", "", 0)
        mock_ssh.__enter__ = MagicMock(return_value=mock_ssh)
        mock_ssh.__exit__ = MagicMock(return_value=False)
        MockSSH.from_credential.return_value = mock_ssh

        with app.app_context():
            guest = _create_guest(app, name="masto-reconf-ok", ip="10.0.0.87", with_credential=True)
            exp = ExporterInstance(
                guest_id=guest.id,
                exporter_type="mastodon",
                port=9394,
                config={"mode": "external", "port": 9394},
                status="installed",
            )
            db.session.add(exp)
            db.session.commit()
            exp_id = exp.id

            new_config = {"mode": "local", "port": 9500, "host": "0.0.0.0"}
            log = []
            with patch("apps.exporters._regenerate_prometheus_config"):
                result = reconfigure_mastodon_exporter(guest.id, new_config, log_callback=log.append)

            assert result is True
            updated = ExporterInstance.query.get(exp_id)
            assert updated.port == 9500
            assert updated.config == new_config

            db.session.delete(updated)
            db.session.delete(guest)
            db.session.commit()


class TestMastodonExporterRoutes:

    def test_mastodon_exporter_status_endpoint(self, auth_client):
        resp = auth_client.get("/prometheus/mastodon-exporter/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "running" in data
        assert "log" in data

    def test_enable_no_guest_configured(self, auth_client, app):
        with app.app_context():
            Setting.set("mastodon_guest_id", "")
            db.session.commit()

        resp = auth_client.post("/prometheus/mastodon-exporter/enable", data={
            "web_detailed_metrics": "on",
            "sidekiq_detailed_metrics": "on",
            "mode": "external",
            "host": "localhost",
            "port": "9394",
        }, follow_redirects=False)
        assert resp.status_code in (302, 303)

    def test_disable_no_guest_configured(self, auth_client, app):
        with app.app_context():
            Setting.set("mastodon_guest_id", "")
            db.session.commit()

        resp = auth_client.post("/prometheus/mastodon-exporter/disable",
                                follow_redirects=False)
        assert resp.status_code in (302, 303)

    def test_reconfigure_no_guest_configured(self, auth_client, app):
        with app.app_context():
            Setting.set("mastodon_guest_id", "")
            db.session.commit()

        resp = auth_client.post("/prometheus/mastodon-exporter/reconfigure", data={
            "web_detailed_metrics": "on",
            "mode": "external",
            "port": "9394",
        }, follow_redirects=False)
        assert resp.status_code in (302, 303)


# ---------------------------------------------------------------------------
# Host-Level Exporter Routes
# ---------------------------------------------------------------------------

def _create_ipmi_host(app, name="ipmi-host", hostname="10.0.0.90"):
    """Create a ProxmoxHost for host-level exporter tests."""
    host = ProxmoxHost(
        name=name,
        hostname=hostname,
        host_type="pve",
        ipmi_enabled=True,
        ipmi_address="10.0.0.50",
    )
    db.session.add(host)
    db.session.commit()
    return host


class TestHostExporterRoutes:

    def test_host_exporter_add_invalid_type(self, auth_client):
        resp = auth_client.post("/prometheus/host-exporters/add", data={
            "host_id": "1",
            "exporter_type": "node_exporter",
            "port": "9100",
        }, follow_redirects=False)
        assert resp.status_code in (302, 303)

    def test_host_exporter_add_missing_host(self, auth_client):
        resp = auth_client.post("/prometheus/host-exporters/add", data={
            "host_id": "",
            "exporter_type": "ipmi_exporter",
            "port": "9290",
        }, follow_redirects=False)
        assert resp.status_code in (302, 303)

    def test_host_exporter_add_success(self, auth_client, app):
        with app.app_context():
            host = _create_ipmi_host(app, name="hexp-add", hostname="10.0.0.91")
            host_id = host.id

        resp = auth_client.post("/prometheus/host-exporters/add", data={
            "host_id": str(host_id),
            "exporter_type": "ipmi_exporter",
            "port": "9290",
        }, follow_redirects=False)
        assert resp.status_code in (302, 303)

        with app.app_context():
            exp = HostExporterInstance.query.filter_by(host_id=host_id).first()
            assert exp is not None
            assert exp.exporter_type == "ipmi_exporter"
            assert exp.port == 9290
            assert exp.status == "pending"

            db.session.delete(exp)
            ProxmoxHost.query.filter_by(id=host_id).delete()
            db.session.commit()

    def test_host_exporter_add_duplicate(self, auth_client, app):
        with app.app_context():
            host = _create_ipmi_host(app, name="hexp-dup", hostname="10.0.0.92")
            exp = HostExporterInstance(
                host_id=host.id,
                exporter_type="ipmi_exporter",
                port=9290,
                status="pending",
            )
            db.session.add(exp)
            db.session.commit()
            host_id = host.id

        resp = auth_client.post("/prometheus/host-exporters/add", data={
            "host_id": str(host_id),
            "exporter_type": "ipmi_exporter",
            "port": "9290",
        }, follow_redirects=False)
        assert resp.status_code in (302, 303)

        with app.app_context():
            count = HostExporterInstance.query.filter_by(
                host_id=host_id, exporter_type="ipmi_exporter"
            ).count()
            assert count == 1

            HostExporterInstance.query.filter_by(host_id=host_id).delete()
            ProxmoxHost.query.filter_by(id=host_id).delete()
            db.session.commit()

    def test_host_exporter_delete(self, auth_client, app):
        with app.app_context():
            host = _create_ipmi_host(app, name="hexp-del", hostname="10.0.0.93")
            exp = HostExporterInstance(
                host_id=host.id,
                exporter_type="ipmi_exporter",
                port=9290,
                status="pending",
            )
            db.session.add(exp)
            db.session.commit()
            exp_id = exp.id
            host_id = host.id

        resp = auth_client.post(f"/prometheus/host-exporters/{exp_id}/delete",
                                follow_redirects=False)
        assert resp.status_code in (302, 303)

        with app.app_context():
            assert HostExporterInstance.query.get(exp_id) is None
            ProxmoxHost.query.filter_by(id=host_id).delete()
            db.session.commit()

    def test_host_exporter_delete_installed_blocked(self, auth_client, app):
        with app.app_context():
            host = _create_ipmi_host(app, name="hexp-del-block", hostname="10.0.0.94")
            exp = HostExporterInstance(
                host_id=host.id,
                exporter_type="ipmi_exporter",
                port=9290,
                status="installed",
            )
            db.session.add(exp)
            db.session.commit()
            exp_id = exp.id
            host_id = host.id

        resp = auth_client.post(f"/prometheus/host-exporters/{exp_id}/delete",
                                follow_redirects=True)
        assert resp.status_code == 200
        assert b"Uninstall" in resp.data

        with app.app_context():
            assert HostExporterInstance.query.get(exp_id) is not None
            HostExporterInstance.query.filter_by(host_id=host_id).delete()
            ProxmoxHost.query.filter_by(id=host_id).delete()
            db.session.commit()

    def test_host_exporter_install_status(self, auth_client):
        resp = auth_client.get("/prometheus/host-exporters/install/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "running" in data

    def test_host_exporter_uninstall_status(self, auth_client):
        resp = auth_client.get("/prometheus/host-exporters/uninstall/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "running" in data


class TestHostExporterModel:

    def test_host_exporter_instance_creation(self, app):
        with app.app_context():
            host = _create_ipmi_host(app, name="hexp-model", hostname="10.0.0.95")
            exp = HostExporterInstance(
                host_id=host.id,
                exporter_type="ipmi_exporter",
                port=9290,
                status="pending",
            )
            db.session.add(exp)
            db.session.commit()
            assert exp.id is not None
            assert exp.host.name == "hexp-model"

            db.session.delete(exp)
            ProxmoxHost.query.filter_by(id=host.id).delete()
            db.session.commit()

    def test_host_exporter_relationship(self, app):
        with app.app_context():
            host = _create_ipmi_host(app, name="hexp-rel", hostname="10.0.0.96")
            exp = HostExporterInstance(
                host_id=host.id,
                exporter_type="ipmi_exporter",
                port=9290,
                status="installed",
            )
            db.session.add(exp)
            db.session.commit()

            host = ProxmoxHost.query.get(host.id)
            assert len(host.host_exporter_instances) == 1
            assert host.host_exporter_instances[0].exporter_type == "ipmi_exporter"

            db.session.delete(exp)
            ProxmoxHost.query.filter_by(id=host.id).delete()
            db.session.commit()

    def test_ipmi_exporter_is_host_level(self):
        from apps.exporters import KNOWN_EXPORTERS
        info = KNOWN_EXPORTERS["ipmi_exporter"]
        assert info.get("host_level") is True

    def test_non_host_level_exporters_lack_flag(self):
        from apps.exporters import KNOWN_EXPORTERS
        assert KNOWN_EXPORTERS["node_exporter"].get("host_level") is not True
        assert KNOWN_EXPORTERS["postgres_exporter"].get("host_level") is not True
