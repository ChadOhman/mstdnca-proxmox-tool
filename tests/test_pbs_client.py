"""Unit tests for PBSClient in clients/pbs_client.py.

These construct a PBSClient with a MagicMock host_model (patching
auth.credential_store.decrypt so no real Fernet key/DB is needed), then mock
requests.Session.post/.get directly -- the boundary PBSClient actually uses
-- to assert login/header/cookie handling and request-building logic
(especially UPID URL-quoting on the task endpoints).
"""
from unittest.mock import MagicMock, patch
from urllib.parse import quote

import pytest
import requests

from clients.pbs_client import PBSClient


def _token_host_model(**overrides):
    m = MagicMock()
    m.hostname = "pbs.test.local"
    m.port = 8007
    m.verify_ssl = True
    m.auth_type = "token"
    m.username = "test-only-user@pbs"
    m.api_token_id = "test-only-tokenid"
    m.api_token_secret = "encrypted-token-blob"
    for k, v in overrides.items():
        setattr(m, k, v)
    return m


def _password_host_model(**overrides):
    m = MagicMock()
    m.hostname = "pbs.test.local"
    m.port = 8007
    m.verify_ssl = True
    m.auth_type = "password"
    m.username = "test-only-user@pbs"
    m.encrypted_password = "encrypted-password-blob"
    for k, v in overrides.items():
        setattr(m, k, v)
    return m


def _password_client(pw="test-only-pw", **overrides):
    """Build a PBSClient using password auth (deferred login), decrypt mocked out."""
    with patch("auth.credential_store.decrypt", return_value=pw):
        return PBSClient(_password_host_model(**overrides))


class TestInit:
    def test_token_auth_sets_authorization_header_and_logs_in_immediately(self):
        with patch("auth.credential_store.decrypt", return_value="test-only-tokensecret"):
            client = PBSClient(_token_host_model())
        assert client._logged_in is True
        assert client.session.headers["Authorization"] == (
            "PBSAPIToken=test-only-user@pbs!test-only-tokenid:test-only-tokensecret"
        )

    def test_token_auth_defaults_username_to_root_pam(self):
        with patch("auth.credential_store.decrypt", return_value="test-only-tokensecret"):
            client = PBSClient(_token_host_model(username=None))
        assert client.session.headers["Authorization"].startswith("PBSAPIToken=root@pam!")

    def test_password_auth_defers_login(self):
        client = _password_client()
        assert client._logged_in is False
        assert client._username == "test-only-user@pbs"
        assert client._password == "test-only-pw"
        assert "Authorization" not in client.session.headers

    def test_base_url_built_from_hostname_and_port(self):
        with patch("auth.credential_store.decrypt", return_value="x"):
            client = PBSClient(_password_host_model(hostname="10.0.0.5", port=8007))
        assert client.base_url == "https://10.0.0.5:8007/api2/json"

    def test_session_verify_follows_host_model(self):
        with patch("auth.credential_store.decrypt", return_value="x"):
            client = PBSClient(_password_host_model(verify_ssl=False))
        assert client.session.verify is False


class TestLogin:
    def test_login_success_sets_cookie_and_csrf_header(self):
        client = _password_client()
        resp = MagicMock(status_code=200)
        resp.json.return_value = {"data": {"ticket": "test-only-ticket", "CSRFPreventionToken": "test-only-csrf"}}
        with patch.object(client.session, "post", return_value=resp) as post:
            ok = client._login()
        assert ok is True
        assert client._logged_in is True
        assert client.session.cookies.get("PBSAuthCookie") == "test-only-ticket"
        assert client.session.headers["CSRFPreventionToken"] == "test-only-csrf"
        post.assert_called_once_with(
            f"{client.base_url}/access/ticket",
            json={"username": "test-only-user@pbs", "password": "test-only-pw"},
            timeout=10,
        )

    def test_login_failure_bad_status_code(self):
        client = _password_client()
        resp = MagicMock(status_code=401)
        with patch.object(client.session, "post", return_value=resp):
            ok = client._login()
        assert ok is False
        assert client._logged_in is False

    def test_login_request_exception_returns_false(self):
        client = _password_client()
        with patch.object(client.session, "post", side_effect=requests.RequestException("boom")):
            ok = client._login()
        assert ok is False
        assert client._logged_in is False

    def test_login_skips_network_call_when_already_logged_in(self):
        client = _password_client()
        client._logged_in = True
        with patch.object(client.session, "post") as post:
            ok = client._login()
        assert ok is True
        post.assert_not_called()


class TestGet:
    def test_get_triggers_login_then_fetches_data(self):
        client = _password_client()
        login_resp = MagicMock(status_code=200)
        login_resp.json.return_value = {"data": {"ticket": "t", "CSRFPreventionToken": "c"}}
        data_resp = MagicMock(status_code=200)
        data_resp.json.return_value = {"data": {"foo": "bar"}}
        with patch.object(client.session, "post", return_value=login_resp), \
                patch.object(client.session, "get", return_value=data_resp) as get:
            result = client._get("/nodes")
        assert result == {"foo": "bar"}
        get.assert_called_once_with(f"{client.base_url}/nodes", params=None, timeout=15)

    def test_get_returns_none_when_login_fails(self):
        client = _password_client()
        with patch.object(client.session, "post", return_value=MagicMock(status_code=401)):
            result = client._get("/nodes")
        assert result is None

    def test_get_returns_none_on_bad_status(self):
        client = _password_client()
        client._logged_in = True
        with patch.object(client.session, "get", return_value=MagicMock(status_code=500)):
            result = client._get("/nodes")
        assert result is None

    def test_get_handles_request_exception(self):
        client = _password_client()
        client._logged_in = True
        with patch.object(client.session, "get", side_effect=requests.RequestException("net down")):
            result = client._get("/nodes")
        assert result is None

    def test_get_passes_params_through(self):
        client = _password_client()
        client._logged_in = True
        data_resp = MagicMock(status_code=200)
        data_resp.json.return_value = {"data": [1, 2, 3]}
        with patch.object(client.session, "get", return_value=data_resp) as get:
            result = client._get("/admin/datastore/store1/snapshots", params={"backup-type": "vm"})
        assert result == [1, 2, 3]
        get.assert_called_once_with(
            f"{client.base_url}/admin/datastore/store1/snapshots", params={"backup-type": "vm"}, timeout=15
        )


class TestPost:
    def test_post_returns_not_authenticated_when_login_fails(self):
        client = _password_client()
        with patch.object(client.session, "post", return_value=MagicMock(status_code=401)):
            ok, data = client._post("/admin/datastore/store1/gc")
        assert ok is False
        assert data == "Not authenticated"

    def test_post_success_returns_data(self):
        client = _password_client()
        client._logged_in = True
        resp = MagicMock(status_code=200)
        resp.json.return_value = {"data": "UPID:pbs:gc"}
        with patch.object(client.session, "post", return_value=resp) as post:
            ok, data = client._post("/admin/datastore/store1/gc")
        assert ok is True
        assert data == "UPID:pbs:gc"
        post.assert_called_once_with(f"{client.base_url}/admin/datastore/store1/gc", json={}, timeout=15)

    def test_post_bad_status_returns_false_with_http_code(self):
        client = _password_client()
        client._logged_in = True
        with patch.object(client.session, "post", return_value=MagicMock(status_code=500)):
            ok, data = client._post("/admin/datastore/store1/gc")
        assert ok is False
        assert data == "HTTP 500"

    def test_post_request_exception(self):
        client = _password_client()
        client._logged_in = True
        with patch.object(client.session, "post", side_effect=requests.Timeout("HTTPSConnectionPool(...) timed out")):
            ok, data = client._post("/admin/datastore/store1/gc")
        assert ok is False
        # Described by exception type; the raw requests text (URL, pool) must not leak.
        assert data == "request timed out"


class TestTaskStatusUrlQuoting:
    """PBS UPIDs contain ':' which must be percent-encoded before hitting the URL."""

    def test_get_task_status_quotes_upid(self):
        client = _password_client()
        upid = "UPID:pbs:00001234:00005678:0011AABB:vzdump:100:root@pam:"
        with patch.object(client, "get_node_name", return_value="pbs-node1"), \
                patch.object(client, "_get", return_value={"status": "stopped"}) as get_mock:
            result = client.get_task_status(upid)
        assert result == {"status": "stopped"}
        expected_path = f"/nodes/pbs-node1/tasks/{quote(upid, safe='')}/status"
        get_mock.assert_called_once_with(expected_path)
        assert "%3A" in expected_path  # colons got percent-encoded

    def test_get_task_log_quotes_upid_and_passes_params(self):
        client = _password_client()
        upid = "UPID:pbs:0000ABCD:00000001:00000002:vzdump:100:root@pam:"
        with patch.object(client, "get_node_name", return_value="pbs-node1"), \
                patch.object(client, "_get", return_value=[{"n": 1, "t": "line"}]) as get_mock:
            result = client.get_task_log(upid, start=5, limit=50)
        assert result == [{"n": 1, "t": "line"}]
        expected_path = f"/nodes/pbs-node1/tasks/{quote(upid, safe='')}/log"
        get_mock.assert_called_once_with(expected_path, params={"start": 5, "limit": 50})

    def test_get_task_log_defaults_to_empty_list_when_get_returns_none(self):
        client = _password_client()
        with patch.object(client, "get_node_name", return_value="pbs-node1"), \
                patch.object(client, "_get", return_value=None):
            result = client.get_task_log("UPID:pbs:1:2:3:vzdump:100:root@pam:")
        assert result == []

    def test_get_task_log_default_start_and_limit(self):
        client = _password_client()
        with patch.object(client, "get_node_name", return_value="pbs-node1"), \
                patch.object(client, "_get", return_value=[]) as get_mock:
            client.get_task_log("UPID:pbs:1:2:3:vzdump:100:root@pam:")
        _, kwargs = get_mock.call_args
        assert kwargs["params"] == {"start": 0, "limit": 500}


class TestGetNodeName:
    def test_returns_first_node_name(self):
        client = _password_client()
        with patch.object(client, "_get", return_value=[{"node": "pbs-node1"}]):
            assert client.get_node_name() == "pbs-node1"

    def test_falls_back_to_pbs_when_empty_list(self):
        client = _password_client()
        with patch.object(client, "_get", return_value=[]):
            assert client.get_node_name() == "pbs"

    def test_falls_back_to_pbs_when_none(self):
        client = _password_client()
        with patch.object(client, "_get", return_value=None):
            assert client.get_node_name() == "pbs"


class TestAptRefresh:
    def test_refresh_apt_cache_returns_upid(self):
        client = _password_client()
        with patch.object(client, "get_node_name", return_value="pbs-node1"), \
                patch.object(client, "_post", return_value=(True, "UPID:pbs:apt")) as post_mock:
            upid = client.refresh_apt_cache()
        assert upid == "UPID:pbs:apt"
        post_mock.assert_called_once_with("/nodes/pbs-node1/apt/update")

    def test_refresh_apt_cache_raises_runtime_error_on_failure(self):
        client = _password_client()
        with patch.object(client, "get_node_name", return_value="pbs-node1"), \
                patch.object(client, "_post", return_value=(False, "HTTP 500")):
            with pytest.raises(RuntimeError, match="HTTP 500"):
                client.refresh_apt_cache()


class TestConnectionAndVersion:
    def test_test_connection_success_with_release(self):
        client = _password_client()
        with patch.object(client, "_get", return_value={"version": "3.2", "release": "1"}):
            ok, msg = client.test_connection()
        assert ok is True
        assert msg == "PBS 3.2-1"

    def test_test_connection_success_without_release(self):
        client = _password_client()
        with patch.object(client, "_get", return_value={"version": "3.2", "release": ""}):
            ok, msg = client.test_connection()
        assert ok is True
        assert msg == "PBS 3.2"

    def test_test_connection_failure_when_no_data(self):
        client = _password_client()
        with patch.object(client, "_get", return_value=None):
            ok, msg = client.test_connection()
        assert ok is False
        assert "Could not connect" in msg


class TestDatastoreAggregation:
    def test_get_all_datastores_with_status_aggregates_counts_and_sorts_groups(self):
        client = _password_client()
        with patch.object(client, "get_datastores", return_value=[{"store": "store1", "path": "/mnt/store1"}]), \
                patch.object(
                    client, "get_datastore_status", return_value={"used": 100, "avail": 900, "gc-status": {"x": 1}}
                ), \
                patch.object(client, "get_backup_groups", return_value=[
                    {"backup-type": "vm", "last-backup": 5},
                    {"backup-type": "ct", "last-backup": 10},
                    {"backup-type": "host", "last-backup": 1},
                ]):
            result = client.get_all_datastores_with_status()
        assert len(result) == 1
        ds = result[0]
        assert ds["name"] == "store1"
        assert ds["path"] == "/mnt/store1"
        assert ds["used"] == 100
        assert ds["avail"] == 900
        assert ds["total"] == 1000
        assert ds["group_count"] == 3
        assert ds["vm_count"] == 1
        assert ds["ct_count"] == 1
        assert ds["host_count"] == 1
        assert ds["gc_status"] == {"x": 1}
        # groups sorted newest-first by last-backup
        assert [g["last-backup"] for g in ds["groups"]] == [10, 5, 1]

    def test_get_all_datastores_skips_entries_without_a_store_name(self):
        client = _password_client()
        with patch.object(client, "get_datastores", return_value=[{"path": "/mnt/x"}]):
            result = client.get_all_datastores_with_status()
        assert result == []

    def test_get_all_datastores_falls_back_to_name_key(self):
        client = _password_client()
        with patch.object(client, "get_datastores", return_value=[{"name": "store2"}]), \
                patch.object(client, "get_datastore_status", return_value={"used": 0, "avail": 0}), \
                patch.object(client, "get_backup_groups", return_value=[]):
            result = client.get_all_datastores_with_status()
        assert len(result) == 1
        assert result[0]["name"] == "store2"
