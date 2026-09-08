"""
Tests for the PostgreSQL plan analyzer (_analyze_pg_plan) and the pg_analyze_plan endpoint.

Unit tests verify the pure-Python rule logic with synthetic plan JSON.
Endpoint tests verify security/validation gates (auth, DB name allowlist, missing params).
"""
import json

import pytest

from models import Guest, GuestService, db
from routes.services import _analyze_pg_plan

# ---------------------------------------------------------------------------
# Helpers to build minimal plan JSON structures
# ---------------------------------------------------------------------------

_BASE_NODE = {
    "Node Type": "Seq Scan",
    "Relation Name": "users",
    "Actual Rows": 1,
    "Actual Loops": 1,
    "Plan Rows": 1,
    "Plan Width": 10,
    "Actual Total Time": 0.1,
}


def _plan(node: dict) -> list:
    """Wrap a node dict in the EXPLAIN FORMAT JSON envelope."""
    return [{"Plan": node}]


def _node(**kwargs) -> dict:
    """Build a node from _BASE_NODE with overrides."""
    n = dict(_BASE_NODE)
    n.update(kwargs)
    return n


# ---------------------------------------------------------------------------
# Unit tests: _analyze_pg_plan rule logic
# ---------------------------------------------------------------------------

class TestAnalyzePgPlanCleanPlan:
    def test_small_seq_scan_no_findings(self):
        node = _node(**{"Node Type": "Seq Scan", "Actual Rows": 500})
        assert _analyze_pg_plan(_plan(node)) == []

    def test_index_scan_good_selectivity_no_findings(self):
        node = _node(**{"Node Type": "Index Scan", "Actual Rows": 100, "Rows Removed by Filter": 10})
        assert _analyze_pg_plan(_plan(node)) == []


class TestSortSpillToDisk:
    def test_sort_disk_triggers_critical(self):
        node = _node(**{
            "Node Type": "Sort",
            "Sort Method": "external merge Disk",
            "Sort Space Used": 8192,
            "Plans": [],
        })
        findings = _analyze_pg_plan(_plan(node))
        rules = [f["rule"] for f in findings]
        assert "sort_spill_to_disk" in rules
        assert any(f["severity"] == "critical" for f in findings if f["rule"] == "sort_spill_to_disk")

    def test_sort_in_memory_no_finding(self):
        node = _node(**{"Node Type": "Sort", "Sort Method": "quicksort", "Sort Space Used": 100})
        findings = _analyze_pg_plan(_plan(node))
        assert not any(f["rule"] == "sort_spill_to_disk" for f in findings)


class TestHashSpillToDisk:
    def test_hash_batches_gt_1_triggers_warning(self):
        node = _node(**{"Node Type": "Hash", "Hash Batches": 4, "Plans": []})
        findings = _analyze_pg_plan(_plan(node))
        rules = [f["rule"] for f in findings]
        assert "hash_spill_to_disk" in rules
        assert any(f["severity"] == "warning" for f in findings if f["rule"] == "hash_spill_to_disk")

    def test_hash_batches_1_no_finding(self):
        node = _node(**{"Node Type": "Hash", "Hash Batches": 1})
        assert not any(f["rule"] == "hash_spill_to_disk" for f in _analyze_pg_plan(_plan(node)))


class TestSeqScanInJoin:
    def test_large_seq_scan_in_join_triggers_critical(self):
        seq_scan = _node(**{"Node Type": "Seq Scan", "Relation Name": "orders", "Actual Rows": 50_000})
        join_node = {
            "Node Type": "Hash Join",
            "Actual Rows": 50_000,
            "Actual Loops": 1,
            "Plan Rows": 50_000,
            "Plan Width": 20,
            "Actual Total Time": 200.0,
            "Plans": [seq_scan],
        }
        findings = _analyze_pg_plan(_plan(join_node))
        rules = [f["rule"] for f in findings]
        assert "seq_scan_in_join" in rules
        assert any(f["severity"] == "critical" for f in findings if f["rule"] == "seq_scan_in_join")

    def test_small_seq_scan_in_join_no_finding(self):
        seq_scan = _node(**{"Node Type": "Seq Scan", "Actual Rows": 500})
        join_node = {"Node Type": "Hash Join", "Actual Rows": 10, "Actual Loops": 1,
                     "Plan Rows": 10, "Plan Width": 10, "Actual Total Time": 1.0, "Plans": [seq_scan]}
        findings = _analyze_pg_plan(_plan(join_node))
        assert not any(f["rule"] == "seq_scan_in_join" for f in findings)

    def test_large_seq_scan_outside_join_no_finding(self):
        """A standalone large seq scan does NOT trigger seq_scan_in_join."""
        node = _node(**{"Node Type": "Seq Scan", "Actual Rows": 50_000})
        findings = _analyze_pg_plan(_plan(node))
        assert not any(f["rule"] == "seq_scan_in_join" for f in findings)


class TestTempBlocksUsage:
    def test_temp_read_blocks_triggers_warning(self):
        node = _node(**{"Temp Read Blocks": 100})
        findings = _analyze_pg_plan(_plan(node))
        assert any(f["rule"] == "temp_blocks_usage" for f in findings)
        assert any(f["severity"] == "warning" for f in findings if f["rule"] == "temp_blocks_usage")

    def test_temp_written_blocks_triggers_warning(self):
        node = _node(**{"Temp Written Blocks": 50})
        assert any(f["rule"] == "temp_blocks_usage" for f in _analyze_pg_plan(_plan(node)))

    def test_no_temp_blocks_no_finding(self):
        node = _node(**{"Temp Read Blocks": 0, "Temp Written Blocks": 0})
        assert not any(f["rule"] == "temp_blocks_usage" for f in _analyze_pg_plan(_plan(node)))


class TestWorkerMismatch:
    def test_fewer_workers_launched_triggers_warning(self):
        node = _node(**{"Workers Planned": 4, "Workers Launched": 1})
        findings = _analyze_pg_plan(_plan(node))
        assert any(f["rule"] == "worker_mismatch" for f in findings)
        assert any(f["severity"] == "warning" for f in findings if f["rule"] == "worker_mismatch")

    def test_workers_match_no_finding(self):
        node = _node(**{"Workers Planned": 4, "Workers Launched": 4})
        assert not any(f["rule"] == "worker_mismatch" for f in _analyze_pg_plan(_plan(node)))

    def test_workers_launched_absent_no_finding(self):
        """If Workers Launched key is missing, no finding (parallel didn't run)."""
        node = _node(**{"Workers Planned": 4})
        assert not any(f["rule"] == "worker_mismatch" for f in _analyze_pg_plan(_plan(node)))


class TestWideRows:
    def test_wide_rows_triggers_info(self):
        node = _node(**{"Plan Width": 3000, "Actual Rows": 5000})
        findings = _analyze_pg_plan(_plan(node))
        assert any(f["rule"] == "wide_rows" for f in findings)
        assert any(f["severity"] == "info" for f in findings if f["rule"] == "wide_rows")

    def test_wide_rows_small_count_no_finding(self):
        node = _node(**{"Plan Width": 3000, "Actual Rows": 50})
        assert not any(f["rule"] == "wide_rows" for f in _analyze_pg_plan(_plan(node)))

    def test_narrow_rows_no_finding(self):
        node = _node(**{"Plan Width": 100, "Actual Rows": 10_000})
        assert not any(f["rule"] == "wide_rows" for f in _analyze_pg_plan(_plan(node)))


class TestMalformedInput:
    def test_none_returns_parse_error(self):
        result = _analyze_pg_plan(None)  # type: ignore[arg-type]
        assert len(result) == 1
        assert result[0]["rule"] == "parse_error"

    def test_empty_list_returns_parse_error(self):
        result = _analyze_pg_plan([])
        assert len(result) == 1
        assert result[0]["rule"] == "parse_error"

    def test_missing_plan_key_no_crash(self):
        """[{}] — top-level object has no 'Plan' key; should return no findings (not crash)."""
        result = _analyze_pg_plan([{}])
        assert isinstance(result, list)
        # Either no findings or a parse_error — must not raise
        assert all(isinstance(f, dict) for f in result)

    def test_non_list_returns_parse_error(self):
        result = _analyze_pg_plan("not a list")  # type: ignore[arg-type]
        assert len(result) == 1
        assert result[0]["rule"] == "parse_error"


class TestDeduplication:
    def test_duplicate_seq_scan_in_join_deduplicated(self):
        """Same table appearing in multiple Nested Loop iterations → single finding."""
        seq_scan = _node(**{"Node Type": "Seq Scan", "Relation Name": "products", "Actual Rows": 20_000})
        join_node = {
            "Node Type": "Nested Loop",
            "Actual Rows": 20_000,
            "Actual Loops": 1,
            "Plan Rows": 20_000,
            "Plan Width": 20,
            "Actual Total Time": 100.0,
            "Plans": [seq_scan, dict(seq_scan)],  # same table twice
        }
        findings = _analyze_pg_plan(_plan(join_node))
        seq_findings = [f for f in findings if f["rule"] == "seq_scan_in_join"]
        assert len(seq_findings) == 1, f"Expected 1 deduped finding, got {len(seq_findings)}"


# ---------------------------------------------------------------------------
# Endpoint tests: pg_analyze_plan security and validation
# ---------------------------------------------------------------------------

_INJECTION_PAYLOADS = [
    "postgres'; rm -rf /",
    "testdb; id",
    "testdb`id`",
    "testdb$(id)",
    "testdb|cat /etc/passwd",
    "testdb&id",
    "../../etc/passwd",
    "a" * 64,
    "",
]


@pytest.fixture()
def pg_service(app):
    """Create a PostgreSQL GuestService for endpoint tests."""
    with app.app_context():
        guest = Guest(name="_analyzer-pg-test", guest_type="ct", enabled=True)
        db.session.add(guest)
        db.session.flush()
        svc = GuestService(
            guest_id=guest.id,
            service_name="postgresql",
            unit_name="postgresql.service",
            port=5432,
        )
        db.session.add(svc)
        db.session.commit()
        svc_id = svc.id
        guest_id = guest.id

    yield svc_id, guest_id

    with app.app_context():
        GuestService.query.filter_by(guest_id=guest_id).delete()
        Guest.query.filter_by(id=guest_id).delete()
        db.session.commit()


@pytest.fixture()
def non_pg_service(app):
    """Create a non-PostgreSQL GuestService to test _pg_guard rejection."""
    with app.app_context():
        guest = Guest(name="_analyzer-redis-test", guest_type="ct", enabled=True)
        db.session.add(guest)
        db.session.flush()
        svc = GuestService(
            guest_id=guest.id,
            service_name="redis",
            unit_name="redis.service",
            port=6379,
        )
        db.session.add(svc)
        db.session.commit()
        svc_id = svc.id
        guest_id = guest.id

    yield svc_id, guest_id

    with app.app_context():
        GuestService.query.filter_by(guest_id=guest_id).delete()
        Guest.query.filter_by(id=guest_id).delete()
        db.session.commit()


class TestPgAnalyzePlanAuth:
    def test_unauthenticated_redirects(self, app, client, pg_service):
        svc_id, _ = pg_service
        resp = client.post(
            f"/services/{svc_id}/pg/analyze-plan",
            data=json.dumps({"database": "postgres", "query": "SELECT 1"}),
            content_type="application/json",
        )
        assert resp.status_code in (302, 401)


class TestPgAnalyzePlanDatabaseValidation:
    def test_injection_payloads_rejected(self, app, auth_client, pg_service):
        svc_id, _ = pg_service
        for payload in _INJECTION_PAYLOADS:
            resp = auth_client.post(
                f"/services/{svc_id}/pg/analyze-plan",
                data=json.dumps({"database": payload, "query": "SELECT 1"}),
                content_type="application/json",
            )
            data = resp.get_json()
            assert resp.status_code == 400, (
                f"Expected 400 for database={payload!r}, got {resp.status_code}: {data}"
            )
            assert data.get("ok") is False


class TestPgAnalyzePlanMissingParams:
    def test_missing_query_returns_400(self, app, auth_client, pg_service):
        svc_id, _ = pg_service
        resp = auth_client.post(
            f"/services/{svc_id}/pg/analyze-plan",
            data=json.dumps({"database": "postgres"}),
            content_type="application/json",
        )
        assert resp.status_code == 400
        assert resp.get_json().get("ok") is False

    def test_missing_database_returns_400(self, app, auth_client, pg_service):
        svc_id, _ = pg_service
        resp = auth_client.post(
            f"/services/{svc_id}/pg/analyze-plan",
            data=json.dumps({"query": "SELECT 1"}),
            content_type="application/json",
        )
        assert resp.status_code == 400
        assert resp.get_json().get("ok") is False

    def test_empty_body_returns_400(self, app, auth_client, pg_service):
        svc_id, _ = pg_service
        resp = auth_client.post(
            f"/services/{svc_id}/pg/analyze-plan",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert resp.status_code == 400
        assert resp.get_json().get("ok") is False


class TestPgAnalyzePlanWrongServiceType:
    def test_non_postgresql_service_rejected(self, app, auth_client, non_pg_service):
        svc_id, _ = non_pg_service
        resp = auth_client.post(
            f"/services/{svc_id}/pg/analyze-plan",
            data=json.dumps({"database": "postgres", "query": "SELECT 1"}),
            content_type="application/json",
        )
        assert resp.status_code == 400
        assert resp.get_json().get("ok") is False
