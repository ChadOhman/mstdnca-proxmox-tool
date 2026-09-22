"""Tests for the scheduled AI upgrade analysis (core.scheduler._run_ai_upgrade_analysis).

Current models think by default, so responses can lead with a thinking block, and
Opus 5 can decline a request (stop_reason "refusal"). The Claude client is mocked.
"""
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from core.scheduler import _run_ai_upgrade_analysis
from models import Guest, Setting, UpdatePackage, db


@pytest.fixture
def guest_with_update(app):
    with app.app_context():
        from auth.credential_store import encrypt
        Setting.set("ai_enabled", "true")
        Setting.set("ai_api_key", encrypt("test-only-ai-api-key"))
        g = Guest(name="ai-analysis-guest", guest_type="ct", enabled=True,
                  ip_address="10.9.9.10", status="updates-available", power_state="running")
        db.session.add(g)
        db.session.flush()
        db.session.add(UpdatePackage(guest_id=g.id, package_name="openssl", severity="critical"))
        db.session.commit()
        guest_id = g.id
    yield
    with app.app_context():
        g = db.session.get(Guest, guest_id)
        if g:
            db.session.delete(g)
        Setting.set("ai_enabled", "false")
        Setting.set("ai_upgrade_analysis", "")
        db.session.commit()


def _response(content, stop_reason="end_turn"):
    return SimpleNamespace(content=content, stop_reason=stop_reason)


def _run(app, response):
    client = MagicMock()
    client.send_message.return_value = response
    with patch("clients.claude_client.get_claude_client", return_value=client):
        _run_ai_upgrade_analysis(app)
    return client


def test_text_is_read_past_leading_thinking_block(app, guest_with_update):
    response = _response([
        SimpleNamespace(type="thinking", thinking="", signature="test-only-signature"),
        SimpleNamespace(type="text", text="Update openssl first. "),
        SimpleNamespace(type="text", text="Reboot afterwards."),
    ])
    client = _run(app, response)

    client.send_message.assert_called_once()
    with app.app_context():
        assert Setting.get("ai_upgrade_analysis") == "Update openssl first. Reboot afterwards."
        assert Setting.get("ai_upgrade_analysis_time")


def test_refusal_keeps_previous_analysis(app, guest_with_update):
    with app.app_context():
        Setting.set("ai_upgrade_analysis", "previous analysis")
    _run(app, _response([], stop_reason="refusal"))

    with app.app_context():
        assert Setting.get("ai_upgrade_analysis") == "previous analysis"
