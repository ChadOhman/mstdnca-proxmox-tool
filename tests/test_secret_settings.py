"""Secret-bearing settings are encrypted at rest (GHSA-8mgh-j8r7-7rf2 / GHSA-23rf-x25p-6q66).

``prometheus_auth_token`` and the two Discord webhook URLs used to be stored
as plaintext Setting rows. They now go through core.secret_settings, which
also migrates a legacy plaintext value the first time it is read.
"""
import pytest

from auth.credential_store import CredentialDecryptError, encrypt
from models import Setting, db

KEYS = ("prometheus_auth_token", "discord_webhook_url", "discord_moderation_webhook_url")


@pytest.fixture(autouse=True)
def _clean(app):
    yield
    with app.app_context():
        for key in KEYS:
            Setting.set(key, "")
        db.session.commit()


class TestSecretSettingHelpers:
    def test_roundtrip_is_ciphertext_at_rest(self, app):
        from core.secret_settings import get_secret_setting, looks_encrypted, set_secret_setting
        with app.app_context():
            set_secret_setting("prometheus_auth_token", "test-only-token")
            raw = Setting.get("prometheus_auth_token")
            assert raw != "test-only-token"
            assert looks_encrypted(raw)
            assert get_secret_setting("prometheus_auth_token") == "test-only-token"

    def test_empty_clears(self, app):
        from core.secret_settings import get_secret_setting, set_secret_setting
        with app.app_context():
            set_secret_setting("prometheus_auth_token", "x")
            set_secret_setting("prometheus_auth_token", "")
            assert get_secret_setting("prometheus_auth_token", "dflt") == "dflt"

    def test_legacy_plaintext_is_returned_and_migrated_once(self, app):
        from core.secret_settings import get_secret_setting, looks_encrypted
        with app.app_context():
            Setting.set("discord_webhook_url", "https://discord.com/api/webhooks/1/legacy")
            assert get_secret_setting("discord_webhook_url") == "https://discord.com/api/webhooks/1/legacy"
            assert looks_encrypted(Setting.get("discord_webhook_url"))
            assert get_secret_setting("discord_webhook_url") == "https://discord.com/api/webhooks/1/legacy"

    def test_undecryptable_ciphertext_is_not_re_encrypted(self, app):
        """A real Fernet token that fails to decrypt means the key changed; it
        must surface as an error, not be treated as plaintext and mangled."""
        from core.secret_settings import get_secret_setting
        with app.app_context():
            bogus = "gAAAAA" + "A" * 80
            Setting.set("prometheus_auth_token", bogus)
            with pytest.raises(CredentialDecryptError):
                get_secret_setting("prometheus_auth_token")
            assert Setting.get("prometheus_auth_token") == bogus


class TestPrometheusTokenAtRest:
    def test_save_encrypts_token(self, app, auth_client):
        from core.secret_settings import looks_encrypted
        resp = auth_client.post("/prometheus/save", data={
            "prometheus_url": "http://prom.example:9090",
            "prometheus_auth_token": "test-only-scrape-token",
        }, follow_redirects=True)
        assert resp.status_code == 200
        with app.app_context():
            assert looks_encrypted(Setting.get("prometheus_auth_token"))

    def test_metrics_endpoint_accepts_encrypted_token(self, app, client):
        with app.app_context():
            Setting.set("prometheus_auth_token", encrypt("test-only-scrape-token"))
        resp = client.get("/metrics", headers={"Authorization": "Bearer test-only-scrape-token"})
        assert resp.status_code == 200
        resp = client.get("/metrics", headers={"Authorization": "Bearer wrong"})
        assert resp.status_code == 401

    def test_metrics_endpoint_migrates_legacy_plaintext_token(self, app, client):
        from core.secret_settings import looks_encrypted
        with app.app_context():
            Setting.set("prometheus_auth_token", "test-only-legacy-token")
        resp = client.get("/metrics", headers={"Authorization": "Bearer test-only-legacy-token"})
        assert resp.status_code == 200
        with app.app_context():
            assert looks_encrypted(Setting.get("prometheus_auth_token"))


class TestDiscordWebhookAtRest:
    def test_save_encrypts_webhook(self, app, auth_client):
        from core.secret_settings import looks_encrypted
        resp = auth_client.post("/settings/discord", data={
            "discord_webhook_url": "https://discord.com/api/webhooks/1/test-only-hook",
            "discord_enabled": "on",
        }, follow_redirects=True)
        assert resp.status_code == 200
        with app.app_context():
            assert looks_encrypted(Setting.get("discord_webhook_url"))

    def test_notifier_reads_encrypted_webhook(self, app):
        from core.notifier import _get_discord_config
        with app.app_context():
            Setting.set("discord_webhook_url", encrypt("https://discord.com/api/webhooks/1/test-only-hook"))
            Setting.set("discord_moderation_webhook_url",
                        encrypt("https://discord.com/api/webhooks/2/test-only-mod-hook"))
            assert _get_discord_config()["webhook_url"] == "https://discord.com/api/webhooks/1/test-only-hook"
            assert _get_discord_config("moderation")["webhook_url"] == \
                "https://discord.com/api/webhooks/2/test-only-mod-hook"

    def test_export_redacts_encrypted_webhook(self, app, auth_client):
        with app.app_context():
            Setting.set("discord_webhook_url", encrypt("https://discord.com/api/webhooks/1/test-only-hook"))
        resp = auth_client.get("/settings/config/export")
        assert resp.status_code == 200
        assert b"test-only-hook" not in resp.data
        assert b"gAAAAA" not in resp.data
