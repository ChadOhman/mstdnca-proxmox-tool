"""Tests for push notification dispatch with event alias mapping."""
from unittest.mock import MagicMock, patch

from models import PushWebhook


class TestServiceFailedAliasMapping:
    """When service_failed fires, webhooks subscribed to service_down should also match."""

    def test_service_failed_matches_service_down_subscription(self, app):
        with app.app_context():
            from models import Guest, ProxmoxHost, User, db

            # Clean up any leftover webhooks
            PushWebhook.query.delete()
            db.session.commit()

            # Create user, host, guest
            user = User.query.filter_by(username="admin").first()
            host = ProxmoxHost(name="pve1", hostname="pve1.local", host_type="pve")
            db.session.add(host)
            db.session.commit()
            guest = Guest(name="web01", vmid=100, guest_type="ct", proxmox_host_id=host.id)
            db.session.add(guest)
            db.session.commit()

            # Create a webhook subscribed to "service_down" (old name)
            wh = PushWebhook(
                user_id=user.id,
                url="https://example.com/push",
                device_token="test-token",
                platform="ios",
                events='["service_down"]',
            )
            db.session.add(wh)
            db.session.commit()

            with patch("core.push_notifier.http_requests") as mock_http, \
                    patch("core.push_notifier.validate_webhook_url", return_value=(True, None)):
                mock_http.post.return_value = MagicMock(status_code=200)
                from core.push_notifier import dispatch_push_alerts

                dispatch_push_alerts(guest, "service_failed", {"service": "nginx"})

                # Should have been called because service_down is an alias for service_failed
                mock_http.post.assert_called_once()

    def test_service_failed_matches_service_failed_subscription(self, app):
        with app.app_context():
            from models import Guest, ProxmoxHost, User, db

            # Clean up any leftover webhooks
            PushWebhook.query.delete()
            db.session.commit()

            user = User.query.filter_by(username="admin").first()
            host = ProxmoxHost(name="pve2", hostname="pve2.local", host_type="pve")
            db.session.add(host)
            db.session.commit()
            guest = Guest(name="web02", vmid=101, guest_type="ct", proxmox_host_id=host.id)
            db.session.add(guest)
            db.session.commit()

            wh = PushWebhook(
                user_id=user.id,
                url="https://example.com/push",
                device_token="test-token-2",
                platform="ios",
                events='["service_failed"]',
            )
            db.session.add(wh)
            db.session.commit()

            with patch("core.push_notifier.http_requests") as mock_http, \
                    patch("core.push_notifier.validate_webhook_url", return_value=(True, None)):
                mock_http.post.return_value = MagicMock(status_code=200)
                from core.push_notifier import dispatch_push_alerts

                dispatch_push_alerts(guest, "service_failed", {"service": "nginx"})

                mock_http.post.assert_called_once()


class TestValidateWebhookUrl:
    """SSRF guard for user-supplied push webhook URLs (issue #77)."""

    def test_rejects_non_http_scheme(self):
        from core.url_safety import validate_webhook_url
        ok, reason = validate_webhook_url("file:///etc/passwd")
        assert ok is False
        assert "http" in reason

    def test_rejects_loopback(self):
        from core.url_safety import validate_webhook_url
        ok, _ = validate_webhook_url("http://127.0.0.1:9090/metrics")
        assert ok is False

    def test_rejects_private_ip(self):
        from core.url_safety import validate_webhook_url
        ok, _ = validate_webhook_url("http://10.0.0.5/admin")
        assert ok is False
        ok, _ = validate_webhook_url("http://192.168.1.1/")
        assert ok is False

    def test_rejects_link_local_metadata_endpoint(self):
        from core.url_safety import validate_webhook_url
        ok, _ = validate_webhook_url("http://169.254.169.254/latest/meta-data/")
        assert ok is False

    def test_rejects_missing_hostname(self):
        from core.url_safety import validate_webhook_url
        ok, _ = validate_webhook_url("https:///path-only")
        assert ok is False

    def test_allows_public_host(self):
        from unittest.mock import patch as _patch

        from core.url_safety import validate_webhook_url
        # Pin DNS to a public address so the test is hermetic/offline-safe.
        with _patch("core.url_safety.socket.getaddrinfo",
                    return_value=[(2, 1, 6, "", ("93.184.216.34", 443))]):
            ok, reason = validate_webhook_url("https://push.example.com/send")
        assert ok is True
        assert reason is None

    def test_blocks_private_ip_even_with_public_hostname(self):
        """DNS-rebinding style: a public name resolving to an internal IP."""
        from unittest.mock import patch as _patch

        from core.url_safety import validate_webhook_url
        with _patch("core.url_safety.socket.getaddrinfo",
                    return_value=[(2, 1, 6, "", ("10.1.2.3", 443))]):
            ok, _ = validate_webhook_url("https://evil.example.com/send")
        assert ok is False


class TestDispatchSkipsUnsafeUrl:
    """dispatch_push_alerts must not POST to a webhook with an internal URL,
    even if one was stored before the registration guard existed."""

    def test_internal_url_is_not_requested(self, app):
        with app.app_context():
            from models import Guest, ProxmoxHost, User, db

            PushWebhook.query.delete()
            db.session.commit()

            user = User.query.filter_by(username="admin").first()
            host = ProxmoxHost(name="pve-ssrf", hostname="pve-ssrf.local", host_type="pve")
            db.session.add(host)
            db.session.commit()
            guest = Guest(name="web-ssrf", vmid=102, guest_type="ct", proxmox_host_id=host.id)
            db.session.add(guest)
            db.session.commit()

            wh = PushWebhook(
                user_id=user.id,
                url="http://169.254.169.254/latest/meta-data/",
                device_token="ssrf-token",
                platform="ios",
                events='["service_failed"]',
            )
            db.session.add(wh)
            db.session.commit()

            with patch("core.push_notifier.http_requests") as mock_http:
                from core.push_notifier import dispatch_push_alerts
                dispatch_push_alerts(guest, "service_failed", {"service": "nginx"})
                mock_http.post.assert_not_called()

            PushWebhook.query.delete()
            Guest.query.filter_by(id=guest.id).delete()
            db.session.commit()
