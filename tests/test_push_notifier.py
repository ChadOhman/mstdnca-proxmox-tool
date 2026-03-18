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

            with patch("core.push_notifier.http_requests") as mock_http:
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

            with patch("core.push_notifier.http_requests") as mock_http:
                mock_http.post.return_value = MagicMock(status_code=200)
                from core.push_notifier import dispatch_push_alerts

                dispatch_push_alerts(guest, "service_failed", {"service": "nginx"})

                mock_http.post.assert_called_once()
