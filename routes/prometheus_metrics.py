"""
Blueprint exposing a /metrics endpoint in Prometheus text exposition format.

Prometheus scrapes this endpoint at its configured interval.  Authentication is
optional — controlled by the ``prometheus_auth_token`` setting.  If a token is
set, the request must include it as a Bearer token in the Authorization header
(which is how the generated prometheus.yml sends it). A ``token`` query
parameter used to be accepted as well, but query strings land in access logs,
proxies and browser history, so it no longer is.
"""

import hmac
import logging

from flask import Blueprint, Response, request
from flask_login import current_user

from core.secret_settings import get_secret_setting

logger = logging.getLogger(__name__)

bp = Blueprint("prometheus_metrics", __name__)


@bp.route("/metrics")
def metrics():
    """Return all registered metrics in Prometheus text exposition format."""
    # Optional bearer token authentication (token is stored encrypted at rest)
    expected_token = get_secret_setting("prometheus_auth_token", "")
    if expected_token:
        # Bearer header only: never read the token from the query string.
        auth_header = request.headers.get("Authorization", "")
        token = auth_header[7:] if auth_header.startswith("Bearer ") else ""

        if not hmac.compare_digest(token, expected_token):
            return Response("Unauthorized", status=401, content_type="text/plain")
    else:
        # No token configured — require session login
        if not current_user.is_authenticated:
            return Response("Unauthorized", status=401, content_type="text/plain")

    from clients.prometheus_exporter import get_metrics
    return Response(get_metrics(), status=200, content_type="text/plain; version=0.0.4; charset=utf-8")
