"""
Blueprint exposing a /metrics endpoint in Prometheus text exposition format.

Prometheus scrapes this endpoint at its configured interval.  Authentication is
optional — controlled by the ``prometheus_auth_token`` setting.  If a token is
set, the request must include it as a Bearer token in the Authorization header
or as a ``token`` query parameter.
"""

import hmac
import logging

from flask import Blueprint, Response, request
from flask_login import current_user

from models import Setting

logger = logging.getLogger(__name__)

bp = Blueprint("prometheus_metrics", __name__)


@bp.route("/metrics")
def metrics():
    """Return all registered metrics in Prometheus text exposition format."""
    # Optional bearer token authentication
    expected_token = Setting.get("prometheus_auth_token", "")
    if expected_token:
        # Check Authorization header first, then query param
        auth_header = request.headers.get("Authorization", "")
        token = None
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
        else:
            token = request.args.get("token", "")

        if not hmac.compare_digest(token or "", expected_token):
            return Response("Unauthorized", status=401, content_type="text/plain")
    else:
        # No token configured — require session login
        if not current_user.is_authenticated:
            return Response("Unauthorized", status=401, content_type="text/plain")

    from clients.prometheus_exporter import get_metrics
    return Response(get_metrics(), status=200, content_type="text/plain; version=0.0.4; charset=utf-8")
