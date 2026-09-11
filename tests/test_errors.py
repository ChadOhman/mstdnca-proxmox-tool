"""core.errors.describe_exception: user-safe messages derived from the exception type only."""

import json
import socket

import paramiko
import pytest
import requests
from proxmoxer.core import ResourceException

from core.errors import describe_exception

_SECRET = "10.0.4.11:22 /etc/ssh/id_rsa Traceback"


@pytest.mark.parametrize("exc, expected", [
    (paramiko.AuthenticationException(_SECRET), "SSH authentication failed"),
    (paramiko.SSHException(_SECRET), "SSH protocol error"),
    (requests.exceptions.SSLError(_SECRET), "TLS handshake failed"),
    (requests.exceptions.ConnectTimeout(_SECRET), "request timed out"),
    (requests.exceptions.ConnectionError(_SECRET), "could not connect to the remote host"),
    (requests.exceptions.HTTPError(_SECRET), "remote API returned an HTTP error"),
    (requests.exceptions.RequestException(_SECRET), "request failed"),
    (socket.gaierror(-2, _SECRET), "hostname could not be resolved"),
    (ConnectionRefusedError(111, _SECRET), "connection refused"),
    (ConnectionResetError(104, _SECRET), "connection reset by peer"),
    (TimeoutError(_SECRET), "connection timed out"),
    (socket.timeout(_SECRET), "connection timed out"),
    (PermissionError(13, _SECRET), "permission denied"),
    (FileNotFoundError(2, _SECRET), "file not found"),
    (OSError(5, _SECRET), "network or I/O error"),
    (json.JSONDecodeError(_SECRET, "{", 0), "invalid JSON"),
    (UnicodeDecodeError("utf-8", b"\xff", 0, 1, _SECRET), "text could not be decoded"),
    (ValueError(_SECRET), "invalid value"),
    (ResourceException(500, "Internal Server Error", _SECRET), "Proxmox API rejected the request (see the server log)"),
])
def test_known_types_map_to_fixed_messages(exc, expected):
    assert describe_exception(exc) == expected


def test_unknown_type_names_the_class_only():
    class WeirdFailure(Exception):
        pass

    msg = describe_exception(WeirdFailure(_SECRET))
    assert msg == "unexpected error (WeirdFailure)"


@pytest.mark.parametrize("exc", [
    RuntimeError(_SECRET),
    paramiko.AuthenticationException(_SECRET),
    OSError(5, _SECRET),
    ResourceException(500, "Internal Server Error", _SECRET),
])
def test_raw_exception_text_never_leaks(exc):
    msg = describe_exception(exc)
    for fragment in ("10.0.4.11", "/etc/ssh", "Traceback"):
        assert fragment not in msg
