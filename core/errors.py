"""Turn a caught exception into a message that is safe to hand back to a user.

Raw ``str(exc)`` text from paramiko, requests, proxmoxer or the OS can carry
internal detail -- hostnames, file paths, library internals -- and it is
exactly what CodeQL's stack-trace-exposure query flags when it reaches an
HTTP response.  Code that returns an error to a route should log the
exception server-side (so nothing is lost for debugging) and return
:func:`describe_exception` instead.  The description is derived only from
the exception *type*, never from its text, so it cannot leak anything the
exception message might contain.
"""

import json
import socket

import paramiko
import requests
from paramiko.ssh_exception import NoValidConnectionsError
from proxmoxer.backends.https import AuthenticationError as ProxmoxAuthenticationError
from proxmoxer.core import ResourceException as ProxmoxResourceException

# Ordered most-specific first: the first isinstance() match wins, so a subclass
# must appear before any of its bases (SSLError before ConnectionError, gaierror
# before OSError, JSONDecodeError before ValueError, ...).
_KNOWN_EXCEPTIONS = (
    (paramiko.AuthenticationException, "SSH authentication failed"),
    (paramiko.BadHostKeyException, "SSH host key verification failed"),
    (NoValidConnectionsError, "SSH port is unreachable"),
    (paramiko.SSHException, "SSH protocol error"),
    (ProxmoxAuthenticationError, "Proxmox API authentication failed"),
    (ProxmoxResourceException, "Proxmox API rejected the request (see the server log)"),
    (requests.exceptions.SSLError, "TLS handshake failed"),
    (requests.exceptions.Timeout, "request timed out"),
    (requests.exceptions.ConnectionError, "could not connect to the remote host"),
    (requests.exceptions.HTTPError, "remote API returned an HTTP error"),
    (requests.exceptions.RequestException, "request failed"),
    (socket.gaierror, "hostname could not be resolved"),
    (ConnectionRefusedError, "connection refused"),
    (ConnectionResetError, "connection reset by peer"),
    (TimeoutError, "connection timed out"),
    (PermissionError, "permission denied"),
    (FileNotFoundError, "file not found"),
    (OSError, "network or I/O error"),
    (json.JSONDecodeError, "invalid JSON"),
    (UnicodeError, "text could not be decoded"),
    (ValueError, "invalid value"),
)


def describe_exception(exc):
    """Return a short, user-safe description of *exc* based on its type only.

    Never includes ``str(exc)``.  Unknown exception types yield
    ``"unexpected error (<ClassName>)"`` so the UI still points at the
    right family of problem while the full text stays in the server log.
    """
    for cls, message in _KNOWN_EXCEPTIONS:
        if isinstance(exc, cls):
            return message
    return f"unexpected error ({type(exc).__name__})"
