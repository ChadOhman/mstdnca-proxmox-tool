import io
import logging
import socket
import time

import paramiko

from auth.credential_store import decrypt
from core.errors import describe_exception

logger = logging.getLogger(__name__)

# Maximum bytes captured per stream (stdout / stderr) by execute().  Output
# beyond this is drained but discarded so a chatty (or hostile) guest cannot
# exhaust memory.
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
# Socket timeout applied to the channel while draining, so recv() never blocks
# for longer than one poll interval.
CHANNEL_READ_TIMEOUT = 0.5
# Idle polling backs off from CHANNEL_MIN_POLL_INTERVAL to CHANNEL_POLL_INTERVAL
# so short commands stay fast while long ones stay cheap.
CHANNEL_POLL_INTERVAL = 0.1
CHANNEL_MIN_POLL_INTERVAL = 0.002
_RECV_CHUNK_SIZE = 65536


class _CappedBuffer:
    """Accumulate output bytes up to ``limit``, discarding the remainder."""

    def __init__(self, limit):
        self._limit = limit
        self._chunks = []
        self._size = 0
        self.truncated = False

    def append(self, data):
        room = self._limit - self._size
        if room <= 0:
            self.truncated = True
            return
        if len(data) > room:
            data = data[:room]
            self.truncated = True
        self._chunks.append(data)
        self._size += len(data)

    def text(self):
        text = b"".join(self._chunks).decode("utf-8", errors="replace")
        if self.truncated:
            text += f"\n[output truncated after {self._limit} bytes]"
        return text


class SSHClient:
    """SSH connection manager using paramiko."""

    def __init__(self, hostname, port=22, username="root", password=None, private_key=None, sudo_password=None, timeout=30):
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password
        self.private_key = private_key
        self.sudo_password = sudo_password
        self.timeout = timeout
        self._client = None

    @classmethod
    def from_credential(cls, hostname, credential_model, port=22):
        """Create SSHClient from a Credential database model."""
        password = None
        private_key = None
        sudo_password = None

        if credential_model.auth_type == "password":
            password = decrypt(credential_model.encrypted_value)
        else:
            private_key = decrypt(credential_model.encrypted_value)

        if credential_model.encrypted_sudo_password:
            sudo_password = decrypt(credential_model.encrypted_sudo_password)

        return cls(
            hostname=hostname,
            port=port,
            username=credential_model.username,
            password=password,
            private_key=private_key,
            sudo_password=sudo_password,
        )

    @property
    def needs_sudo(self):
        """Check if commands should be wrapped with sudo (non-root user)."""
        return self.username != "root"

    def sudo_wrap(self, command):
        """Wrap a command with sudo if the user is not root.

        If a sudo password is set, uses ``sudo -S`` so the password can be
        fed safely via stdin (see ``_feed_sudo_password``).  This avoids
        interpolating the password into a shell string where special
        characters (like single-quotes) could cause injection.
        """
        if not self.needs_sudo:
            return command
        escaped_cmd = command.replace("'", "'\\''")
        if self.sudo_password:
            return f"sudo -S sh -c '{escaped_cmd}'"
        return f"sudo sh -c '{escaped_cmd}'"

    def _feed_sudo_password(self, channel_stdin):
        """Feed the sudo password into an exec_command stdin channel.

        Paramiko stdin channels are binary, so we encode before writing.
        """
        if self.sudo_password and self.needs_sudo:
            channel_stdin.write((self.sudo_password + "\n").encode("utf-8"))
            channel_stdin.flush()

    def connect(self):
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        kwargs = {
            "hostname": self.hostname,
            "port": self.port,
            "username": self.username,
            "timeout": self.timeout,
        }

        if self.private_key:
            key_file = io.StringIO(self.private_key)
            try:
                pkey = paramiko.RSAKey.from_private_key(key_file)
            except paramiko.SSHException:
                key_file.seek(0)
                try:
                    pkey = paramiko.Ed25519Key.from_private_key(key_file)
                except paramiko.SSHException:
                    key_file.seek(0)
                    pkey = paramiko.ECDSAKey.from_private_key(key_file)
            kwargs["pkey"] = pkey
        elif self.password:
            kwargs["password"] = self.password

        self._client.connect(**kwargs)
        return self._client

    def _drain_channel(self, channel, deadline, on_stdout, on_stderr, stop_fn=None):
        """Drain stdout/stderr from ``channel`` until the command finishes.

        Data is handed to ``on_stdout`` / ``on_stderr`` as raw bytes as it
        arrives.  Draining *before* ``recv_exit_status()`` is mandatory:
        paramiko blocks forever in ``recv_exit_status()`` once the remote
        output exceeds the channel window (2 MiB by default).

        ``deadline`` is an absolute ``time.monotonic()`` value, or None for no
        wall-clock limit.  Returns True when the command finished (or was
        stopped via ``stop_fn``), False when the deadline expired.
        """
        channel.settimeout(CHANNEL_READ_TIMEOUT)
        idle_wait = CHANNEL_MIN_POLL_INTERVAL

        while True:
            if stop_fn and stop_fn():
                channel.close()
                return True

            got_data = False
            for ready, recv, sink in (
                (channel.recv_ready, channel.recv, on_stdout),
                (channel.recv_stderr_ready, channel.recv_stderr, on_stderr),
            ):
                try:
                    if ready():
                        data = recv(_RECV_CHUNK_SIZE)
                        if data:
                            sink(data)
                            got_data = True
                except socket.timeout:  # paramiko raises socket.timeout on a read timeout
                    continue

            if got_data:
                idle_wait = CHANNEL_MIN_POLL_INTERVAL
            else:
                # Nothing buffered: the command is done once the exit status is
                # in and both streams are drained.  A closed channel also ends
                # the loop — recv_exit_status() cannot block on it.
                if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                    return True
                if channel.closed:
                    return True

            now = time.monotonic()
            if deadline is not None and now >= deadline:
                return False

            if not got_data:
                sleep_for = idle_wait
                if deadline is not None:
                    sleep_for = min(sleep_for, deadline - now)
                if sleep_for > 0:
                    time.sleep(sleep_for)
                idle_wait = min(idle_wait * 2, CHANNEL_POLL_INTERVAL)

    def execute(self, command, timeout=120, _sudo=False):
        """Execute a command and return (stdout, stderr, exit_code).

        When ``_sudo`` is True the sudo password (if any) is piped into
        stdin rather than being embedded in the command string.

        Output is drained before the exit status is collected (see
        ``_drain_channel``) and capped at ``MAX_OUTPUT_BYTES`` per stream.
        ``timeout`` is a real wall-clock budget for the whole command: on
        expiry the channel is closed and ``(stdout_so_far, stderr_so_far +
        marker, -1)`` is returned.
        """
        if self._client is None:
            self.connect()

        try:
            stdin, stdout, stderr = self._client.exec_command(command, timeout=timeout)
            if _sudo:
                self._feed_sudo_password(stdin)

            channel = stdout.channel
            out_buf = _CappedBuffer(MAX_OUTPUT_BYTES)
            err_buf = _CappedBuffer(MAX_OUTPUT_BYTES)
            deadline = time.monotonic() + timeout if timeout else None

            finished = self._drain_channel(channel, deadline, out_buf.append, err_buf.append)
            out_text = out_buf.text()
            err_text = err_buf.text()

            if not finished:
                # Deliberately not logging the command text: remote file writes
                # carry the file contents (base64) inline, which can include
                # credentials such as the UniFi password in up.conf.
                logger.warning(f"SSH command timed out after {timeout}s on {self.hostname} ({len(command)}-char command)")
                try:
                    channel.close()
                except Exception:  # noqa: S110 - best-effort teardown
                    pass
                return out_text, f"{err_text}\n[timeout after {timeout} s]", -1

            return out_text, err_text, channel.recv_exit_status()
        except Exception as e:
            logger.error(f"SSH command failed on {self.hostname}: {e}")
            return "", f"SSH command failed: {describe_exception(e)}", -1

    def execute_sudo(self, command, timeout=120):
        """Execute a command with sudo wrapping if needed."""
        wrapped = self.sudo_wrap(command)
        needs_stdin = bool(self.sudo_password and self.needs_sudo)
        return self.execute(wrapped, timeout=timeout, _sudo=needs_stdin)

    def execute_streaming(self, command, callback, timeout=600, _sudo=False, stop_fn=None):
        """Execute a command and call callback(chunk) as output arrives.

        Returns (exit_code).  The callback receives raw string chunks
        from both stdout and stderr as they become available.
        """
        if self._client is None:
            self.connect()

        try:
            stdin, stdout, stderr = self._client.exec_command(command, timeout=timeout)
            if _sudo:
                self._feed_sudo_password(stdin)
            channel = stdout.channel

            def _emit(data):
                text = data.decode("utf-8", errors="replace")
                if text:
                    callback(text)

            # Stream output until the command finishes.  The drain loop owns
            # the channel's socket timeout, so no blocking read is left to
            # trip over it once exit-status arrives before eof.
            self._drain_channel(channel, None, _emit, _emit, stop_fn=stop_fn)

            return channel.recv_exit_status()
        except Exception as e:
            logger.error(f"SSH streaming command failed on {self.hostname}: {e}")
            callback(f"\n[SSH Error: {describe_exception(e)}]\n")
            return -1

    def execute_sudo_streaming(self, command, callback, timeout=600, stop_fn=None):
        """Execute a command with sudo wrapping, streaming output via callback."""
        wrapped = self.sudo_wrap(command)
        needs_stdin = bool(self.sudo_password and self.needs_sudo)
        return self.execute_streaming(wrapped, callback, timeout=timeout, _sudo=needs_stdin, stop_fn=stop_fn)

    def close(self):
        if self._client:
            self._client.close()
            self._client = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def test_connection(self):
        """Test SSH connectivity."""
        try:
            self.connect()
            stdout, stderr, code = self.execute("echo ok")
            self.close()
            if code == 0 and "ok" in stdout:
                return True, "SSH connection successful"
            return False, stderr or "Unexpected output"
        except Exception as e:
            logger.warning(f"SSH connection test failed on {self.hostname}: {e}")
            return False, describe_exception(e)
