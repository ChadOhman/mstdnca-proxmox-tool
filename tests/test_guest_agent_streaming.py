"""ProxmoxClient.exec_guest_agent_streaming — live output over the QEMU guest agent.

QGA's guest-exec returns stdout only after the process exits, so the update
page showed nothing for a whole apt run and reported a timeout while apt was
still going.  The streaming variant launches the command detached with its
output in a per-run file and tails that file.  These tests drive it against a
simulated guest: the fake API interprets the launcher, poll, kill and cleanup
commands the client sends, so the exact shell text is exercised too.
"""
import base64
import re
from types import SimpleNamespace

import pytest

import clients.proxmox_api as pm
from clients.proxmox_api import ProxmoxClient


class FakeGuest:
    """Minimal guest: files, a 'process' whose log grows per poll, exec history."""

    def __init__(self, log_steps, exit_code=0, launch_error=None):
        self.files = {}
        self.log_steps = list(log_steps)  # chunks appended one per poll
        self.exit_code = exit_code
        self.launch_error = launch_error
        self.commands = []
        self.killed = False
        self.base = None
        self._pid = 100
        self._pending = {}  # pid -> (out, exitcode)

    # --- the proxmoxer surface the client touches ---------------------------------
    def nodes(self, node):
        return self

    def qemu(self, vmid):
        return self

    @property
    def agent(self):
        outer = self

        class _Agent:
            def __call__(self, what):
                assert what == "exec-status"
                return SimpleNamespace(get=outer._exec_status)

            @property
            def exec(self):
                return SimpleNamespace(post=outer._exec)

        return _Agent()

    # --- command interpreter -----------------------------------------------------------
    def _exec(self, command):
        self.commands.append(command)
        self._pid += 1
        self._pending[self._pid] = self._run(command)
        return {"pid": self._pid}

    def _exec_status(self, pid):
        out, code = self._pending[pid]
        return {"exited": 1, "out-data": out, "err-data": "", "exitcode": code}

    def _run(self, command):
        m = re.match(r"sh -c 'echo (\S+) \| base64 -d > (\S+)\.sh && : > \S+\.log && "
                     r"\(setsid sh \S+\.sh < /dev/null > /dev/null 2>&1 &\)'$", command)
        if m:
            if self.launch_error:
                return "", 127
            self.base = m.group(2)
            self.files[self.base + ".sh"] = base64.b64decode(m.group(1)).decode()
            self.files[self.base + ".log"] = ""
            self.files[self.base + ".pid"] = "4242"
            return "", 0
        if command.startswith("sh -c 'R=$(cat "):
            assert self.base and f"{self.base}.rc" in command and f"{self.base}.log" in command
            offset = int(re.search(r"tail -c \+(\d+)", command).group(1)) - 1
            rc = self.files.get(self.base + ".rc", "")
            # the process makes progress between polls
            if self.log_steps and not self.killed:
                self.files[self.base + ".log"] += self.log_steps.pop(0)
                if not self.log_steps:
                    self.files[self.base + ".rc"] = f"{self.exit_code}\n"
            log = self.files[self.base + ".log"]
            size = len(log.encode())
            chunk = log.encode()[offset:size].decode() if size > offset else ""
            return f"LAMBNET_RC={rc.strip()}\nLAMBNET_SIZE={size}\n{chunk}", 0
        if command.startswith("sh -c 'kill -TERM -- -$(cat "):
            assert f"{self.base}.pid" in command
            self.killed = True
            return "", 0
        if command.startswith("sh -c 'rm -f "):
            for suffix in (".sh", ".log", ".rc", ".pid"):
                self.files.pop(self.base + suffix, None)
            return "", 0
        raise AssertionError(f"unexpected guest command: {command}")


def _client(fake):
    client = ProxmoxClient(SimpleNamespace(hostname="pve", port=8006, verify_ssl=False))
    client._api = fake
    return client


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(pm.time, "sleep", lambda *_: None)


class TestStreaming:
    def test_streams_chunks_in_order_and_returns_exit_code(self):
        fake = FakeGuest(["Reading package lists...\n", "Setting up pgbouncer …\n", "done\n"], exit_code=0)
        chunks = []
        rc = _client(fake).exec_guest_agent_streaming("pve", 101, "apt-get upgrade -y", chunks.append)
        assert rc == 0
        assert "".join(chunks) == "Reading package lists...\nSetting up pgbouncer …\ndone\n"
        # multi-byte output is offset by bytes, never re-sent or split
        assert chunks == ["Reading package lists...\n", "Setting up pgbouncer …\n", "done\n"]

    def test_script_runs_command_with_stdin_from_dev_null(self):
        fake = FakeGuest(["x\n"])
        _client(fake).exec_guest_agent_streaming("pve", 101, "apt-get update && apt-get upgrade -y", lambda _: None)
        # the script was removed by cleanup; recover it from the launcher
        launcher = fake.commands[0]
        b64 = re.search(r"echo (\S+) \| base64 -d", launcher).group(1)
        script = base64.b64decode(b64).decode()
        assert "( apt-get update && apt-get upgrade -y ) < /dev/null >" in script
        assert f"echo $$ > {fake.base}.pid" in script
        assert f"echo $? > {fake.base}.rc" in script

    def test_nonzero_exit_code_is_returned(self):
        fake = FakeGuest(["E: dpkg was interrupted\n"], exit_code=100)
        chunks = []
        rc = _client(fake).exec_guest_agent_streaming("pve", 101, "apt-get upgrade -y", chunks.append)
        assert rc == 100
        assert chunks == ["E: dpkg was interrupted\n"]

    def test_cleans_up_run_files_on_completion(self):
        fake = FakeGuest(["ok\n"])
        _client(fake).exec_guest_agent_streaming("pve", 101, "true", lambda _: None)
        assert fake.files == {}
        assert fake.commands[-1].startswith("sh -c 'rm -f ")

    def test_launch_failure_is_reported_not_swallowed(self):
        fake = FakeGuest([], launch_error=True)
        chunks = []
        rc = _client(fake).exec_guest_agent_streaming("pve", 101, "true", chunks.append)
        assert rc is None
        assert "[Agent Error] Could not start the command" in "".join(chunks)
        assert len(fake.commands) == 1  # no polling after a failed launch

    def test_cancel_kills_the_process_group(self):
        fake = FakeGuest(["a\n", "b\n", "c\n"])
        chunks = []
        polls = {"n": 0}

        def stop():
            polls["n"] += 1
            return polls["n"] > 2  # cancel after the first poll returned

        rc = _client(fake).exec_guest_agent_streaming("pve", 101, "apt-get upgrade -y", chunks.append, stop_fn=stop)
        assert rc is None
        assert fake.killed is True
        assert "[Cancelled: sent SIGTERM" in "".join(chunks)
        assert chunks[0] == "a\n"  # output before the cancel was delivered

    def test_timeout_leaves_process_running_and_names_the_log(self, monkeypatch):
        fake = FakeGuest(["slow\n"] * 50)
        chunks = []
        clock = {"t": 0.0}
        monkeypatch.setattr(pm.time, "monotonic", lambda: clock.__setitem__("t", clock["t"] + 10) or clock["t"])
        rc = _client(fake).exec_guest_agent_streaming("pve", 101, "apt-get upgrade -y", chunks.append, timeout=15)
        assert rc is None
        assert fake.killed is False
        joined = "".join(chunks)
        assert "[Timeout] Still running after 15s" in joined
        assert f"{fake.base}.log" in joined

    def test_repeated_poll_failures_abort_with_a_message(self):
        fake = FakeGuest(["a\n"] * 20)
        real_run = fake._run

        def broken(command):
            if command.startswith("sh -c 'R=$(cat "):
                return "garbage", 1
            return real_run(command)

        fake._run = broken
        chunks = []
        rc = _client(fake).exec_guest_agent_streaming("pve", 101, "apt-get upgrade -y", chunks.append)
        assert rc is None
        polls = [c for c in fake.commands if c.startswith("sh -c 'R=$(cat ")]
        assert len(polls) == ProxmoxClient.GUEST_EXEC_POLL_FAILURES
        assert "[Agent Error] Lost contact with the guest agent" in "".join(chunks)


class TestPollParsing:
    def test_running_process(self):
        assert ProxmoxClient._parse_guest_exec_poll("LAMBNET_RC=\nLAMBNET_SIZE=5\nhello") == (None, 5, "hello")

    def test_finished_process_with_no_new_output(self):
        assert ProxmoxClient._parse_guest_exec_poll("LAMBNET_RC=0\nLAMBNET_SIZE=5\n") == (0, 5, "")

    def test_malformed(self):
        assert ProxmoxClient._parse_guest_exec_poll("") is None
        assert ProxmoxClient._parse_guest_exec_poll(None) is None
        assert ProxmoxClient._parse_guest_exec_poll("LAMBNET_RC=0") is None
        assert ProxmoxClient._parse_guest_exec_poll("LAMBNET_RC=x\nLAMBNET_SIZE=1\n") is None
