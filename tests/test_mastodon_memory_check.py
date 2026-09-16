"""Tests for the Mastodon upgrade memory-headroom pre-flight check."""

from apps.mastodon import _MIN_AVAILABLE_MEMORY_MB, _check_memory_headroom, _parse_meminfo_mb


class FakeSSH:
    def __init__(self, stdout="", code=0):
        self.stdout = stdout
        self.code = code
        self.calls = []

    def execute_sudo(self, cmd, timeout=None):
        self.calls.append(cmd)
        return (self.stdout, "", self.code)


def _meminfo(total_mb=32092, available_mb=1529, swap_total_mb=4095, swap_free_mb=5):
    return (
        f"MemTotal:       {total_mb * 1024} kB\n"
        f"MemFree:         1595392 kB\n"
        f"MemAvailable:   {available_mb * 1024} kB\n"
        f"Buffers:           12345 kB\n"
        f"SwapTotal:      {swap_total_mb * 1024} kB\n"
        f"SwapFree:       {swap_free_mb * 1024} kB\n"
        "HugePages_Total:       0\n"
    )


class TestParseMeminfo:
    def test_converts_kb_fields_to_mb(self):
        info = _parse_meminfo_mb(_meminfo(total_mb=32092, available_mb=1529))
        assert info["MemTotal"] == 32092
        assert info["MemAvailable"] == 1529
        assert info["SwapFree"] == 5
        assert "HugePages_Total" not in info

    def test_empty_and_none(self):
        assert _parse_meminfo_mb("") == {}
        assert _parse_meminfo_mb(None) == {}


class TestCheckMemoryHeadroom:
    def test_reads_proc_meminfo(self):
        ssh = FakeSSH(_meminfo(available_mb=8000))
        _check_memory_headroom(ssh)
        assert ssh.calls == ["cat /proc/meminfo"]

    def test_enough_memory_passes(self):
        ok, detail = _check_memory_headroom(FakeSSH(_meminfo(available_mb=8000)))
        assert ok is True
        assert "8000 MB available of 32092 MB" in detail
        assert "swap 5/4095 MB free" in detail

    def test_exact_threshold_passes(self):
        ok, _ = _check_memory_headroom(FakeSSH(_meminfo(available_mb=_MIN_AVAILABLE_MEMORY_MB)))
        assert ok is True

    def test_low_memory_fails_with_remediation_hint(self):
        # The 2026-09-16 failure: 1.5 GB available, swap exhausted, vite OOM-killed.
        ok, detail = _check_memory_headroom(FakeSSH(_meminfo(available_mb=1529)))
        assert ok is False
        assert "1529 MB available" in detail
        assert f"at least {_MIN_AVAILABLE_MEMORY_MB} MB" in detail
        assert "WEB_CONCURRENCY" in detail

    def test_no_swap_fields_still_reports(self):
        text = "MemTotal:       8000000 kB\nMemAvailable:   6000000 kB\n"
        ok, detail = _check_memory_headroom(FakeSSH(text))
        assert ok is True
        assert "swap" not in detail

    def test_unreadable_meminfo_is_warn_not_fail(self):
        ok, detail = _check_memory_headroom(FakeSSH("", code=1))
        assert ok is None
        assert "MemAvailable" in detail

    def test_missing_memavailable_is_warn_not_fail(self):
        ok, _ = _check_memory_headroom(FakeSSH("MemTotal:       8000000 kB\n"))
        assert ok is None
