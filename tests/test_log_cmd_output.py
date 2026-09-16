"""Tests for apps.utils._log_cmd_output truncation and error excerpts."""

from apps.utils import _error_excerpt, _log_cmd_output


def _collect():
    lines = []
    return lines, lines.append


def _build_output(middle_lines):
    """Chatty build log (head) + the given middle lines + a Ruby backtrace (tail)."""
    head = "\n".join(f"[vite] transforming module {i}/7631 ..." for i in range(60))
    tail = "\n".join(
        f"/home/mastodon/live/vendor/bundle/ruby/4.0.0/gems/railties-8.1.3.1/lib/rails/command.rb:{i}:in 'invoke'"
        for i in range(40)
    )
    return head + "\n" + "\n".join(middle_lines) + "\n" + tail


class TestErrorExcerpt:
    def test_picks_fatal_lines_only(self):
        text = "building...\nKilled\nmore progress\nerror Command failed with signal \"SIGKILL\".\ndone"
        assert _error_excerpt(text) == ["Killed", 'error Command failed with signal "SIGKILL".']

    def test_includes_line_after_rake_aborted(self):
        text = "rake aborted!\nViteRuby::Error: Bundling with Vite failed\nnext line is ignored"
        assert _error_excerpt(text) == ["rake aborted!", "ViteRuby::Error: Bundling with Vite failed"]

    def test_caps_line_count_and_length(self):
        text = "\n".join("ERROR " + "x" * 1000 for _ in range(50))
        picked = _error_excerpt(text, limit=3)
        assert len(picked) == 3
        assert all(len(line) == 300 for line in picked)

    def test_empty(self):
        assert _error_excerpt("") == []


class TestLogCmdOutput:
    def test_short_output_logged_verbatim(self):
        logs, log = _collect()
        _log_cmd_output(log, "hello", "warn", 1)
        assert logs == ["hello\nwarn"]

    def test_empty_output_logs_nothing(self):
        logs, log = _collect()
        _log_cmd_output(log, "", "", 1)
        assert logs == []

    def test_success_keeps_the_end(self):
        logs, log = _collect()
        _log_cmd_output(log, "a" * 3000 + "END", "", 0, max_chars=100)
        assert logs == ["a" * 97 + "END"]

    def test_failure_surfaces_error_buried_in_the_middle(self):
        logs, log = _collect()
        stdout = _build_output(["[vite] rendering chunks...", "Killed", "rake aborted!", "SystemExit: exit"])
        _log_cmd_output(log, stdout, "", 137)
        joined = "\n".join(logs)
        assert joined.startswith("[vite] transforming module 0/7631")
        assert "error-like lines from the omitted part" in joined
        assert "  | Killed" in joined
        assert "  | rake aborted!" in joined
        assert "  | SystemExit: exit" in joined
        assert "[... end of excerpt ...]" in joined
        assert joined.rstrip().endswith("in 'invoke'")

    def test_failure_without_error_lines_keeps_plain_marker(self):
        logs, log = _collect()
        stdout = _build_output(["[vite] rendering chunks...", "[vite] computing gzip size..."])
        _log_cmd_output(log, stdout, "", 1)
        assert "[... output truncated ...]" in logs
        assert not any(line.startswith("  | ") for line in logs)

    def test_excerpt_does_not_duplicate_head_or_tail(self):
        logs, log = _collect()
        # "error" appears only inside the head and the tail, never in the middle.
        head = "error in head " + "h" * 1500
        tail = "t" * 480 + " error in tail"
        _log_cmd_output(log, head + "\n" + "m" * 3000 + "\n" + tail, "", 1)
        assert "[... output truncated ...]" in logs
