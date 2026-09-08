"""Byte-identity proof for the core.scanner Redis/Sidekiq script de-duplication.

Before de-duplication, `core/scanner.py` had eight near-identical inline
Python scripts (shipped to guests over SSH, base64-encoded and executed with
`python3 -c`) that each hand-rolled the same RESP-protocol Redis client and
`.env.production` connection discovery. This test locks in the exact bytes
that shipped before the refactor (captured in
``tests/fixtures/redis_scripts_baseline/*.bin``) and proves that every script
now built from the shared ``_REDIS_PRELUDE`` constant is byte-for-byte
identical to its original -- except for two deliberate, documented
normalisations:

1. Socket timeout unified to 8s (was 5s for five of the eight scripts, 8s for
   the other three). Only ever makes a call *more* tolerant of a slow Redis
   server, never less -- it cannot newly time out a call that used to
   succeed.
2. The import line always imports ``json, time`` even for scripts that don't
   use them (three scripts previously omitted `json`, one omitted both).
   These are free stdlib imports; the only cost is composability.

Every other byte -- the RESP client (`rc`/`rr`), the `.env.production`
parsing loop, the REDIS_URL/host/port/password/db resolution, the
CONNECT/AUTH/SELECT handshake, and every script's own body -- is asserted
unchanged.
"""
import os

import core.scanner as scanner

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "redis_scripts_baseline")

SCRIPT_NAMES = [
    "_SIDEKIQ_REDIS_SCRIPT",
    "_SIDEKIQ_CLEAR_DEAD_SCRIPT",
    "_SIDEKIQ_RETRY_DEAD_SCRIPT",
    "_SIDEKIQ_CLEAR_RETRY_SCRIPT",
    "_SIDEKIQ_RETRY_RETRY_SCRIPT",
    "_SIDEKIQ_LIST_JOBS_TEMPLATE",
    "_SIDEKIQ_DELETE_JOB_TEMPLATE",
    "_SIDEKIQ_RETRY_JOB_TEMPLATE",
]

NORMALISED_IMPORT_LINE = b"import socket, urllib.parse as up, json, time"
NORMALISED_TIMEOUT_LINE = b"    s.settimeout(8)"


def _load_baseline(name):
    with open(os.path.join(FIXTURES_DIR, f"{name}.bin"), "rb") as f:
        return f.read()


def _expected_bytes(baseline):
    """Apply the two documented, intentional normalisations to a pre-refactor
    baseline script and return the bytes the de-duplicated constant should
    now produce."""
    lines = baseline.split(b"\n")
    assert lines[0].startswith(b"import socket, urllib.parse as up")
    lines[0] = NORMALISED_IMPORT_LINE
    for i, line in enumerate(lines):
        if line in (b"    s.settimeout(5)", b"    s.settimeout(8)"):
            lines[i] = NORMALISED_TIMEOUT_LINE
            break
    else:
        raise AssertionError("no settimeout(...) line found in baseline")
    return b"\n".join(lines)


class TestRedisPreludeDeduplication:
    def test_baseline_fixtures_present(self):
        for name in SCRIPT_NAMES:
            assert os.path.isfile(os.path.join(FIXTURES_DIR, f"{name}.bin")), name

    def test_every_script_matches_normalised_baseline_byte_for_byte(self):
        for name in SCRIPT_NAMES:
            baseline = _load_baseline(name)
            expected = _expected_bytes(baseline)
            live = getattr(scanner, name)
            assert live == expected, f"{name} diverged from its normalised baseline"

    def test_scripts_share_the_same_prelude_object(self):
        prelude = scanner._REDIS_PRELUDE
        assert isinstance(prelude, bytes) and prelude
        for name in SCRIPT_NAMES:
            live = getattr(scanner, name)
            assert live.startswith(prelude), f"{name} does not start with _REDIS_PRELUDE"

    def test_prelude_defines_rc_and_rr_exactly_once(self):
        prelude = scanner._REDIS_PRELUDE
        assert prelude.count(b"def rc(s, *args):") == 1
        assert prelude.count(b"def rr(s, bf):") == 1

    def test_non_template_scripts_compile(self):
        # The five scripts with no __PLACEHOLDER__ substitution should compile
        # as-is.
        for name in ("_SIDEKIQ_REDIS_SCRIPT", "_SIDEKIQ_CLEAR_DEAD_SCRIPT",
                     "_SIDEKIQ_RETRY_DEAD_SCRIPT", "_SIDEKIQ_CLEAR_RETRY_SCRIPT",
                     "_SIDEKIQ_RETRY_RETRY_SCRIPT"):
            src = getattr(scanner, name).decode()
            compile(src, f"<{name}>", "exec")

    def test_template_scripts_compile_after_placeholder_substitution(self):
        cases = [
            ("_SIDEKIQ_LIST_JOBS_TEMPLATE", {b"__QUEUEKEY__": b"'dead'", b"__OFFSET__": b"0", b"__ENDIDX__": b"24"}),
            ("_SIDEKIQ_DELETE_JOB_TEMPLATE", {b"__QUEUEKEY__": b"'dead'", b"__JID__": b"'abc123'"}),
            ("_SIDEKIQ_RETRY_JOB_TEMPLATE", {b"__QUEUEKEY__": b"'dead'", b"__JID__": b"'abc123'"}),
        ]
        for name, subs in cases:
            script = getattr(scanner, name)
            for placeholder, value in subs.items():
                script = script.replace(placeholder, value)
            compile(script.decode(), f"<{name}>", "exec")
