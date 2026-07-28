# CLAUDE.md

Flask-based Proxmox datacenter administration tool (Python 3.13). Manages VMs/LXCs across PVE/PBS hosts with web SSH terminal, service monitoring, app upgrade automation, UniFi integration, and real-time collaboration via SSE + WebSocket.

## Commands

```bash
make install-dev   # Install dev dependencies
make test          # Full test suite (~1600 tests, in-memory SQLite)
make lint          # ruff check .
make security      # bandit + pip-audit
make all           # lint + security + test
ruff check . --fix # auto-fix lint
```

Single test: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev pytest tests/test_auth.py::TestLogin::test_valid_login -v`

## Working Standards

- **Own all failures:** Never dismiss test failures as "pre-existing." Investigate and fix in the same PR.
- **CI must pass:** Every push must have green CI. Own all failures on the branch.

## Lint / Style

- Ruff: `line-length = 120`, `target-version = "py313"`
- Rules: E, F, W, B (bugbear), S (bandit/security)
- `routes/terminal.py` allows S602; `tests/**/*.py` allows S101

## Deep Dives

Detailed docs live in [docs/claude/](docs/claude/) — read on demand, not upfront:

- [architecture.md](docs/claude/architecture.md) — app factory, directory structure, blueprints, DB, auth, frontend
- [patterns.md](docs/claude/patterns.md) — permission gates, audit logging, settings cache, import conventions
- [testing.md](docs/claude/testing.md) — fixtures, coverage, test environment setup
