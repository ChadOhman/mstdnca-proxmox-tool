# Testing

## Environment

Tests use a file-backed SQLite database in a per-session temp directory (so background threads get their own connections, with the same WAL/busy_timeout/foreign_keys pragmas as production) and a session-scoped app fixture (`tests/conftest.py`). `DATABASE_URL` is ignored by the suite.

Required env vars for manual runs:
```bash
FLASK_SECRET_KEY=dev-secret
DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db"
MSTDNCA_DATA_DIR=/tmp/mstdnca-dev
```

## Fixtures

- `auth_client` — pre-authenticated admin client
- Credential store is redirected to a temp file — tests never touch `/etc/mstdnca`

## Coverage

- Threshold: 40% (`--cov-fail-under=40`) in both CI and local Makefile
- No integration tests for Proxmox/SSH/UniFi — those modules are omitted from coverage
- pyproject.toml omits: core/scanner, clients/proxmox_api, clients/pbs_client, apps/mastodon, apps/ghost, clients/unifi_client, clients/unifi_geoip