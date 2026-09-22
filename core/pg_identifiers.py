"""Shared validation for PostgreSQL identifiers (database names) that flow

into shell commands. Used both for user-supplied input (routes/services.py)
and for remote-sourced identifiers parsed from `psql`/`pg_stat_database`
output on a monitored guest (core/scanner.py) -- the guest is a trust
boundary, so identifiers read back from it must be validated exactly like
user input before they are interpolated into a command string.
"""
import re

# Allowlist for PostgreSQL database names: letters, digits, underscores only
# (max 63 chars, matching PostgreSQL's NAMEDATALEN limit). Prevents command
# injection in shell commands that embed the database name unquoted.
PG_DB_NAME_RE = re.compile(r'^[A-Za-z0-9_]{1,63}$')


def validate_pg_db_name(name):
    """Return True if `name` is safe to interpolate into a shell command.

    Rejects anything but `[A-Za-z0-9_]{1,63}` -- in particular, any quoting,
    whitespace, or shell metacharacters that a real (but unusual) PostgreSQL
    identifier could legally contain.
    """
    return bool(name) and bool(PG_DB_NAME_RE.match(name))
