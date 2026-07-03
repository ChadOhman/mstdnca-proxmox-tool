"""Aggregate UpdateHistory data for the trends/history page.

Kept separate from the route module so the ranking/bucketing logic can be
unit tested without going through Flask request plumbing.
"""

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from models import UpdateHistory, UpdatePackage, db

DEFAULT_TREND_DAYS = 90


def weekly_apply_series(guest_ids, days=DEFAULT_TREND_DAYS):
    """Bucket UpdateHistory rows into weekly totals for the given guests.

    Returns a list of dicts, oldest week first, each with:
        week_start (date), total (int), security (int)
    Weeks with no activity are included (zero-filled) so the chart has a
    continuous x-axis.
    """
    now = datetime.now(timezone.utc)
    since = now - timedelta(days=days)

    # Week buckets are anchored to `since`, in 7-day increments, so the
    # bucket boundaries are stable regardless of what day "today" is.
    num_weeks = max(1, -(-days // 7))  # ceil division
    buckets = []
    for i in range(num_weeks):
        start = since + timedelta(days=i * 7)
        buckets.append({"week_start": start.date().isoformat(), "total": 0, "security": 0})

    if not guest_ids:
        return buckets

    rows = (
        UpdateHistory.query
        .filter(UpdateHistory.guest_id.in_(guest_ids))
        .filter(UpdateHistory.applied_at >= since)
        .all()
    )

    for row in rows:
        applied_at = row.applied_at
        if applied_at.tzinfo is None:
            applied_at = applied_at.replace(tzinfo=timezone.utc)
        offset_days = (applied_at - since).days
        idx = min(offset_days // 7, num_weeks - 1)
        if idx < 0:
            continue
        buckets[idx]["total"] += row.package_count or 0
        buckets[idx]["security"] += row.security_count or 0

    return buckets


def chronically_behind(guests, now=None):
    """Rank guests by how long they've had pending updates outstanding.

    For each guest with at least one pending update, computes:
        - pending_count / pending_security_count
        - oldest_pending_days: days since the oldest still-pending update
          was first discovered (how long it's been waiting)
        - days_since_last_update: days since the guest's last successful
          UpdateHistory entry, or None if it has never had one applied

    Returns a list of dicts sorted descending by oldest_pending_days (guests
    that have been waiting longest come first). Guests with no pending
    updates are excluded.
    """
    now = now or datetime.now(timezone.utc)
    guest_ids = [g.id for g in guests]
    if not guest_ids:
        return []

    pending_rows = (
        UpdatePackage.query
        .filter(UpdatePackage.guest_id.in_(guest_ids))
        .filter(UpdatePackage.status == "pending")
        .all()
    )
    pending_by_guest = defaultdict(list)
    for row in pending_rows:
        pending_by_guest[row.guest_id].append(row)

    last_history = (
        db.session.query(UpdateHistory.guest_id, db.func.max(UpdateHistory.applied_at))
        .filter(UpdateHistory.guest_id.in_(guest_ids))
        .group_by(UpdateHistory.guest_id)
        .all()
    )
    last_applied_by_guest = dict(last_history)

    guests_by_id = {g.id: g for g in guests}

    results = []
    for guest_id, pkgs in pending_by_guest.items():
        guest = guests_by_id.get(guest_id)
        if guest is None:
            continue

        oldest_discovered = min(
            (p.discovered_at for p in pkgs if p.discovered_at is not None),
            default=None,
        )
        if oldest_discovered is not None:
            if oldest_discovered.tzinfo is None:
                oldest_discovered = oldest_discovered.replace(tzinfo=timezone.utc)
            oldest_pending_days = max(0, (now - oldest_discovered).days)
        else:
            oldest_pending_days = 0

        last_applied = last_applied_by_guest.get(guest_id)
        if last_applied is not None:
            if last_applied.tzinfo is None:
                last_applied = last_applied.replace(tzinfo=timezone.utc)
            days_since_last_update = max(0, (now - last_applied).days)
        else:
            days_since_last_update = None

        security_count = sum(1 for p in pkgs if p.severity == "critical")

        results.append({
            "guest": guest,
            "pending_count": len(pkgs),
            "pending_security_count": security_count,
            "oldest_pending_days": oldest_pending_days,
            "days_since_last_update": days_since_last_update,
        })

    results.sort(key=lambda r: r["oldest_pending_days"], reverse=True)
    return results


def guest_history(guest_id, limit=50):
    """Return a guest's applied-update timeline, newest first."""
    return (
        UpdateHistory.query
        .filter_by(guest_id=guest_id)
        .order_by(UpdateHistory.applied_at.desc())
        .limit(limit)
        .all()
    )
