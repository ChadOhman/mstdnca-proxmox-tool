"""Record UpdateHistory rows when guest updates are applied.

Single shared helper so every apply code path (interactive single-guest apply,
bulk "update all", and scheduled maintenance-window auto-updates) writes a
consistent history entry. Callers MUST build the ``applied_pkgs`` list
*before* ``db.session.commit()`` — see the comments in routes/api.py and
core/scheduler.py about ``applied_at`` being a timezone-naive column.
"""

from datetime import datetime, timezone

from models import UpdateHistory, db

# Cap on how many package names go into the summary text, to keep rows small.
_SUMMARY_MAX_PACKAGES = 25


def record_update_history(guest, applied_pkgs, initiated_by=None):
    """Add an UpdateHistory row for a completed apply.

    Args:
        guest: The Guest the update was applied to.
        applied_pkgs: Iterable of UpdatePackage instances that were just
            marked applied (captured before commit).
        initiated_by: Username string, "scheduler" for unattended
            maintenance-window auto-updates, or None if unknown.

    Does not commit — caller is expected to commit alongside the rest of the
    apply transaction, same convention as auth.audit.log_action().
    """
    applied_pkgs = list(applied_pkgs)
    package_count = len(applied_pkgs)
    security_count = sum(1 for p in applied_pkgs if p.severity == "critical")
    names = [p.package_name for p in applied_pkgs[:_SUMMARY_MAX_PACKAGES]]
    summary = ", ".join(names)
    if package_count > _SUMMARY_MAX_PACKAGES:
        summary += f", and {package_count - _SUMMARY_MAX_PACKAGES} more"

    db.session.add(UpdateHistory(
        guest_id=guest.id,
        applied_at=datetime.now(timezone.utc),
        package_count=package_count,
        security_count=security_count,
        packages_summary=summary or None,
        initiated_by=initiated_by,
    ))
