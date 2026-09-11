# Key Patterns

## Permission Gate

`@bp.before_request` + `@login_required` + check `current_user.can_*`

## Audit Logging

```python
from auth.audit import log_action
log_action("action", "resource_type", resource_id=..., resource_name=...)
db.session.commit()
```

## Settings Cache

`Setting.get()` caches per-request via `Flask g._settings_cache`; invalidated on `Setting.set()`.

## Accessible Confirms

All `confirm()` dialogs use Bootstrap modal (`#confirmModal` in `base.html`). Forms use `data-confirm="..."` attribute; JS intercepts submit.

## SQLAlchemy Filters

`== True` comparisons are intentional (E712 is ignored in ruff) — required by SQLAlchemy filter syntax.

## User-Facing Error Messages

Never return `str(e)` / `f"...{e}"` from a caught exception to a route (JSON, flash, streamed log). Log the exception server-side and return `describe_exception(e)` from `core.errors` — a message derived from the exception *type* only. CodeQL flags exception text reaching an HTTP response as stack-trace exposure.

## Redirects Back to the Referrer

Never `redirect(request.referrer)` or `redirect(request.args["next"])`. Use `redirect_back("endpoint", **values)` / `resolve_local_url(target)` from `core.local_redirect`: the target is matched against the app's URL map and rebuilt with `url_for`, so it can only land on a route of this app.

## Import Conventions

Core modules (`models`, `config`) are at root. Everything else uses package imports:
- `from auth.audit import log_action`
- `from clients.ssh_client import SSHClient`
- `from core.scanner import scan_guest`
- `from apps.mastodon import check_mastodon_release`