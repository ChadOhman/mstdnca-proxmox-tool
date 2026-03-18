# Unified Notification Standard & Host Update Tracking

**Date:** 2026-03-18
**Status:** Approved
**PR:** TBD

## Problem

Discord notifications and the web dashboard report different update counts because:

1. **Host updates are not persisted.** The `_check_host_updates` scheduler job fetches APT packages from the Proxmox API and sends a Discord notification, but never stores the data. The dashboard's "Pending Updates" count only includes guest packages from the `UpdatePackage` table.
2. **No "resolved" notifications.** When updates are applied (manually or via auto-update), the old Discord notification remains showing stale counts. There is no follow-up notification confirming updates were applied.
3. **Inconsistent notification lifecycle.** App upgrades have start+result notifications. Guest/host updates only have "available" notifications. Service failures only have push webhooks (no Discord). There is no unified standard.

## Solution

### 1. `HostUpdatePackage` Model

New model mirroring `UpdatePackage`, with FK to `ProxmoxHost`:

| Column | Type | Notes |
|--------|------|-------|
| id | Integer PK | |
| host_id | FK -> ProxmoxHost | NOT NULL, `ondelete="CASCADE"` (matches `HostExporterInstance` pattern) |
| package_name | String(256) | |
| current_version | String(128) | |
| available_version | String(128) | |
| severity | String(32) | "critical", "important", "normal" |
| discovered_at | DateTime UTC | |
| applied_at | DateTime UTC | nullable |
| status | String(32) | "pending", "applied", "skipped" |

Index: `ix_host_update_pkg_host_status` on (host_id, status).

`ProxmoxHost` gets `pending_updates()` and `security_updates()` convenience methods matching the `Guest` pattern.

Data is persisted during `_check_host_updates` by parsing the Proxmox API APT response. Old pending packages are cleared and replaced on each check (same pattern as guest scanning).

`ProxmoxHost` also gets a `host_update_packages` relationship with `cascade="all, delete-orphan"` for ORM-level cascade.

#### Proxmox API Field Mapping

The Proxmox API `GET /nodes/{node}/apt/update` returns objects with fields including `Package`, `OldVersion`, `NewVersion`, and `Priority`. The PBS API returns a similar structure. Map as follows:

| Proxmox Field | `HostUpdatePackage` Column |
|---------------|---------------------------|
| `Package` | `package_name` |
| `OldVersion` | `current_version` |
| `NewVersion` / `Version` | `available_version` |
| `Priority` | `severity` (mapped: "important" -> "critical", "required" -> "important", all others -> "normal") |

For host packages, there is no separate security advisory database like with guests. The priority mapping provides a reasonable approximation — Proxmox marks kernel and critical library updates as "important" priority.

### 2. Dashboard Integration

`get_dashboard_stats()` adds:
- `host_pending_updates` — count of `HostUpdatePackage` where status="pending"
- `host_security_updates` — count with severity="critical"

`dashboard.html` gets two new stat cards in the bottom row for host updates.

### 3. Unified "Applied/Resolved" Notifications

#### Guest & Host Updates: `send_updates_applied_notification(results)`

- **Trigger (auto):** End of `_run_auto_updates` loop — batch all apply outcomes, send one notification.
- **Trigger (manual):** Immediately after `apply_updates()` succeeds for a single guest or host. For guests, this is in `_run_update_background` in `routes/api.py`. For hosts, this is in `_run_apply` in `routes/hosts.py`.
- **Format:** Green embed, compact. Security counts called out separately but not verbose (updates were already reported in detail in the "available" notification).

**`results` parameter shape:**
```python
[{
    "name": str,          # guest or host name
    "type": str,          # "CT", "VM", "PVE", or "PBS"
    "applied": int,       # total packages applied
    "security": int,      # security/critical packages applied
}]
```

```
Title: "Updates applied"
Description: "85 update(s) applied across 3 guest(s)."
Fields:
  lambnet-pt (CT): 70 applied (17 security)
  mstdnca-srv1 (VM): 10 applied (1 security)
  agnes (PVE): 5 applied
Footer: "Log in to MCAT to review details."
```

- Color: GREEN
- Dedup: None (applies are one-time events)
- Guests and hosts can appear in the same batched notification

#### Service State Changes

**`send_service_failed_notification(guest, service_name)`**
- Trigger: `_upsert_service` detects transition from "running" to "failed"
- Color: RED
- Format: Simple embed with guest name and service name

**`send_service_recovery_notification(guest, service_name)`**
- Trigger: `_upsert_service` detects transition from "failed" to "running"
- Color: GREEN
- Format: Simple embed with guest name and service name

Both only fire on actual state transitions, not on every scan seeing the same status. A newly discovered service in a "failed" state should trigger the failed notification (it is new information from the user's perspective), but subsequent scans seeing the same "failed" status should not re-fire.

New setting: `discord_notify_services` (default "true").

### 4. Unified Notification Lifecycle (After Changes)

| Entity | Available | Resolved/Applied |
|--------|-----------|-----------------|
| Guest updates | Scan notification (deduped) | Applied notification |
| Host updates | Scan notification (deduped) | Applied notification |
| App upgrades | Version notification (deduped) | Started + result notifications |
| Services | Failed notification (transition) | Recovery notification (transition) |
| Exporters | N/A | Result notification |

### 5. Mobile API Changes

**`GET /api/v1/dashboard/summary`** — add:
- `host_pending_updates` (int)
- `host_security_updates` (int)

**`GET /api/v1/hosts`** — add to each host:
- `pending_updates_count` (int)
- `security_updates_count` (int)

**`GET /api/v1/hosts/<host_id>`** — add:
- `pending_updates_count`, `security_updates_count`
- `updates` array: `[{package_name, current_version, available_version, severity}]`

**`GET /api/v1/dashboard/alerts`** — add:
- `host_security_updates`: `[{host_id, host_name, count}]`

**Push webhooks** — update `PushWebhook.VALID_EVENTS` in `models.py`:
- Add `"service_failed"` (canonical name) and `"service_recovered"`
- Keep `"service_down"` in the set as a backwards-compatible alias for `"service_failed"`
- In `core/push_notifier.py`, when dispatching a `service_failed` event, also match webhooks subscribed to `service_down`

### 6. Wiki Documentation Updates

- **Configuration.md** — Discord notifications section: add "Updates Applied", "Service Failed/Recovered", `discord_notify_services` setting
- **Mobile-API.md** — Update response schemas for dashboard summary, hosts, alerts, push webhook events
- **API-Reference.md** — Update affected internal API endpoints
- **Hosts.md** — Add section on host update tracking
- **Services.md** — Add section on Discord notifications for service state changes

### 7. Implementation Files

| File | Changes |
|------|---------|
| `models.py` | Add `HostUpdatePackage` model, `ProxmoxHost.pending_updates()`, `ProxmoxHost.security_updates()`, `host_update_packages` relationship. Update `PushWebhook.VALID_EVENTS` with `service_failed` and `service_recovered` |
| `core/scanner.py` | Track service state transitions in `_upsert_service` (compare old vs new status before updating) |
| `core/scheduler.py` | Persist host packages in `_check_host_updates`, batch apply results in `_run_auto_updates`, call `send_updates_applied_notification` with batch |
| `core/notifier.py` | Add `send_updates_applied_notification`, `send_service_failed_notification`, `send_service_recovery_notification` |
| `core/push_notifier.py` | Handle `service_failed`/`service_down` alias mapping in dispatch, add `service_recovered` dispatch |
| `core/dashboard_stats.py` | Add host update counts to stats |
| `routes/api.py` | Call `send_updates_applied_notification` after manual guest apply in `_run_update_background` |
| `routes/api_v1.py` | Add host update fields to dashboard/hosts/alerts endpoints |
| `routes/hosts.py` | Call `send_updates_applied_notification` after manual host apply in `_run_apply` |
| `templates/dashboard.html` | Add host update stat cards |
| `tests/` | Tests for all new models, notifications, API changes, dashboard stats, push webhook alias |
| Wiki (5 files) | Documentation updates |

### 8. Test Coverage

- `HostUpdatePackage` model CRUD and lifecycle
- `send_updates_applied_notification` with single and batched results (guests + hosts mixed)
- `send_service_failed_notification` and `send_service_recovery_notification`
- Service state transition detection (only fires on actual changes, not repeated status)
- Dashboard stats including host update counts
- Host update persistence in `_check_host_updates`
- Mobile API response schema changes (dashboard summary, hosts, alerts)
- Push webhook `service_recovered` event delivery
