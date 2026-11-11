# 0003 — Explicit snapshot IDs with a seal step

Status: accepted (2026-11-09)

## Context
We do not know what one delivered file represents in production (full
crawl, slice, or day). Attribution uses snapshot-wide aggregates
(infrastructure domains seen on >= 1,000 IPs; orgs with > 100 customer
domains), so running it over a partly delivered snapshot gives wrong tiers.

## Decision
Every file is registered with a `snapshot_id` (default: UTC delivery date).
Per-file layers (observations, flags, services, signals) run as files
complete. Attribution and account rollups run only on a sealed snapshot. A
new file registered into a sealed snapshot unseals it.

A file belongs to exactly one snapshot, the one it was first registered
into. A redelivery of the same bytes under another snapshot id is recorded
as a duplicate delivery and does not move the file. `seal` refuses an
unknown snapshot id.

## Consequences
Someone, or a schedule, must seal snapshots. Rolling-window freshness is
derived from `observed_at`, not from snapshot membership.
