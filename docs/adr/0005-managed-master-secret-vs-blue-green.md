# 0005. Keep the RDS-managed master secret; turn it off only for blue/green upgrades

Status: accepted (2026-11-04)

## Context

The module sets `manage_master_user_password = true`, so RDS generates the master
password, stores it in Secrets Manager under the module's KMS key, and rotates it. Nobody
types it, and it never lands in Terraform state.

AWS documents that blue/green deployments do not support master passwords managed with
Secrets Manager. Blue/green is the low-downtime path for a major engine upgrade, so the
two defaults collide once every year or two.

## Decision

Keep the managed secret as the default. For a major upgrade, `rdsops upgrade-plan`
reports the conflict as a failure (UPG006) and the runbook switches the instance to a
self-managed password for the upgrade window, then turns management back on after
switchover. The temporary password comes from the team's own vault and is used once.

## Consequences

- Day to day, the stronger setting holds: no human-known master password.
- The upgrade runbook gains two steps, and the window during which a human-set password
  exists is bounded by the change.
- If AWS lifts the limitation, UPG006 and the two steps go away; the rest of the plan is
  unchanged.
