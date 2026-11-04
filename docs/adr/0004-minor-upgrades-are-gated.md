# 0004. Minor engine upgrades are manual and gated by the Esri support matrix

Status: accepted (2026-11-04)

## Context

RDS can apply minor engine versions automatically in the maintenance window, and most
security baselines (checkov CKV_AWS_226 among them) want that on. For an enterprise
geodatabase it is riskier than it looks. Esri certifies specific PostgreSQL and PostGIS
versions per ArcGIS release, and a known PostGIS regression (issue 5978, versions 3.5.3
and later) broke SRID creation in geodatabases on RDS. An unattended upgrade that changes
the available extension versions can leave ArcGIS clients on an unsupported combination
with nobody having looked.

## Decision

The module sets `auto_minor_version_upgrade = false` and skips CKV_AWS_226 inline with a
pointer to this ADR. Minor upgrades follow the upgrade runbook: `rdsops compat` against
the target version, apply in a lower environment, check from an ArcGIS client, then
production. `rdsops inventory` warns when auto minor upgrade is on.

## Consequences

- Security patches arrive on a schedule people own instead of automatically. The runbook
  sets a target: minor versions applied within 30 days of release unless `compat` says no.
- Deprecation deadlines still apply. RDS eventually forces upgrades off deprecated minors,
  so skipping the runbook does not avoid the change, it only removes the warning.
