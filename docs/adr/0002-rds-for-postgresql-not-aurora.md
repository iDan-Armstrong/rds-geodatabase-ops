# 0002. Target RDS for PostgreSQL, not Aurora

Status: accepted (2026-11-04)

## Context

Esri supports enterprise geodatabases on both Amazon RDS for PostgreSQL and Aurora
PostgreSQL. The two differ where operations work happens: storage and replication are
different under Aurora, backups and restores are cluster-level, failover uses readers
instead of a Multi-AZ standby, and the parameter and version surfaces differ. Supporting
both in one tool doubles the test matrix for every check.

## Decision

rdsops and the Terraform module target RDS for PostgreSQL instances only. `inventory`
reports a non-postgres engine as a failure rather than producing half-right output.

## Consequences

- Checks can assume one storage model, one backup model and one failover model.
- Teams on Aurora can reuse the SQL-level checks (bloat, vacuum age, geodatabase state
  growth) but not the control-plane ones. Adding Aurora later means a separate code path
  and its own ADR.
