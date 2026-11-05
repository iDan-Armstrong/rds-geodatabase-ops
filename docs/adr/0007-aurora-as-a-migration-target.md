# 0007. Aurora as a migration target

Status: accepted (2026-11-04). Amends [0002](0002-rds-for-postgresql-not-aurora.md).

## Context

ADR 0002 keeps rdsops on RDS for PostgreSQL so every check can assume one storage,
backup and failover model. Teams still move geodatabases from RDS to Aurora PostgreSQL,
and the questions before that move are the kind rdsops already answers: which version,
supported by which ArcGIS release, with what preconditions, in what order.

## Decision

- `compat` gains a platform: `--platform aurora` checks against Esri's Aurora PostgreSQL
  list, which differs from the RDS list (for 12.1: Aurora 14.19 to 17.6, no 18).
- `aurora-plan` plans the move from an RDS instance: the target Aurora version (the
  lowest one the Region offers that AWS allows for the source and Esri supports), the
  read replica or snapshot method and its AWS preconditions, encryption, WAL headroom,
  and a runbook including the ArcGIS cutover.
- It reads and plans only. It never creates a cluster; the runbook is for a person.
- It is partition-aware: GovCloud Regions get `aws-us-gov` ARNs, and versions are read
  from the Region because GovCloud can lag commercial Regions. An unencrypted source is a
  failure in GovCloud and a warning elsewhere.
- Operating an Aurora cluster after the move (cluster-level backups, readers, Aurora
  storage) stays out of scope, as ADR 0002 says.

## Consequences

- One more platform in the matrix to keep current.
- The planner's version choice depends on `describe-db-engine-versions` in the Region;
  offline planning says so instead of guessing.
