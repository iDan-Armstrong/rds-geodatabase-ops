# 0009. Recovery times are measured, not guessed; failover drills print

Status: accepted (2026-11-05)

## Context

`rdsops resilience` answers whether a geodatabase can come back from losing its zone or
its Region within the agreed recovery time (RTO) and data loss (RPO). Data loss can be
read from timestamps AWS reports: the latest restorable time, replicated backups in the
other Region, replica lag, the age of a snapshot copy.

Recovery time cannot. AWS documents one figure, Multi-AZ failover "typically 60 to 120
seconds". A restore depends on database size, instance class and what ArcGIS has to do
afterwards. Any formula here would be a guess that looks like a measurement.

Drills that prove the times are disruptive or costly. A zone drill forces a real
failover. A Region drill that promotes the cross-Region replica cannot be undone and
leaves the database without DR until a new replica is built.

## Decision

- Data loss per recovery path comes from AWS timestamps. Unknown stays unknown (RES003
  INFO) and is never shown as safe.
- Recovery time comes from AWS's Multi-AZ figure (two minutes, plus a minute for clients
  to reconnect) or from the operator's own measured drills: `rdsops restore-drill
  --report` and `rdsops failover-drill --result`, passed back with `--report`. With
  neither, RES004 says it was never measured (WARN for production).
- `rdsops failover-drill` prints the plan and scores a recorded result. It runs nothing,
  like the incident playbooks (ADR 0008). A Region drill restores the replicated backups
  or a snapshot copy to a scratch instance and deletes it; promoting the real replica is
  a tabletop step.
- A drill is not done when the database is writable. It is done when ArcGIS answers
  (`apps_ok_at`); the gap is scored (DRD003), because DNS caching in ArcGIS Server's JVM
  is the usual reason a two-minute failover becomes a twenty-minute outage.

## Consequences

- The first run on a new instance will say recovery time was never measured. That is the
  point: it asks for a drill.
- Times measured on one instance class do not carry over to another. Re-drill after
  resizing.
