# Runbook: major engine upgrade with RDS blue/green

Use `rdsops upgrade-plan` to produce the instance-specific version of this runbook. This
page explains the why behind each step.

```bash
rdsops upgrade-plan --instance egdb-prod --target 18.1 --arcgis 12.1 \
    --host <endpoint> --user ops --dbname egdb --iam
```

## Before the window

1. **Support.** The target engine must be on the Esri matrix for your ArcGIS release
   (`rdsops compat`). Check PostGIS separately once green exists; RDS ships the PostGIS
   version, and Esri blocks some (issue 5978).
2. **Source minor.** Blue/green major upgrades are not available from 15.3 and lower,
   14.8 and lower, 13.11 and lower, 12.15 and lower, or 11.20 and lower. Patch first.
3. **Geodatabase on 11.x or earlier.** Esri requires pg_dump and pg_restore; an engine
   upgrade is not the path.
4. **Master password.** Blue/green does not support Secrets Manager-managed master
   passwords. Switch to self-managed for the window ([ADR 0005](../adr/0005-managed-master-secret-vs-blue-green.md)).
5. **Logical replication.** Major-version blue/green uses logical replication:
   `rds.logical_replication = 1` (module variable `logical_replication = true`), and
   `max_replication_slots` above the number of databases. Both need a reboot.
6. **Blockers in the data.**
   - Existing logical slots cancel the deployment. Drop the ones whose consumer is gone.
   - UPDATE and DELETE fail on tables with no primary key and no replica identity while
     the deployment runs. Add a key, set `REPLICA IDENTITY USING INDEX`, or freeze edits.
   - Large objects are not replicated, and touching them degrades the deployment.
   - Unlogged tables are not replicated.
   - pg_partman, pglogical and pgactive off on blue; pg_cron off on green.
7. **Snapshot.** Take a manual snapshot. Point-in-time restore history does not carry
   over to the new instance, so this snapshot is the way back.
8. **Rehearse** in a lower environment, including an ArcGIS Pro connection, an edit to a
   versioned feature class, and a compress.

## During the window

9. **Schema freeze.** DDL is not replicated, and one `CREATE TABLE` degrades the
   deployment, which then has to be deleted and recreated. For ArcGIS users: no new
   feature classes, no Add Field, no index builds, no domain or relationship class
   changes.
10. Create the deployment with the target engine version and a parameter group for the
    new family (same settings, including pgaudit in `shared_preload_libraries`).
11. Watch replication lag. Logical apply is single-threaded.
12. On green: check `pg_available_extension_versions` for PostGIS, run `rdsops compat`
    with it, `ALTER EXTENSION postgis UPDATE`, and `ANALYZE`.
13. Point a test ArcGIS Pro at the green endpoint and draw the main maps.
14. Switch over in a quiet period. Sequences are synced at switchover; a very large
    number of sequences can need a longer timeout.

## After

15. `rdsops inventory`, `health` and `maintenance` against the new instance.
16. Turn Secrets Manager management of the master password back on.
17. Lift the schema freeze. Refresh materialized views, which do not refresh on green.
18. Delete the deployment, and the old instance after a soak period.

## Sources (checked 2026-11-04)

- [AWS: limitations and considerations for blue/green deployments](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/blue-green-deployments-considerations.html)
- [AWS: replication methods for PostgreSQL blue/green deployments](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/blue-green-deployments-replication-type.html)
- [AWS re:Post: resolve blue/green deployment errors for RDS for PostgreSQL](https://repost.aws/knowledge-center/rds-postgresql-blue-green-deployment-error)
- [Esri: PostgreSQL requirements (dump/restore from 11.x)](https://doc.esri.com/en/arcgis-enterprise/latest/plan/database-requirements-postgresql.html)
