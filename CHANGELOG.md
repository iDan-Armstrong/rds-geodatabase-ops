# Changelog

## 0.8.0 (2026-11-05)

- `rdsops resilience`: zone loss and Region loss scored against `--rto-minutes` and
  `--rpo-minutes`: Multi-AZ, point-in-time restore, cross-Region replicas (lag from
  CloudWatch with `--replica-lag`), replicated automated backups and snapshot copies in
  the DR Region; a KMS key and the engine version in the DR Region; failover event
  subscriptions. Recovery times only from AWS's Multi-AZ figure or measured drills.
- `rdsops failover-drill`: plans zone and Region drills and scores a recorded result
  (`--result`), including how long ArcGIS took after the database. Prints only.
- ADR 0009, runbook disaster-recovery.md.

## 0.7.0 (2026-11-05)

- `rdsops security`: TLS required and minimum version, md5 or SCRAM password storage, the
  certificate authority and server certificate expiry, internet exposure of the port,
  public, shared and unencrypted snapshots, KMS key rotation, managed master secret
  rotation, audit trail gaps, deletion protection and restore window; with a connection,
  non-TLS sessions, extra rds_superuser members and CREATE on public. Metadata only.
- `rdsops incident`: playbooks for credentials, aws-keys, exposure, destruction,
  exfiltration and certificate incidents, filled in for the instance, with readiness
  findings. Prints only (ADR 0008). Evidence before destructive steps, deletion
  protection first, CISA one-hour notification with `--federal`.
- Runbook: security-incidents.md.

## 0.6.0 (2026-11-04)

- `rdsops fleet`: every RDS for PostgreSQL instance across Regions (`REGION@PROFILE` for
  GovCloud or other accounts), optionally filtered by tag. Per instance, the inventory
  posture check and the Esri compat check against its `arcgis-release` tag;
  `environment=prod` makes availability gaps failures. Fleet findings for minor-version
  drift, mixed ArcGIS releases and untagged instances. A Region that cannot be read is a
  finding, not a crash.
- `inventory.facts_from_api` shared by inventory and fleet.

## 0.5.0 (2026-11-04)

- `rdsops aurora-plan`: plan the move from RDS for PostgreSQL to Aurora PostgreSQL. Picks
  the lowest Aurora version the Region offers that AWS allows for the source and Esri
  supports for the ArcGIS release; checks the read replica or snapshot method's AWS
  preconditions, encryption and WAL headroom; prints a runbook with the CLI commands and
  the ArcGIS cutover. Read-only. Partition-aware for GovCloud.
- `rdsops compat --platform aurora`, against Esri's Aurora PostgreSQL list.
- Support matrix: Aurora versions for 12.1, 12.0 and 11.5. Correction: Esri's 11.5 page
  blocks PostGIS 3.5.3 and 3.6.0, not "3.5.3 and later"; rechecked 2026-11-04.
- ADR 0007: Aurora as a migration target (amends 0002). Runbook: aurora-migration.md.

## 0.4.0 (2026-11-04)

- `rdsops restore-drill`: point-in-time or snapshot restore to a throwaway copy, timed,
  verified over SQL (PostGIS, geodatabase, row counts), then deleted. Plan only unless
  `--execute`. Findings against RTO and RPO targets, and a JSON-lines report for audit.
- The copy is created without deletion protection, and cleanup turns it off if any path
  copied it; cleanup refuses to delete the source or anything without the drill tag.
- Runbook: restore drill, including the IAM permissions it needs.
- CI actions moved to their Node 24 majors (checkout v5, setup-python v6).

## 0.3.0 (2026-11-04)

- `rdsops compat`: engine and PostGIS versions against a dated, sourced copy of the Esri
  support matrix for ArcGIS Enterprise 12.1, 12.0 and 11.5, including the PostGIS issue
  5978 blocks. Reads versions from the instance and database when connected.
- `rdsops upgrade-plan`: preflight for minor and major upgrades and an ordered runbook.
  Major upgrades check the blue/green preconditions: source minor floor, managed master
  secret, logical replication settings, slots, primary keys, large objects, unlogged
  tables, and extensions.
- Terraform: `logical_replication` variable (default off).
- ADR 0005 (managed master secret vs blue/green), ADR 0006 (checks are pure functions).
- Runbook: major engine upgrade with RDS blue/green.
- Inventory titles now state what is true when a check fails ("Deletion protection is
  off", not "Deletion protection on" next to a WARN). Found while building the SIMServo
  training game on top of these checks.
- Test that every check module imports without boto3 or psycopg; the free-storage
  check is split into a pure `storage_evaluate` and a CloudWatch wrapper.

## 0.2.0 (2026-11-04)

- `rdsops health`: connections, long queries, idle-in-transaction sessions, lock waits,
  wraparound age, replication slots, cache hit ratio, top queries, PostGIS version, and
  free storage from CloudWatch with `--instance`.
- `rdsops maintenance`: dead rows, stale statistics, unused, duplicate and invalid
  indexes, and spatial columns without a spatial index.
- Connections by IAM auth token, Secrets Manager secret, or connection string; always
  read-only. No password options.
- `--quiet` hides passing checks.
- CI: integration tests against PostGIS 16 and 17 with problems seeded on purpose.

## 0.1.0 (2026-11-04)

- Terraform module `egdb-postgres`: KMS encryption, TLS required, IAM auth, RDS-managed
  master secret, pgaudit and pg_stat_statements, CloudWatch alarms, required tags.
- Examples: `minimal` (lab) and `govcloud` (production-shaped, FIPS endpoints).
- `rdsops inventory`: control-plane facts and nine posture checks, text or JSON, with
  exit codes for automation.
- CI: ruff and pytest on 3.11 to 3.13; terraform fmt and validate; tflint; checkov.
- ADRs 0001 to 0004 and the agreed scope.
