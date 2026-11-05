# Changelog

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
