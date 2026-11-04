# Changelog

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
- Test that every check module imports without boto3 or psycopg.

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
