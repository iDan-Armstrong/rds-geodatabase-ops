# rds-geodatabase-ops

![CI](https://github.com/iDan-Armstrong/rds-geodatabase-ops/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-green)

Terraform and a Python CLI for standing up and operating an ArcGIS enterprise
geodatabase on Amazon RDS for PostgreSQL. The infrastructure is hardened by default, the
checks are plain functions with tests, and CI proves all of it without an AWS account.

[postgis-enterprise-patterns](https://github.com/iDan-Armstrong/postgis-enterprise-patterns)
covers how the database is designed. This repo covers how it is run: what the baseline
is, how you know the live instance still matches it, and how you prove a restore or an
upgrade will work before you need it.

**Status:** v0.4. The Terraform module and `rdsops inventory`, `health`,
`maintenance`, `compat`, `upgrade-plan` and `restore-drill` are done.
[docs/SCOPE.md](docs/SCOPE.md) lists what comes next and the facts it is built on.

## What to look at first

1. [`terraform/modules/egdb-postgres/main.tf`](terraform/modules/egdb-postgres/main.tf):
   the baseline, with a comment on each choice that is not obvious.
2. [ADR 0004](docs/adr/0004-minor-upgrades-are-gated.md): why this module turns off
   automatic minor upgrades when the security scanner says to turn them on.
3. [`src/rdsops/inventory.py`](src/rdsops/inventory.py) and its
   [tests](tests/test_inventory.py): the check pattern every later command follows.

## The baseline

| Setting | Value | Why |
| --- | --- | --- |
| Encryption | customer-managed KMS key, rotation on | snapshots and Performance Insights use the same key |
| Transport | `rds.force_ssl = 1` | no plaintext connections, including from ArcGIS clients |
| Master password | generated and held by RDS in Secrets Manager | never in Terraform state, tfvars or a wiki |
| Authentication | IAM database auth available | admins and automation use short-lived tokens |
| Network | private, ingress only from named security groups | no CIDR rules, no public endpoint |
| Auditing | pgaudit (`ddl,role`), connection logging, slow-query log to CloudWatch | who changed schema or privileges, and when |
| Query stats | `pg_stat_statements` preloaded | what `rdsops health` reads (v0.2) |
| Minor upgrades | manual, gated by the Esri support matrix | [ADR 0004](docs/adr/0004-minor-upgrades-are-gated.md) |
| Logical replication | off; `logical_replication = true` for a blue/green major upgrade | extra WAL is only worth it during an upgrade |
| Alarms | CPU, free storage, freeable memory, connections | the four that take a geodatabase down |
| Tags | `Owner`, `Environment`, `DataClassification` required | variable validation fails the plan without them |

GovCloud: every ARN is built from `aws_partition`, and the
[govcloud example](terraform/examples/govcloud/main.tf) turns on FIPS endpoints, Multi-AZ
and 35-day retention.

## rdsops

On Windows, double-click `rdsops-launcher.bat`. The first run builds a private Python
environment in `.venv`; after that it opens a menu (console, offline test suite, update).
Elsewhere:

```bash
pip install -e ".[dev]"
rdsops inventory --instance egdb-lab --profile lab
```

```
egdb-lab  postgres 17.7  db.t4g.micro  [available]
  endpoint   egdb-lab.aaaaaaaaaa.us-east-1.rds.amazonaws.com:5432
  storage    20 GB
  params     default.postgres17

  [ok  ] INV001  Storage encrypted at rest
  [ok  ] INV002  No public endpoint
  [ok  ] INV003  Deletion protection on
  [WARN] INV004  Backup retention 1 day(s), below the 7-day baseline
               Retention also bounds how far back point-in-time restore can go.
  [ok  ] INV005  IAM database authentication available
  [info] INV006  Single-AZ: no standby
               Single AZ: an AZ outage or host failure means a restore, not a failover.
  ...
  [WARN] INV009  Using a default parameter group
               Default groups cannot be edited, so rds.force_ssl, pgaudit and
               pg_stat_statements cannot be set. Attach a custom group.
```

(Output above is from the moto-backed test fixture, not a live account.)

- Exit code is 0 when clean, 1 on warnings, 2 on failures, so a scheduler or pipeline can
  act on it. `--json` gives the same findings for other tools.
- `--production` turns availability gaps (single AZ, short retention, no deletion
  protection) from warnings into failures.
- Credentials come only from the standard AWS chain (profile, SSO, instance role). There
  is no option to pass keys, on purpose.

Every check returns `Finding` objects and never prints or exits. The CLI renders them.
That is what makes each check a unit-testable function.

### health and maintenance

These two connect to the database and read catalogs. The connection is opened
read-only with a 60-second statement timeout; the checks tell you what to run and
never run it themselves.

```bash
# IAM token (nothing stored), RDS-managed secret, or a plain connection string
rdsops health --host egdb-lab.xxxx.us-east-1.rds.amazonaws.com --user ops --dbname egdb --iam --instance egdb-lab
rdsops maintenance --secret-arn arn:aws:secretsmanager:...:secret:rds!db-... --host ... --dbname egdb
RDSOPS_DSN="host=localhost dbname=egdb" rdsops maintenance --quiet
```

| Code | `health` checks | Code | `maintenance` checks |
| --- | --- | --- | --- |
| HLT001 | connections against usable slots | MNT001 | dead rows (ratio and count), with a compress hint for sde state and lineage tables |
| HLT002 | long-running queries | MNT002 | statistics never or not recently analyzed |
| HLT003 | sessions idle in transaction | MNT003 | large indexes never scanned, downgraded while stats are young |
| HLT004 | sessions waiting on locks | MNT004 | duplicate index definitions |
| HLT005 | transaction ID wraparound age | MNT005 | invalid indexes left by a failed concurrent build |
| HLT006 | replication slots: inactive or holding WAL | MNT006 | geometry or geography columns with no spatial index |
| HLT007 | cache hit ratio | | |
| HLT008 | top queries from `pg_stat_statements` | | |
| HLT009 | PostGIS present and its version | | |
| HLT010 | free storage from CloudWatch (with `--instance`) | | |

`maintenance` against a test schema with problems seeded on purpose (PostgreSQL 16,
PostGIS 3.4):

```
maintenance  3 tables checked, statistics 0.0 days old

  [WARN] MNT001  sewer.manholes: 40,000 dead rows (33%)
               Last vacuum: never. Run VACUUM (ANALYZE) sewer.manholes; if this recurs,
               lower autovacuum_vacuum_scale_factor for the table.
  [WARN] MNT002  sewer.manholes: statistics stale (never analyzed)
  [ok  ] MNT003  No large unused indexes (3 small ones under 8.0 MiB not listed)
  [WARN] MNT004  Duplicate indexes on sewer.manholes: manholes_fid_idx, manholes_fid_idx2
               Identical definitions. Keep one and DROP INDEX CONCURRENTLY the others
               (wasted: 3.5 MiB).
  [ok  ] MNT005  No invalid indexes
  [WARN] MNT006  sewer.manholes.shape (geometry) has no spatial index
               About 120,000 rows. Every map draw and spatial query on this column is a
               full scan. CREATE INDEX CONCURRENTLY ON sewer.manholes USING GIST (shape);
               or Add Spatial Index in ArcGIS for registered data.
```

### compat and upgrade-plan

`compat` checks an engine and PostGIS version against a dated copy of Esri's support
matrix ([`src/rdsops/data/esri_rds_postgresql.json`](src/rdsops/data/esri_rds_postgresql.json)),
including the PostGIS versions Esri blocks for issue 5978. Every entry carries its source
URL and check date, and the check warns when the data is more than 120 days old.

```
compat  RDS for PostgreSQL 16.4, PostGIS 3.5.3  vs ArcGIS 12.1

  [FAIL] CMP002  RDS 16.4 is below the certified minimum 16.11
  [FAIL] CMP003  PostGIS 3.5.3 is not supported by ArcGIS Enterprise 12.1 / Pro 3.7
               PostGIS issue 5978: SRID creation and spatial data creation fail or are
               malformed in enterprise geodatabases.
```

`upgrade-plan` reads the instance (and, if you connect, the database) and lists what has
to be true before an engine upgrade, then prints the runbook in order. For a major
upgrade it checks the blue/green preconditions AWS documents: source minor floor,
logical replication settings, existing slots, tables without a primary key, large
objects, unlogged tables, and extensions that must be turned off. Anything it cannot see
is reported as "not checked" rather than guessed.

One finding is worth calling out: the module's own default, an RDS-managed master
password in Secrets Manager, is not supported by blue/green.
[ADR 0005](docs/adr/0005-managed-master-secret-vs-blue-green.md) keeps the secure
default and has the runbook switch it off for the window only. The full reasoning per
step is in [docs/runbooks/major-upgrade-blue-green.md](docs/runbooks/major-upgrade-blue-green.md).

### restore-drill

Restores the instance to a throwaway copy, times how long until the copy is usable,
connects and verifies the data, and deletes the copy. Without `--execute` it only
prints the plan, so the default is free and read-only.

```
restore-drill  egdb-lab  mode pitr

  [ok  ] DRL010  Restore completed in 14.0 min
  [ok  ] DRL011  Time to a usable copy: 21.0 min (target 60)
  [ok  ] DRL012  Restore point 5 min before the drill started (target 15)
  [ok  ] DRL013  Verify: PostGIS present
  [ok  ] DRL013  Verify: gis.parcels rows
  [ok  ] DRL014  Copy egdb-lab-drill-202611041800 deleted
```

(Output from the mocked test drill; timings come from a fake clock there.)

The copy is private, single-AZ and has deletion protection turned off. Without that,
RDS copies deletion protection from the source and the cleanup fails. Cleanup deletes
only an instance tagged `rdsops-drill=true` that is not the source. See
[docs/runbooks/restore-drill.md](docs/runbooks/restore-drill.md).

## How it is tested

| Layer | How | Where |
| --- | --- | --- |
| AWS API calls | moto, with fake credentials forced for every test | `tests/` |
| SQL checks | thresholds unit-tested on snapshots; then problems seeded into real PostGIS 16 and 17 (dead rows, duplicate and invalid indexes, a missing spatial index, a held lock) and each one must be found | `tests/integration/`, CI `postgis` job |
| Python | ruff and pytest on 3.11, 3.12, 3.13 | CI `python` job |
| Portability | check modules must import with boto3 and psycopg blocked ([ADR 0006](docs/adr/0006-checks-are-pure-functions-over-snapshots.md)) | `tests/test_portable.py` |
| Terraform | `fmt`, `validate` for the module and both examples | CI `terraform` job |
| Terraform policy | tflint with the AWS ruleset, checkov | CI `lint-and-scan` job |

checkov runs clean on the production-shaped example with four inline skips, each with its
reason next to it in the code. The lab example additionally skips Multi-AZ, deletion
protection and Enhanced Monitoring, which it turns off to keep a drill cheap; the CI file
says so where it does it. [ADR 0003](docs/adr/0003-test-without-an-aws-account.md) covers
the testing approach and its limits.

## Running the lab example

Costs money while it exists (a `db.t4g.micro` and 20 GB). You need a VPC with two private
subnets.

```bash
cd terraform/examples/minimal
terraform init
terraform apply -var vpc_id=vpc-... -var 'private_subnet_ids=["subnet-a","subnet-b"]' -var owner=you
rdsops inventory --instance egdb-lab
terraform destroy
```

Then follow [docs/geodatabase-on-rds.md](docs/geodatabase-on-rds.md) to create the
geodatabase from ArcGIS Pro.

## Repository layout

```
terraform/modules/egdb-postgres   the module
terraform/examples/minimal        cheapest working stack, disposable
terraform/examples/govcloud       production-shaped, aws-us-gov partition
src/rdsops/                       CLI and checks
tests/                            unit tests (moto for AWS)
tests/integration/                tests against a real PostGIS
docs/SCOPE.md                     agreed scope, dated sources, release plan
docs/adr/                         decisions
```
