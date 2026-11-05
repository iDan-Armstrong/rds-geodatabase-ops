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

**Status:** v0.6. The Terraform module and `rdsops inventory`, `health`,
`maintenance`, `compat`, `upgrade-plan`, `restore-drill`, `aurora-plan` and `fleet` are
done.
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

  [ok  ] DRL010  Restore completed in 16.0 min
  [ok  ] DRL011  Time to a usable copy: 20.0 min (target 60)
  [ok  ] DRL012  Restore point 5 min before the drill started (target 15)
  [ok  ] DRL013  Verify: connect
  [ok  ] DRL013  Verify: PostGIS present
               PostGIS 3.5.2
  [ok  ] DRL013  Verify: gis.parcels rows
               210,000 rows
  [ok  ] DRL014  Copy egdb-lab-drill-202611041800 deleted
```

(Output from a drill against mocked RDS with a stepped clock and stub verification checks, so the
minutes are illustrative. Real timings depend on database size and instance class.)

The copy is private, single-AZ and has deletion protection turned off. Without that,
RDS copies deletion protection from the source and the cleanup fails. Cleanup deletes
only an instance tagged `rdsops-drill=true` that is not the source. See
[docs/runbooks/restore-drill.md](docs/runbooks/restore-drill.md).

### aurora-plan

Plans the move from this RDS instance to Aurora PostgreSQL, for when a team or a client
wants Aurora. It picks the target version (the lowest the Region offers that AWS allows
for the source and Esri supports for the ArcGIS release), checks the read replica or
snapshot method's preconditions, encryption and room for WAL, and prints the runbook
with the ArcGIS cutover. It reads only; it never creates a cluster.
[ADR 0007](docs/adr/0007-aurora-as-a-migration-target.md) explains how this fits with
ADR 0002, and [docs/runbooks/aurora-migration.md](docs/runbooks/aurora-migration.md) the
choices behind each step.

GovCloud works as is: the partition comes from the Region, so ARNs read
`arn:aws-us-gov:...`, and the Aurora versions are read from the Region, because GovCloud
can lag commercial Regions. An unencrypted source is a failure there.

```bash
rdsops aurora-plan --instance egdb-client --region us-gov-west-1 --arcgis 12.1
```

```
aurora-plan  egdb-client (RDS for PostgreSQL 17.5, us-gov-west-1, partition aws-us-gov)  replica method  for ArcGIS 12.1

  [info] AUR001  Target Aurora PostgreSQL 17.6
               Aurora versions in the Region were not read.
  [ok  ] CMP001  Aurora PostgreSQL 17 is supported by ArcGIS Enterprise 12.1 / Pro 3.7
  [ok  ] CMP002  Aurora 17.6 is the certified minor
  [ok  ] CMP003  PostGIS 3.5.2 is not on the blocked list
  [ok  ] CMP004  Support data for 12.1 checked 2026-11-04 (0 days ago)
  [ok  ] AUR002  Aurora read replica method is available
               Little downtime: the replica catches up while ArcGIS keeps working, and writes stop only for the promotion.
  [ok  ] AUR003  Source is encrypted; the cluster will be too
               AWS does not allow an unencrypted cluster from an encrypted source, so --storage-encrypted is required on create-db-cluster.
  [info] AUR004  No Multi-AZ during the migration
               AWS: Multi-AZ is not available during the migration. After promotion, add an Aurora reader in a second Availability Zone for failover.
  [info] AUR006  ArcGIS must be pointed at the cluster
               Registered data stores and .sde connection files name the RDS endpoint. After promotion, update each to the cluster writer endpoint, validate them, then check PostGIS on the cluster.

  Runbook
   1. Take a WebGISDR backup of ArcGIS Enterprise and a manual snapshot of egdb-client: aws rds create-db-snapshot --region us-gov-west-1 --db-instance-identifier egdb-client --db-snapshot-identifier egdb-client-pre-aurora
   2. aws rds create-db-cluster --region us-gov-west-1 --db-cluster-identifier egdb-client-aurora --engine aurora-postgresql --engine-version 17.6 --replication-source-identifier arn:aws-us-gov:rds:us-gov-west-1:<account-id>:db:egdb-client --storage-encrypted
   3. aws rds create-db-instance --region us-gov-west-1 --db-cluster-identifier egdb-client-aurora --db-instance-identifier egdb-client-aurora-1 --db-instance-class db.r6g.large --engine aurora-postgresql
   4. Watch RDSToAuroraPostgreSQLReplicaLag on the cluster, and FreeStorageSpace and OldestReplicationSlotLag on the source, until the replica is caught up
   5. Stop writes: stop ArcGIS services and edit sessions that write to the geodatabase. Check SELECT pg_current_wal_lsn() on the source is behind SELECT pg_last_wal_replay_lsn() on the cluster, and replica lag is 0
   6. aws rds promote-read-replica-db-cluster --region us-gov-west-1 --db-cluster-identifier egdb-client-aurora
   7. aws rds create-db-instance --region us-gov-west-1 --db-cluster-identifier egdb-client-aurora --db-instance-identifier egdb-client-aurora-2 --db-instance-class db.r6g.large --engine aurora-postgresql --availability-zone <a second AZ>  (reader for failover)
   8. Point ArcGIS at the cluster writer endpoint: update each registered data store (Server Manager > Site > Data Stores, or POST admin/data/items/<item>/edit) and the .sde connection files, then validate the data stores
   9. On the cluster: SELECT postgis_full_version(); then rdsops compat --platform aurora --engine-version 17.6 --postgis <version> --arcgis 12.1
  10. Start ArcGIS services and test editing. Keep the source instance stopped, not deleted, until the cluster has run cleanly for an agreed period (RDS starts a stopped instance again after seven days); delete it with a final snapshot
```

(Offline planning: `--engine-version 17.5 --region us-gov-west-1 --encrypted yes`, so the
Region's Aurora versions were not read and the account is a placeholder. With `--instance`
both come from AWS.)

`rdsops compat --platform aurora` checks an Aurora version against Esri's Aurora list,
which is not the RDS list: for 12.1 it stops at Aurora 17.6, with no 18.

### fleet

One view of every geodatabase instance across Regions and accounts. Each instance gets
the same posture check as `inventory` and the same Esri check as `compat`, against the
release in its `arcgis-release` tag; an `environment=prod` tag makes availability gaps
failures. Then what only shows across many: minor-version drift, mixed ArcGIS releases,
and instances nobody tagged. GovCloud is another Region with its own profile.

```bash
rdsops fleet --region us-east-1 --region us-gov-west-1@gov --tag geodatabase=true --arcgis 12.1
```

```
fleet  us-east-1, us-gov-west-1  tag geodatabase=true  default ArcGIS 12.1

  [ok  ] FLT000  4 instance(s) in 2 Region(s): 0 clean, 1 with warnings, 3 failing
  [WARN] FLT001  us-east-1/egdb-lab PostgreSQL 17.7: 0 FAIL, 1 WARN
               INV009 Using a default parameter group
  [FAIL] FLT001  us-east-1/parks-egdb PostgreSQL 17.5: 2 FAIL, 2 WARN
               INV002 Instance is publicly accessible; CMP002 RDS 17.5 is below the certified minimum 17.7; INV004 Backup retention 1 day(s), below the 7-day baseline; INV009 Using a default parameter group
  [FAIL] FLT001  us-gov-west-1/nwsa-egdb PostgreSQL 16.8: 1 FAIL, 1 WARN
               INV006 Single-AZ: no standby; INV009 Using a default parameter group
  [FAIL] FLT001  us-gov-west-1/nwsa-egdb-test PostgreSQL 16.6: 1 FAIL, 1 WARN
               CMP002 RDS 16.6 is below the certified minimum 16.11; INV009 Using a default parameter group
  [info] FLT002  PostgreSQL 16 runs on 2 minors: 16.6, 16.8
               Patch to one certified minor so a fix tested on one instance holds on all.
  [info] FLT002  PostgreSQL 17 runs on 2 minors: 17.5, 17.7
               Patch to one certified minor so a fix tested on one instance holds on all.
  [info] FLT002  Instances serve 2 ArcGIS releases: 11.5, 12.1
               Each is checked against its own release.
  [info] FLT003  1 instance(s) without an arcgis-release tag
               Checked against --arcgis 12.1. us-gov-west-1/nwsa-egdb-test
```

(Four instances created in mocked AWS across us-east-1 and us-gov-west-1.)

It needs `rds:DescribeDBInstances` in each account, nothing else. A Region it cannot
read is reported and the rest still runs.

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
