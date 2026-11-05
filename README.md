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

**Status:** v0.8. The Terraform module and `rdsops inventory`, `health`,
`maintenance`, `compat`, `upgrade-plan`, `restore-drill`, `aurora-plan`, `fleet`,
`security`, `incident`, `resilience` and `failover-drill` are done.
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

### security

A deeper look than `inventory`: TLS required and its minimum version, password storage
(md5 or SCRAM), the certificate authority and server certificate, whether the port is
open to the internet, public or unencrypted snapshots, KMS key rotation, the managed
master secret, the audit trail (log export, pgaudit, connection logging), deletion
protection and the restore window, and with a database connection, connections without
TLS, extra `rds_superuser` members and `CREATE` on the public schema.

```
security  egdb-lab  postgres 17.7

  [FAIL] SEC001  Unencrypted connections are allowed (rds.force_ssl = 0)
               Credentials and geodatabase traffic can cross the network in clear text. Set rds.force_ssl = 1 in the custom parameter group; ArcGIS clients connect over TLS by default.
  [WARN] SEC003  2 role(s) still have md5 passwords
               sde, gis_editor. Reset them with password_encryption = scram-sha-256 (rds_tools.role_password_encryption_type() lists them), then set rds.accepted_password_auth_method = scram.
  [WARN] SEC004  Server certificate expires in 12 days
               Current CAs rotate the server certificate automatically on engine versions that support it; otherwise rotate it in a maintenance window.
  [FAIL] SEC005  Port 5432 is open to the internet
               The instance has a public address and sg-0a1b2c3d allows 0.0.0.0/0. Remove the rule and turn off public access now; treat the credentials as exposed (rdsops incident --kind exposure).
  [FAIL] SEC006  1 snapshot(s) can be restored by any AWS account
               egdb-lab-before-upgrade. Anyone can copy the whole geodatabase. Remove 'all' from the restore attribute now, then find out who set it (rdsops incident --kind exposure).
  [WARN] SEC008  Master password is not managed by Secrets Manager
               Someone knows it, and it does not rotate. Switch with --manage-master-user-password (see ADR 0005 before a blue/green upgrade).
  [WARN] SEC009  Audit trail gaps: pgaudit is not loaded
               After an incident these are what show who connected and what they ran. Without them the investigation starts blind.
  [WARN] SEC010  Deletion protection is off
               One API call with stolen credentials deletes the instance.
  [WARN] SEC011  1 role(s) besides the master user hold rds_superuser
               sde. The sde owner and ArcGIS connections do not need it after setup.
```

(Evaluated on facts for a deliberately misconfigured lab instance, `--quiet`; with
`--instance` they come from AWS and, with `--dsn`, from the database.)

It reads metadata only: `rds:Describe*`, `ec2:DescribeSecurityGroups`,
`kms:DescribeKey`, `kms:GetKeyRotationStatus` and `secretsmanager:DescribeSecret`. It
never calls `GetSecretValue`. Anything it cannot read is reported as not checked, not as
safe.

### incident

Contingency playbooks for security incidents, filled in for the instance: `credentials`,
`aws-keys`, `exposure`, `destruction`, `exfiltration` and `certificate`. Phases follow
NIST SP 800-61 Rev. 3. Evidence is preserved before anything that destroys it, deletion
protection goes on first if it is off, and `--federal` puts the CISA one-hour
notification right after triage. It prints and never runs anything
([ADR 0008](docs/adr/0008-incident-playbooks-print-never-act.md));
[docs/runbooks/security-incidents.md](docs/runbooks/security-incidents.md) explains each
playbook.

```bash
rdsops incident --kind exposure --instance nwsa-egdb --region us-gov-west-1 \
    --snapshot nwsa-egdb-before-upgrade --federal
```

```
incident  exposure: The database or a snapshot was reachable from the internet
  instance nwsa-egdb  us-gov-west-1  federal

  [info] INC005  Federal: CISA notification within one hour of identification
               The Notify step comes right after triage for that reason.

  Playbook (nothing here has been run)

  Triage
   1. Open an incident record and name one incident lead
      Start a timeline now (UTC). Every action from here on goes in it with who and when.
   2. Scope: what can this instance reach, and what can reach it
      $ aws rds describe-db-instances --region us-gov-west-1 --db-instance-identifier nwsa-egdb
      Note the endpoint, security groups, snapshots and the ArcGIS sites that connect.

  Notify
   3. Report to CISA within one hour of identification
      > https://www.cisa.gov/report
      CISA's Federal Incident Notification Guidelines: federal Executive Branch civilian agencies notify CISA within one hour of the incident being identified by the agency's top-level CSIRT, SOC or IT department. Report what is known; update later. Contractors and cloud providers report through the agency and their FedRAMP or contract terms.
   4. Tell the agency SOC and the system owner
      Follow the agency incident response plan for internal escalation and for privacy officials if personal data may be involved.

  Contain
   5. Make snapshot nwsa-egdb-before-upgrade private
      $ aws rds modify-db-snapshot-attribute --region us-gov-west-1 --db-snapshot-identifier nwsa-egdb-before-upgrade --attribute-name restore --values-to-remove all
      Every minute it is public, any AWS account can copy the whole geodatabase.
   6. Turn off public access
      $ aws rds modify-db-instance --region us-gov-west-1 --db-instance-identifier nwsa-egdb --no-publicly-accessible --apply-immediately
      ArcGIS connects from inside the VPC and does not need it.
   7. Find anything else that is open
      $ aws rds describe-db-instances --region us-gov-west-1 --db-instance-identifier nwsa-egdb --query 'DBInstances[0].[PubliclyAccessible,VpcSecurityGroups]'; aws ec2 describe-security-groups --region us-gov-west-1 --group-ids <groups>; for each manual snapshot: aws rds describe-db-snapshot-attributes --region us-gov-west-1 --db-snapshot-identifier <snapshot>
      Public address, a 0.0.0.0/0 rule on the port, or a snapshot whose restore attribute includes all. Close each one the same way.

  Preserve
   8. Snapshot the instance as it is now
      $ aws rds create-db-snapshot --region us-gov-west-1 --db-instance-identifier nwsa-egdb --db-snapshot-identifier nwsa-egdb-incident-202611051429 --tags Key=incident,Value=true
      The configuration and logs show how long it was open.
   9. Keep the database logs for the window
      $ aws rds describe-db-log-files --region us-gov-west-1 --db-instance-identifier nwsa-egdb; aws logs create-export-task --region us-gov-west-1 --log-group-name /aws/rds/instance/nwsa-egdb/postgresql --from <ms> --to <ms> --destination <evidence bucket>
      Log files on the instance rotate away. pgaudit lines show what each role ran.
  ...
```

(The first part of a real run with `--offline`; the rest covers preserving logs and the
CloudTrail record, finding who opened it, checking who connected while it was open,
rotating credentials, a guard rail, and the review.)

### resilience

Losing the instance or its zone, and losing the Region: which recovery paths exist
(Multi-AZ standby, point-in-time restore, cross-Region replica, replicated automated
backups, snapshot copies), how much data each would lose, and how long each takes,
against your targets. Data loss comes from AWS timestamps. Time comes from AWS's
Multi-AZ figure or from your own drills, never from a formula
([ADR 0009](docs/adr/0009-recovery-times-are-measured-not-guessed.md)).

```bash
rdsops resilience --instance nwsa-egdb --region us-gov-west-1 --dr-region us-gov-east-1 \
    --dr-kms-key alias/egdb-dr --production --rto-minutes 60 --rpo-minutes 15 \
    --report drills.jsonl
```

```
resilience  nwsa-egdb  us-gov-west-1  DR us-gov-east-1  targets RTO 60 min, RPO 15 min

  [ok  ] RES001  Instance or zone loss: 2 recovery path(s)
               Multi-AZ standby: data loss 0 s, back in 3 min
               Point-in-time restore in the Region: data loss 4 min, back in 46 min
  [ok  ] RES003  Instance or zone loss: best data loss 0 s via Multi-AZ standby (target 15 min)
  [ok  ] RES004  Instance or zone loss: back in 3 min via Multi-AZ standby (target 60 min)
  [ok  ] RES002  Region loss: 1 recovery path(s)
               Snapshot copy nwsa-egdb-weekly-1101 (us-gov-east-1): data loss 96.0 h, back in 46 min
  [FAIL] RES003  Region loss: best data loss 96.0 h via Snapshot copy nwsa-egdb-weekly-1101 (us-gov-east-1) (target 15 min)
               Over target. A replica or replicated backups lose minutes; copied snapshots lose everything since the copy.
  [ok  ] RES004  Region loss: back in 46 min via Snapshot copy nwsa-egdb-weekly-1101 (us-gov-east-1) (target 60 min)
  [ok  ] RES005  KMS key ready in us-gov-east-1
  [info] RES008  No event subscription covers failover
               Subscribe to the failover and availability categories so a failover at night reaches someone (aws rds create-event-subscription).
```

(Evaluated on facts for a made-up client instance whose only DR copy is a weekly snapshot,
with a measured 46-minute restore; clock fixed at 2026-11-05 12:00 UTC.)

### failover-drill

Plans a zone drill (a forced Multi-AZ failover in an announced window) or a Region drill
(a scratch restore in the DR Region; the real replica is never promoted), and scores the
recorded result: time to writable, time until ArcGIS answers, data lost.
[docs/runbooks/disaster-recovery.md](docs/runbooks/disaster-recovery.md) has the paths
and the drill record format.

```
failover-drill  region  nwsa-egdb  (plan; nothing here has been run)

  [ok  ] DRD000  Non-disruptive: restores a scratch copy in us-gov-east-1, production is untouched

  Steps
   1. Note the start time (UTC) in the drill record: this is when the Region is 'lost'.
   2. Note the newest committed change in us-gov-west-1 (it is what a real event would lose if it is not in the copy).
   3. aws rds restore-db-instance-to-point-in-time --region us-gov-east-1 --source-db-instance-automated-backups-arn <replicated backups ARN> --target-db-instance-identifier nwsa-egdb-dr-drill-202611051548 --use-latest-restorable-time --no-publicly-accessible --tags Key=rdsops-drill,Value=true
   4. aws rds wait db-instance-available --region us-gov-east-1 --db-instance-identifier nwsa-egdb-dr-drill-202611051548
   5. Record writable_at. Check PostGIS and the geodatabase: rdsops health against the copy.
   6. Register the copy as a data store on a staging ArcGIS Server in the DR Region, validate it, and open a busy service; record apps_ok_at.
   7. Compare the newest change in the copy with the one noted: data_loss_seconds.
  ...
```

(The first part of a real `--offline` run.)

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
