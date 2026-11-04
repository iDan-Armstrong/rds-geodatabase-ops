# Scope

Agreed 2026-11-04. This file is the contract for what the repo will and will not cover.
Changes to scope get a line in the changelog and, if they change a decision, an ADR.

## Goal

Show, as running and tested code, how to stand up and operate a PostgreSQL database on
Amazon RDS that hosts an ArcGIS enterprise geodatabase: the infrastructure, the routine
checks, the restore drills and the upgrade path. The companion repo
[postgis-enterprise-patterns](https://github.com/iDan-Armstrong/postgis-enterprise-patterns)
covers database design. This one covers operations.

## Facts the design rests on

Checked 2026-11-04. Each one is re-checked before a release that depends on it.

| Fact | Source |
| --- | --- |
| ArcGIS Enterprise 12.1 and Pro 3.7 support RDS for PostgreSQL 14.20, 15.15, 16.11, 17.7 and 18.1, with the PostGIS versions AWS ships for each | [Esri: databases in the cloud](https://doc.esri.com/en/arcgis-enterprise/latest/plan/databases-in-the-cloud.html) |
| On database-as-a-service offerings only the PostGIS spatial type is available; ST_Geometry cannot be loaded | [Esri 11.5: databases in the cloud](https://enterprise.arcgis.com/en/system-requirements/11.5/linux/databases-in-the-cloud.htm) |
| PostGIS 3.5.3 and later broke correct SRID creation in enterprise geodatabases on RDS (PostGIS issue 5978); Esri's Kubernetes doc for 12.1 still lists 3.5.3 and 3.6.0 as unsupported | [Esri: cloud relational store](https://doc.esri.com/en/arcgis-enterprise-k8s/latest/deploy/considerations-for-using-a-cloud-relational-store.html) |
| ArcGIS connections to a cloud database must come from machines in the same cloud; cross-region and on-premises connections perform poorly | Esri: databases in the cloud (above) |
| Blue/green deployments minimize downtime for major upgrades, but are not available from older minors (15.3 and lower, 14.8 and lower, and so on) | [AWS: blue/green replication methods](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/blue-green-deployments-replication-type.html) |
| PostGIS major upgrades need a manual `ALTER EXTENSION ... UPDATE` after the engine upgrade | [AWS: upgrading the PostgreSQL engine](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_UpgradeDBInstance.PostgreSQL.html) |

## In scope

1. **Terraform module** `terraform/modules/egdb-postgres`: KMS encryption, TLS required,
   IAM auth, RDS-managed master secret, pgaudit and pg_stat_statements, no public
   endpoint, CloudWatch alarms, required tags. Examples for a cheap lab and for GovCloud.
2. **`rdsops` CLI** (Python, boto3, psycopg):
   - `inventory`: control-plane facts and security posture (v0.1)
   - `health`: connections, storage headroom, replication lag, top queries
   - `maintenance`: bloat, vacuum and analyze age, unused and duplicate indexes
   - `compat`: engine and PostGIS versions against a dated Esri support matrix
   - `upgrade-plan`: blue/green preflight and the runbook steps it implies
   - `drift`: live parameters against the Terraform baseline
   - `restore-drill`: snapshot or point-in-time restore to a throwaway instance, timed and verified
3. **Geodatabase checks**: sde state and lineage growth, compress and analyze cadence.
4. **Runbooks** for restore, failover, credential rotation and upgrade; ADRs; a 5-minute
   demo script.

## Out of scope

- Aurora PostgreSQL (ADR 0002).
- Creating the geodatabase itself. That is done from ArcGIS Pro or ArcGIS Server with
  Esri's tools; this repo documents the steps and checks the result.
- ArcGIS Enterprise (Portal, Server, Data Store) administration.

## Testing without an AWS bill

- AWS API calls are tested with moto. No account and no credentials in CI.
- SQL checks run against real PostgreSQL and PostGIS in Docker in GitHub Actions.
- Geodatabase checks run against a fixture schema that mimics the sde system tables,
  because CI cannot create a real geodatabase without ArcGIS. The tests say so.
- An optional live mode runs against a real account, by hand, by the account owner.

## Phases

| Release | Contents |
| --- | --- |
| v0.1 | Repo, Terraform module and examples, `inventory`, CI green |
| v0.2 | `health` and `maintenance` with PostGIS-in-Docker tests |
| v0.3 | `compat` and `upgrade-plan` |
| v0.4 | `restore-drill` (moto plus optional live mode) |
| v0.5 | Runbooks, geodatabase checks, demo script |
