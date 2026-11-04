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

**Status:** v0.1. The Terraform module and `rdsops inventory` are done.
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
| Alarms | CPU, free storage, freeable memory, connections | the four that take a geodatabase down |
| Tags | `Owner`, `Environment`, `DataClassification` required | variable validation fails the plan without them |

GovCloud: every ARN is built from `aws_partition`, and the
[govcloud example](terraform/examples/govcloud/main.tf) turns on FIPS endpoints, Multi-AZ
and 35-day retention.

## rdsops

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
  [WARN] INV004  Backup retention 1 day(s) (baseline 7+)
               Retention also bounds how far back point-in-time restore can go.
  [ok  ] INV005  IAM database authentication available
  [info] INV006  Multi-AZ standby
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

## How it is tested

| Layer | How | Where |
| --- | --- | --- |
| AWS API calls | moto, with fake credentials forced for every test | `tests/` |
| Python | ruff and pytest on 3.11, 3.12, 3.13 | CI `python` job |
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
tests/                            moto-backed tests
docs/SCOPE.md                     agreed scope, dated sources, release plan
docs/adr/                         decisions
```
