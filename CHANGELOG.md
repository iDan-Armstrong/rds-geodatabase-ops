# Changelog

## 0.1.0 (unreleased)

- Terraform module `egdb-postgres`: KMS encryption, TLS required, IAM auth, RDS-managed
  master secret, pgaudit and pg_stat_statements, CloudWatch alarms, required tags.
- Examples: `minimal` (lab) and `govcloud` (production-shaped, FIPS endpoints).
- `rdsops inventory`: control-plane facts and nine posture checks, text or JSON, with
  exit codes for automation.
- CI: ruff and pytest on 3.11 to 3.13; terraform fmt and validate; tflint; checkov.
- ADRs 0001 to 0004 and the agreed scope.
