# 0003. Prove it works without an AWS account

Status: accepted (2026-11-04)

## Context

Operations tooling is usually tested by running it against production and hoping. A
public repo has no AWS account behind its CI, and credentials in CI are a liability
anyway.

## Decision

- Control-plane code is tested with moto. A conftest fixture sets fake credentials for
  every test, so a missing mock fails safe instead of reaching a real account.
- Terraform is checked with fmt, validate, tflint (AWS ruleset) and checkov. No plan or
  apply in CI.
- SQL checks run against real PostgreSQL and PostGIS containers in GitHub Actions.
- Anything that can only be proven against real AWS (restore timing, blue/green
  switchover) gets an explicit live mode that the account owner runs by hand, and its
  results are recorded in the runbook, dated.

## Consequences

CI is free and runs on every push. moto does not model every RDS behavior (it attaches
default parameter groups and does not enforce engine-specific rules), so tests assert
the logic of the checks, not AWS's behavior. Where moto and AWS disagree, the test says
so in a comment.
