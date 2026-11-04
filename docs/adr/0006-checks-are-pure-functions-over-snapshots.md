# 0006. Checks are pure functions over snapshots

Status: accepted (2026-11-04)

## Context

Every check needs data from somewhere: the RDS API, CloudWatch, or the database catalogs.
If the code that fetches data and the code that judges it are mixed, the judging can
only be tested against a live system, and it can only run where boto3, psycopg and
credentials exist.

## Decision

Each check is split in two:

- `gather` (or `context_from_*`) reads the real system into a plain snapshot. It takes
  its client or connection as an argument.
- `evaluate` (or `check`, `plan`) takes a snapshot and returns `Finding` objects. It
  imports only the standard library and other pure modules.

Finding codes are stable identifiers. The fix for each finding is in its detail text.
`tests/test_portable.py` imports every check module with boto3, botocore and psycopg
blocked, and fails if any of them is needed.

## Consequences

- Every threshold is unit-tested with hand-built snapshots; no server needed.
- The same evaluators run anywhere Python runs, including a browser through Pyodide.
  That is how a training simulator can feed simulated snapshots through the real rules
  and teach the real finding codes and fixes.
- New checks must follow the split. A check that cannot be expressed this way needs its
  own ADR.
