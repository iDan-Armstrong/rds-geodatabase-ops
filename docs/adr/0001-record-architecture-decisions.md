# 0001. Record architecture decisions

Status: accepted (2026-11-04)

## Context

Operational choices on a production database (what gets patched when, what a restore
must prove, what the baseline allows) outlive the people who made them. Without a record,
the next admin either repeats the debate or quietly undoes the decision.

## Decision

Each decision that shapes the module defaults or a check's severity gets a short ADR in
this folder: context, decision, consequences. Code that depends on one cites its number.

## Consequences

A reviewer can trace any default or finding back to a written reason, and a change of
mind means a new ADR that supersedes the old one, not a silent edit.
