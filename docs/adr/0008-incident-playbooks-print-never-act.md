# 0008. Incident playbooks print; they never act

Status: accepted (2026-11-05)

## Context

`rdsops incident` gives the steps for a security incident on a geodatabase instance:
leaked credentials, exposed endpoints or snapshots, destroyed data, exfiltration, leaked
AWS keys, certificate failures. Most of those steps change things: rotate the master
password, revoke sessions, remove security group rules, restore to a new instance.

During an incident, the order of those changes decides what can still be learned and
recovered. A restore before an evidence snapshot can overwrite the state that shows what
happened. Ending sessions before recording them loses where an attacker connected from.

## Decision

- The command prints the playbook and runs nothing. The incident lead decides what to run
  and records it in the incident timeline.
- Every playbook preserves evidence before any step that destroys it, ends with a review,
  and turns deletion protection on first if it is off. Tests enforce these orderings.
- `--federal` puts the CISA notification step directly after triage, because federal
  Executive Branch civilian agencies notify CISA within one hour of identification.
- When the instance can be read, the playbook is filled in from it (managed secret,
  deletion protection, public access, the restore window); `--offline` plans without AWS.
- Phases follow NIST SP 800-61 Rev. 3: triage, notify, contain, preserve, eradicate,
  recover, learn.

## Consequences

- No automation that can make an incident worse at 3 a.m. The cost is that a person runs
  each command, which is also what most incident response plans require.
- The playbooks are reviewable in code and covered by tests like any other check.
