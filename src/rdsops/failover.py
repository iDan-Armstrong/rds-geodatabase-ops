"""Failover drills: rehearse losing the zone or the Region, and score the rehearsal.

``plan`` is pure. It checks the drill can run (a Multi-AZ standby for a zone drill; a copy
in the DR Region for a Region drill) and returns the steps. It never runs them: a zone
drill forces a real failover with a minute or two of downtime, so a person runs it in a
window they announced (ADR 0009).

A Region drill does not promote the real cross-Region replica, because promotion is not
reversible and would leave you without DR until it is rebuilt. It restores the replicated
backups (or the newest snapshot copy) to a scratch instance in the DR Region, proves
ArcGIS can use it, times it, and deletes it. Promoting the replica is rehearsed as a
tabletop step.

``evaluate`` scores a recorded result (a JSON file a person fills in during the drill)
against the recovery targets.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from .findings import Finding, Severity
from .resilience import ResilienceSnapshot

KINDS = ("az", "region")
RECONNECT_WARN_MINUTES = 5.0


@dataclass
class FailoverRequest:
    kind: str
    instance: str
    region: str
    dr_region: str | None = None
    rto_minutes: float = 60.0
    rpo_minutes: float = 15.0
    target: str | None = None  # scratch instance for a Region drill


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class FailoverResult:
    kind: str
    started: datetime
    writable_at: datetime | None = None  # the database took writes again
    apps_ok_at: datetime | None = None  # ArcGIS services answered again
    data_loss_seconds: float | None = None  # newest committed write missing after recovery
    checks: list[Check] = field(default_factory=list)
    error: str | None = None


def _m(a: datetime | None, b: datetime | None) -> float | None:
    return None if a is None or b is None else (b - a).total_seconds() / 60


def plan(req: FailoverRequest, s: ResilienceSnapshot | None, now: datetime):
    if req.kind not in KINDS:
        raise ValueError(f"unknown drill kind {req.kind!r}; one of {', '.join(KINDS)}")
    r = f"--region {req.region}"
    findings: list[Finding] = []
    steps: list[str] = []
    stamp = now.strftime("%Y%m%d%H%M")

    if req.kind == "az":
        if s is not None and not s.facts.multi_az:
            findings.append(
                Finding(
                    "DRD000",
                    Severity.FAIL,
                    f"{req.instance} is Single-AZ: there is no standby to fail over to",
                    "Turn on Multi-AZ first (aws rds modify-db-instance --multi-az). Until then a "
                    "zone loss means a point-in-time restore: rehearse that with rdsops "
                    "restore-drill.",
                )
            )
            return findings, steps
        findings.append(
            Finding(
                "DRD000",
                Severity.WARN,
                "This drill causes a real outage of a minute or two",
                "Run it in an announced window. AWS documents Multi-AZ failover as typically "
                "60 to 120 seconds; connections drop and clients must reconnect.",
            )
        )
        steps += [
            "Announce the window to ArcGIS users; note the time (UTC) in the drill record.",
            "Record the newest committed change: SELECT now(), pg_current_wal_lsn(); and the "
            "newest edit in a busy versioned table.",
            f"aws rds reboot-db-instance {r} --db-instance-identifier {req.instance} "
            "--force-failover",
            f"aws rds wait db-instance-available {r} --db-instance-identifier {req.instance}",
            "Record when the database takes writes again (writable_at): connect and insert into "
            "a scratch table.",
            "egisops datastore --url <server> and egisops server-health --url <server>; record "
            "when services answer (apps_ok_at). Slow reconnects point at DNS caching: AWS "
            "advises a JVM DNS TTL of 60 seconds or less.",
            f"aws rds describe-events {r} --source-type db-instance --source-identifier "
            f"{req.instance} --duration 60  (expect the failover events)",
            "Confirm the newest change recorded before the failover is there (data_loss_seconds "
            "should be 0 for a synchronous standby).",
            f"rdsops failover-drill --kind az --instance {req.instance} {r} --result drill.json "
            "--report drills.jsonl",
        ]
        return findings, steps

    # region
    dr = req.dr_region or (s.dr_region if s else None)
    if not dr:
        findings.append(Finding("DRD000", Severity.FAIL, "No DR Region given", "Pass --dr-region."))
        return findings, steps
    target = req.target or f"{req.instance[:40]}-dr-drill-{stamp}"
    source = None
    if s is not None:
        if s.backup_replications:
            source = (
                f"aws rds restore-db-instance-to-point-in-time --region {dr} "
                f"--source-db-instance-automated-backups-arn {s.backup_replications[0].arn} "
                f"--target-db-instance-identifier {target} --use-latest-restorable-time "
                "--no-publicly-accessible --tags Key=rdsops-drill,Value=true"
            )
        elif s.snapshot_copies:
            newest = max(s.snapshot_copies, key=lambda c: c.created)
            source = (
                f"aws rds restore-db-instance-from-db-snapshot --region {dr} "
                f"--db-snapshot-identifier {newest.identifier} --db-instance-identifier {target} "
                "--no-publicly-accessible --tags Key=rdsops-drill,Value=true"
            )
            findings.append(
                Finding(
                    "DRD000",
                    Severity.INFO,
                    f"Drilling from snapshot copy {newest.identifier}",
                    "Data loss in a real event would be everything since that copy.",
                )
            )
        elif s.replicas:
            findings.append(
                Finding(
                    "DRD000",
                    Severity.WARN,
                    "Only a cross-Region replica: nothing to restore from without promoting it",
                    "Do not promote the real replica in a drill; it cannot go back. Turn on "
                    "backup replication to the same Region so the drill has something to restore.",
                )
            )
            return findings, steps
        else:
            findings.append(
                Finding(
                    "DRD000",
                    Severity.FAIL,
                    f"Nothing in {dr} to recover from",
                    "Turn on cross-Region automated backup replication first: "
                    f"aws rds start-db-instance-automated-backups-replication --region {dr} "
                    f"--source-db-instance-arn <arn of {req.instance}> --source-region "
                    f"{req.region} --kms-key-id <key in {dr}>",
                )
            )
            return findings, steps
    source = source or (
        f"aws rds restore-db-instance-to-point-in-time --region {dr} "
        f"--source-db-instance-automated-backups-arn <replicated backups ARN> "
        f"--target-db-instance-identifier {target} --use-latest-restorable-time "
        "--no-publicly-accessible --tags Key=rdsops-drill,Value=true"
    )
    findings.append(
        Finding(
            "DRD000",
            Severity.OK,
            f"Non-disruptive: restores a scratch copy in {dr}, production is untouched",
        )
    )
    steps += [
        "Note the start time (UTC) in the drill record: this is when the Region is 'lost'.",
        f"Note the newest committed change in {req.region} (it is what a real event would "
        "lose if it is not in the copy).",
        source,
        f"aws rds wait db-instance-available --region {dr} --db-instance-identifier {target}",
        "Record writable_at. Check PostGIS and the geodatabase: rdsops health against the copy.",
        "Register the copy as a data store on a staging ArcGIS Server in the DR Region, "
        "validate it, and open a busy service; record apps_ok_at.",
        "Compare the newest change in the copy with the one noted: data_loss_seconds.",
        "Tabletop: who promotes the cross-Region replica (if any), who changes DNS or the .sde "
        "files, who tells the users. Promotion is not reversible.",
        f"aws rds delete-db-instance --region {dr} --db-instance-identifier {target} "
        "--skip-final-snapshot  (only the instance tagged rdsops-drill)",
        f"rdsops failover-drill --kind region --instance {req.instance} --region {req.region} "
        f"--dr-region {dr} --result drill.json --report drills.jsonl",
    ]
    return findings, steps


def evaluate(r: FailoverResult, req: FailoverRequest) -> list[Finding]:
    out: list[Finding] = []
    if r.error or r.writable_at is None:
        out.append(
            Finding(
                "DRD005",
                Severity.FAIL,
                "The drill did not reach a writable database",
                r.error or "No writable_at recorded.",
                {"kind": r.kind},
            )
        )
        return out
    end = r.apps_ok_at or r.writable_at
    rto = _m(r.started, end)
    ok = rto <= req.rto_minutes
    out.append(
        Finding(
            "DRD001",
            Severity.OK if ok else Severity.FAIL,
            f"{'Zone' if r.kind == 'az' else 'Region'} recovery took {rto:.1f} min "
            f"(target {req.rto_minutes:g})",
            ""
            if ok
            else (
                "Over target. For a zone: check DNS caching in ArcGIS Server's JVM. For a "
                "Region: a replica ready to promote is faster than restoring backups."
            ),
            {"kind": r.kind, "rto_minutes": round(rto, 1)},
        )
    )
    if r.data_loss_seconds is not None:
        mins = r.data_loss_seconds / 60
        ok = mins <= req.rpo_minutes
        sev = Severity.OK if ok else Severity.FAIL
        if r.kind == "az" and r.data_loss_seconds > 0:
            sev = Severity.FAIL
        out.append(
            Finding(
                "DRD002",
                sev,
                f"Data lost: {r.data_loss_seconds:.0f} s (target {req.rpo_minutes:g} min)",
                "A Multi-AZ standby is synchronous; any loss there needs explaining."
                if r.kind == "az" and r.data_loss_seconds > 0
                else ""
                if ok
                else "Over target: replicate more often or keep a replica.",
                {"kind": r.kind, "data_loss_seconds": r.data_loss_seconds},
            )
        )
    else:
        out.append(
            Finding("DRD002", Severity.INFO, "Data loss not recorded", "Record data_loss_seconds.")
        )
    if r.apps_ok_at:
        gap = _m(r.writable_at, r.apps_ok_at)
        if gap > RECONNECT_WARN_MINUTES:
            out.append(
                Finding(
                    "DRD003",
                    Severity.WARN,
                    f"ArcGIS took {gap:.0f} min longer than the database",
                    "Clients held on to the old address or old connections. Lower the JVM DNS "
                    "TTL (AWS advises 60 seconds or less), and restart or recycle services in "
                    "the runbook, not by surprise.",
                    {"kind": r.kind, "reconnect_minutes": round(gap, 1)},
                )
            )
        else:
            out.append(
                Finding("DRD003", Severity.OK, f"ArcGIS back {gap:.0f} min after the database")
            )
    else:
        out.append(
            Finding(
                "DRD003",
                Severity.WARN,
                "ArcGIS was not checked",
                "A database that is back is not a service that is back. Record apps_ok_at.",
            )
        )
    for c in r.checks:
        out.append(
            Finding("DRD004", Severity.OK if c.ok else Severity.FAIL, f"Verify: {c.name}", c.detail)
        )
    return out


def result_from_dict(d: dict) -> FailoverResult:
    def t(k):
        v = d.get(k)
        return datetime.fromisoformat(v.replace("Z", "+00:00")) if v else None

    return FailoverResult(
        kind=d["kind"],
        started=t("started"),
        writable_at=t("writable_at"),
        apps_ok_at=t("apps_ok_at"),
        data_loss_seconds=d.get("data_loss_seconds"),
        checks=[Check(**c) for c in d.get("checks", [])],
        error=d.get("error"),
    )
