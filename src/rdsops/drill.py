"""Restore drills: prove a restore works, and how long it takes, before you need one.

A drill restores the instance to a new, throwaway copy (point in time or from a
snapshot), waits for it, optionally connects and verifies the data, records the timings,
and deletes the copy. Nothing touches the source instance.

Split per ADR 0006:

- ``plan`` and ``evaluate`` are pure: facts and timings in, findings out.
- ``gather_backup_facts`` reads the RDS API; ``run`` does the restore and cleanup.
  Both take their client as an argument and are never imported by the pure path.

The CLI only runs a drill with ``--execute``; without it, it prints the plan.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta

from .findings import Finding, Severity

DRILL_TAG = "rdsops-drill"


@dataclass
class DrillRequest:
    source: str
    mode: str = "pitr"  # pitr | snapshot
    restore_time: datetime | None = None  # pitr only; None = latest restorable
    snapshot_id: str | None = None  # snapshot only; None = newest available
    target_id: str | None = None
    instance_class: str | None = None  # None = same as source
    rto_minutes: float = 60.0
    rpo_minutes: float = 15.0
    verify_tables: list[str] = field(default_factory=list)
    keep: bool = False


@dataclass
class Snapshot:
    identifier: str
    created: datetime
    kind: str  # automated | manual


@dataclass
class BackupFacts:
    source: str
    engine_version: str
    instance_class: str
    retention_days: int
    latest_restorable: datetime | None
    earliest_restorable: datetime | None
    snapshots: list[Snapshot]
    subnet_group: str | None
    security_groups: list[str]
    parameter_group: str | None
    iam_auth: bool
    deletion_protection: bool


@dataclass
class VerifyCheck:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class DrillResult:
    target_id: str
    restore_point: datetime | None
    started: datetime
    restore_requested: datetime | None = None
    available: datetime | None = None
    verified: datetime | None = None
    deleted: datetime | None = None
    checks: list[VerifyCheck] = field(default_factory=list)
    error: str | None = None
    kept: bool = False

    def to_dict(self) -> dict:
        d = asdict(self)
        for k, v in d.items():
            if isinstance(v, datetime):
                d[k] = v.isoformat()
        return d


def _minutes(a: datetime | None, b: datetime | None) -> float | None:
    return None if a is None or b is None else (b - a).total_seconds() / 60


def default_target(source: str, now: datetime) -> str:
    # RDS identifiers: max 63 chars, letters, digits, hyphens
    return f"{source[:40]}-drill-{now:%Y%m%d%H%M}"


def choose_snapshot(req: DrillRequest, facts: BackupFacts) -> Snapshot | None:
    if req.snapshot_id:
        return next((s for s in facts.snapshots if s.identifier == req.snapshot_id), None)
    return max(facts.snapshots, key=lambda s: s.created, default=None)


# ------------------------------------------------------------------ pure: plan


def plan(req: DrillRequest, facts: BackupFacts, now: datetime) -> tuple[list[Finding], list[str]]:
    out: list[Finding] = []
    target = req.target_id or default_target(req.source, now)
    restore_point: datetime | None = None

    if req.mode == "pitr":
        if facts.retention_days < 1:
            out.append(
                Finding(
                    "DRL001",
                    Severity.FAIL,
                    "Automated backups are off",
                    "Point-in-time restore needs backup retention of at least 1 day. Set the "
                    "module's backup_retention_days (baseline 7).",
                )
            )
        else:
            out.append(
                Finding(
                    "DRL001", Severity.OK, f"Automated backups on ({facts.retention_days} days)"
                )
            )
        latest = facts.latest_restorable
        earliest = facts.earliest_restorable or (
            now - timedelta(days=facts.retention_days) if facts.retention_days else None
        )
        restore_point = req.restore_time or latest
        if req.restore_time and latest and earliest:
            inside = earliest <= req.restore_time <= latest
            out.append(
                Finding(
                    "DRL002",
                    Severity.OK if inside else Severity.FAIL,
                    f"Restore point {req.restore_time:%Y-%m-%d %H:%M} UTC "
                    + ("is inside" if inside else "is outside")
                    + f" the window {earliest:%Y-%m-%d %H:%M} to {latest:%Y-%m-%d %H:%M}",
                    "" if inside else "Choose a time inside the restore window, or a snapshot.",
                )
            )
        elif latest is None and facts.retention_days:
            out.append(
                Finding(
                    "DRL002",
                    Severity.WARN,
                    "Latest restorable time is unknown",
                    "describe-db-instances did not report LatestRestorableTime.",
                )
            )
    else:
        snap = choose_snapshot(req, facts)
        if snap is None:
            out.append(
                Finding(
                    "DRL001",
                    Severity.FAIL,
                    f"Snapshot {req.snapshot_id} not found"
                    if req.snapshot_id
                    else "No snapshots exist for this instance",
                    "Create one: aws rds create-db-snapshot --db-instance-identifier "
                    f"{req.source} --db-snapshot-identifier {req.source}-manual",
                )
            )
        else:
            restore_point = snap.created
            out.append(
                Finding(
                    "DRL001",
                    Severity.OK,
                    f"Snapshot {snap.identifier} ({snap.kind}, {snap.created:%Y-%m-%d %H:%M} UTC)",
                )
            )

    if restore_point:
        rpo = max(0.0, (now - restore_point).total_seconds() / 60)  # clock skew is not data
        sev = Severity.OK if rpo <= req.rpo_minutes else Severity.WARN
        out.append(
            Finding(
                "DRL003",
                sev,
                f"Data loss if this were real: about {rpo:.0f} min (target {req.rpo_minutes:.0f})",
                ""
                if sev == Severity.OK
                else "Everything written after the restore point would be lost. Point-in-time "
                "restore to the latest time keeps this to a few minutes; snapshots are older.",
                {"rpo_minutes": round(rpo, 1)},
            )
        )

    out.append(
        Finding(
            "DRL004",
            Severity.INFO,
            f"The copy {target} is private, single-AZ and deletable",
            "A drill copy gets no public endpoint, no standby and no deletion protection, so it "
            "is cheap and the cleanup cannot be blocked. RDS would otherwise copy deletion "
            "protection from the source.",
            {"target_id": target, "instance_class": req.instance_class or facts.instance_class},
        )
    )

    if req.mode == "pitr":
        when = (
            f"--restore-time {req.restore_time:%Y-%m-%dT%H:%M:%SZ}"
            if req.restore_time
            else "--use-latest-restorable-time"
        )
        restore_cmd = (
            f"aws rds restore-db-instance-to-point-in-time --source-db-instance-identifier "
            f"{req.source} --target-db-instance-identifier {target} {when}"
        )
    else:
        snap = choose_snapshot(req, facts)
        restore_cmd = (
            f"aws rds restore-db-instance-from-db-snapshot --db-instance-identifier "
            f"{target} --db-snapshot-identifier {snap.identifier if snap else '<id>'}"
        )
    steps = [
        f"{restore_cmd} --no-publicly-accessible --no-multi-az --no-deletion-protection "
        "--tags Key=rdsops-drill,Value=true",
        f"aws rds wait db-instance-available --db-instance-identifier {target}  (timed)",
        "Connect to the copy and verify: PostGIS present, geodatabase tables present"
        + (f", row counts for {', '.join(req.verify_tables)}" if req.verify_tables else ""),
        "Record restore and verify times against the RTO target",
        f"aws rds delete-db-instance --db-instance-identifier {target} --skip-final-snapshot "
        "--delete-automated-backups" + ("  (skipped: --keep)" if req.keep else ""),
    ]
    return out, steps


# -------------------------------------------------------------- pure: evaluate


def evaluate(result: DrillResult, req: DrillRequest) -> list[Finding]:
    out: list[Finding] = []
    if result.error or result.available is None:
        out.append(
            Finding(
                "DRL010",
                Severity.FAIL,
                "Restore did not complete",
                result.error or "The copy never became available.",
            )
        )
    else:
        mins = _minutes(result.restore_requested or result.started, result.available)
        out.append(
            Finding(
                "DRL010",
                Severity.OK,
                f"Restore completed in {mins:.1f} min",
                evidence={"restore_minutes": round(mins, 1)},
            )
        )

    end = result.verified or result.available
    rto = _minutes(result.started, end)
    if rto is not None:
        sev = Severity.OK if rto <= req.rto_minutes else Severity.FAIL
        out.append(
            Finding(
                "DRL011",
                sev,
                f"Time to a usable copy: {rto:.1f} min (target {req.rto_minutes:.0f})",
                ""
                if sev == Severity.OK
                else "Over target. Options: a Multi-AZ standby for zone failures, a bigger restore "
                "class, a smaller database (archive cold data), or a realistic target.",
                {"rto_minutes": round(rto, 1)},
            )
        )

    if result.restore_point:
        rpo = max(0.0, (result.started - result.restore_point).total_seconds() / 60)
        sev = Severity.OK if rpo <= req.rpo_minutes else Severity.WARN
        out.append(
            Finding(
                "DRL012",
                sev,
                f"Restore point {rpo:.0f} min before the drill started "
                f"(target {req.rpo_minutes:.0f})",
                evidence={"rpo_minutes": round(rpo, 1)},
            )
        )

    if result.checks:
        for c in result.checks:
            out.append(
                Finding(
                    "DRL013", Severity.OK if c.ok else Severity.FAIL, f"Verify: {c.name}", c.detail
                )
            )
    elif result.available:
        out.append(
            Finding(
                "DRL013",
                Severity.WARN,
                "Copy was not verified",
                "A restore that nobody connected to is only half a drill. Pass "
                "connection options (for example --user and --iam).",
            )
        )

    if result.kept:
        out.append(
            Finding(
                "DRL014",
                Severity.WARN,
                f"Copy {result.target_id} was kept",
                "It is running and billing. Delete it when you are done: "
                f"aws rds delete-db-instance --db-instance-identifier "
                f"{result.target_id} --skip-final-snapshot",
            )
        )
    elif result.deleted:
        out.append(Finding("DRL014", Severity.OK, f"Copy {result.target_id} deleted"))
    elif result.available or result.restore_requested:
        out.append(
            Finding(
                "DRL014",
                Severity.FAIL,
                f"Copy {result.target_id} was not deleted",
                "Delete it by hand; it is billing.",
            )
        )
    return out


# ---------------------------------------------------------- gather and execute


def gather_backup_facts(rds, source: str) -> BackupFacts:
    db = rds.describe_db_instances(DBInstanceIdentifier=source)["DBInstances"][0]
    earliest = None
    try:
        for b in rds.describe_db_instance_automated_backups(DBInstanceIdentifier=source).get(
            "DBInstanceAutomatedBackups", []
        ):
            window = b.get("RestoreWindow") or {}
            if window.get("EarliestTime"):
                earliest = window["EarliestTime"]
    except Exception:  # noqa: BLE001 - optional detail; the plan falls back to retention
        earliest = None
    snaps = [
        Snapshot(
            s["DBSnapshotIdentifier"], s["SnapshotCreateTime"], s.get("SnapshotType", "manual")
        )
        for s in rds.describe_db_snapshots(DBInstanceIdentifier=source).get("DBSnapshots", [])
        if s.get("Status", "available") == "available" and s.get("SnapshotCreateTime")
    ]
    groups = [g["DBParameterGroupName"] for g in db.get("DBParameterGroups", [])]
    return BackupFacts(
        source=source,
        engine_version=db["EngineVersion"],
        instance_class=db["DBInstanceClass"],
        retention_days=int(db.get("BackupRetentionPeriod", 0)),
        latest_restorable=db.get("LatestRestorableTime"),
        earliest_restorable=earliest,
        snapshots=snaps,
        subnet_group=(db.get("DBSubnetGroup") or {}).get("DBSubnetGroupName"),
        security_groups=[g["VpcSecurityGroupId"] for g in db.get("VpcSecurityGroups", [])],
        parameter_group=groups[0] if groups and not groups[0].startswith("default.") else None,
        iam_auth=bool(db.get("IAMDatabaseAuthenticationEnabled")),
        deletion_protection=bool(db.get("DeletionProtection")),
    )


def run(
    rds,
    req: DrillRequest,
    facts: BackupFacts,
    *,
    now,
    verifier=None,
    log=print,
    wait_delay: int = 30,
    wait_attempts: int = 240,
) -> DrillResult:
    """Restore, wait, verify, clean up. ``now`` is a clock function; ``verifier`` takes
    the restored endpoint and returns VerifyChecks."""
    started = now()
    target = req.target_id or default_target(req.source, started)
    result = DrillResult(target_id=target, restore_point=None, started=started)
    common = dict(
        DBInstanceClass=req.instance_class or facts.instance_class,
        PubliclyAccessible=False,
        MultiAZ=False,
        DeletionProtection=False,
        EnableIAMDatabaseAuthentication=facts.iam_auth,
        Tags=[
            {"Key": DRILL_TAG, "Value": "true"},
            {"Key": f"{DRILL_TAG}-source", "Value": req.source},
        ],
    )
    if facts.subnet_group:
        common["DBSubnetGroupName"] = facts.subnet_group
    if facts.security_groups:
        common["VpcSecurityGroupIds"] = facts.security_groups
    if facts.parameter_group:
        common["DBParameterGroupName"] = facts.parameter_group
    try:
        if req.mode == "pitr":
            kw = (
                {"RestoreTime": req.restore_time}
                if req.restore_time
                else {"UseLatestRestorableTime": True}
            )
            result.restore_point = req.restore_time or facts.latest_restorable or started
            log(f"Restoring {req.source} to point in time as {target}")
            rds.restore_db_instance_to_point_in_time(
                SourceDBInstanceIdentifier=req.source,
                TargetDBInstanceIdentifier=target,
                **kw,
                **common,
            )
        else:
            snap = choose_snapshot(req, facts)
            if snap is None:
                raise RuntimeError("no snapshot to restore from")
            result.restore_point = snap.created
            log(f"Restoring snapshot {snap.identifier} as {target}")
            rds.restore_db_instance_from_db_snapshot(
                DBInstanceIdentifier=target, DBSnapshotIdentifier=snap.identifier, **common
            )
        result.restore_requested = now()
        log("Waiting for the copy to become available (this is the part you are timing)")
        rds.get_waiter("db_instance_available").wait(
            DBInstanceIdentifier=target,
            WaiterConfig={"Delay": wait_delay, "MaxAttempts": wait_attempts},
        )
        result.available = now()
        if verifier:
            ep = rds.describe_db_instances(DBInstanceIdentifier=target)["DBInstances"][0]
            host = (ep.get("Endpoint") or {}).get("Address")
            log(f"Verifying {host}")
            result.checks = verifier(host)
            result.verified = now()
    except Exception as e:  # noqa: BLE001 - every failure is reported and cleanup still runs
        result.error = f"{type(e).__name__}: {e}"
        log(f"Drill error: {result.error}")
    finally:
        if req.keep:
            result.kept = True
        elif result.restore_requested:
            try:
                _delete_copy(rds, target, req.source)
                result.deleted = now()
                log(f"Deleted {target}")
            except Exception as e:  # noqa: BLE001
                log(f"Could not delete {target}: {e}")
    return result


def _delete_copy(rds, target: str, source: str) -> None:
    """Delete the drill copy, and only the drill copy."""
    if target == source:
        raise RuntimeError("refusing to delete the source instance")
    db = rds.describe_db_instances(DBInstanceIdentifier=target)["DBInstances"][0]
    tags = {t["Key"]: t["Value"] for t in db.get("TagList", [])}
    if tags.get(DRILL_TAG) != "true":
        raise RuntimeError(f"{target} is not tagged {DRILL_TAG}=true; not deleting it")
    if db.get("DeletionProtection"):
        # The restore asks for no deletion protection; this covers any path that copied it.
        rds.modify_db_instance(
            DBInstanceIdentifier=target, DeletionProtection=False, ApplyImmediately=True
        )
    rds.delete_db_instance(
        DBInstanceIdentifier=target, SkipFinalSnapshot=True, DeleteAutomatedBackups=True
    )


def verify_restored(conn, tables: list[str]) -> list[VerifyCheck]:
    """SQL checks against the restored copy. Read-only."""
    checks = [
        VerifyCheck("connect", True, conn.execute("SELECT version() AS v").fetchone()["v"][:60])
    ]
    row = conn.execute("SELECT extversion FROM pg_extension WHERE extname = 'postgis'").fetchone()
    checks.append(
        VerifyCheck(
            "PostGIS present",
            bool(row),
            f"PostGIS {row['extversion']}" if row else "extension missing",
        )
    )
    gdb = conn.execute(
        "SELECT 1 FROM pg_tables WHERE schemaname = 'sde' AND tablename = 'sde_version'"
    ).fetchone()
    checks.append(
        VerifyCheck(
            "geodatabase present",
            True,
            "sde.sde_version found" if gdb else "no sde schema (plain PostGIS)",
        )
    )
    for t in tables:
        schema, _, name = t.partition(".")
        exists = conn.execute(
            "SELECT 1 FROM pg_tables WHERE schemaname = %s AND tablename = %s", (schema, name)
        ).fetchone()
        if not exists:
            checks.append(VerifyCheck(f"{t} rows", False, "table not found in the copy"))
            continue
        n = conn.execute(f'SELECT count(*) AS n FROM "{schema}"."{name}"').fetchone()["n"]
        checks.append(VerifyCheck(f"{t} rows", n > 0, f"{n:,} rows"))
    return checks
