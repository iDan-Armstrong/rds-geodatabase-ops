"""Resilience: can this geodatabase survive losing its instance, its zone, or its Region,
within the recovery time and data loss the business agreed to?

Two scenarios are scored:

- **Instance or zone loss.** A Multi-AZ standby is replicated synchronously and takes over
  on its own; AWS documents failover as typically 60 to 120 seconds. Without one, the way
  back is a point-in-time restore from automated backups.
- **Region loss.** Three ways to have a copy in another Region: a cross-Region read
  replica (promoted; not reversible), cross-Region automated backup replication (restore
  to a point in time there), or manual snapshots copied there.

The recovery point of each path comes from timestamps AWS reports (latest restorable
time, replica lag, snapshot age). Recovery time comes only from AWS's documented
Multi-AZ figure or from your own measured drills (``rdsops restore-drill --report`` and
``rdsops failover-drill --result``; a Region drill restores from the replicated backups
or a copy, so its time applies to those paths). Where neither exists it is reported as
unknown, never guessed. Sources are in docs/runbooks/disaster-recovery.md.

``gather`` reads the source Region and the DR Region; ``evaluate`` is pure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from .findings import Finding, Severity
from .inventory import InstanceFacts

MULTI_AZ_FAILOVER_MINUTES = 2.0  # AWS: "typically 60-120 seconds"
RECONNECT_MINUTES = 1.0  # clients re-resolve DNS; AWS advises a JVM DNS TTL of 60 s or less


@dataclass
class Targets:
    rto_minutes: float = 60.0
    rpo_minutes: float = 15.0


@dataclass(frozen=True)
class Replica:
    identifier: str
    region: str
    status: str | None = None  # replicating | error | stopped ...
    lag_seconds: float | None = None


@dataclass(frozen=True)
class BackupReplication:
    region: str
    arn: str
    retention_days: int | None = None
    latest_restorable: datetime | None = None
    status: str | None = None  # replicating | pending | stopped ...


@dataclass(frozen=True)
class SnapshotCopy:
    identifier: str
    region: str
    created: datetime
    encrypted: bool = True


@dataclass
class ResilienceSnapshot:
    facts: InstanceFacts
    region: str
    dr_region: str | None = None
    production: bool = False
    latest_restorable: datetime | None = None
    replicas: list[Replica] = field(default_factory=list)
    backup_replications: list[BackupReplication] = field(default_factory=list)
    snapshot_copies: list[SnapshotCopy] | None = None  # None when the DR Region was not read
    dr_kms_key: bool | None = None  # a usable KMS key in the DR Region
    dr_engine_available: bool | None = None  # the engine version is offered in the DR Region
    failover_events: bool | None = None  # an event subscription covers failover
    measured_restore_minutes: float | None = None  # from restore-drill reports
    measured_region_minutes: float | None = None  # from failover-drill results (region)
    measured_az_minutes: float | None = None  # from failover-drill results (az)
    errors: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Path:
    scenario: str  # zone | region
    name: str
    rpo_minutes: float | None
    rto_minutes: float | None
    how: str


def _age(t: datetime | None, now: datetime) -> float | None:
    return None if t is None else max(0.0, (now - t).total_seconds() / 60)


def paths(s: ResilienceSnapshot, now: datetime) -> list[Path]:
    out: list[Path] = []
    if s.facts.multi_az:
        rto = s.measured_az_minutes or MULTI_AZ_FAILOVER_MINUTES + RECONNECT_MINUTES
        out.append(
            Path(
                "zone",
                "Multi-AZ standby",
                0.0,
                rto,
                "Automatic failover to the synchronous standby; the endpoint follows.",
            )
        )
    if s.facts.backup_retention_days:
        out.append(
            Path(
                "zone",
                "Point-in-time restore in the Region",
                _age(s.latest_restorable, now),
                s.measured_restore_minutes,
                "Restore to a new instance from automated backups, then repoint ArcGIS.",
            )
        )
    for r in s.replicas:
        if r.region == s.region:
            continue
        healthy = r.status in (None, "replicating")
        out.append(
            Path(
                "region",
                f"Cross-Region read replica {r.identifier} ({r.region})",
                None if r.lag_seconds is None or not healthy else r.lag_seconds / 60,
                s.measured_region_minutes,
                "Promote it (it stops replicating for good), then repoint ArcGIS.",
            )
        )
    for b in s.backup_replications:
        out.append(
            Path(
                "region",
                f"Replicated automated backups ({b.region})",
                _age(b.latest_restorable, now),
                s.measured_region_minutes or s.measured_restore_minutes,
                "Restore to a point in time in that Region, then repoint ArcGIS.",
            )
        )
    copies = [c for c in s.snapshot_copies or [] if c.region != s.region]
    if copies:
        newest = max(copies, key=lambda c: c.created)
        out.append(
            Path(
                "region",
                f"Snapshot copy {newest.identifier} ({newest.region})",
                _age(newest.created, now),
                s.measured_region_minutes or s.measured_restore_minutes,
                "Restore the copy, then repoint ArcGIS. Everything after it is lost.",
            )
        )
    return out


def _best(ps: list[Path], key: str) -> Path | None:
    known = [p for p in ps if getattr(p, key) is not None]
    return min(known, key=lambda p: getattr(p, key)) if known else None


def _fmt(m: float | None) -> str:
    if m is None:
        return "unknown"
    if m < 1:
        return f"{m * 60:.0f} s"
    if m < 120:
        return f"{m:.0f} min"
    return f"{m / 60:.1f} h"


def evaluate(s: ResilienceSnapshot, now: datetime, t: Targets | None = None) -> list[Finding]:
    t = t or Targets()
    out: list[Finding] = []
    all_paths = paths(s, now)
    bad = Severity.FAIL if s.production else Severity.WARN

    for scenario, code, label in (
        ("zone", "RES001", "instance or zone loss"),
        ("region", "RES002", "Region loss"),
    ):
        ps = [p for p in all_paths if p.scenario == scenario]
        if not ps:
            out.append(
                Finding(
                    code,
                    bad,
                    f"No recovery path for {label}",
                    "Automated backups are off, so there is nothing to restore from."
                    if scenario == "zone"
                    else "Nothing is copied to another Region. Turn on cross-Region automated "
                    "backup replication (cheapest), or add a cross-Region read replica (fastest).",
                    {"scenario": scenario},
                )
            )
            continue
        rpo = _best(ps, "rpo_minutes")
        rto = _best(ps, "rto_minutes")
        lines = [
            f"{p.name}: data loss {_fmt(p.rpo_minutes)}, back in {_fmt(p.rto_minutes)}" for p in ps
        ]
        out.append(
            Finding(
                code,
                Severity.OK,
                f"{label.capitalize()}: {len(ps)} recovery path(s)",
                "\n".join(lines),
                {"scenario": scenario, "paths": [p.__dict__ for p in ps]},
            )
        )
        # RES003 data loss against the target
        if rpo is None:
            out.append(
                Finding(
                    "RES003",
                    Severity.INFO,
                    f"{label.capitalize()}: data loss not measured",
                    "No timestamp to measure it from (replica lag needs CloudWatch). "
                    "Check it before relying on the path.",
                    {"scenario": scenario},
                )
            )
        else:
            ok = rpo.rpo_minutes <= t.rpo_minutes
            out.append(
                Finding(
                    "RES003",
                    Severity.OK if ok else bad,
                    f"{label.capitalize()}: best data loss {_fmt(rpo.rpo_minutes)} via "
                    f"{rpo.name} (target {t.rpo_minutes:g} min)",
                    ""
                    if ok
                    else "Over target. A replica or replicated backups lose minutes; copied "
                    "snapshots lose everything since the copy.",
                    {"scenario": scenario, "rpo_minutes": round(rpo.rpo_minutes, 1)},
                )
            )
        # RES004 time back against the target
        if rto is None:
            out.append(
                Finding(
                    "RES004",
                    Severity.WARN if s.production else Severity.INFO,
                    f"{label.capitalize()}: time to recover never measured",
                    "Run rdsops restore-drill (and failover-drill for a Region) and pass the "
                    "reports, so this is a number and not a hope.",
                    {"scenario": scenario},
                )
            )
        else:
            ok = rto.rto_minutes <= t.rto_minutes
            out.append(
                Finding(
                    "RES004",
                    Severity.OK if ok else bad,
                    f"{label.capitalize()}: back in {_fmt(rto.rto_minutes)} via {rto.name} "
                    f"(target {t.rto_minutes:g} min)",
                    ""
                    if ok
                    else "Over target. Multi-AZ covers zone loss in minutes; for a Region, a "
                    "replica ready to promote is faster than restoring.",
                    {"scenario": scenario, "rto_minutes": round(rto.rto_minutes, 1)},
                )
            )

    # RES005 DR encryption needs a key in the DR Region
    needs_key = bool(s.facts.storage_encrypted and s.dr_region)
    if needs_key and s.dr_kms_key is False:
        out.append(
            Finding(
                "RES005",
                Severity.FAIL,
                f"No usable KMS key in {s.dr_region}",
                "KMS keys belong to one Region. Encrypted snapshot copies and replicated backups "
                "need a key in the destination Region; create one before you need it.",
                {"region": s.dr_region},
            )
        )
    elif needs_key and s.dr_kms_key:
        out.append(Finding("RES005", Severity.OK, f"KMS key ready in {s.dr_region}"))

    # RES006 the engine version can run in the DR Region
    if s.dr_region and s.dr_engine_available is False:
        out.append(
            Finding(
                "RES006",
                Severity.WARN,
                f"PostgreSQL {s.facts.engine_version} is not offered in {s.dr_region}",
                "A replica or restore there needs the same version. Patch to a minor both "
                "Regions offer.",
                {"region": s.dr_region, "version": s.facts.engine_version},
            )
        )

    # RES007 replicas and replication that are not healthy
    for r in s.replicas:
        if r.status and r.status != "replicating":
            out.append(
                Finding(
                    "RES007",
                    Severity.FAIL,
                    f"Replica {r.identifier} is {r.status}",
                    "It is not following the source. Check the replica's events; recreate it if "
                    "replication cannot resume.",
                    {"replica": r.identifier},
                )
            )
        elif r.lag_seconds is not None and r.lag_seconds / 60 > t.rpo_minutes:
            out.append(
                Finding(
                    "RES007",
                    Severity.WARN,
                    f"Replica {r.identifier} is {_fmt(r.lag_seconds / 60)} behind",
                    "More than the data-loss target. RDS also reports up to five minutes of lag "
                    "when nothing is being written, so check under load.",
                    {"replica": r.identifier, "lag_seconds": r.lag_seconds},
                )
            )
    for b in s.backup_replications:
        if b.status and b.status not in ("replicating", "active"):
            out.append(
                Finding(
                    "RES007",
                    Severity.FAIL,
                    f"Backup replication to {b.region} is {b.status}",
                    "The DR Region is not receiving new backups.",
                    {"region": b.region},
                )
            )

    # RES008 someone hears about a failover
    if s.failover_events is False:
        out.append(
            Finding(
                "RES008",
                Severity.INFO,
                "No event subscription covers failover",
                "Subscribe to the failover and availability categories so a failover at night "
                "reaches someone (aws rds create-event-subscription).",
            )
        )
    elif s.failover_events:
        out.append(Finding("RES008", Severity.OK, "Failover events reach a subscription"))

    for e in s.errors:
        out.append(Finding("RES009", Severity.WARN, "Part of the check could not run", e))
    return out


# --------------------------------------------------------------- gathering


def _region_of_arn(arn: str) -> str | None:
    parts = arn.split(":")
    return parts[3] if len(parts) > 3 else None


def gather(
    rds,
    identifier: str,
    region: str,
    *,
    dr_rds=None,
    dr_region=None,
    kms=None,
    dr_kms_key_id: str | None = None,
    cloudwatch=None,
    production: bool = False,
):
    from .inventory import facts_from_api

    db = rds.describe_db_instances(DBInstanceIdentifier=identifier)["DBInstances"][0]
    s = ResilienceSnapshot(
        facts=facts_from_api(db),
        region=region,
        dr_region=dr_region,
        production=production,
        latest_restorable=db.get("LatestRestorableTime"),
    )
    for rid in db.get("ReadReplicaDBInstanceIdentifiers") or []:
        rregion = _region_of_arn(rid) if rid.startswith("arn:") else region
        name = rid.split(":")[-1]
        status = None
        if rregion == dr_region and dr_rds is not None:
            try:
                rep = dr_rds.describe_db_instances(DBInstanceIdentifier=name)["DBInstances"][0]
                status = next(
                    (
                        x.get("Status")
                        for x in rep.get("StatusInfos") or []
                        if x.get("StatusType") == "read replication"
                    ),
                    None,
                )
            except Exception as e:  # noqa: BLE001
                s.errors.append(f"replica {name}: {e}")
        lag = None
        if cloudwatch is not None and rregion == dr_region:
            lag = _replica_lag(cloudwatch, name)
        s.replicas.append(Replica(name, rregion or region, status, lag))

    for rep in db.get("DBInstanceAutomatedBackupsReplications") or []:
        arn = rep.get("DBInstanceAutomatedBackupsArn", "")
        b_region = _region_of_arn(arn) or dr_region or "?"
        latest = retention = status = None
        if dr_rds is not None and b_region == dr_region:
            try:
                ab = dr_rds.describe_db_instance_automated_backups(
                    DBInstanceAutomatedBackupsArn=arn
                )["DBInstanceAutomatedBackups"][0]
                latest = (ab.get("RestoreWindow") or {}).get("LatestTime")
                retention = ab.get("BackupRetentionPeriod")
                status = ab.get("Status")
            except Exception as e:  # noqa: BLE001
                s.errors.append(f"replicated backups in {b_region}: {e}")
        s.backup_replications.append(BackupReplication(b_region, arn, retention, latest, status))

    if dr_rds is not None:
        try:
            snaps = dr_rds.describe_db_snapshots(
                DBInstanceIdentifier=identifier, SnapshotType="manual"
            )["DBSnapshots"]
            s.snapshot_copies = [
                SnapshotCopy(
                    x["DBSnapshotIdentifier"],
                    dr_region,
                    x["SnapshotCreateTime"],
                    bool(x.get("Encrypted")),
                )
                for x in snaps
                if x.get("Status") == "available"
            ]
        except Exception as e:  # noqa: BLE001
            s.errors.append(f"snapshots in {dr_region}: {e}")
        try:
            v = dr_rds.describe_db_engine_versions(
                Engine="postgres", EngineVersion=s.facts.engine_version
            )["DBEngineVersions"]
            s.dr_engine_available = bool(v)
        except Exception as e:  # noqa: BLE001
            s.errors.append(f"engine versions in {dr_region}: {e}")
    if kms is not None and dr_kms_key_id:
        try:
            meta = kms.describe_key(KeyId=dr_kms_key_id)["KeyMetadata"]
            s.dr_kms_key = meta.get("Enabled", False) and meta.get("KeyState") == "Enabled"
        except Exception:  # noqa: BLE001 - not found or no access: not usable
            s.dr_kms_key = False
    try:
        subs = rds.describe_event_subscriptions()["EventSubscriptionsList"]
        s.failover_events = any(
            x.get("Enabled")
            and x.get("SourceType") in (None, "db-instance")
            and (not x.get("EventCategoriesList") or "failover" in x["EventCategoriesList"])
            and (not x.get("SourceIdsList") or identifier in x["SourceIdsList"])
            for x in subs
        )
    except Exception as e:  # noqa: BLE001
        s.errors.append(f"event subscriptions: {e}")
    return s


def _replica_lag(cloudwatch, replica: str) -> float | None:
    from datetime import UTC, timedelta
    from datetime import datetime as dt

    end = dt.now(UTC)
    r = cloudwatch.get_metric_statistics(
        Namespace="AWS/RDS",
        MetricName="ReplicaLag",
        Dimensions=[{"Name": "DBInstanceIdentifier", "Value": replica}],
        StartTime=end - timedelta(minutes=15),
        EndTime=end,
        Period=300,
        Statistics=["Maximum"],
    )
    points = sorted(r.get("Datapoints") or [], key=lambda p: p["Timestamp"])
    return float(points[-1]["Maximum"]) if points else None


def measured_minutes(report_lines: list[str]) -> dict[str, float]:
    """Newest measured times from rdsops restore-drill --report and failover-drill results."""
    import json

    out: dict[str, float] = {}
    for line in report_lines:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        for f in rec.get("findings", []):
            ev = f.get("evidence") or {}
            if f.get("code") == "DRL011" and "rto_minutes" in ev:
                out["restore"] = ev["rto_minutes"]
            if f.get("code") == "DRD001" and "rto_minutes" in ev:
                out[ev.get("kind", "az")] = ev["rto_minutes"]
    return out
