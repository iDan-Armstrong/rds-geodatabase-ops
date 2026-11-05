"""rdsops command line.

rdsops inventory   --instance egdb-lab [--production] [--json]
rdsops health      --host H --user U --dbname egdb --iam [--instance egdb-lab]
rdsops maintenance --dsn "postgresql://..."            [--json]
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .aws import session
from .findings import Finding, Severity, exit_code

MARK = {Severity.OK: "ok  ", Severity.INFO: "info", Severity.WARN: "WARN", Severity.FAIL: "FAIL"}


def render_findings(findings: list[Finding], quiet: bool = False) -> list[str]:
    lines = []
    for f in findings:
        if quiet and f.severity == Severity.OK:
            continue
        lines.append(f"  [{MARK[f.severity]}] {f.code}  {f.title}")
        lines.extend(f"               {d}" for d in f.detail.splitlines())
    return lines


def emit(args, header: list[str], findings: list[Finding], extra: dict) -> int:
    if args.json:
        print(
            json.dumps(
                {**extra, "findings": [f.to_dict() for f in findings]}, indent=2, default=str
            )
        )
    else:
        print("\n".join(header + [""] + render_findings(findings, args.quiet)))
    return exit_code(findings)


# ---------------------------------------------------------------- inventory


def cmd_inventory(args) -> int:
    from .inventory import describe_instance, posture_findings

    rds = session(args.region, args.profile).client("rds")
    facts = describe_instance(rds, args.instance)
    findings = posture_findings(facts, production=args.production)
    endpoint = f"{facts.endpoint}:{facts.port}" if facts.endpoint else "(none yet)"
    autoscale = facts.max_allocated_storage_gb
    header = [
        f"{facts.identifier}  {facts.engine} {facts.engine_version}  {facts.instance_class}  "
        f"[{facts.status}]",
        f"  endpoint   {endpoint}",
        f"  storage    {facts.allocated_storage_gb} GB"
        + (f" (autoscale to {autoscale} GB)" if autoscale else ""),
        f"  params     {', '.join(facts.parameter_groups) or '(none)'}",
    ]
    return emit(args, header, findings, {"instance": facts.to_dict()})


# ------------------------------------------------------------- SQL commands


def _connect(args):
    from .db import ConnectOptions, connect

    opts = ConnectOptions(
        dsn=args.dsn,
        host=args.host,
        port=args.port,
        user=args.user,
        dbname=args.dbname,
        iam=args.iam,
        secret_arn=args.secret_arn,
        sslmode=args.sslmode,
    )
    needs_aws = args.iam or args.secret_arn
    return connect(opts, session(args.region, args.profile) if needs_aws else None)


def cmd_health(args) -> int:
    from . import health

    t = health.Thresholds(long_query_seconds=args.long_query_seconds)
    with _connect(args) as conn:
        snap = health.gather(conn, t)
    findings = health.evaluate(snap, t)
    if args.instance:
        s = session(args.region, args.profile)
        findings += health.storage_findings(s.client("cloudwatch"), s.client("rds"), args.instance)
    header = [
        f"health  PostgreSQL {snap.server_version}"
        + (f", PostGIS {snap.postgis_version}" if snap.postgis_version else "")
        + f"  size {snap.database_size_bytes / (1 << 30):.2f} GiB"
    ]
    return emit(args, header, findings, {"server_version": snap.server_version})


def cmd_maintenance(args) -> int:
    from . import maintenance

    with _connect(args) as conn:
        snap = maintenance.gather(conn)
    findings = maintenance.evaluate(snap)
    header = [
        f"maintenance  {len(snap.tables)} tables checked, statistics "
        f"{snap.stats_age_days:.1f} days old"
    ]
    return emit(args, header, findings, {"stats_age_days": snap.stats_age_days})


def _db_requested(args) -> bool:
    import os

    return bool(args.dsn or args.host or args.secret_arn or os.environ.get("RDSOPS_DSN"))


def cmd_compat(args) -> int:
    from . import compat

    engine, postgis = args.engine_version, args.postgis
    if args.instance:
        rds = session(args.region, args.profile).client("rds")
        db = rds.describe_db_instances(DBInstanceIdentifier=args.instance)["DBInstances"][0]
        engine = db["EngineVersion"]
    if _db_requested(args):
        with _connect(args) as conn:
            row = conn.execute(
                "SELECT extversion FROM pg_extension WHERE extname = 'postgis'"
            ).fetchone()
            postgis = postgis or (row["extversion"] if row else None)
    if not engine:
        raise SystemExit("rdsops compat: give --engine-version or --instance")
    findings = compat.check(engine, args.arcgis, postgis, platform=args.platform)
    header = [
        f"compat  {'Aurora' if args.platform == 'aurora' else 'RDS for'} PostgreSQL {engine}"
        + (f", PostGIS {postgis}" if postgis else "")
        + f"  vs ArcGIS {args.arcgis}"
    ]
    return emit(
        args,
        header,
        findings,
        {"engine_version": engine, "postgis": postgis, "arcgis": args.arcgis},
    )


def cmd_upgrade_plan(args) -> int:
    from . import upgrade

    ctx = upgrade.UpgradeContext(
        current_version=args.current or "0", target_version=args.target, arcgis=args.arcgis
    )
    if args.instance:
        rds = session(args.region, args.profile).client("rds")
        upgrade.context_from_aws(rds, args.instance, ctx)
    elif not args.current:
        raise SystemExit("rdsops upgrade-plan: give --instance or --current")
    if _db_requested(args):
        with _connect(args) as conn:
            upgrade.context_from_db(conn, ctx)
    result = upgrade.plan(ctx)
    header = [
        f"upgrade-plan  {result.kind} upgrade {ctx.current_version} -> "
        f"{ctx.target_version} for ArcGIS {ctx.arcgis}"
    ]
    if args.json:
        return emit(args, header, result.findings, {"kind": result.kind, "steps": result.steps})
    code = emit(args, header, result.findings, {})
    if result.steps:
        print("\n  Runbook")
        for n, step in enumerate(result.steps, 1):
            print(f"  {n:>2}. {step}")
    return code


def parse_targets(values: list[str], profile: str | None) -> list[tuple[str, str | None]]:
    """'us-gov-west-1@gov' -> ('us-gov-west-1', 'gov'); a bare Region uses --profile."""
    out = []
    for v in values:
        region, _, prof = v.partition("@")
        out.append((region, prof or profile))
    return out


def cmd_security(args) -> int:
    from datetime import UTC, datetime

    from . import security

    s = session(args.region, args.profile)
    snap = security.gather(
        s.client("rds"),
        s.client("ec2"),
        s.client("kms"),
        s.client("secretsmanager"),
        args.instance,
        args.region or "",
    )
    if _db_requested(args):
        with _connect(args) as conn:
            security.gather_db(conn, snap)
    findings = security.evaluate(snap, datetime.now(UTC))
    header = [f"security  {snap.facts.identifier}  {snap.facts.engine} {snap.facts.engine_version}"]
    return emit(args, header, findings, {"instance": snap.facts.identifier})


def cmd_incident(args) -> int:
    from datetime import UTC, datetime

    from . import incident

    since = datetime.fromisoformat(args.since) if args.since else None
    ctx = incident.IncidentContext(
        kind=args.kind,
        instance=args.instance,
        region=args.region or "<region>",
        federal=args.federal,
        role=args.role,
        access_key=args.access_key,
        since=since,
        now=datetime.now(UTC),
        snapshot=args.snapshot,
        group=args.group,
        cidr=args.cidr,
        arcgis=not args.no_arcgis,
    )
    if not args.offline:
        rds = session(args.region, args.profile).client("rds")
        db = rds.describe_db_instances(DBInstanceIdentifier=args.instance)["DBInstances"][0]
        ctx.managed_secret = bool(db.get("MasterUserSecret"))
        ctx.deletion_protection = bool(db.get("DeletionProtection"))
        ctx.publicly_accessible = bool(db.get("PubliclyAccessible"))
        ctx.backup_retention_days = int(db.get("BackupRetentionPeriod", 0))
        try:
            backups = rds.describe_db_instance_automated_backups(DBInstanceIdentifier=args.instance)
            win = (backups["DBInstanceAutomatedBackups"] or [{}])[0].get("RestoreWindow") or {}
            ctx.earliest_restorable = win.get("EarliestTime")
        except Exception:  # noqa: BLE001 - readiness then just omits the window check
            pass
    pb = incident.playbook(ctx)
    header = [
        f"incident  {args.kind}: {incident.KINDS[args.kind]}",
        f"  instance {args.instance}  {ctx.region}" + ("  federal" if args.federal else ""),
    ]
    if args.json:
        print(json.dumps(pb.to_dict(), indent=2, default=str))
        return exit_code(pb.findings)
    code = emit(args, header, pb.findings, {})
    print("\n  Playbook (nothing here has been run)")
    phase = None
    for n, st in enumerate(pb.steps, 1):
        if st.phase != phase:
            phase = st.phase
            print(f"\n  {phase}")
        print(f"  {n:>2}. {st.title}")
        if st.command:
            print(f"      {'$' if incident.is_command(st.command) else '>'} {st.command}")
        if st.why:
            print(f"      {st.why}")
    return code


def cmd_fleet(args) -> int:
    from . import fleet

    if not args.region:
        raise SystemExit("rdsops fleet: give at least one --region (REGION or REGION@PROFILE)")
    tag = tuple(args.tag.split("=", 1)) if args.tag else None
    clients = [
        (region, session(region, prof).client("rds"))
        for region, prof in parse_targets(args.region, args.profile)
    ]
    snap = fleet.gather(clients, tag=tag, default_arcgis=args.arcgis)
    findings = fleet.evaluate(snap)
    header = [
        f"fleet  {', '.join(snap.regions)}"
        + (f"  tag {args.tag}" if args.tag else "")
        + (f"  default ArcGIS {args.arcgis}" if args.arcgis else "")
    ]
    return emit(args, header, findings, {"instances": [m.name for m in snap.members]})


def cmd_aurora_plan(args) -> int:
    from . import aurora

    if args.instance:
        if not args.region:
            raise SystemExit("rdsops aurora-plan: give --region with --instance")
        s = session(args.region, args.profile)
        facts = aurora.gather(s.client("rds"), s.client("cloudwatch"), args.instance, args.region)
    elif args.engine_version and args.region:
        facts = aurora.AuroraFacts(
            source=args.source or "<instance>",
            region=args.region,
            engine_version=args.engine_version,
            encrypted=None if args.encrypted is None else args.encrypted == "yes",
        )
    else:
        raise SystemExit(
            "rdsops aurora-plan: give --instance and --region, or --engine-version and "
            "--region for offline planning"
        )
    facts.postgis_version = args.postgis or facts.postgis_version
    if _db_requested(args):
        with _connect(args) as conn:
            row = conn.execute(
                "SELECT extversion FROM pg_extension WHERE extname = 'postgis'"
            ).fetchone()
            facts.postgis_version = facts.postgis_version or (row["extversion"] if row else None)
    req = aurora.AuroraRequest(
        arcgis=args.arcgis,
        method=args.method,
        target_region=args.target_region,
        cluster=args.cluster,
        writer_class=args.writer_class,
    )
    findings, steps = aurora.plan(req, facts)
    header = [
        f"aurora-plan  {facts.source} (RDS for PostgreSQL {facts.engine_version}, "
        f"{facts.region}, partition {aurora.partition(facts.region)})  {req.method} method  "
        f"for ArcGIS {req.arcgis}"
    ]
    if args.json:
        return emit(
            args, header, findings, {"steps": steps, "partition": aurora.partition(facts.region)}
        )
    code = emit(args, header, findings, {})
    if steps:
        print("\n  Runbook")
        for n, step in enumerate(steps, 1):
            print(f"  {n:>2}. {step}")
    return code


def cmd_restore_drill(args) -> int:
    from datetime import UTC, datetime

    from . import drill
    from .findings import Severity

    def now():
        return datetime.now(UTC)

    rds = session(args.region, args.profile).client("rds")
    req = drill.DrillRequest(
        source=args.instance,
        mode=args.mode,
        restore_time=datetime.fromisoformat(args.restore_time.replace("Z", "+00:00"))
        if args.restore_time
        else None,
        snapshot_id=args.snapshot,
        target_id=args.target,
        instance_class=args.instance_class,
        rto_minutes=args.rto_minutes,
        rpo_minutes=args.rpo_minutes,
        verify_tables=args.verify_table or [],
        keep=args.keep,
    )
    facts = drill.gather_backup_facts(rds, args.instance)
    findings, steps = drill.plan(req, facts, now())
    header = [
        f"restore-drill  {args.instance}  mode {args.mode}"
        + ("" if args.execute else "  (plan only; add --execute to run it)")
    ]

    if not args.execute or any(f.severity == Severity.FAIL for f in findings):
        if args.json:
            return emit(args, header, findings, {"steps": steps, "executed": False})
        code = emit(args, header, findings, {})
        print("\n  Steps")
        for n, step in enumerate(steps, 1):
            print(f"  {n}. {step}")
        if args.execute:
            print("\n  Not running: the plan has failures.")
        return code

    verifier = None
    if args.user or args.secret_arn or args.dsn:
        from .db import ConnectOptions, connect

        def verifier(host):
            opts = ConnectOptions(
                host=host,
                port=args.port,
                user=args.user,
                dbname=args.dbname,
                iam=args.iam,
                secret_arn=args.secret_arn,
                sslmode=args.sslmode,
            )
            aws = session(args.region, args.profile) if (args.iam or args.secret_arn) else None
            with connect(opts, aws) as conn:
                return drill.verify_restored(conn, req.verify_tables)

    log = (lambda m: None) if args.json else (lambda m: print(f"  .. {m}"))
    result = drill.run(rds, req, facts, now=now, verifier=verifier, log=log)
    findings = drill.evaluate(result, req)
    if args.report:
        import json as _json

        with open(args.report, "a", encoding="utf-8") as fh:
            fh.write(
                _json.dumps(
                    {"result": result.to_dict(), "findings": [f.to_dict() for f in findings]}
                )
                + "\n"
            )
    return emit(args, header, findings, {"result": result.to_dict()})


def _read_reports(paths) -> list[str]:
    lines: list[str] = []
    for p in paths or []:
        with open(p, encoding="utf-8") as fh:
            lines += fh.readlines()
    return lines


def cmd_resilience(args) -> int:
    from datetime import UTC, datetime

    from . import resilience

    src = session(args.region, args.profile)
    dr = session(args.dr_region, args.dr_profile or args.profile) if args.dr_region else None
    snap = resilience.gather(
        src.client("rds"),
        args.instance,
        args.region or src.region_name,
        dr_rds=dr.client("rds") if dr else None,
        dr_region=args.dr_region,
        kms=dr.client("kms") if dr and args.dr_kms_key else None,
        dr_kms_key_id=args.dr_kms_key,
        cloudwatch=dr.client("cloudwatch") if dr and args.replica_lag else None,
        production=args.production,
    )
    m = resilience.measured_minutes(_read_reports(args.report))
    snap.measured_restore_minutes = m.get("restore")
    snap.measured_az_minutes = m.get("az")
    snap.measured_region_minutes = m.get("region")
    findings = resilience.evaluate(
        snap, datetime.now(UTC), resilience.Targets(args.rto_minutes, args.rpo_minutes)
    )
    header = [
        f"resilience  {args.instance}  {snap.region}"
        + (
            f"  DR {args.dr_region}"
            if args.dr_region
            else "  (no --dr-region: Region loss not read)"
        )
        + f"  targets RTO {args.rto_minutes:g} min, RPO {args.rpo_minutes:g} min"
    ]
    return emit(args, header, findings, {"instance": args.instance})


def cmd_failover_drill(args) -> int:
    import json as _json
    from datetime import UTC, datetime

    from . import failover, resilience

    req = failover.FailoverRequest(
        kind=args.kind,
        instance=args.instance,
        region=args.region or "<region>",
        dr_region=args.dr_region,
        rto_minutes=args.rto_minutes,
        rpo_minutes=args.rpo_minutes,
        target=args.target,
    )
    if args.result:
        with open(args.result, encoding="utf-8") as fh:
            result = failover.result_from_dict(_json.load(fh))
        findings = failover.evaluate(result, req)
        if args.report:
            with open(args.report, "a", encoding="utf-8") as fh:
                fh.write(
                    _json.dumps({"kind": args.kind, "findings": [f.to_dict() for f in findings]})
                    + "\n"
                )
        header = [f"failover-drill  {args.kind}  {args.instance}  result {args.result}"]
        return emit(args, header, findings, {"kind": args.kind})

    snap = None
    if not args.offline:
        src = session(args.region, args.profile)
        dr = session(args.dr_region, args.dr_profile or args.profile) if args.dr_region else None
        snap = resilience.gather(
            src.client("rds"),
            args.instance,
            args.region or src.region_name,
            dr_rds=dr.client("rds") if dr else None,
            dr_region=args.dr_region,
        )
    findings, steps = failover.plan(req, snap, datetime.now(UTC))
    header = [f"failover-drill  {args.kind}  {args.instance}  (plan; nothing here has been run)"]
    if args.json:
        return emit(args, header, findings, {"steps": steps})
    code = emit(args, header, findings, {})
    if steps:
        print("\n  Steps")
        for n, st in enumerate(steps, 1):
            print(f"  {n:>2}. {st}")
        print(
            "\n  Record started, writable_at, apps_ok_at, data_loss_seconds and checks in a JSON "
            "file and score it with --result."
        )
    return code


# ------------------------------------------------------------------- parser


def _aws_args(p):
    p.add_argument("--region")
    p.add_argument("--profile", help="AWS profile (credentials never go on the command line)")


def _output_args(p):
    p.add_argument("--json", action="store_true", help="Machine-readable output")
    p.add_argument("--quiet", action="store_true", help="Hide passing checks")


def _db_args(p):
    g = p.add_argument_group("database connection (no password options, by design)")
    g.add_argument("--dsn", help="libpq connection string; default $RDSOPS_DSN or PG* variables")
    g.add_argument("--host")
    g.add_argument("--port", type=int, default=5432)
    g.add_argument("--user")
    g.add_argument("--dbname")
    g.add_argument("--iam", action="store_true", help="Authenticate with an IAM auth token")
    g.add_argument("--secret-arn", help="Read username/password from Secrets Manager")
    g.add_argument("--sslmode", help="libpq sslmode (require, verify-full, ...)")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="rdsops", description=__doc__.splitlines()[0])
    p.add_argument("--version", action="version", version=f"rdsops {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    inv = sub.add_parser("inventory", help="Describe the instance and check security posture")
    inv.add_argument("--instance", required=True, help="DB instance identifier")
    inv.add_argument(
        "--production",
        action="store_true",
        help="Treat availability gaps (single AZ, short retention) as failures",
    )
    _aws_args(inv)
    _output_args(inv)
    inv.set_defaults(func=cmd_inventory)

    hl = sub.add_parser("health", help="Connections, locks, wraparound, WAL slots, top queries")
    _db_args(hl)
    hl.add_argument("--instance", help="Also check free storage from CloudWatch")
    hl.add_argument("--long-query-seconds", type=int, default=900)
    _aws_args(hl)
    _output_args(hl)
    hl.set_defaults(func=cmd_health)

    mt = sub.add_parser(
        "maintenance", help="Dead rows, stale stats, unused/duplicate/invalid/spatial indexes"
    )
    _db_args(mt)
    _aws_args(mt)
    _output_args(mt)
    mt.set_defaults(func=cmd_maintenance)
    cp = sub.add_parser("compat", help="Engine and PostGIS versions against the Esri matrix")
    cp.add_argument("--arcgis", required=True, help="Enterprise version (12.1) or pro3.7")
    cp.add_argument("--engine-version", help="RDS engine version, e.g. 17.7")
    cp.add_argument("--postgis", help="PostGIS version, e.g. 3.5.2")
    cp.add_argument("--instance", help="Read the engine version from this instance")
    cp.add_argument(
        "--platform",
        choices=["rds", "aurora"],
        default="rds",
        help="RDS for PostgreSQL (default) or Aurora PostgreSQL",
    )
    _db_args(cp)
    _aws_args(cp)
    _output_args(cp)
    cp.set_defaults(func=cmd_compat)

    sc = sub.add_parser(
        "security", help="Deep security posture: TLS, CA, exposure, snapshots, keys, audit"
    )
    sc.add_argument("--instance", required=True)
    _db_args(sc)
    _aws_args(sc)
    _output_args(sc)
    sc.set_defaults(func=cmd_security)

    ic = sub.add_parser(
        "incident", help="Contingency playbook for a security incident (prints only)"
    )
    ic.add_argument(
        "--kind",
        required=True,
        choices=sorted(__import__("rdsops.incident", fromlist=["KINDS"]).KINDS),
    )
    ic.add_argument("--instance", required=True)
    ic.add_argument("--role", help="Database role involved")
    ic.add_argument("--access-key", help="AWS access key id involved")
    ic.add_argument("--since", help="Last known good time or start, ISO 8601")
    ic.add_argument("--snapshot", help="Snapshot involved")
    ic.add_argument("--group", help="Security group involved")
    ic.add_argument("--cidr", help="CIDR of the rule involved")
    ic.add_argument(
        "--federal", action="store_true", help="Federal agency: CISA one-hour notification"
    )
    ic.add_argument("--no-arcgis", action="store_true", help="No ArcGIS clients connect")
    ic.add_argument("--offline", action="store_true", help="Do not read the instance from AWS")
    _aws_args(ic)
    _output_args(ic)
    ic.set_defaults(func=cmd_incident)

    fl = sub.add_parser("fleet", help="Every geodatabase instance across Regions, in one view")
    fl.add_argument(
        "--region",
        action="append",
        help="Region to read, repeatable; REGION@PROFILE to use another profile (GovCloud)",
    )
    fl.add_argument("--profile", help="Profile for Regions given without one")
    fl.add_argument("--tag", help="Only instances with this tag, KEY=VALUE")
    fl.add_argument("--arcgis", help="ArcGIS release for instances without an arcgis-release tag")
    _output_args(fl)
    fl.set_defaults(func=cmd_fleet)

    au = sub.add_parser("aurora-plan", help="Preflight and runbook for moving to Aurora PostgreSQL")
    au.add_argument("--arcgis", required=True, help="Enterprise version (12.1) or pro3.7")
    au.add_argument("--instance", help="Read the source from this RDS instance")
    au.add_argument("--method", choices=["replica", "snapshot"], default="replica")
    au.add_argument("--target-region", help="Region for the cluster (snapshot method only)")
    au.add_argument("--cluster", help="Cluster identifier (default: <instance>-aurora)")
    au.add_argument("--writer-class", default="db.r6g.large")
    au.add_argument("--postgis", help="PostGIS version, if not read from the database")
    au.add_argument("--engine-version", help="Source engine version (offline planning)")
    au.add_argument("--source", help="Source identifier (offline planning)")
    au.add_argument("--encrypted", choices=["yes", "no"], help="Source encryption (offline)")
    _db_args(au)
    _aws_args(au)
    _output_args(au)
    au.set_defaults(func=cmd_aurora_plan)

    up = sub.add_parser("upgrade-plan", help="Preflight and runbook for an engine upgrade")
    up.add_argument("--target", required=True, help="Target engine version, e.g. 18.1")
    up.add_argument("--arcgis", required=True, help="Enterprise version (12.1) or pro3.7")
    up.add_argument("--instance", help="Read version, secret and parameters from this instance")
    up.add_argument("--current", help="Current engine version (offline planning)")
    _db_args(up)
    _aws_args(up)
    _output_args(up)
    up.set_defaults(func=cmd_upgrade_plan)
    dr = sub.add_parser(
        "restore-drill", help="Restore to a throwaway copy, time it, verify it, delete it"
    )
    dr.add_argument("--instance", required=True, help="Source DB instance identifier")
    dr.add_argument("--mode", choices=["pitr", "snapshot"], default="pitr")
    dr.add_argument(
        "--restore-time",
        help="pitr: ISO time, e.g. 2026-11-04T13:00:00Z (default latest restorable)",
    )
    dr.add_argument("--snapshot", help="snapshot: identifier (default newest)")
    dr.add_argument("--target", help="Identifier for the copy (default <source>-drill-<time>)")
    dr.add_argument("--instance-class", help="Class for the copy (default same as source)")
    dr.add_argument("--rto-minutes", type=float, default=60.0)
    dr.add_argument("--rpo-minutes", type=float, default=15.0)
    dr.add_argument("--verify-table", action="append", help="schema.table to count rows in")
    dr.add_argument("--keep", action="store_true", help="Do not delete the copy afterwards")
    dr.add_argument("--report", help="Append the result as a JSON line to this file")
    dr.add_argument(
        "--execute",
        action="store_true",
        help="Actually run the drill. Without it, only the plan is printed.",
    )
    _db_args(dr)
    _aws_args(dr)
    _output_args(dr)
    dr.set_defaults(func=cmd_restore_drill)

    rs = sub.add_parser(
        "resilience",
        help="Zone and Region loss: recovery paths, data loss and time against targets",
    )
    rs.add_argument("--instance", required=True)
    rs.add_argument("--dr-region", help="The Region you would recover into")
    rs.add_argument("--dr-profile", help="AWS profile for the DR Region (default --profile)")
    rs.add_argument("--dr-kms-key", help="KMS key id or alias in the DR Region to check")
    rs.add_argument("--replica-lag", action="store_true", help="Read ReplicaLag from CloudWatch")
    rs.add_argument("--production", action="store_true", help="Gaps are failures")
    rs.add_argument("--rto-minutes", type=float, default=60.0)
    rs.add_argument("--rpo-minutes", type=float, default=15.0)
    rs.add_argument(
        "--report",
        action="append",
        help="restore-drill or failover-drill report (JSON lines) with measured times",
    )
    _aws_args(rs)
    _output_args(rs)
    rs.set_defaults(func=cmd_resilience)

    fo = sub.add_parser(
        "failover-drill", help="Plan a zone or Region failover drill, or score a recorded one"
    )
    fo.add_argument("--kind", required=True, choices=["az", "region"])
    fo.add_argument("--instance", required=True)
    fo.add_argument("--dr-region")
    fo.add_argument("--dr-profile")
    fo.add_argument("--target", help="Scratch instance name for a Region drill")
    fo.add_argument("--rto-minutes", type=float, default=60.0)
    fo.add_argument("--rpo-minutes", type=float, default=15.0)
    fo.add_argument("--offline", action="store_true", help="Plan without reading AWS")
    fo.add_argument("--result", help="JSON record of a drill to score")
    fo.add_argument("--report", help="Append the scored result to this JSON lines file")
    _aws_args(fo)
    _output_args(fo)
    fo.set_defaults(func=cmd_failover_drill)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
