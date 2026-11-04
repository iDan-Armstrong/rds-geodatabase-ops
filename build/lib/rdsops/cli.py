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
    findings = compat.check(engine, args.arcgis, postgis)
    header = [
        f"compat  RDS for PostgreSQL {engine}"
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
    _db_args(cp)
    _aws_args(cp)
    _output_args(cp)
    cp.set_defaults(func=cmd_compat)

    up = sub.add_parser("upgrade-plan", help="Preflight and runbook for an engine upgrade")
    up.add_argument("--target", required=True, help="Target engine version, e.g. 18.1")
    up.add_argument("--arcgis", required=True, help="Enterprise version (12.1) or pro3.7")
    up.add_argument("--instance", help="Read version, secret and parameters from this instance")
    up.add_argument("--current", help="Current engine version (offline planning)")
    _db_args(up)
    _aws_args(up)
    _output_args(up)
    up.set_defaults(func=cmd_upgrade_plan)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
