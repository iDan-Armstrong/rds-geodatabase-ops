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
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
