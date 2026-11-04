"""rdsops command line.

rdsops inventory --instance egdb-lab [--region us-east-1] [--profile lab] [--json]
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .aws import session
from .findings import Finding, Severity, exit_code
from .inventory import describe_instance, posture_findings

MARK = {Severity.OK: "ok  ", Severity.INFO: "info", Severity.WARN: "WARN", Severity.FAIL: "FAIL"}


def render_text(facts, findings: list[Finding]) -> str:
    endpoint = f"{facts.endpoint}:{facts.port}" if facts.endpoint else "(none yet)"
    autoscale = facts.max_allocated_storage_gb
    lines = [
        f"{facts.identifier}  {facts.engine} {facts.engine_version}  {facts.instance_class}  "
        f"[{facts.status}]",
        f"  endpoint   {endpoint}",
        f"  storage    {facts.allocated_storage_gb} GB"
        + (f" (autoscale to {autoscale} GB)" if autoscale else ""),
        f"  params     {', '.join(facts.parameter_groups) or '(none)'}",
        "",
    ]
    for f in findings:
        lines.append(f"  [{MARK[f.severity]}] {f.code}  {f.title}")
        if f.detail:
            lines.append(f"               {f.detail}")
    return "\n".join(lines)


def cmd_inventory(args) -> int:
    rds = session(args.region, args.profile).client("rds")
    facts = describe_instance(rds, args.instance)
    findings = posture_findings(facts, production=args.production)
    if args.json:
        print(
            json.dumps(
                {"instance": facts.to_dict(), "findings": [f.to_dict() for f in findings]}, indent=2
            )
        )
    else:
        print(render_text(facts, findings))
    return exit_code(findings)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="rdsops", description=__doc__.splitlines()[0])
    p.add_argument("--version", action="version", version=f"rdsops {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    inv = sub.add_parser("inventory", help="Describe the instance and check security posture")
    inv.add_argument("--instance", required=True, help="DB instance identifier")
    inv.add_argument("--region")
    inv.add_argument("--profile", help="AWS profile (credentials never go on the command line)")
    inv.add_argument(
        "--production",
        action="store_true",
        help="Treat availability gaps (single AZ, short retention) as failures",
    )
    inv.add_argument("--json", action="store_true", help="Machine-readable output")
    inv.set_defaults(func=cmd_inventory)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
