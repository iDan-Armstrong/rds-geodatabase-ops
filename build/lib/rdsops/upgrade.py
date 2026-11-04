"""Upgrade planning: what has to be true before an engine upgrade, and in what order.

``plan`` is pure. It takes what is known about the instance and database (an
``UpgradeContext``) and returns findings plus an ordered runbook. Anything not known is
left as ``None`` and becomes a step to check by hand rather than a guess.

Sources are in docs/SCOPE.md and docs/runbooks/major-upgrade-blue-green.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import compat
from .findings import Finding, Severity

# AWS: major upgrades through blue/green need the source at or above these minors.
BLUE_GREEN_MIN_SOURCE = {11: (11, 21), 12: (12, 16), 13: (13, 12), 14: (14, 9), 15: (15, 4)}

BLOCKING_EXTENSIONS = {
    "pg_partman": "Disable on blue before creating the deployment; it runs DDL that breaks "
    "logical replication.",
    "pglogical": "Disable on blue before creating the deployment; re-enable after switchover.",
    "pgactive": "Disable on blue before creating the deployment; re-enable after switchover.",
    "pg_cron": "Keep cron jobs off on every green database for the whole deployment.",
}


@dataclass
class UpgradeContext:
    current_version: str
    target_version: str
    arcgis: str
    instance: str = "<instance>"
    postgis_version: str | None = None
    managed_master_secret: bool | None = None
    logical_replication_param: str | None = None  # rds.logical_replication value
    max_replication_slots: int | None = None
    database_count: int | None = None
    logical_slots: list[str] | None = None
    tables_without_pk: list[str] | None = None
    unlogged_tables: list[str] | None = None
    large_object_count: int | None = None
    extensions: list[str] | None = None
    has_geodatabase: bool | None = None


@dataclass
class UpgradePlan:
    kind: str  # major | minor | none | downgrade
    findings: list[Finding] = field(default_factory=list)
    steps: list[str] = field(default_factory=list)


def _unknown(code: str, title: str, how: str) -> Finding:
    return Finding(code, Severity.INFO, f"{title}: not checked", how)


def plan(ctx: UpgradeContext, matrix=None) -> UpgradePlan:
    cur, tgt = compat.vtuple(ctx.current_version), compat.vtuple(ctx.target_version)
    if tgt[:2] == cur[:2]:
        return UpgradePlan(
            "none", [Finding("UPG001", Severity.INFO, f"Already on {ctx.current_version}")]
        )
    if tgt < cur:
        return UpgradePlan(
            "downgrade",
            [
                Finding(
                    "UPG001",
                    Severity.FAIL,
                    f"{ctx.target_version} is older than {ctx.current_version}",
                    "RDS cannot downgrade an engine. Restore a snapshot taken before the upgrade.",
                )
            ],
        )

    kind = "major" if tgt[0] != cur[0] else "minor"
    p = UpgradePlan(kind)
    f, steps = p.findings, p.steps
    f.append(
        Finding(
            "UPG001",
            Severity.INFO,
            f"{kind.title()} upgrade {ctx.current_version} -> {ctx.target_version}",
        )
    )

    # Target must be supported by the ArcGIS release in use.
    target_compat = compat.check(ctx.target_version, ctx.arcgis, None, matrix)
    bad = [x for x in target_compat if x.severity == Severity.FAIL]
    if bad:
        f.append(
            Finding(
                "UPG002",
                Severity.FAIL,
                f"Target {ctx.target_version} is not supported by ArcGIS {ctx.arcgis}",
                " ".join(x.title for x in bad),
            )
        )
    else:
        f.append(
            Finding(
                "UPG002",
                Severity.OK,
                f"Target {ctx.target_version} is supported by ArcGIS {ctx.arcgis}",
            )
        )

    rel = compat.find_release(matrix or compat.load_matrix(), ctx.arcgis)
    if ctx.postgis_version and rel and rel.postgis_is_blocked(ctx.postgis_version):
        f.append(
            Finding(
                "UPG003",
                Severity.FAIL,
                f"Current PostGIS {ctx.postgis_version} is on the blocked list",
                rel.postgis_blocked_note,
            )
        )

    if kind == "major" and cur[0] <= 11 and ctx.has_geodatabase is not False:
        f.append(
            Finding(
                "UPG004",
                Severity.FAIL,
                "A geodatabase on PostgreSQL 11 or earlier cannot be upgraded in place",
                "Esri requires pg_dump and pg_restore to move a geodatabase off 11.x or earlier. "
                "Plan a dump/restore migration instead of an engine upgrade.",
            )
        )

    steps.append(
        f"Run `rdsops compat --engine-version {ctx.target_version} --arcgis "
        f"{ctx.arcgis}` and keep the output with the change record."
    )
    steps.append(
        "Take a manual snapshot and note its identifier: "
        f"aws rds create-db-snapshot --db-instance-identifier {ctx.instance} "
        f"--db-snapshot-identifier {ctx.instance}-pre-{ctx.target_version}"
    )
    steps.append(
        "Apply the same upgrade to a lower environment first and connect from ArcGIS "
        "Pro: open a map, edit a versioned feature class, run a compress."
    )

    if kind == "minor":
        steps.append(
            f"aws rds modify-db-instance --db-instance-identifier {ctx.instance} "
            f"--engine-version {ctx.target_version} --no-apply-immediately "
            "(applies in the maintenance window; Multi-AZ upgrades the standby first)"
        )
        steps.append(
            "After the window: `rdsops inventory` and `rdsops health`, then "
            "ALTER EXTENSION postgis UPDATE if a new PostGIS minor is available."
        )
        return p

    # ---- major upgrade through blue/green
    floor = BLUE_GREEN_MIN_SOURCE.get(cur[0])
    if floor and cur[:2] < floor:
        f.append(
            Finding(
                "UPG005",
                Severity.WARN,
                f"Blue/green major upgrades need {cur[0]}.{floor[1]} or later as the source",
                f"Upgrade to the latest {cur[0]}.x minor first, then run the major upgrade.",
            )
        )
        steps.append(f"Minor-upgrade the source to the latest {cur[0]}.x before anything below.")
    else:
        f.append(Finding("UPG005", Severity.OK, "Source version is eligible for blue/green"))

    if ctx.managed_master_secret is None:
        f.append(
            _unknown(
                "UPG006",
                "Secrets Manager master password",
                "Check MasterUserSecret in describe-db-instances.",
            )
        )
    elif ctx.managed_master_secret:
        f.append(
            Finding(
                "UPG006",
                Severity.FAIL,
                "Master password is managed in Secrets Manager; blue/green does not support that",
                "Switch to a self-managed master password for the upgrade window, then turn "
                "management back on after switchover (ADR 0005).",
            )
        )
        steps.append(
            f"aws rds modify-db-instance --db-instance-identifier {ctx.instance} "
            "--no-manage-master-user-password --master-user-password <from your vault> "
            "--apply-immediately"
        )
    else:
        f.append(Finding("UPG006", Severity.OK, "Master password is self-managed"))

    if ctx.logical_replication_param is None:
        f.append(
            _unknown(
                "UPG007",
                "rds.logical_replication",
                "Major-version blue/green uses logical replication; it must be 1.",
            )
        )
    elif ctx.logical_replication_param != "1":
        f.append(
            Finding(
                "UPG007",
                Severity.WARN,
                "rds.logical_replication is off",
                "Set logical_replication = true in the Terraform module (or "
                "rds.logical_replication = 1 in the parameter group) and reboot before "
                "creating the deployment.",
            )
        )
        steps.append(
            "Enable rds.logical_replication (module variable logical_replication = "
            "true), apply, and reboot in a quiet period."
        )
    else:
        f.append(Finding("UPG007", Severity.OK, "rds.logical_replication is on"))

    if ctx.max_replication_slots is not None and ctx.database_count is not None:
        ok = ctx.max_replication_slots > ctx.database_count
        f.append(
            Finding(
                "UPG008",
                Severity.OK if ok else Severity.WARN,
                f"max_replication_slots {ctx.max_replication_slots} for {ctx.database_count} "
                "database(s)",
                ""
                if ok
                else "Blue/green needs one logical slot per database; raise "
                "max_replication_slots above the database count.",
            )
        )

    if ctx.logical_slots is None:
        f.append(
            _unknown(
                "UPG009",
                "Existing logical replication slots",
                "SELECT slot_name FROM pg_replication_slots WHERE slot_type <> 'physical';",
            )
        )
    elif ctx.logical_slots:
        f.append(
            Finding(
                "UPG009",
                Severity.FAIL,
                f"{len(ctx.logical_slots)} logical slot(s) exist: {', '.join(ctx.logical_slots)}",
                "Blue/green creation is cancelled while external replication exists. Confirm the "
                "consumer is gone, then SELECT pg_drop_replication_slot('<name>');",
            )
        )
    else:
        f.append(Finding("UPG009", Severity.OK, "No logical replication slots"))

    if ctx.tables_without_pk is None:
        f.append(
            _unknown(
                "UPG010",
                "Tables without a primary key",
                "Connect to the database so rdsops can list them.",
            )
        )
    elif ctx.tables_without_pk:
        shown = ", ".join(ctx.tables_without_pk[:10])
        more = len(ctx.tables_without_pk) - 10
        f.append(
            Finding(
                "UPG010",
                Severity.WARN,
                f"{len(ctx.tables_without_pk)} table(s) without a primary key",
                f"UPDATE and DELETE on these fail while the deployment replicates: {shown}"
                + (f" and {more} more" if more > 0 else "")
                + ". Add a primary key, use REPLICA IDENTITY USING INDEX on a unique index, or "
                "freeze edits on them for the window.",
                {"tables": ctx.tables_without_pk},
            )
        )
    else:
        f.append(Finding("UPG010", Severity.OK, "Every table has a primary key"))

    if ctx.unlogged_tables:
        f.append(
            Finding(
                "UPG011",
                Severity.WARN,
                f"{len(ctx.unlogged_tables)} unlogged table(s) will not be replicated",
                ", ".join(ctx.unlogged_tables[:10]),
            )
        )

    if ctx.large_object_count:
        f.append(
            Finding(
                "UPG012",
                Severity.FAIL,
                f"{ctx.large_object_count} large object(s) present",
                "Large objects are not replicated and any change to them degrades the deployment. "
                "Move them to bytea or S3, or use a dump/restore or DMS migration.",
            )
        )

    for ext in sorted(set(ctx.extensions or []) & BLOCKING_EXTENSIONS.keys()):
        f.append(
            Finding(
                "UPG013", Severity.WARN, f"Extension {ext} needs handling", BLOCKING_EXTENSIONS[ext]
            )
        )

    f.append(
        Finding(
            "UPG014",
            Severity.INFO,
            "Schema freeze for the deployment window",
            "DDL is not replicated and a single CREATE TABLE degrades the deployment. In ArcGIS "
            "terms: no new feature classes, no Add Field, no index builds, no domain or "
            "relationship class changes until switchover. Normal edits and compress are DML "
            "and are fine on tables with a primary key.",
        )
    )
    f.append(
        Finding(
            "UPG015",
            Severity.INFO,
            "Point-in-time restore history does not carry over",
            "After switchover the new instance's restore window starts at green creation. The "
            "pre-upgrade manual snapshot is the way back.",
        )
    )

    steps += [
        "Announce the schema freeze to editors and ArcGIS admins.",
        f"aws rds create-blue-green-deployment --blue-green-deployment-name "
        f"{ctx.instance}-to-{tgt[0]} --source <instance ARN> --target-engine-version "
        f"{ctx.target_version} --target-db-parameter-group-name <postgres{tgt[0]} group>",
        "Wait for green to be available. Watch replication lag; logical apply is "
        "single-threaded, so a heavy write load can keep it behind.",
        "On green: SELECT * FROM pg_available_extension_versions WHERE name = 'postgis'; "
        "run `rdsops compat` with that version, then ALTER EXTENSION postgis UPDATE; "
        "and run ANALYZE on the whole database.",
        "Point a test ArcGIS Pro at the green endpoint (read-only) and draw the main maps.",
        "Switch over in a quiet period: aws rds switchover-blue-green-deployment "
        "--blue-green-deployment-identifier <id> --switchover-timeout 600",
        "After switchover: `rdsops inventory`, `rdsops health`, `rdsops maintenance`; "
        "re-enable Secrets Manager management of the master password if it was turned off; "
        "lift the schema freeze.",
        "Delete the blue/green deployment and, after a soak period, the old blue instance.",
    ]
    return p


# ------------------------------------------------------------------ gathering
# These take clients and connections as arguments and import nothing heavy, so this
# module still loads where boto3 and psycopg are absent.


def context_from_aws(rds, identifier: str, ctx: UpgradeContext) -> UpgradeContext:
    db = rds.describe_db_instances(DBInstanceIdentifier=identifier)["DBInstances"][0]
    ctx.instance = identifier
    ctx.current_version = db["EngineVersion"]
    ctx.managed_master_secret = bool(db.get("MasterUserSecret"))
    groups = [g["DBParameterGroupName"] for g in db.get("DBParameterGroups", [])]
    if groups and not groups[0].startswith("default."):
        wanted = {"rds.logical_replication", "max_replication_slots"}
        found: dict[str, str] = {}
        paginator = rds.get_paginator("describe_db_parameters")
        for page in paginator.paginate(DBParameterGroupName=groups[0]):
            for prm in page["Parameters"]:
                if prm["ParameterName"] in wanted and "ParameterValue" in prm:
                    found[prm["ParameterName"]] = prm["ParameterValue"]
        ctx.logical_replication_param = found.get("rds.logical_replication", "0")
        if "max_replication_slots" in found and found["max_replication_slots"].isdigit():
            ctx.max_replication_slots = int(found["max_replication_slots"])
    elif groups:
        ctx.logical_replication_param = "0"  # default groups cannot enable it
    return ctx


def context_from_db(conn, ctx: UpgradeContext) -> UpgradeContext:
    q = conn.execute
    row = q("SELECT extversion FROM pg_extension WHERE extname = 'postgis'").fetchone()
    ctx.postgis_version = row["extversion"] if row else None
    ctx.extensions = [r["extname"] for r in q("SELECT extname FROM pg_extension")]
    ctx.database_count = q(
        "SELECT count(*) AS n FROM pg_database WHERE NOT datistemplate "
        "AND datname NOT IN ('rdsadmin')"
    ).fetchone()["n"]
    ctx.logical_slots = [
        r["slot_name"]
        for r in q("SELECT slot_name FROM pg_replication_slots WHERE slot_type <> 'physical'")
    ]
    if ctx.max_replication_slots is None:
        ctx.max_replication_slots = int(
            q("SHOW max_replication_slots").fetchone()["max_replication_slots"]
        )
    system = "('pg_catalog', 'information_schema', 'pg_toast')"
    ctx.tables_without_pk = [
        r["t"]
        for r in q(
            f"""
            SELECT n.nspname || '.' || c.relname AS t
              FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE c.relkind IN ('r', 'p') AND NOT c.relispartition
               AND n.nspname NOT IN {system} AND n.nspname NOT LIKE 'pg_temp%%'
               AND NOT EXISTS (SELECT 1 FROM pg_constraint k
                                WHERE k.conrelid = c.oid AND k.contype = 'p')
               AND c.relreplident NOT IN ('f', 'i')
             ORDER BY 1
            """
        )
    ]
    ctx.unlogged_tables = [
        r["t"]
        for r in q(
            f"""
            SELECT n.nspname || '.' || c.relname AS t
              FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE c.relkind = 'r' AND c.relpersistence = 'u'
               AND n.nspname NOT IN {system}
             ORDER BY 1
            """
        )
    ]
    ctx.large_object_count = q("SELECT count(*) AS n FROM pg_largeobject_metadata").fetchone()["n"]
    ctx.has_geodatabase = bool(
        q(
            "SELECT 1 FROM pg_tables WHERE schemaname = 'sde' "
            "AND tablename IN ('sde_version', 'gdb_items') LIMIT 1"
        ).fetchone()
    )
    return ctx
