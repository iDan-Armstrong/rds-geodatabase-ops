"""Maintenance: what needs vacuuming, analyzing or re-indexing.

Same split as health: ``gather`` reads catalogs, ``evaluate`` decides. Reads only; every
finding says what command fixes it, and nothing here runs that command for you.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from .findings import Finding, Severity

SKIP_SCHEMAS = ("pg_catalog", "information_schema", "pg_toast", "topology", "tiger")


@dataclass(frozen=True)
class Thresholds:
    dead_ratio_warn: float = 0.20
    dead_rows_min: int = 10_000
    stale_analyze_ratio: float = 0.20
    stale_analyze_rows_min: int = 10_000
    never_analyzed_rows_min: int = 1_000
    unused_index_min_bytes: int = 8 << 20
    # idx_scan = 0 means nothing until stats have covered a normal business cycle.
    stats_min_age_days: int = 7


DEFAULTS = Thresholds()


@dataclass(frozen=True)
class TableStat:
    schema: str
    table: str
    live: int
    dead: int
    mod_since_analyze: int
    last_vacuum: datetime | None
    last_analyze: datetime | None
    total_bytes: int

    @property
    def name(self) -> str:
        return f"{self.schema}.{self.table}"

    @property
    def dead_ratio(self) -> float:
        total = self.live + self.dead
        return self.dead / total if total else 0.0


@dataclass(frozen=True)
class IndexRef:
    schema: str
    table: str
    index: str
    bytes: int
    definition: str = ""

    @property
    def name(self) -> str:
        return f"{self.schema}.{self.index}"


@dataclass(frozen=True)
class SpatialColumn:
    schema: str
    table: str
    column: str
    kind: str  # geometry | geography
    rows: int


@dataclass
class MaintenanceSnapshot:
    stats_age_days: float | None
    tables: list[TableStat] = field(default_factory=list)
    unused_indexes: list[IndexRef] = field(default_factory=list)
    duplicate_indexes: list[list[IndexRef]] = field(default_factory=list)
    invalid_indexes: list[IndexRef] = field(default_factory=list)
    unindexed_spatial: list[SpatialColumn] = field(default_factory=list)


def gather(conn) -> MaintenanceSnapshot:
    q = conn.execute
    skip = list(SKIP_SCHEMAS)

    reset = q(
        "SELECT extract(epoch FROM now() - stats_reset) / 86400 AS days "
        "FROM pg_stat_database WHERE datname = current_database()"
    ).fetchone()
    stats_age = float(reset["days"]) if reset and reset["days"] is not None else None
    if stats_age is None:
        # Never reset: stats are as old as the cluster's postmaster start, at least.
        up = q("SELECT extract(epoch FROM now() - pg_postmaster_start_time()) / 86400 AS d")
        stats_age = float(up.fetchone()["d"])

    tables = [
        TableStat(
            r["schemaname"],
            r["relname"],
            r["n_live_tup"],
            r["n_dead_tup"],
            r["n_mod_since_analyze"],
            r["last_vac"],
            r["last_an"],
            r["bytes"],
        )
        for r in q(
            """
            SELECT schemaname, relname, n_live_tup, n_dead_tup, n_mod_since_analyze,
                   greatest(last_vacuum, last_autovacuum) AS last_vac,
                   greatest(last_analyze, last_autoanalyze) AS last_an,
                   pg_total_relation_size(relid) AS bytes
              FROM pg_stat_user_tables
             WHERE schemaname <> ALL(%s)
            """,
            (skip,),
        )
    ]

    unused = [
        IndexRef(r["schemaname"], r["relname"], r["indexrelname"], r["bytes"], r["def"])
        for r in q(
            """
            SELECT s.schemaname, s.relname, s.indexrelname,
                   pg_relation_size(s.indexrelid) AS bytes,
                   pg_get_indexdef(s.indexrelid) AS def
              FROM pg_stat_user_indexes s
              JOIN pg_index i ON i.indexrelid = s.indexrelid
             WHERE s.idx_scan = 0
               AND NOT i.indisunique AND NOT i.indisprimary AND NOT i.indisexclusion
               AND s.schemaname <> ALL(%s)
             ORDER BY bytes DESC
            """,
            (skip,),
        )
    ]

    groups: dict[str, list[IndexRef]] = {}
    for r in q(
        """
        SELECT n.nspname AS schema, t.relname AS tbl, c.relname AS idx,
               pg_relation_size(c.oid) AS bytes, pg_get_indexdef(c.oid) AS def,
               i.indrelid::text || ':' || i.indkey::text || ':' || i.indclass::text || ':' ||
               coalesce(pg_get_expr(i.indexprs, i.indrelid), '') || ':' ||
               coalesce(pg_get_expr(i.indpred, i.indrelid), '') AS sig
          FROM pg_index i
          JOIN pg_class c ON c.oid = i.indexrelid
          JOIN pg_class t ON t.oid = i.indrelid
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname <> ALL(%s)
        """,
        (skip,),
    ):
        groups.setdefault(r["sig"], []).append(
            IndexRef(r["schema"], r["tbl"], r["idx"], r["bytes"], r["def"])
        )
    duplicates = [sorted(g, key=lambda x: x.index) for g in groups.values() if len(g) > 1]

    invalid = [
        IndexRef(r["schema"], r["tbl"], r["idx"], r["bytes"], r["def"])
        for r in q(
            """
            SELECT n.nspname AS schema, t.relname AS tbl, c.relname AS idx,
                   pg_relation_size(c.oid) AS bytes, pg_get_indexdef(c.oid) AS def
              FROM pg_index i
              JOIN pg_class c ON c.oid = i.indexrelid
              JOIN pg_class t ON t.oid = i.indrelid
              JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE NOT i.indisvalid
            """
        )
    ]

    unindexed: list[SpatialColumn] = []
    has_postgis = q("SELECT 1 FROM pg_extension WHERE extname = 'postgis'").fetchone()
    if has_postgis:
        unindexed = [
            SpatialColumn(r["schema"], r["tbl"], r["col"], r["kind"], r["rows"])
            for r in q(
                """
                SELECT n.nspname AS schema, c.relname AS tbl, a.attname AS col,
                       ty.typname AS kind, greatest(c.reltuples, 0)::bigint AS rows
                  FROM pg_attribute a
                  JOIN pg_class c ON c.oid = a.attrelid AND c.relkind IN ('r', 'p', 'm')
                  JOIN pg_namespace n ON n.oid = c.relnamespace
                  JOIN pg_type ty ON ty.oid = a.atttypid
                 WHERE ty.typname IN ('geometry', 'geography')
                   AND a.attnum > 0 AND NOT a.attisdropped
                   AND n.nspname <> ALL(%s)
                   AND NOT EXISTS (
                         SELECT 1
                           FROM pg_index i
                           JOIN pg_class ic ON ic.oid = i.indexrelid
                           JOIN pg_am am ON am.oid = ic.relam
                          WHERE i.indrelid = c.oid
                            AND a.attnum = ANY(i.indkey)
                            AND am.amname IN ('gist', 'spgist', 'brin'))
                 ORDER BY 1, 2, 3
                """,
                (skip,),
            )
        ]

    return MaintenanceSnapshot(stats_age, tables, unused, duplicates, invalid, unindexed)


def _mib(n: int) -> str:
    return f"{n / (1 << 20):.1f} MiB"


def evaluate(s: MaintenanceSnapshot, t: Thresholds = DEFAULTS) -> list[Finding]:
    out: list[Finding] = []

    bloated = [
        x for x in s.tables if x.dead >= t.dead_rows_min and x.dead_ratio >= t.dead_ratio_warn
    ]
    for x in sorted(bloated, key=lambda x: x.dead, reverse=True):
        hint = (
            " If this is an sde state or lineage table, a full compress removes the rows "
            "vacuum cannot."
            if x.schema == "sde" or x.table.startswith(("sde_state", "sde_lineage"))
            else ""
        )
        out.append(
            Finding(
                "MNT001",
                Severity.WARN,
                f"{x.name}: {x.dead:,} dead rows ({x.dead_ratio:.0%})",
                f"Last vacuum: {x.last_vacuum or 'never'}. Run VACUUM (ANALYZE) {x.name}; if this "
                f"recurs, lower autovacuum_vacuum_scale_factor for the table.{hint}",
                {"table": x.name, "dead": x.dead, "live": x.live, "bytes": x.total_bytes},
            )
        )
    if not bloated:
        out.append(Finding("MNT001", Severity.OK, "No tables over the dead-row threshold"))

    stale = []
    for x in s.tables:
        if x.last_analyze is None and x.live >= t.never_analyzed_rows_min:
            stale.append((x, "never analyzed"))
        elif (
            x.mod_since_analyze >= t.stale_analyze_rows_min
            and x.mod_since_analyze >= t.stale_analyze_ratio * max(x.live, 1)
        ):
            stale.append((x, f"{x.mod_since_analyze:,} rows changed since last analyze"))
    for x, why in stale:
        out.append(
            Finding(
                "MNT002",
                Severity.WARN,
                f"{x.name}: statistics stale ({why})",
                f"Run ANALYZE {x.name}. Stale stats make the planner skip spatial indexes. "
                "After a bulk load in ArcGIS, the Analyze Datasets tool does the same.",
                {"table": x.name},
            )
        )
    if not stale:
        out.append(Finding("MNT002", Severity.OK, "Planner statistics are current"))

    young = s.stats_age_days is not None and s.stats_age_days < t.stats_min_age_days
    big_unused = [i for i in s.unused_indexes if i.bytes >= t.unused_index_min_bytes]
    for i in big_unused:
        out.append(
            Finding(
                "MNT003",
                Severity.INFO if young else Severity.WARN,
                f"{i.name} on {i.schema}.{i.table} never scanned ({_mib(i.bytes)})",
                (
                    f"Statistics are only {s.stats_age_days:.1f} days old, so this may just be "
                    "quiet. "
                    if young
                    else ""
                )
                + "Confirm it is not used by a monthly or yearly job, then DROP INDEX "
                "CONCURRENTLY. Every unused index slows every write.",
                {"index": i.name, "definition": i.definition},
            )
        )
    small = len(s.unused_indexes) - len(big_unused)
    if not big_unused:
        out.append(
            Finding(
                "MNT003",
                Severity.OK,
                "No large unused indexes"
                + (
                    f" ({small} small ones under {_mib(t.unused_index_min_bytes)} not listed)"
                    if small
                    else ""
                ),
            )
        )

    for group in s.duplicate_indexes:
        keep, *extra = group
        out.append(
            Finding(
                "MNT004",
                Severity.WARN,
                f"Duplicate indexes on {keep.schema}.{keep.table}: "
                + ", ".join(i.index for i in group),
                f"Identical definitions. Keep one and DROP INDEX CONCURRENTLY the others "
                f"(wasted: {_mib(sum(i.bytes for i in extra))}).",
                {"indexes": [i.definition for i in group]},
            )
        )
    if not s.duplicate_indexes:
        out.append(Finding("MNT004", Severity.OK, "No duplicate indexes"))

    for i in s.invalid_indexes:
        out.append(
            Finding(
                "MNT005",
                Severity.FAIL,
                f"Invalid index {i.name} on {i.schema}.{i.table}",
                "Left by a failed CREATE INDEX CONCURRENTLY. It is maintained on every write but "
                "never used. DROP INDEX CONCURRENTLY it and rebuild.",
                {"definition": i.definition},
            )
        )
    if not s.invalid_indexes:
        out.append(Finding("MNT005", Severity.OK, "No invalid indexes"))

    for c in s.unindexed_spatial:
        out.append(
            Finding(
                "MNT006",
                Severity.WARN,
                f"{c.schema}.{c.table}.{c.column} ({c.kind}) has no spatial index",
                f"About {c.rows:,} rows. Every map draw and spatial query on this column is a "
                f"full scan. CREATE INDEX CONCURRENTLY ON {c.schema}.{c.table} USING GIST "
                f"({c.column}); or Add Spatial Index in ArcGIS for registered data.",
                {"table": f"{c.schema}.{c.table}", "column": c.column},
            )
        )
    if not s.unindexed_spatial:
        out.append(Finding("MNT006", Severity.OK, "Every spatial column has a spatial index"))

    return out
