"""Health: is the database serving well right now?

``gather`` runs read-only catalog queries and returns a snapshot. ``evaluate`` turns a
snapshot into findings and never touches the database, so every threshold is tested
without a server.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .findings import Finding, Severity


@dataclass(frozen=True)
class Thresholds:
    connections_warn_pct: float = 80.0
    connections_fail_pct: float = 95.0
    long_query_seconds: int = 900
    idle_in_txn_seconds: int = 300
    # Wraparound shutdown happens near 2.1 billion. RDS autovacuum freezes from 200
    # million by default, so a database past 500 million means autovacuum is losing.
    xid_age_warn: int = 500_000_000
    xid_age_fail: int = 1_000_000_000
    slot_retained_warn_bytes: int = 1 << 30
    cache_hit_warn: float = 0.90
    top_queries: int = 5


DEFAULTS = Thresholds()


@dataclass(frozen=True)
class Session:
    pid: int
    user: str | None
    application: str | None
    state: str | None
    seconds: float
    query: str


@dataclass(frozen=True)
class Slot:
    name: str
    active: bool
    retained_bytes: int | None


@dataclass(frozen=True)
class TopQuery:
    query: str
    calls: int
    total_ms: float
    mean_ms: float


@dataclass
class HealthSnapshot:
    server_version: str
    postgis_version: str | None
    max_connections: int
    reserved_connections: int
    client_connections: int
    connections_by_state: dict[str, int]
    long_running: list[Session] = field(default_factory=list)
    idle_in_transaction: list[Session] = field(default_factory=list)
    blocked_pids: list[int] = field(default_factory=list)
    oldest_xid_age: int = 0
    oldest_xid_database: str | None = None
    slots: list[Slot] = field(default_factory=list)
    database_size_bytes: int = 0
    cache_hit_ratio: float | None = None
    stat_statements: str = "missing"  # ok | not-preloaded | missing
    top_queries: list[TopQuery] = field(default_factory=list)


_SINCE = {"query_start", "state_change"}


def _sessions(conn, since: str, state_filter: str, seconds: int) -> list[Session]:
    """Client sessions matching state_filter whose `since` column is older than seconds."""
    assert since in _SINCE  # column names are fixed in code, never user input
    rows = conn.execute(
        f"""
        SELECT pid, usename, application_name, state,
               extract(epoch FROM clock_timestamp() - {since}) AS seconds,
               left(regexp_replace(query, '\\s+', ' ', 'g'), 160) AS query
          FROM pg_stat_activity
         WHERE backend_type = 'client backend'
           AND pid <> pg_backend_pid()
           AND {state_filter}
           AND clock_timestamp() - {since} > make_interval(secs => %s)
         ORDER BY seconds DESC
        """,
        (seconds,),
    ).fetchall()
    return [
        Session(
            r["pid"],
            r["usename"],
            r["application_name"],
            r["state"],
            float(r["seconds"]),
            r["query"],
        )
        for r in rows
    ]


def gather(conn, t: Thresholds = DEFAULTS) -> HealthSnapshot:
    q = conn.execute
    settings = {
        r["name"]: r["setting"]
        for r in q(
            "SELECT name, setting FROM pg_settings WHERE name IN "
            "('max_connections','superuser_reserved_connections','reserved_connections',"
            "'shared_preload_libraries','server_version')"
        )
    }
    reserved = int(settings.get("superuser_reserved_connections", 0)) + int(
        settings.get("reserved_connections", 0)
    )
    postgis = q("SELECT extversion FROM pg_extension WHERE extname = 'postgis'").fetchone()

    by_state = {
        (r["state"] or "unknown"): r["n"]
        for r in q(
            "SELECT state, count(*) AS n FROM pg_stat_activity "
            "WHERE backend_type = 'client backend' GROUP BY state"
        )
    }

    xid = q(
        "SELECT datname, age(datfrozenxid) AS age FROM pg_database "
        "WHERE datallowconn ORDER BY age DESC LIMIT 1"
    ).fetchone()

    slots = [
        Slot(r["slot_name"], r["active"], r["retained"])
        for r in q(
            "SELECT slot_name, active, "
            "CASE WHEN restart_lsn IS NULL THEN NULL ELSE "
            "pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn)::bigint END AS retained "
            "FROM pg_replication_slots"
        )
    ]

    stats = q(
        "SELECT pg_database_size(current_database()) AS size, "
        "blks_hit, blks_read FROM pg_stat_database WHERE datname = current_database()"
    ).fetchone()
    reads = (stats["blks_hit"] or 0) + (stats["blks_read"] or 0)
    cache_hit = (stats["blks_hit"] / reads) if reads > 10_000 else None

    blocked = [
        r["pid"]
        for r in q("SELECT pid FROM pg_stat_activity WHERE cardinality(pg_blocking_pids(pid)) > 0")
    ]

    snap = HealthSnapshot(
        server_version=settings.get("server_version", "?"),
        postgis_version=postgis["extversion"] if postgis else None,
        max_connections=int(settings["max_connections"]),
        reserved_connections=reserved,
        client_connections=sum(by_state.values()),
        connections_by_state=by_state,
        long_running=_sessions(conn, "query_start", "state = 'active'", t.long_query_seconds),
        idle_in_transaction=_sessions(
            conn, "state_change", "state LIKE 'idle in transaction%%'", t.idle_in_txn_seconds
        ),
        blocked_pids=blocked,
        oldest_xid_age=int(xid["age"]),
        oldest_xid_database=xid["datname"],
        slots=slots,
        database_size_bytes=int(stats["size"]),
        cache_hit_ratio=cache_hit,
    )

    has_ext = q("SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements'").fetchone()
    preloaded = "pg_stat_statements" in settings.get("shared_preload_libraries", "")
    if has_ext and preloaded:
        snap.stat_statements = "ok"
        snap.top_queries = [
            TopQuery(r["query"], int(r["calls"]), float(r["total_ms"]), float(r["mean_ms"]))
            for r in q(
                """
                SELECT left(regexp_replace(query, '\\s+', ' ', 'g'), 160) AS query,
                       calls, total_exec_time AS total_ms, mean_exec_time AS mean_ms
                  FROM pg_stat_statements
                 WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
                 ORDER BY total_exec_time DESC
                 LIMIT %s
                """,
                (t.top_queries,),
            )
        ]
    elif preloaded:
        snap.stat_statements = "not-created"
    else:
        snap.stat_statements = "not-preloaded"
    return snap


def _gib(n: int | None) -> str:
    return "unknown" if n is None else f"{n / (1 << 30):.1f} GiB"


def evaluate(s: HealthSnapshot, t: Thresholds = DEFAULTS) -> list[Finding]:
    out: list[Finding] = []

    usable = max(s.max_connections - s.reserved_connections, 1)
    pct = 100.0 * s.client_connections / usable
    sev = (
        Severity.FAIL
        if pct >= t.connections_fail_pct
        else Severity.WARN
        if pct >= t.connections_warn_pct
        else Severity.OK
    )
    out.append(
        Finding(
            "HLT001",
            sev,
            f"Connections {s.client_connections}/{usable} ({pct:.0f}%)",
            ""
            if sev == Severity.OK
            else "ArcGIS Server holds a pool per service instance. Check service min/max "
            "instances before raising max_connections, which costs memory per connection.",
            {"by_state": s.connections_by_state},
        )
    )

    if s.long_running:
        worst = s.long_running[0]
        out.append(
            Finding(
                "HLT002",
                Severity.WARN,
                f"{len(s.long_running)} quer{'y' if len(s.long_running) == 1 else 'ies'} "
                f"running longer than {t.long_query_seconds}s",
                f"Longest: pid {worst.pid} ({worst.user}, {worst.seconds:.0f}s): {worst.query}",
                {"pids": [x.pid for x in s.long_running]},
            )
        )
    else:
        out.append(Finding("HLT002", Severity.OK, "No long-running queries"))

    if s.idle_in_transaction:
        worst = s.idle_in_transaction[0]
        out.append(
            Finding(
                "HLT003",
                Severity.WARN,
                f"{len(s.idle_in_transaction)} session(s) idle in transaction over "
                f"{t.idle_in_txn_seconds}s",
                "Open transactions hold locks and stop vacuum from cleaning up. "
                f"Oldest: pid {worst.pid} ({worst.user}, {worst.application}, "
                f"{worst.seconds:.0f}s).",
                {"pids": [x.pid for x in s.idle_in_transaction]},
            )
        )
    else:
        out.append(Finding("HLT003", Severity.OK, "No sessions idle in transaction"))

    if s.blocked_pids:
        out.append(
            Finding(
                "HLT004",
                Severity.WARN,
                f"{len(s.blocked_pids)} session(s) waiting on locks",
                "Find the blocker with pg_blocking_pids(). Common cause on a geodatabase: a "
                "schema change or compress running while services hold shared locks.",
                {"pids": s.blocked_pids},
            )
        )
    else:
        out.append(Finding("HLT004", Severity.OK, "No lock waits"))

    sev = (
        Severity.FAIL
        if s.oldest_xid_age >= t.xid_age_fail
        else Severity.WARN
        if s.oldest_xid_age >= t.xid_age_warn
        else Severity.OK
    )
    out.append(
        Finding(
            "HLT005",
            sev,
            f"Transaction ID age {s.oldest_xid_age:,} ({s.oldest_xid_database})",
            ""
            if sev == Severity.OK
            else "Autovacuum is not keeping up with freezing. Find the oldest tables with "
            "age(relfrozenxid) and VACUUM (FREEZE) them before the wraparound safety stop.",
        )
    )

    if not s.slots:
        out.append(Finding("HLT006", Severity.OK, "No replication slots"))
    for slot in s.slots:
        big = slot.retained_bytes is not None and slot.retained_bytes >= t.slot_retained_warn_bytes
        sev = Severity.WARN if (not slot.active or big) else Severity.OK
        out.append(
            Finding(
                "HLT006",
                sev,
                f"Replication slot {slot.name}: {'active' if slot.active else 'INACTIVE'}, "
                f"retaining {_gib(slot.retained_bytes)} of WAL",
                ""
                if sev == Severity.OK
                else "A slot nobody reads holds WAL forever and fills storage. Drop it if its "
                "consumer (DMS task, blue/green leftover) is gone.",
            )
        )

    if s.cache_hit_ratio is None:
        out.append(Finding("HLT007", Severity.INFO, "Cache hit ratio: not enough reads yet"))
    else:
        sev = Severity.WARN if s.cache_hit_ratio < t.cache_hit_warn else Severity.OK
        out.append(
            Finding(
                "HLT007",
                sev,
                f"Cache hit ratio {s.cache_hit_ratio:.1%}",
                ""
                if sev == Severity.OK
                else "Working set does not fit in memory. Check top queries for missing indexes "
                "before sizing up the instance.",
            )
        )

    if s.stat_statements == "ok":
        if s.top_queries:
            top = s.top_queries[0]
            detail = "\n".join(
                f"{x.total_ms / 1000:.1f}s total, {x.calls} calls, {x.mean_ms:.1f} ms avg: "
                f"{x.query[:80]}"
                for x in s.top_queries
            )
            out.append(
                Finding(
                    "HLT008",
                    Severity.INFO,
                    f"Top query uses {top.total_ms / 1000:.1f}s total over {top.calls} calls",
                    detail,
                    {"top_queries": [vars(x) for x in s.top_queries]},
                )
            )
        else:
            out.append(Finding("HLT008", Severity.INFO, "pg_stat_statements has no data yet"))
    elif s.stat_statements == "not-created":
        out.append(
            Finding(
                "HLT008",
                Severity.WARN,
                "pg_stat_statements loaded but extension not created",
                "Run CREATE EXTENSION pg_stat_statements in this database.",
            )
        )
    else:
        out.append(
            Finding(
                "HLT008",
                Severity.WARN,
                "pg_stat_statements not in shared_preload_libraries",
                "Set it in the parameter group (the Terraform module does) and reboot.",
            )
        )

    out.append(
        Finding(
            "HLT009",
            Severity.INFO if s.postgis_version else Severity.WARN,
            f"PostGIS {s.postgis_version}" if s.postgis_version else "PostGIS not installed",
            ""
            if s.postgis_version
            else "An RDS geodatabase stores spatial data as PostGIS. CREATE EXTENSION postgis "
            "before enabling the geodatabase.",
            {"server_version": s.server_version, "database_size_bytes": s.database_size_bytes},
        )
    )
    return out


def storage_findings(cloudwatch, rds, identifier: str) -> list[Finding]:
    """Free storage from CloudWatch against allocated storage from the RDS API."""
    from datetime import UTC, datetime, timedelta

    db = rds.describe_db_instances(DBInstanceIdentifier=identifier)["DBInstances"][0]
    allocated = int(db["AllocatedStorage"]) * (1 << 30)
    ceiling = db.get("MaxAllocatedStorage")
    end = datetime.now(UTC) + timedelta(minutes=1)
    result = cloudwatch.get_metric_data(
        MetricDataQueries=[
            {
                "Id": "free",
                "MetricStat": {
                    "Metric": {
                        "Namespace": "AWS/RDS",
                        "MetricName": "FreeStorageSpace",
                        "Dimensions": [{"Name": "DBInstanceIdentifier", "Value": identifier}],
                    },
                    "Period": 300,
                    "Stat": "Minimum",
                },
            }
        ],
        StartTime=end - timedelta(minutes=30),
        EndTime=end,
    )["MetricDataResults"]
    points = result[0]["Values"] if result else []
    if not points:
        return [
            Finding(
                "HLT010",
                Severity.WARN,
                "No FreeStorageSpace data in the last 30 minutes",
                "Check the instance is running and CloudWatch access is allowed.",
            )
        ]
    free = int(min(points))
    pct = 100.0 * free / allocated
    autoscale = f", autoscaling to {ceiling} GB" if ceiling else ", no storage autoscaling"
    sev = Severity.FAIL if pct < 5 else Severity.WARN if pct < 15 else Severity.OK
    return [
        Finding(
            "HLT010",
            sev,
            f"Free storage {_gib(free)} of {_gib(allocated)} ({pct:.0f}%){autoscale}",
            ""
            if sev == Severity.OK
            else "A full volume stops all writes. Look for retained WAL (slots), bloat and old "
            "logs before adding storage, which cannot be shrunk later.",
            {"free_bytes": free, "allocated_bytes": allocated},
        )
    ]
