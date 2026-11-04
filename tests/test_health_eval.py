"""Threshold logic for `rdsops health`, no database needed."""

from rdsops.findings import Severity
from rdsops.health import HealthSnapshot, Session, Slot, Thresholds, TopQuery, evaluate


def snap(**kw):
    base = dict(
        server_version="17.7",
        postgis_version="3.5.2",
        max_connections=100,
        reserved_connections=3,
        client_connections=10,
        connections_by_state={"active": 2, "idle": 8},
        oldest_xid_age=50_000_000,
        oldest_xid_database="egdb",
        cache_hit_ratio=0.99,
        stat_statements="ok",
    )
    base.update(kw)
    return HealthSnapshot(**base)


def code(findings, c):
    return [f for f in findings if f.code == c]


def test_quiet_database_is_all_ok_or_info():
    assert all(f.severity <= Severity.INFO for f in evaluate(snap()))


def test_connection_thresholds_use_usable_slots():
    # 97 usable after 3 reserved: 78 is 80.4% -> warn, 93 is 95.9% -> fail
    assert code(evaluate(snap(client_connections=77)), "HLT001")[0].severity == Severity.OK
    assert code(evaluate(snap(client_connections=78)), "HLT001")[0].severity == Severity.WARN
    assert code(evaluate(snap(client_connections=93)), "HLT001")[0].severity == Severity.FAIL


def test_long_running_and_idle_in_transaction_warn_with_the_worst_offender():
    s = snap(
        long_running=[Session(42, "gis_editor", "ArcGIS Pro", "active", 1800, "SELECT ...")],
        idle_in_transaction=[Session(7, "sde", "ArcSOC", "idle in transaction", 900, "")],
    )
    f = evaluate(s)
    assert code(f, "HLT002")[0].severity == Severity.WARN
    assert "pid 42" in code(f, "HLT002")[0].detail
    assert code(f, "HLT003")[0].severity == Severity.WARN
    assert "ArcSOC" in code(f, "HLT003")[0].detail


def test_xid_age_bands():
    t = Thresholds()
    assert code(evaluate(snap(oldest_xid_age=t.xid_age_warn - 1)), "HLT005")[0].severity == 0
    assert code(evaluate(snap(oldest_xid_age=t.xid_age_warn)), "HLT005")[0].severity == 2
    assert code(evaluate(snap(oldest_xid_age=t.xid_age_fail)), "HLT005")[0].severity == 3


def test_inactive_or_bloated_slot_warns():
    f = evaluate(
        snap(
            slots=[
                Slot("dms_task", active=False, retained_bytes=10 << 20),
                Slot("live_replica", active=True, retained_bytes=5 << 30),
                Slot("healthy", active=True, retained_bytes=1 << 20),
            ]
        )
    )
    sev = {x.title.split(":")[0]: x.severity for x in code(f, "HLT006")}
    assert sev["Replication slot dms_task"] == Severity.WARN
    assert sev["Replication slot live_replica"] == Severity.WARN
    assert sev["Replication slot healthy"] == Severity.OK


def test_stat_statements_states():
    assert code(evaluate(snap(stat_statements="not-preloaded")), "HLT008")[0].severity == 2
    assert code(evaluate(snap(stat_statements="not-created")), "HLT008")[0].severity == 2
    top = [TopQuery("SELECT shape FROM parcels", 1000, 12000.0, 12.0)]
    f = code(evaluate(snap(top_queries=top)), "HLT008")[0]
    assert f.severity == Severity.INFO and "parcels" in f.detail


def test_missing_postgis_warns():
    assert code(evaluate(snap(postgis_version=None)), "HLT009")[0].severity == Severity.WARN


def test_low_cache_hit_warns_and_unknown_is_info():
    assert code(evaluate(snap(cache_hit_ratio=0.80)), "HLT007")[0].severity == Severity.WARN
    assert code(evaluate(snap(cache_hit_ratio=None)), "HLT007")[0].severity == Severity.INFO
