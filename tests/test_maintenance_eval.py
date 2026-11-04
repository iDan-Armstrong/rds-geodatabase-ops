"""Threshold logic for `rdsops maintenance`, no database needed."""

from datetime import UTC, datetime

from rdsops.findings import Severity
from rdsops.maintenance import (
    IndexRef,
    MaintenanceSnapshot,
    SpatialColumn,
    TableStat,
    evaluate,
)

NOW = datetime(2026, 11, 4, tzinfo=UTC)


def table(name="parcels", schema="gis", live=100_000, dead=0, mod=0, analyzed=NOW):
    return TableStat(schema, name, live, dead, mod, NOW, analyzed, 50 << 20)


def code(findings, c):
    return [f for f in findings if f.code == c]


def test_clean_snapshot_is_all_ok():
    f = evaluate(MaintenanceSnapshot(stats_age_days=30, tables=[table()]))
    assert all(x.severity == Severity.OK for x in f)


def test_dead_rows_need_both_ratio_and_count():
    s = MaintenanceSnapshot(
        30,
        tables=[
            table("big_ratio_few_rows", live=100, dead=900),  # 90% but only 900 rows
            table("many_rows_low_ratio", live=10_000_000, dead=50_000),  # 0.5%
            table("bloated", live=100_000, dead=60_000),
        ],
    )
    hits = code(evaluate(s), "MNT001")
    assert [h.evidence["table"] for h in hits] == ["gis.bloated"]


def test_sde_state_tables_get_the_compress_hint():
    s = MaintenanceSnapshot(
        30, tables=[table("sde_state_lineages", schema="sde", live=50_000, dead=200_000)]
    )
    assert "compress" in code(evaluate(s), "MNT001")[0].detail


def test_stale_and_never_analyzed_statistics():
    s = MaintenanceSnapshot(
        30,
        tables=[
            table("fresh_load", live=500_000, analyzed=None),
            table("heavy_edits", live=100_000, mod=40_000),
            table("light_edits", live=100_000, mod=5_000),
        ],
    )
    names = {f.evidence["table"] for f in code(evaluate(s), "MNT002")}
    assert names == {"gis.fresh_load", "gis.heavy_edits"}


def test_unused_index_is_info_while_stats_are_young():
    idx = IndexRef("gis", "parcels", "parcels_owner_idx", 64 << 20, "CREATE INDEX ...")
    old = code(evaluate(MaintenanceSnapshot(30, unused_indexes=[idx])), "MNT003")[0]
    young = code(evaluate(MaintenanceSnapshot(2, unused_indexes=[idx])), "MNT003")[0]
    assert old.severity == Severity.WARN
    assert young.severity == Severity.INFO and "2.0 days" in young.detail


def test_small_unused_indexes_are_summarised_not_listed():
    small = IndexRef("gis", "t", "tiny_idx", 16 << 10)
    f = code(evaluate(MaintenanceSnapshot(30, unused_indexes=[small])), "MNT003")
    assert len(f) == 1 and f[0].severity == Severity.OK and "1 small" in f[0].title


def test_duplicates_invalid_and_unindexed_spatial():
    a = IndexRef("gis", "parcels", "parcels_apn_a", 10 << 20)
    b = IndexRef("gis", "parcels", "parcels_apn_b", 10 << 20)
    bad = IndexRef("gis", "parcels", "parcels_geom_ccnew", 1 << 20)
    col = SpatialColumn("gis", "manholes", "shape", "geometry", 12_000)
    f = evaluate(
        MaintenanceSnapshot(
            30, duplicate_indexes=[[a, b]], invalid_indexes=[bad], unindexed_spatial=[col]
        )
    )
    assert code(f, "MNT004")[0].severity == Severity.WARN
    assert "10.0 MiB" in code(f, "MNT004")[0].detail
    assert code(f, "MNT005")[0].severity == Severity.FAIL
    m6 = code(f, "MNT006")[0]
    assert m6.severity == Severity.WARN and "USING GIST (shape)" in m6.detail
