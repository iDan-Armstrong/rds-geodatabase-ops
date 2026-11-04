"""Seed real problems into PostGIS and check `maintenance.gather` finds each one."""

import psycopg
import pytest

from rdsops import maintenance
from rdsops.findings import Severity


def by_code(findings, c):
    return [f for f in findings if f.code == c]


def test_finds_seeded_problems(admin, schema, ro):
    s = schema
    admin.execute(f"""
        CREATE TABLE {s}.manholes (
            id bigint PRIMARY KEY,
            asset_id text,
            shape geometry(Point, 4326)
        ) WITH (autovacuum_enabled = false);
        INSERT INTO {s}.manholes
        SELECT g, 'MH-' || g, ST_SetSRID(ST_MakePoint(-77 + g * 1e-5, 38), 4326)
          FROM generate_series(1, 50000) g;
        CREATE INDEX mh_asset_a ON {s}.manholes (asset_id);
        CREATE INDEX mh_asset_b ON {s}.manholes (asset_id);
        CREATE TABLE {s}.parcels (id int PRIMARY KEY, shape geometry(Polygon, 4326));
        CREATE INDEX parcels_shape_gix ON {s}.parcels USING gist (shape);
        DELETE FROM {s}.manholes WHERE id <= 30000;
    """)
    # A failed CREATE INDEX CONCURRENTLY leaves an invalid index behind.
    admin.execute(
        f"INSERT INTO {s}.manholes VALUES (40001000, 'MH-1', NULL), (40001001, 'MH-1', NULL)"
    )
    with pytest.raises(psycopg.errors.UniqueViolation):
        admin.execute(
            f"CREATE UNIQUE INDEX CONCURRENTLY mh_asset_unique ON {s}.manholes (asset_id)"
        )
    admin.execute("SELECT pg_stat_force_next_flush()")

    snap = maintenance.gather(ro)
    mine = [t for t in snap.tables if t.schema == s]
    manholes = next(t for t in mine if t.table == "manholes")
    assert manholes.dead >= 30_000

    f = maintenance.evaluate(snap)
    assert any(x.evidence.get("table") == f"{s}.manholes" for x in by_code(f, "MNT001"))
    dup = [x for x in by_code(f, "MNT004") if s in x.title]
    assert dup and "mh_asset_a" in dup[0].title and "mh_asset_b" in dup[0].title
    assert any("mh_asset_unique" in x.title for x in by_code(f, "MNT005"))
    assert all(x.severity == Severity.FAIL for x in by_code(f, "MNT005"))
    unindexed = {x.evidence["table"] for x in by_code(f, "MNT006") if x.evidence}
    assert f"{s}.manholes" in unindexed
    assert f"{s}.parcels" not in unindexed


def test_connection_is_read_only(ro, schema):
    with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
        ro.execute(f"CREATE TABLE {schema}.nope (id int)")
