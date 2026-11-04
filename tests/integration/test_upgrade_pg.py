"""Upgrade context read from a real database with blockers seeded on purpose."""

from rdsops.findings import Severity
from rdsops.upgrade import UpgradeContext, context_from_db, plan


def test_context_from_db_finds_replication_blockers(admin, schema, ro):
    s = schema
    admin.execute(f"""
        CREATE TABLE {s}.with_pk (id int PRIMARY KEY);
        CREATE TABLE {s}.no_pk (objectid int, name text);
        CREATE TABLE {s}.unique_idx_only (objectid int NOT NULL);
        CREATE UNIQUE INDEX {s}_uix ON {s}.unique_idx_only (objectid);
        ALTER TABLE {s}.unique_idx_only REPLICA IDENTITY USING INDEX {s}_uix;
        CREATE UNLOGGED TABLE {s}.scratch (id int PRIMARY KEY);
    """)
    lo = admin.execute("SELECT lo_create(0) AS oid").fetchone()["oid"]
    try:
        ctx = context_from_db(ro, UpgradeContext("16.11", "18.1", "12.1"))
        assert ctx.postgis_version
        assert f"{s}.no_pk" in ctx.tables_without_pk
        assert f"{s}.with_pk" not in ctx.tables_without_pk
        assert f"{s}.unique_idx_only" not in ctx.tables_without_pk  # replica identity set
        assert f"{s}.scratch" in ctx.unlogged_tables
        assert ctx.large_object_count >= 1
        assert ctx.has_geodatabase is False
        p = plan(ctx)
        assert "UPG012" in {f.code for f in p.findings if f.severity == Severity.FAIL}
    finally:
        admin.execute(f"SELECT lo_unlink({lo})")
