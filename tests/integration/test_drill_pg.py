"""verify_restored against a real PostGIS (standing in for the restored copy)."""

from rdsops.drill import verify_restored


def test_verify_counts_rows_and_reports_missing_tables(admin, schema, ro):
    admin.execute(f"CREATE TABLE {schema}.parcels (id int PRIMARY KEY)")
    admin.execute(f"INSERT INTO {schema}.parcels SELECT generate_series(1, 25)")
    checks = {c.name: c for c in verify_restored(ro, [f"{schema}.parcels", f"{schema}.missing"])}
    assert checks["connect"].ok
    assert checks["PostGIS present"].ok
    assert (
        checks[f"{schema}.parcels rows"].ok and "25 rows" in checks[f"{schema}.parcels rows"].detail
    )
    assert not checks[f"{schema}.missing rows"].ok
