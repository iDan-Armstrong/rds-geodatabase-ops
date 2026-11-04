"""Integration tests need a real PostgreSQL with PostGIS and pg_stat_statements preloaded.

CI starts postgis/postgis in a service container and sets RDSOPS_TEST_DSN. Locally:

    docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=gis postgis/postgis:17-3.5 \\
        -c shared_preload_libraries=pg_stat_statements
    export RDSOPS_TEST_DSN="host=localhost user=postgres password=gis dbname=postgres"

Each test builds its own schema and drops it afterwards.
"""

import os
import uuid

import psycopg
import pytest
from psycopg.rows import dict_row

DSN = os.environ.get("RDSOPS_TEST_DSN")


def pytest_collection_modifyitems(items):
    skip = pytest.mark.skip(reason="RDSOPS_TEST_DSN not set")
    for item in items:
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.pg)
            if not DSN:
                item.add_marker(skip)


@pytest.fixture
def admin():
    """Read-write connection for building fixtures (rdsops itself only ever reads)."""
    with psycopg.connect(DSN, autocommit=True, row_factory=dict_row) as conn:
        conn.execute("CREATE EXTENSION IF NOT EXISTS postgis")
        conn.execute("CREATE EXTENSION IF NOT EXISTS pg_stat_statements")
        yield conn


@pytest.fixture
def schema(admin):
    name = f"t_{uuid.uuid4().hex[:8]}"
    admin.execute(f"CREATE SCHEMA {name}")
    yield name
    admin.execute(f"DROP SCHEMA {name} CASCADE")


@pytest.fixture
def ro():
    from rdsops.db import ConnectOptions, connect

    with connect(ConnectOptions(dsn=DSN)) as conn:
        yield conn
