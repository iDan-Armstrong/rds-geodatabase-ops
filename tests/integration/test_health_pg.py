"""Health checks against a live server, including a real blocked session."""

import contextlib
import threading
import time

import psycopg

from rdsops import health
from rdsops.findings import Severity

from .conftest import DSN


def by_code(findings, c):
    return [f for f in findings if f.code == c]


def test_baseline_snapshot(ro, admin):
    snap = health.gather(ro)
    assert snap.postgis_version
    assert snap.max_connections > snap.client_connections > 0
    assert snap.stat_statements == "ok"
    f = health.evaluate(snap)
    assert by_code(f, "HLT001")[0].severity == Severity.OK
    assert by_code(f, "HLT009")[0].severity == Severity.INFO


def test_idle_in_transaction_and_lock_wait_are_seen(ro, schema, admin):
    admin.execute(f"CREATE TABLE {schema}.edits (id int)")
    holder = psycopg.connect(DSN, application_name="ArcSOC-test")
    holder.execute(f"LOCK TABLE {schema}.edits IN ACCESS EXCLUSIVE MODE")  # opens a txn

    def waiter():
        with psycopg.connect(DSN, autocommit=True) as c:
            c.execute("SET lock_timeout = '10s'")
            with contextlib.suppress(psycopg.errors.LockNotAvailable):
                c.execute(f"SELECT count(*) FROM {schema}.edits")

    t = threading.Thread(target=waiter)
    t.start()
    try:
        time.sleep(1.5)
        th = health.Thresholds(idle_in_txn_seconds=1)
        f = health.evaluate(health.gather(ro, th), th)
        idle = by_code(f, "HLT003")[0]
        assert idle.severity == Severity.WARN and "ArcSOC-test" in idle.detail
        assert by_code(f, "HLT004")[0].severity == Severity.WARN
    finally:
        holder.rollback()
        holder.close()
        t.join()
