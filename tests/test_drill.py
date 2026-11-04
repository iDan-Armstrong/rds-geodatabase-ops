"""Restore drills: pure planning and scoring, then a full drill against mocked RDS."""

import json
from datetime import UTC, datetime, timedelta

import pytest
from conftest import make_instance

from rdsops import drill
from rdsops.cli import main
from rdsops.drill import BackupFacts, DrillRequest, DrillResult, Snapshot, VerifyCheck
from rdsops.findings import Severity

NOW = datetime(2026, 11, 4, 18, 0, tzinfo=UTC)


def facts(**kw):
    base = dict(
        source="egdb",
        engine_version="17.7",
        instance_class="db.t4g.micro",
        retention_days=7,
        latest_restorable=NOW - timedelta(minutes=4),
        earliest_restorable=NOW - timedelta(days=7),
        snapshots=[Snapshot("rds:egdb-2026-11-04-07-00", NOW - timedelta(hours=11), "automated")],
        subnet_group="egdb",
        security_groups=["sg-1"],
        parameter_group="egdb-pg17",
        iam_auth=True,
        deletion_protection=True,
    )
    base.update(kw)
    return BackupFacts(**base)


def sev(findings, code):
    return [f.severity for f in findings if f.code == code]


# ------------------------------------------------------------------- plan


def test_pitr_plan_is_clean_and_steps_are_safe():
    f, steps = drill.plan(DrillRequest("egdb"), facts(), NOW)
    assert all(x.severity <= Severity.INFO for x in f)
    assert "--use-latest-restorable-time" in steps[0]
    assert "--no-deletion-protection" in steps[0] and "--no-publicly-accessible" in steps[0]
    assert "delete-db-instance" in steps[-1]


def test_pitr_without_backups_fails():
    f, _ = drill.plan(DrillRequest("egdb"), facts(retention_days=0, latest_restorable=None), NOW)
    assert sev(f, "DRL001") == [Severity.FAIL]


def test_restore_time_outside_window_fails():
    req = DrillRequest("egdb", restore_time=NOW - timedelta(days=10))
    f, _ = drill.plan(req, facts(), NOW)
    assert sev(f, "DRL002") == [Severity.FAIL]


def test_snapshot_mode_uses_newest_and_flags_rpo():
    snaps = [
        Snapshot("old", NOW - timedelta(days=2), "automated"),
        Snapshot("new", NOW - timedelta(hours=11), "manual"),
    ]
    f, steps = drill.plan(DrillRequest("egdb", mode="snapshot"), facts(snapshots=snaps), NOW)
    assert "new" in steps[0]
    assert sev(f, "DRL003") == [Severity.WARN]  # 11 hours of data loss vs 15 min target


def test_snapshot_mode_without_snapshots_fails():
    f, _ = drill.plan(DrillRequest("egdb", mode="snapshot"), facts(snapshots=[]), NOW)
    assert sev(f, "DRL001") == [Severity.FAIL]


# --------------------------------------------------------------- evaluate


def result(**kw):
    base = dict(
        target_id="egdb-drill",
        restore_point=NOW - timedelta(minutes=5),
        started=NOW,
        restore_requested=NOW + timedelta(minutes=1),
        available=NOW + timedelta(minutes=22),
        verified=NOW + timedelta(minutes=24),
        deleted=NOW + timedelta(minutes=25),
        checks=[VerifyCheck("connect", True), VerifyCheck("gis.parcels rows", True, "10 rows")],
    )
    base.update(kw)
    return DrillResult(**base)


def test_good_drill_passes_with_measured_times():
    f = drill.evaluate(result(), DrillRequest("egdb", rto_minutes=60, rpo_minutes=15))
    assert all(x.severity == Severity.OK for x in f)
    rto = next(x for x in f if x.code == "DRL011")
    assert rto.evidence["rto_minutes"] == 24.0


def test_slow_drill_fails_rto():
    f = drill.evaluate(result(), DrillRequest("egdb", rto_minutes=15))
    assert sev(f, "DRL011") == [Severity.FAIL]


def test_failed_check_unverified_kept_and_errors():
    bad = result(checks=[VerifyCheck("gis.parcels rows", False, "table not found in the copy")])
    assert Severity.FAIL in sev(drill.evaluate(bad, DrillRequest("egdb")), "DRL013")
    unverified = result(checks=[], verified=None)
    assert sev(drill.evaluate(unverified, DrillRequest("egdb")), "DRL013") == [Severity.WARN]
    kept = result(kept=True, deleted=None)
    assert sev(drill.evaluate(kept, DrillRequest("egdb")), "DRL014") == [Severity.WARN]
    broke = result(available=None, verified=None, error="InsufficientDBInstanceCapacity")
    f = drill.evaluate(broke, DrillRequest("egdb"))
    assert sev(f, "DRL010") == [Severity.FAIL]


# ---------------------------------------------------------- mocked drill


class Clock:
    def __init__(self):
        self.t = NOW

    def __call__(self):
        self.t += timedelta(minutes=7)
        return self.t


@pytest.mark.parametrize("mode", ["pitr", "snapshot"])
def test_full_drill_restores_verifies_and_deletes(rds, mode):
    make_instance(rds, DeletionProtection=True)  # the copy must not inherit this
    rds.create_db_snapshot(DBInstanceIdentifier="egdb-lab", DBSnapshotIdentifier="egdb-manual")
    f = drill.gather_backup_facts(rds, "egdb-lab")
    req = DrillRequest("egdb-lab", mode=mode, target_id="egdb-lab-drill")
    seen = []
    res = drill.run(
        rds,
        req,
        f,
        now=Clock(),
        log=lambda m: None,
        wait_delay=1,
        wait_attempts=2,
        verifier=lambda host: seen.append(host) or [VerifyCheck("connect", True)],
    )
    assert res.error is None, res.error
    assert res.deleted and seen and seen[0]
    left = [d["DBInstanceIdentifier"] for d in rds.describe_db_instances()["DBInstances"]]
    assert left == ["egdb-lab"]
    findings = drill.evaluate(res, req)
    assert not [x for x in findings if x.severity >= Severity.WARN], findings


def test_keep_leaves_the_copy(rds):
    make_instance(rds)
    f = drill.gather_backup_facts(rds, "egdb-lab")
    res = drill.run(
        rds,
        DrillRequest("egdb-lab", target_id="kept", keep=True),
        f,
        now=Clock(),
        log=lambda m: None,
        wait_delay=1,
        wait_attempts=2,
    )
    assert res.kept and not res.deleted
    assert "kept" in [d["DBInstanceIdentifier"] for d in rds.describe_db_instances()["DBInstances"]]


def test_cli_plans_by_default_and_creates_nothing(rds, capsys):
    make_instance(rds)
    code = main(["restore-drill", "--instance", "egdb-lab", "--region", "us-east-1"])
    out = capsys.readouterr().out
    assert "plan only" in out and "Steps" in out
    assert code == 0
    assert len(rds.describe_db_instances()["DBInstances"]) == 1


def test_cli_execute_writes_a_report(rds, capsys, tmp_path, monkeypatch):
    make_instance(rds)
    monkeypatch.setattr(drill, "run", _fast_run(drill.run))
    report = tmp_path / "drills.jsonl"
    code = main(
        [
            "restore-drill",
            "--instance",
            "egdb-lab",
            "--region",
            "us-east-1",
            "--execute",
            "--report",
            str(report),
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["result"]["deleted"]
    assert code == 1  # not verified (no connection options) is a warning
    line = json.loads(report.read_text().splitlines()[0])
    assert line["result"]["target_id"].startswith("egdb-lab-drill-")


def _fast_run(real):
    def wrapper(*a, **kw):
        kw.update(wait_delay=1, wait_attempts=2)
        return real(*a, **kw)

    return wrapper


def test_delete_guard_refuses_source_and_untagged(rds):
    make_instance(rds)
    make_instance(rds, identifier="not-a-drill")
    with pytest.raises(RuntimeError, match="source"):
        drill._delete_copy(rds, "egdb-lab", "egdb-lab")
    with pytest.raises(RuntimeError, match="not tagged"):
        drill._delete_copy(rds, "not-a-drill", "egdb-lab")
    assert len(rds.describe_db_instances()["DBInstances"]) == 2


def test_restore_point_after_start_is_not_negative_data_loss():
    r = result(restore_point=NOW + timedelta(minutes=3))  # clock skew between hosts
    rpo = next(x for x in drill.evaluate(r, DrillRequest("egdb")) if x.code == "DRL012")
    assert rpo.evidence["rpo_minutes"] == 0.0
