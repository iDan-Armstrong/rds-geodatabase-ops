import json
from datetime import UTC, datetime, timedelta

import boto3
import pytest
from conftest import make_instance
from moto import mock_aws
from test_security import facts

from rdsops import failover, resilience
from rdsops.findings import Severity

NOW = datetime(2026, 11, 5, 12, tzinfo=UTC)
T = resilience.Targets(rto_minutes=60, rpo_minutes=15)


def snap(**kw):
    base = dict(
        facts=facts(multi_az=True),
        region="us-east-1",
        dr_region="us-west-2",
        latest_restorable=NOW - timedelta(minutes=4),
        backup_replications=[
            resilience.BackupReplication(
                "us-west-2",
                "arn:aws:rds:us-west-2:111122223333:auto-backup:ab-x",
                7,
                NOW - timedelta(minutes=9),
                "replicating",
            )
        ],
        snapshot_copies=[],
        dr_kms_key=True,
        dr_engine_available=True,
        failover_events=True,
        measured_restore_minutes=41.0,
    )
    base.update(kw)
    return resilience.ResilienceSnapshot(**base)


def by(f, code):
    return [x for x in f if x.code == code]


def test_multi_az_with_replicated_backups_meets_targets():
    f = resilience.evaluate(snap(), NOW, T)
    assert not [x for x in f if x.severity >= Severity.WARN], [x.title for x in f]
    zone = [x for x in by(f, "RES003") if x.evidence["scenario"] == "zone"][0]
    assert zone.evidence["rpo_minutes"] == 0  # synchronous standby
    region = [x for x in by(f, "RES004") if x.evidence["scenario"] == "region"][0]
    assert region.evidence["rto_minutes"] == 41.0  # measured, not guessed


def test_no_dr_copy_and_single_az():
    s = snap(facts=facts(multi_az=False), backup_replications=[], measured_restore_minutes=None)
    f = resilience.evaluate(s, NOW, T)
    assert by(f, "RES002")[0].severity == Severity.WARN
    assert "No recovery path" in by(f, "RES002")[0].title
    # without a drill, the time to recover is unknown, never invented
    rto = [x for x in by(f, "RES004") if x.evidence["scenario"] == "zone"][0]
    assert "never measured" in rto.title
    s.production = True
    f = resilience.evaluate(s, NOW, T)
    assert by(f, "RES002")[0].severity == Severity.FAIL
    assert [x for x in by(f, "RES004") if x.evidence["scenario"] == "zone"][
        0
    ].severity == Severity.WARN


def test_old_snapshot_copy_is_the_data_loss():
    s = snap(
        backup_replications=[],
        snapshot_copies=[
            resilience.SnapshotCopy("egdb-copy", "us-west-2", NOW - timedelta(days=3))
        ],
    )
    f = resilience.evaluate(s, NOW, T)
    r = [x for x in by(f, "RES003") if x.evidence["scenario"] == "region"][0]
    assert r.severity == Severity.WARN and "3.0 h" not in r.title and "72" in r.title


def test_replica_lag_and_broken_replication():
    s = snap(replicas=[resilience.Replica("egdb-dr", "us-west-2", "replicating", 30)])
    f = resilience.evaluate(s, NOW, T)
    best = [x for x in by(f, "RES003") if x.evidence["scenario"] == "region"][0]
    assert "30 s" in best.title
    s = snap(replicas=[resilience.Replica("egdb-dr", "us-west-2", "error", None)])
    assert by(resilience.evaluate(s, NOW, T), "RES007")[0].severity == Severity.FAIL
    s = snap(replicas=[resilience.Replica("egdb-dr", "us-west-2", "replicating", 3600)])
    assert by(resilience.evaluate(s, NOW, T), "RES007")[0].severity == Severity.WARN


def test_dr_region_prerequisites():
    f = resilience.evaluate(
        snap(dr_kms_key=False, dr_engine_available=False, failover_events=False), NOW, T
    )
    assert by(f, "RES005")[0].severity == Severity.FAIL
    assert by(f, "RES006")[0].severity == Severity.WARN
    assert by(f, "RES008")[0].severity == Severity.INFO


def test_measured_times_from_reports():
    lines = [
        json.dumps({"findings": [{"code": "DRL011", "evidence": {"rto_minutes": 38.5}}]}),
        json.dumps(
            {"findings": [{"code": "DRD001", "evidence": {"kind": "region", "rto_minutes": 52}}]}
        ),
        "not json",
    ]
    m = resilience.measured_minutes(lines)
    assert m == {"restore": 38.5, "region": 52}


def test_gather_two_regions_with_moto():
    with mock_aws():
        rds = boto3.client("rds", region_name="us-east-1")
        dr = boto3.client("rds", region_name="us-west-2")
        kms = boto3.client("kms", region_name="us-west-2")
        key = kms.create_key(Description="dr")["KeyMetadata"]["KeyId"]
        make_instance(rds, "egdb-lab", MultiAZ=True)
        rds.create_db_snapshot(DBInstanceIdentifier="egdb-lab", DBSnapshotIdentifier="egdb-nightly")
        src = rds.describe_db_snapshots(DBSnapshotIdentifier="egdb-nightly")["DBSnapshots"][0]
        dr.copy_db_snapshot(
            SourceDBSnapshotIdentifier=src["DBSnapshotArn"],
            TargetDBSnapshotIdentifier="egdb-nightly-west",
            KmsKeyId=key,
            SourceRegion="us-east-1",
        )
        s = resilience.gather(
            rds,
            "egdb-lab",
            "us-east-1",
            dr_rds=dr,
            dr_region="us-west-2",
            kms=kms,
            dr_kms_key_id=key,
        )
    assert s.facts.multi_az
    assert [c.identifier for c in s.snapshot_copies] == ["egdb-nightly-west"]
    assert s.dr_kms_key is True
    f = resilience.evaluate(s, NOW, T)
    assert by(f, "RES002")[0].severity == Severity.OK


# ----------------------------------------------------------------- failover drills


def req(kind="az", **kw):
    return failover.FailoverRequest(kind, "egdb-lab", "us-east-1", "us-west-2", **kw)


def test_az_drill_needs_a_standby_and_warns_of_downtime():
    f, steps = failover.plan(req(), snap(facts=facts(multi_az=False)), NOW)
    assert f[0].severity == Severity.FAIL and not steps
    f, steps = failover.plan(req(), snap(), NOW)
    assert f[0].severity == Severity.WARN
    assert any("--force-failover" in s for s in steps)
    assert any("DNS TTL" in s for s in steps)


def test_region_drill_restores_a_scratch_copy_and_never_promotes():
    f, steps = failover.plan(req("region"), snap(), NOW)
    text = "\n".join(steps)
    assert "--source-db-instance-automated-backups-arn" in text and "us-west-2" in text
    assert "promote-read-replica" not in text and "not reversible" in text
    assert any(s.startswith("aws rds delete-db-instance") for s in steps)
    only_replica = snap(
        backup_replications=[], replicas=[resilience.Replica("egdb-dr", "us-west-2")]
    )
    f, steps = failover.plan(req("region"), only_replica, NOW)
    assert f[0].severity == Severity.WARN and not steps
    f, steps = failover.plan(req("region"), snap(backup_replications=[]), NOW)
    assert (
        f[0].severity == Severity.FAIL
        and "start-db-instance-automated-backups-replication" in f[0].detail
    )


def test_scoring_a_drill():
    start = NOW
    r = failover.FailoverResult(
        "az", start, start + timedelta(minutes=2), start + timedelta(minutes=11), 0
    )
    f = failover.evaluate(r, req(rto_minutes=15))
    assert by(f, "DRD001")[0].severity == Severity.OK
    assert by(f, "DRD003")[0].severity == Severity.WARN  # ArcGIS lagged the database
    r = failover.FailoverResult("az", start, start + timedelta(minutes=2), None, 5)
    f = failover.evaluate(r, req())
    assert by(f, "DRD002")[0].severity == Severity.FAIL  # loss on a synchronous standby
    assert by(f, "DRD003")[0].severity == Severity.WARN
    r = failover.FailoverResult("region", start, error="restore failed: KMS key not accessible")
    assert by(failover.evaluate(r, req("region")), "DRD005")[0].severity == Severity.FAIL


def test_result_round_trip_and_unknown_kind():
    d = {
        "kind": "region",
        "started": "2026-11-05T12:00:00Z",
        "writable_at": "2026-11-05T12:40:00Z",
        "apps_ok_at": "2026-11-05T12:44:00Z",
        "data_loss_seconds": 300,
        "checks": [{"name": "PostGIS", "ok": True}],
    }
    r = failover.result_from_dict(d)
    f = failover.evaluate(r, req("region"))
    assert by(f, "DRD001")[0].evidence == {"kind": "region", "rto_minutes": 44.0}
    with pytest.raises(ValueError):
        failover.plan(req("moon"), None, NOW)
