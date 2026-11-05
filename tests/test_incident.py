from datetime import UTC, datetime, timedelta

import pytest

from rdsops import incident
from rdsops.findings import Severity

NOW = datetime(2026, 11, 5, 14, tzinfo=UTC)


def ctx(kind, **kw):
    base = dict(
        kind=kind,
        instance="nwsa-egdb",
        region="us-gov-west-1",
        now=NOW,
        managed_secret=True,
        deletion_protection=True,
        publicly_accessible=False,
        backup_retention_days=7,
    )
    base.update(kw)
    return incident.IncidentContext(**base)


def first(pb, pred):
    return next(i for i, s in enumerate(pb.steps) if pred(s))


@pytest.mark.parametrize("kind", sorted(incident.KINDS))
def test_every_playbook_has_its_shape(kind):
    pb = incident.playbook(ctx(kind))
    phases = [s.phase for s in pb.steps]
    assert phases[0] == "Triage" and phases[-1] == "Learn"
    assert "Contain" in phases and "Notify" in phases
    assert all(s.phase in incident.PHASES for s in pb.steps)
    # every regional AWS command names the Region (IAM is global)
    assert all(
        "--region us-gov-west-1" in s.command
        for s in pb.steps
        if s.command.startswith("aws ") and not s.command.startswith("aws iam")
    )
    assert not any("—" in s.title + s.why + s.command for s in pb.steps)


@pytest.mark.parametrize("kind", ["credentials", "destruction", "aws-keys"])
def test_evidence_before_anything_that_destroys_it(kind):
    pb = incident.playbook(ctx(kind, role="sde_editor", since=NOW - timedelta(hours=5)))
    snap = first(pb, lambda s: s.title == "Snapshot the instance as it is now")
    destructive = [
        i
        for i, s in enumerate(pb.steps)
        if "restore-db-instance" in s.command
        or "\\password" in s.command
        or "rotate-master-user-password" in s.command
        or "Undo what it changed" in s.title
    ]
    assert destructive and all(snap < i for i in destructive), (snap, destructive)


def test_federal_notification_right_after_triage():
    pb = incident.playbook(ctx("exposure", federal=True, snapshot="leak"))
    notify = first(pb, lambda s: s.phase == "Notify")
    assert all(s.phase == "Triage" for s in pb.steps[:notify])
    assert "within one hour" in pb.steps[notify].title
    assert any(f.code == "INC005" for f in pb.findings)


def test_credentials_without_managed_secret_moves_it_into_secrets_manager():
    pb = incident.playbook(ctx("credentials", managed_secret=False, role="sde"))
    rotate = [s for s in pb.steps if "master credential" in s.title][0]
    assert "--manage-master-user-password" in rotate.command
    assert any(f.code == "INC003" for f in pb.findings)
    nolog = first(pb, lambda s: "NOLOGIN" in s.command)
    sessions = first(pb, lambda s: "pg_stat_activity" in s.command and "copy" in s.command)
    assert sessions < nolog


def test_exposure_contains_first_and_turns_on_deletion_protection():
    pb = incident.playbook(
        ctx(
            "exposure",
            snapshot="leak",
            group="sg-1",
            cidr="0.0.0.0/0",
            publicly_accessible=True,
            deletion_protection=False,
        )
    )
    contain = [s for s in pb.steps if s.phase == "Contain"]
    assert "--values-to-remove all" in contain[0].command
    assert any("revoke-security-group-ingress" in s.command for s in contain)
    assert any("--deletion-protection" in s.command for s in contain)
    assert {f.code for f in pb.findings} >= {"INC002", "INC004"}


def test_destruction_readiness_and_restore_target():
    since = NOW - timedelta(days=10)
    pb = incident.playbook(
        ctx("destruction", since=since, earliest_restorable=NOW - timedelta(days=7))
    )
    assert (
        pb.findings[0].severity == Severity.FAIL
        and "older than the earliest" in pb.findings[0].title
    )
    pb = incident.playbook(ctx("destruction", backup_retention_days=0))
    assert "automated backups are off" in pb.findings[0].title
    pb = incident.playbook(
        ctx(
            "destruction",
            since=NOW - timedelta(hours=2),
            earliest_restorable=NOW - timedelta(days=7),
        )
    )
    restore = [s for s in pb.steps if "restore-db-instance-to-point-in-time" in s.command][0]
    assert "--target-db-instance-identifier nwsa-egdb-restored-" in restore.command
    assert "--no-publicly-accessible" in restore.command


def test_certificate_updates_clients_before_rotating():
    pb = incident.playbook(ctx("certificate"))
    bundle = first(pb, lambda s: "trust bundle" in s.title)
    rotate = first(pb, lambda s: "--ca-certificate-identifier" in s.command)
    assert bundle < rotate


def test_unknown_kind():
    with pytest.raises(ValueError):
        incident.playbook(ctx("ufo"))
