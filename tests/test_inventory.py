from conftest import make_instance

from rdsops.findings import Severity, exit_code
from rdsops.inventory import describe_instance, posture_findings


def by_code(findings):
    return {f.code: f for f in findings}


def test_describe_reads_control_plane_settings(rds):
    make_instance(rds)
    facts = describe_instance(rds, "egdb-lab")
    assert facts.engine == "postgres"
    assert facts.engine_major == 17
    assert facts.storage_encrypted and facts.iam_auth and facts.deletion_protection
    assert facts.backup_retention_days == 7
    assert not facts.publicly_accessible


def test_baseline_instance_has_no_warnings_or_failures(rds):
    make_instance(rds)
    facts = describe_instance(rds, "egdb-lab")
    # moto attaches default.postgres17 when no group is given; the real module never does.
    findings = [f for f in posture_findings(facts) if f.code != "INV009"]
    assert all(f.severity <= Severity.INFO for f in findings), [
        f for f in findings if f.severity > Severity.INFO
    ]


def test_unencrypted_or_public_instance_fails(rds):
    make_instance(rds, StorageEncrypted=False, PubliclyAccessible=True)
    f = by_code(posture_findings(describe_instance(rds, "egdb-lab")))
    assert f["INV001"].severity == Severity.FAIL
    assert f["INV002"].severity == Severity.FAIL
    assert exit_code(list(f.values())) == 2


def test_availability_gaps_warn_in_lab_and_fail_in_production(rds):
    make_instance(rds, DeletionProtection=False, BackupRetentionPeriod=1)
    facts = describe_instance(rds, "egdb-lab")
    lab = by_code(posture_findings(facts))
    prod = by_code(posture_findings(facts, production=True))
    for code in ("INV003", "INV004"):
        assert lab[code].severity == Severity.WARN
        assert prod[code].severity == Severity.FAIL
    assert lab["INV006"].severity == Severity.INFO
    assert prod["INV006"].severity == Severity.FAIL


def test_auto_minor_upgrade_is_flagged(rds):
    make_instance(rds, AutoMinorVersionUpgrade=True)
    f = by_code(posture_findings(describe_instance(rds, "egdb-lab")))
    assert f["INV008"].severity == Severity.WARN
    assert "ADR 0004" in f["INV008"].detail


def test_default_parameter_group_is_flagged(rds):
    make_instance(rds)
    facts = describe_instance(rds, "egdb-lab")
    assert facts.parameter_groups and facts.parameter_groups[0].startswith("default.")
    assert by_code(posture_findings(facts))["INV009"].severity == Severity.WARN


def test_custom_parameter_group_passes(rds):
    rds.create_db_parameter_group(
        DBParameterGroupName="egdb-lab-pg17",
        DBParameterGroupFamily="postgres17",
        Description="test",
    )
    make_instance(rds, DBParameterGroupName="egdb-lab-pg17")
    f = by_code(posture_findings(describe_instance(rds, "egdb-lab")))
    assert f["INV009"].severity == Severity.OK
