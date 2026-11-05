from dataclasses import replace
from datetime import UTC, datetime, timedelta

import boto3
from conftest import make_instance
from moto import mock_aws

from rdsops import security
from rdsops.findings import Severity
from rdsops.inventory import InstanceFacts

NOW = datetime(2026, 11, 5, 12, tzinfo=UTC)


def facts(**kw):
    base = dict(
        identifier="egdb-lab",
        engine="postgres",
        engine_version="17.7",
        instance_class="db.t4g.micro",
        status="available",
        endpoint="egdb-lab.x.us-east-1.rds.amazonaws.com",
        port=5432,
        multi_az=False,
        publicly_accessible=False,
        storage_encrypted=True,
        kms_key_id="k",
        deletion_protection=True,
        backup_retention_days=7,
        iam_auth=True,
        auto_minor_version_upgrade=False,
        performance_insights=True,
        parameter_groups=("egdb-lab-pg17",),
        ca_cert="rds-ca-rsa2048-g1",
        allocated_storage_gb=20,
        max_allocated_storage_gb=100,
        managed_master_secret=True,
    )
    base.update(kw)
    return InstanceFacts(**base)


GOOD_PARAMS = {
    "rds.force_ssl": "1",
    "ssl_min_protocol_version": "TLSv1.2",
    "password_encryption": "scram-sha-256",
    "rds.accepted_password_auth_method": "scram",
    "shared_preload_libraries": "pg_stat_statements,pgaudit",
    "pgaudit.log": "ddl,role",
    "log_connections": "1",
}


def good(**kw):
    s = security.SecuritySnapshot(
        facts=facts(),
        ca_identifier="rds-ca-rsa2048-g1",
        cert_valid_till=NOW + timedelta(days=300),
        params=dict(GOOD_PARAMS),
        log_exports=["postgresql"],
        ingress=[],
        snapshots=[],
        kms_customer_managed=True,
        kms_rotation=True,
        secret_rotation=True,
        non_ssl_connections=0,
        md5_roles=[],
        superuser_members=[],
        public_schema_create=False,
    )
    return replace(s, **kw)


def sev(findings, code):
    return max((f.severity for f in findings if f.code == code), default=None)


def test_baseline_is_clean():
    f = security.evaluate(good(), NOW)
    assert max(x.severity for x in f) == Severity.OK, [(x.code, x.title) for x in f if x.severity]


def test_tls_off_and_old_versions():
    f = security.evaluate(
        good(params={**GOOD_PARAMS, "rds.force_ssl": "0", "ssl_min_protocol_version": "TLSv1"}), NOW
    )
    assert sev(f, "SEC001") == Severity.FAIL and sev(f, "SEC002") == Severity.WARN


def test_md5_passwords():
    f = security.evaluate(
        good(params={**GOOD_PARAMS, "password_encryption": "md5"}, md5_roles=["sde", "editor"]), NOW
    )
    assert sev(f, "SEC003") == Severity.WARN
    assert any("2 role(s)" in x.title for x in f if x.code == "SEC003")


def test_retired_ca_and_expiring_certificate():
    f = security.evaluate(
        good(ca_identifier="rds-ca-2019", cert_valid_till=NOW - timedelta(days=3)), NOW
    )
    titles = [x.title for x in f if x.code == "SEC004"]
    assert any("rds-ca-2019 is not a current" in t for t in titles) and any(
        "expired 3 days ago" in t for t in titles
    )
    f = security.evaluate(good(cert_valid_till=NOW + timedelta(days=10)), NOW)
    assert sev(f, "SEC004") == Severity.WARN


def test_exposure_levels():
    world = [security.OpenRule("sg-1", 5432, 5432, "0.0.0.0/0")]
    assert (
        sev(
            security.evaluate(good(facts=facts(publicly_accessible=True), ingress=world), NOW),
            "SEC005",
        )
        == Severity.FAIL
    )
    assert sev(security.evaluate(good(ingress=world), NOW), "SEC005") == Severity.WARN
    assert (
        sev(security.evaluate(good(facts=facts(publicly_accessible=True)), NOW), "SEC005")
        == Severity.WARN
    )


def test_public_and_unencrypted_snapshots():
    snaps = [
        security.SnapshotShare("egdb-lab-before-upgrade", True, True),
        security.SnapshotShare("egdb-lab-2019", False, False, ("111122223333",)),
    ]
    f = security.evaluate(good(snapshots=snaps), NOW)
    found = {(x.code, x.severity) for x in f}
    assert (
        ("SEC006", Severity.FAIL) in found
        and ("SEC006", Severity.WARN) in found
        and ("SEC006", Severity.INFO) in found
    )


def test_keys_secret_audit_guardrails_and_sql():
    f = security.evaluate(
        good(
            facts=facts(
                managed_master_secret=False, deletion_protection=False, backup_retention_days=1
            ),
            kms_rotation=False,
            log_exports=[],
            params={
                **GOOD_PARAMS,
                "shared_preload_libraries": "pg_stat_statements",
                "log_connections": "0",
            },
            non_ssl_connections=3,
            superuser_members=["sde"],
            public_schema_create=True,
        ),
        NOW,
    )
    assert sev(f, "SEC007") == Severity.WARN and sev(f, "SEC008") == Severity.WARN
    audit = [x for x in f if x.code == "SEC009"][0]
    assert "not exported" in audit.title and "pgaudit is not loaded" in audit.title
    assert len([x for x in f if x.code == "SEC010"]) == 2
    assert len([x for x in f if x.code == "SEC011"]) == 3


def test_unencrypted_storage_fails():
    assert (
        sev(security.evaluate(good(facts=facts(storage_encrypted=False)), NOW), "SEC007")
        == Severity.FAIL
    )


def test_unknowns_are_not_called_safe():
    s = security.SecuritySnapshot(facts=facts())
    f = security.evaluate(s, NOW)
    assert [x.title for x in f if x.code == "SEC001"] == ["rds.force_ssl not read"]
    assert sev(f, "SEC005") is None and sev(f, "SEC006") is None


def test_gather_with_moto_finds_open_group_and_public_snapshot():
    with mock_aws():
        rds = boto3.client("rds", region_name="us-east-1")
        ec2 = boto3.client("ec2", region_name="us-east-1")
        kms = boto3.client("kms", region_name="us-east-1")
        sm = boto3.client("secretsmanager", region_name="us-east-1")
        vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
        sg = ec2.create_security_group(GroupName="egdb", Description="egdb", VpcId=vpc)["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=sg,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 5432,
                    "ToPort": 5432,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )
        make_instance(rds, "egdb-lab", PubliclyAccessible=True, VpcSecurityGroupIds=[sg])
        rds.create_db_snapshot(DBInstanceIdentifier="egdb-lab", DBSnapshotIdentifier="leak")
        rds.modify_db_snapshot_attribute(
            DBSnapshotIdentifier="leak", AttributeName="restore", ValuesToAdd=["all"]
        )
        s = security.gather(rds, ec2, kms, sm, "egdb-lab", "us-east-1")
    f = security.evaluate(s, NOW)
    assert sev(f, "SEC005") == Severity.FAIL
    assert (
        sev(f, "SEC006") == Severity.FAIL
        and "leak" in [x for x in f if x.code == "SEC006"][0].detail
    )
