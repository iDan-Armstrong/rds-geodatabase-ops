import boto3
from conftest import make_instance
from moto import mock_aws

from rdsops import aurora
from rdsops.findings import Severity

V121 = ["14.19", "15.14", "16.10", "17.4", "17.5", "17.6", "17.7"]


def facts(**kw):
    base = dict(
        source="egdb-client",
        region="us-gov-west-1",
        engine_version="17.5",
        account="123456789012",
        encrypted=True,
        kms_key_id="arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/abc",
        multi_az=True,
        allocated_gb=100,
        free_bytes=60 * (1 << 30),
        subnet_group="egdb-private",
        security_groups=["sg-1"],
        aurora_versions=V121,
        postgis_version="3.5.2",
    )
    base.update(kw)
    return aurora.AuroraFacts(**base)


def by_code(findings, code):
    return [f for f in findings if f.code == code]


def test_partition_and_arn():
    assert aurora.partition("us-gov-west-1") == "aws-us-gov"
    assert aurora.partition("us-east-1") == "aws"
    assert (
        aurora.source_arn(facts()) == "arn:aws-us-gov:rds:us-gov-west-1:123456789012:db:egdb-client"
    )


def test_govcloud_replica_plan_picks_esri_minimum_and_uses_gov_arns():
    f, steps = aurora.plan(aurora.AuroraRequest(arcgis="12.1"), facts())
    t = by_code(f, "AUR001")[0]
    assert t.severity == Severity.OK and t.title == "Target Aurora PostgreSQL 17.6"
    assert {x.code: x.severity for x in f}["CMP001"] == Severity.OK
    assert by_code(f, "AUR002")[0].severity == Severity.OK
    joined = "\n".join(steps)
    assert "--replication-source-identifier arn:aws-us-gov:rds:us-gov-west-1:" in joined
    assert (
        "--engine-version 17.6" in joined
        and "--storage-encrypted --kms-key-id arn:aws-us-gov:kms" in joined
    )
    assert "--region us-gov-west-1" in joined and "promote-read-replica-db-cluster" in joined
    assert "registered data store" in joined and "Multi-AZ" in by_code(f, "AUR004")[0].title


def test_region_that_has_not_caught_up_fails():
    # A GovCloud Region that does not offer Esri's minimum yet
    f, steps = aurora.plan(
        aurora.AuroraRequest(arcgis="12.1"), facts(aurora_versions=["17.4", "17.5"])
    )
    t = by_code(f, "AUR001")[0]
    assert t.severity == Severity.FAIL and "17.4, 17.5" in t.detail and "17.6" in t.detail
    assert steps == []


def test_source_newer_than_esri_minimum_takes_the_next_offered():
    f, _ = aurora.plan(aurora.AuroraRequest(arcgis="12.1"), facts(engine_version="17.7"))
    assert by_code(f, "AUR001")[0].title == "Target Aurora PostgreSQL 17.7"
    assert {x.code: x.severity for x in f}["CMP002"] == Severity.INFO  # supported, not certified


def test_major_esri_does_not_list_on_aurora():
    f, _ = aurora.plan(
        aurora.AuroraRequest(arcgis="12.1"), facts(engine_version="18.1", aurora_versions=["18.1"])
    )
    t = by_code(f, "AUR001")[0]
    assert t.severity == Severity.FAIL and "no Aurora PostgreSQL 18" in t.detail


def test_replica_blockers():
    f, _ = aurora.plan(
        aurora.AuroraRequest(arcgis="12.1"),
        facts(
            aurora_replica_clusters=["old-try"],
            cross_region_replicas=["arn:aws-us-gov:rds:us-gov-east-1:1:db:dr"],
        ),
    )
    b = by_code(f, "AUR002")[0]
    assert b.severity == Severity.FAIL and "old-try" in b.title and "cross-Region" in b.title
    f, _ = aurora.plan(aurora.AuroraRequest(arcgis="12.1", target_region="us-gov-east-1"), facts())
    assert by_code(f, "AUR002")[0].severity == Severity.FAIL


def test_snapshot_cross_region_copies_first():
    f, steps = aurora.plan(
        aurora.AuroraRequest(arcgis="12.1", method="snapshot", target_region="us-gov-east-1"),
        facts(),
    )
    assert by_code(f, "AUR002")[0].severity == Severity.INFO
    joined = "\n".join(steps)
    assert "copy-db-snapshot --region us-gov-east-1 --source-region us-gov-west-1" in joined
    assert "arn:aws-us-gov:rds:us-gov-west-1:123456789012:snapshot:egdb-client-to-aurora" in joined
    assert "restore-db-cluster-from-snapshot --region us-gov-east-1" in joined


def test_unencrypted_source_fails_in_govcloud_and_warns_elsewhere():
    f, steps = aurora.plan(
        aurora.AuroraRequest(arcgis="12.1"), facts(encrypted=False, kms_key_id=None)
    )
    assert by_code(f, "AUR003")[0].severity == Severity.FAIL
    assert "--storage-encrypted --kms-key-id <kms key arn>" in "\n".join(steps)
    f, _ = aurora.plan(
        aurora.AuroraRequest(arcgis="12.1"), facts(region="us-east-1", encrypted=False)
    )
    assert by_code(f, "AUR003")[0].severity == Severity.WARN


def test_wal_headroom():
    f, _ = aurora.plan(aurora.AuroraRequest(arcgis="12.1"), facts(free_bytes=10 * (1 << 30)))
    assert by_code(f, "AUR005")[0].severity == Severity.WARN


def test_offline_without_region_versions():
    f, steps = aurora.plan(
        aurora.AuroraRequest(arcgis="11.5"), facts(engine_version="16.8", aurora_versions=None)
    )
    t = by_code(f, "AUR001")[0]
    assert t.severity == Severity.INFO and t.title == "Target Aurora PostgreSQL 16.8" and steps


def test_gather_with_moto():
    with mock_aws():
        rds = boto3.client("rds", region_name="us-east-1")
        cw = boto3.client("cloudwatch", region_name="us-east-1")
        make_instance(rds, "egdb-client")

        class WithVersions:
            """moto has no describe_db_engine_versions; answer it, pass the rest through."""

            def __getattr__(self, name):
                return getattr(rds, name)

            def get_paginator(self, op):
                assert op == "describe_db_engine_versions"

                class P:
                    def paginate(self, Engine):
                        assert Engine == "aurora-postgresql"
                        yield {"DBEngineVersions": [{"EngineVersion": v} for v in V121]}

                return P()

        fa = aurora.gather(WithVersions(), cw, "egdb-client", "us-east-1")
        assert fa.engine_version == "17.7" and fa.encrypted is True
        assert fa.account and fa.arn.startswith("arn:aws:rds:us-east-1:")
        assert isinstance(fa.aurora_versions, list)
        f, steps = aurora.plan(aurora.AuroraRequest(arcgis="12.1"), fa)
        assert by_code(f, "AUR001")
