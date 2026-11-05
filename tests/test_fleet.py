from datetime import date

import boto3
from conftest import make_instance
from moto import mock_aws

from rdsops import fleet
from rdsops.cli import parse_targets
from rdsops.findings import Severity

TODAY = date(2026, 11, 4)


def by_code(findings, code):
    return [f for f in findings if f.code == code]


def tags(**kw):
    return [{"Key": k.replace("_", "-"), "Value": v} for k, v in kw.items()]


def test_parse_targets():
    assert parse_targets(["us-east-1", "us-gov-west-1@gov"], "lab") == [
        ("us-east-1", "lab"),
        ("us-gov-west-1", "gov"),
    ]


def test_two_regions_drift_tags_and_a_failing_region():
    with mock_aws():
        east = boto3.client("rds", region_name="us-east-1")
        west = boto3.client("rds", region_name="us-west-2")
        make_instance(east, "egdb-a", Tags=tags(arcgis_release="12.1", geodatabase="true"))
        make_instance(
            east,
            "egdb-b",
            EngineVersion="17.5",
            PubliclyAccessible=True,
            Tags=tags(arcgis_release="11.5", environment="prod", geodatabase="true"),
        )
        make_instance(west, "egdb-c", EngineVersion="16.8", Tags=tags(geodatabase="true"))
        make_instance(west, "scratch", Tags=tags(geodatabase="false"))

        class Broken:
            def get_paginator(self, op):
                raise RuntimeError("AccessDenied: not authorized in this account")

        snap = fleet.gather(
            [("us-east-1", east), ("us-west-2", west), ("us-gov-west-1", Broken())],
            tag=("geodatabase", "true"),
            default_arcgis="12.1",
        )
        assert sorted(m.facts.identifier for m in snap.members) == ["egdb-a", "egdb-b", "egdb-c"]
        f = fleet.evaluate(snap, today=TODAY)

    total = by_code(f, "FLT000")[0]
    assert total.title.startswith("3 instance(s) in 3 Region(s)")
    rows = {x.evidence["instance"]: x for x in by_code(f, "FLT001")}
    # tagged 11.5, which supports no PostgreSQL 17, and public: it fails
    assert rows["egdb-b"].severity == Severity.FAIL
    assert {"INV002", "CMP001"} <= set(rows["egdb-b"].evidence["codes"])
    assert rows["egdb-b"].evidence["production"] is True
    assert rows["egdb-c"].evidence["arcgis"] == "12.1"  # untagged, default release
    drift = [x for x in by_code(f, "FLT002") if "PostgreSQL 17" in x.title]
    assert drift and "17.5, 17.7" in drift[0].title
    assert any("ArcGIS releases: 11.5, 12.1" in x.title for x in by_code(f, "FLT002"))
    assert "us-west-2/egdb-c" in by_code(f, "FLT003")[0].detail
    assert "AccessDenied" in by_code(f, "FLT009")[0].detail


def test_empty_fleet_warns():
    f = fleet.evaluate(fleet.FleetSnapshot(regions=["us-east-1"]), today=TODAY)
    assert f[0].code == "FLT000" and f[0].severity == Severity.WARN
