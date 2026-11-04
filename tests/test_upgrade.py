"""Upgrade planning: pure logic, plus reading context from a mocked RDS API."""

import pytest
from conftest import make_instance

from rdsops.findings import Severity
from rdsops.upgrade import UpgradeContext, context_from_aws, plan


def ready(**kw):
    """A context where every precondition for a blue/green major upgrade is met."""
    base = dict(
        current_version="16.11",
        target_version="18.1",
        arcgis="12.1",
        instance="egdb",
        postgis_version="3.5.2",
        managed_master_secret=False,
        logical_replication_param="1",
        max_replication_slots=20,
        database_count=3,
        logical_slots=[],
        tables_without_pk=[],
        unlogged_tables=[],
        large_object_count=0,
        extensions=["postgis", "pgaudit"],
        has_geodatabase=True,
    )
    base.update(kw)
    return UpgradeContext(**base)


def codes(p, severity=None):
    return {f.code for f in p.findings if severity is None or f.severity == severity}


def test_ready_major_upgrade_has_no_failures_or_warnings():
    p = plan(ready())
    assert p.kind == "major"
    assert not codes(p, Severity.FAIL) and not codes(p, Severity.WARN)
    assert any("create-blue-green-deployment" in s for s in p.steps)
    assert any("ALTER EXTENSION postgis UPDATE" in s for s in p.steps)


def test_managed_master_secret_blocks_blue_green():
    p = plan(ready(managed_master_secret=True))
    assert "UPG006" in codes(p, Severity.FAIL)
    assert any("--no-manage-master-user-password" in s for s in p.steps)


@pytest.mark.parametrize(
    "current,eligible", [("15.3", False), ("15.4", True), ("14.8", False), ("16.1", True)]
)
def test_blue_green_source_floor(current, eligible):
    p = plan(ready(current_version=current))
    w = "UPG005" in codes(p, Severity.WARN)
    assert w is (not eligible)


def test_replication_blockers():
    p = plan(
        ready(
            logical_replication_param="0",
            logical_slots=["dms_old_task"],
            tables_without_pk=["gis.parcels_h"],
            unlogged_tables=["gis.scratch"],
            large_object_count=4,
            extensions=["postgis", "pg_cron"],
            max_replication_slots=2,
        )
    )
    assert {"UPG009", "UPG012"} <= codes(p, Severity.FAIL)
    assert {"UPG007", "UPG008", "UPG010", "UPG011", "UPG013"} <= codes(p, Severity.WARN)


def test_unsupported_target_and_blocked_postgis():
    p = plan(ready(target_version="18.1", arcgis="12.0", postgis_version="3.5.3"))
    assert {"UPG002", "UPG003"} <= codes(p, Severity.FAIL)


def test_geodatabase_on_11_needs_dump_restore():
    p = plan(ready(current_version="11.22", target_version="16.11"))
    assert "UPG004" in codes(p, Severity.FAIL)


def test_unknowns_become_info_not_guesses():
    p = plan(UpgradeContext("16.11", "18.1", "12.1"))
    assert not codes(p, Severity.FAIL)
    assert {"UPG006", "UPG007", "UPG009", "UPG010"} <= codes(p, Severity.INFO)


def test_minor_upgrade_and_edge_cases():
    p = plan(ready(target_version="16.12"))
    assert p.kind == "minor"
    assert any("modify-db-instance" in s for s in p.steps)
    assert plan(ready(target_version="16.11")).kind == "none"
    assert plan(ready(target_version="15.15")).kind == "downgrade"


def test_context_from_aws_reads_parameter_group(rds):
    rds.create_db_parameter_group(
        DBParameterGroupName="egdb-pg16", DBParameterGroupFamily="postgres16", Description="t"
    )
    rds.modify_db_parameter_group(
        DBParameterGroupName="egdb-pg16",
        Parameters=[
            {
                "ParameterName": "rds.logical_replication",
                "ParameterValue": "1",
                "ApplyMethod": "pending-reboot",
            },
            {
                "ParameterName": "max_replication_slots",
                "ParameterValue": "25",
                "ApplyMethod": "pending-reboot",
            },
        ],
    )
    make_instance(rds, EngineVersion="16.11", DBParameterGroupName="egdb-pg16")
    ctx = context_from_aws(rds, "egdb-lab", UpgradeContext("0", "18.1", "12.1"))
    assert ctx.current_version == "16.11"
    assert ctx.logical_replication_param == "1"
    assert ctx.max_replication_slots == 25
    assert ctx.managed_master_secret is False


def test_context_from_aws_default_group_means_logical_off(rds):
    make_instance(rds, EngineVersion="16.11")
    ctx = context_from_aws(rds, "egdb-lab", UpgradeContext("0", "18.1", "12.1"))
    assert ctx.logical_replication_param == "0"
