"""Free-storage check: CloudWatch metric against allocated storage, mocked with moto."""

from datetime import UTC, datetime

import boto3
from conftest import make_instance
from moto import mock_aws

from rdsops.findings import Severity
from rdsops.health import storage_findings


def run(free_bytes):
    with mock_aws():
        rds = boto3.client("rds", region_name="us-east-1")
        cw = boto3.client("cloudwatch", region_name="us-east-1")
        make_instance(rds, AllocatedStorage=100)
        if free_bytes is not None:
            cw.put_metric_data(
                Namespace="AWS/RDS",
                MetricData=[
                    {
                        "MetricName": "FreeStorageSpace",
                        "Dimensions": [{"Name": "DBInstanceIdentifier", "Value": "egdb-lab"}],
                        "Timestamp": datetime.now(UTC),
                        "Value": float(free_bytes),
                    }
                ],
            )
        return storage_findings(cw, rds, "egdb-lab")[0]


def test_storage_bands():
    gib = 1 << 30
    assert run(50 * gib).severity == Severity.OK
    assert run(10 * gib).severity == Severity.WARN
    assert run(2 * gib).severity == Severity.FAIL


def test_missing_metric_warns():
    assert run(None).severity == Severity.WARN
