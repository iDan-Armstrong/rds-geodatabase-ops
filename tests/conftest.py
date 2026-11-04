import boto3
import pytest
from moto import mock_aws


@pytest.fixture(autouse=True)
def _fake_aws_env(monkeypatch):
    # Belt and braces: even if a test forgets mock_aws, nothing can reach a real account.
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.delenv("AWS_PROFILE", raising=False)


@pytest.fixture
def rds():
    with mock_aws():
        yield boto3.client("rds", region_name="us-east-1")


def make_instance(rds, identifier="egdb-lab", **overrides):
    params = dict(
        DBInstanceIdentifier=identifier,
        DBInstanceClass="db.t4g.micro",
        Engine="postgres",
        EngineVersion="17.7",
        AllocatedStorage=20,
        MasterUsername="rdsadmin_gis",
        MasterUserPassword="not-a-real-password-1",
        StorageEncrypted=True,
        PubliclyAccessible=False,
        DeletionProtection=True,
        BackupRetentionPeriod=7,
        EnableIAMDatabaseAuthentication=True,
        AutoMinorVersionUpgrade=False,
        MultiAZ=False,
    )
    params.update(overrides)
    rds.create_db_instance(**params)
    return identifier
