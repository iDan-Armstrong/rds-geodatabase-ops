"""Connection resolution: secrets and IAM tokens, mocked with moto."""

import json

import boto3
import pytest
from moto import mock_aws

from rdsops.db import ConnectOptions, resolve_conninfo


def test_dsn_from_environment(monkeypatch):
    monkeypatch.setenv("RDSOPS_DSN", "host=localhost dbname=egdb")
    kw = resolve_conninfo(ConnectOptions())
    assert kw["conninfo"] == "host=localhost dbname=egdb"
    assert kw["application_name"] == "rdsops"
    assert "password" not in kw


def test_secret_supplies_credentials_and_cli_values_win():
    with mock_aws():
        s = boto3.session.Session(region_name="us-east-1")
        arn = s.client("secretsmanager").create_secret(
            Name="rds!db-123",
            SecretString=json.dumps({"username": "rdsadmin_gis", "password": "pw-from-secret"}),
        )["ARN"]
        kw = resolve_conninfo(ConnectOptions(host="egdb.example", dbname="egdb", secret_arn=arn), s)
    assert kw["user"] == "rdsadmin_gis"
    assert kw["password"] == "pw-from-secret"
    assert kw["host"] == "egdb.example" and kw["dbname"] == "egdb"


def test_iam_token_forces_tls():
    with mock_aws():
        s = boto3.session.Session(region_name="us-east-1")
        kw = resolve_conninfo(
            ConnectOptions(host="egdb.abc.us-east-1.rds.amazonaws.com", user="ops", iam=True), s
        )
    assert kw["sslmode"] == "require"
    assert "Action=connect" in kw["password"] and "DBUser=ops" in kw["password"]


def test_iam_needs_host_and_user_and_excludes_secret():
    with pytest.raises(ValueError, match="--host and --user"):
        resolve_conninfo(ConnectOptions(iam=True), object())
    with pytest.raises(ValueError, match="not both"):
        resolve_conninfo(ConnectOptions(iam=True, secret_arn="x", host="h", user="u"), object())
