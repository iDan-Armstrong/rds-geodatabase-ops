"""Database connections for the SQL-level checks.

Three ways to authenticate, in order of preference:

1. ``--iam``: a 15-minute IAM auth token generated from your AWS credentials. Nothing to
   store. Requires IAM database auth on the instance (the module turns it on) and a
   database user granted ``rds_iam``.
2. ``--secret-arn``: read username and password from a Secrets Manager secret, for
   example the RDS-managed master secret the Terraform module outputs.
3. A libpq connection string (``--dsn`` or ``RDSOPS_DSN``) or the standard ``PG*``
   environment variables, for local databases and CI.

Passwords are never accepted as command-line arguments.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

import psycopg
from psycopg.rows import dict_row


@dataclass
class ConnectOptions:
    dsn: str | None = None
    host: str | None = None
    port: int = 5432
    user: str | None = None
    dbname: str | None = None
    iam: bool = False
    secret_arn: str | None = None
    sslmode: str | None = None


def resolve_conninfo(opts: ConnectOptions, aws_session=None) -> dict:
    """Turn options into keyword arguments for psycopg.connect. Pure apart from AWS calls."""
    kw: dict = {}
    dsn = opts.dsn or os.environ.get("RDSOPS_DSN")
    if dsn:
        kw["conninfo"] = dsn
    for key in ("host", "user", "dbname"):
        value = getattr(opts, key)
        if value:
            kw[key] = value
    if opts.host:
        kw["port"] = opts.port

    if opts.iam and opts.secret_arn:
        raise ValueError("Use --iam or --secret-arn, not both.")

    if opts.secret_arn:
        if aws_session is None:
            raise ValueError("--secret-arn needs AWS credentials")
        sm = aws_session.client("secretsmanager")
        secret = json.loads(sm.get_secret_value(SecretId=opts.secret_arn)["SecretString"])
        kw["user"] = opts.user or secret["username"]
        kw["password"] = secret["password"]
        for src, dst in (("host", "host"), ("port", "port"), ("dbname", "dbname")):
            if src in secret and dst not in kw:
                kw[dst] = secret[src]

    if opts.iam:
        if not (opts.host and opts.user):
            raise ValueError("--iam needs --host and --user")
        if aws_session is None:
            raise ValueError("--iam needs AWS credentials")
        rds = aws_session.client("rds")
        kw["password"] = rds.generate_db_auth_token(
            DBHostname=opts.host, Port=opts.port, DBUsername=opts.user
        )
        kw["sslmode"] = "require"  # IAM tokens are only accepted over TLS

    if opts.sslmode:
        kw["sslmode"] = opts.sslmode
    kw.setdefault("application_name", "rdsops")
    return kw


def connect(opts: ConnectOptions, aws_session=None) -> psycopg.Connection:
    """Read-only, autocommit connection with dict rows. Checks never write."""
    conn = psycopg.connect(
        **resolve_conninfo(opts, aws_session), autocommit=True, row_factory=dict_row
    )
    conn.execute("SET default_transaction_read_only = on")
    conn.execute("SET statement_timeout = '60s'")
    return conn
