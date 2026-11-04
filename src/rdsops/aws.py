"""boto3 session handling. Credentials come from the standard AWS chain only.

rdsops never accepts keys on the command line or in config files: use an AWS
profile, SSO, or an instance role.
"""

from __future__ import annotations

import boto3


def session(region: str | None = None, profile: str | None = None) -> boto3.session.Session:
    return boto3.session.Session(region_name=region, profile_name=profile)
