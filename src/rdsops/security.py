"""Security: a deeper posture check than inventory, from the control plane and the database.

``gather`` reads the instance, its parameter group, security groups, manual snapshots and
their sharing, the KMS key, the managed master secret, and (with a database connection)
TLS use, password storage and role privileges. ``evaluate`` is pure.

Sources are in docs/SCOPE.md and docs/runbooks/security-incidents.md. Values that cannot be
read (no permission, no connection) stay None and are reported as not checked, never
assumed safe.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from .findings import Finding, Severity
from .inventory import InstanceFacts

# AWS: current RDS certificate authorities. Instances on anything else need rotating.
CURRENT_CAS = ("rds-ca-rsa2048-g1", "rds-ca-rsa4096-g1", "rds-ca-ecc384-g1")
CERT_WARN_DAYS = 30
OPEN = ("0.0.0.0/0", "::/0")


@dataclass(frozen=True)
class OpenRule:
    group: str
    from_port: int
    to_port: int
    cidr: str


@dataclass(frozen=True)
class SnapshotShare:
    identifier: str
    encrypted: bool
    public: bool
    accounts: tuple[str, ...] = ()


@dataclass
class SecuritySnapshot:
    facts: InstanceFacts
    region: str = ""
    ca_identifier: str | None = None
    cert_valid_till: datetime | None = None
    params: dict[str, str | None] = field(default_factory=dict)
    log_exports: list[str] | None = None
    ingress: list[OpenRule] | None = None  # rules that reach the DB port
    snapshots: list[SnapshotShare] | None = None
    kms_customer_managed: bool | None = None
    kms_rotation: bool | None = None
    secret_rotation: bool | None = None
    # From the database (None without a connection)
    non_ssl_connections: int | None = None
    md5_roles: list[str] | None = None
    superuser_members: list[str] | None = None
    public_schema_create: bool | None = None
    errors: list[str] = field(default_factory=list)


def _p(s: SecuritySnapshot, name: str) -> str | None:
    v = s.params.get(name)
    return None if v is None else str(v).strip()


def evaluate(s: SecuritySnapshot, now: datetime) -> list[Finding]:
    out: list[Finding] = []
    f = s.facts
    port = f.port or 5432

    # SEC001 TLS required
    force = _p(s, "rds.force_ssl")
    if force is None:
        out.append(
            Finding("SEC001", Severity.INFO, "rds.force_ssl not read", "Read the parameter group.")
        )
    elif force == "1":
        out.append(Finding("SEC001", Severity.OK, "Connections must use TLS (rds.force_ssl = 1)"))
    else:
        out.append(
            Finding(
                "SEC001",
                Severity.FAIL,
                "Unencrypted connections are allowed (rds.force_ssl = 0)",
                "Credentials and geodatabase traffic can cross the network in clear text. Set "
                "rds.force_ssl = 1 in the custom parameter group; ArcGIS clients connect over "
                "TLS by default.",
            )
        )

    # SEC002 TLS minimum version
    tls_min = _p(s, "ssl_min_protocol_version")
    if tls_min and tls_min in ("TLSv1", "TLSv1.1"):
        out.append(
            Finding(
                "SEC002",
                Severity.WARN,
                f"TLS {tls_min.removeprefix('TLSv')} is still accepted",
                "Set ssl_min_protocol_version = TLSv1.2 (or TLSv1.3 if every client supports it).",
            )
        )

    # SEC003 password storage and accepted methods
    enc = _p(s, "password_encryption")
    accepted = _p(s, "rds.accepted_password_auth_method")
    if enc and enc != "scram-sha-256":
        out.append(
            Finding(
                "SEC003",
                Severity.WARN,
                f"New passwords are stored as {enc}",
                "Set password_encryption = scram-sha-256, then reset each password.",
            )
        )
    if s.md5_roles:
        out.append(
            Finding(
                "SEC003",
                Severity.WARN,
                f"{len(s.md5_roles)} role(s) still have md5 passwords",
                ", ".join(s.md5_roles[:10])
                + ". Reset them with password_encryption = scram-sha-256 (rds_tools."
                "role_password_encryption_type() lists them), then set "
                "rds.accepted_password_auth_method = scram.",
                {"roles": s.md5_roles},
            )
        )
    elif accepted and accepted != "scram" and s.md5_roles == []:
        out.append(
            Finding(
                "SEC003",
                Severity.INFO,
                "md5 logins are still accepted, though no role uses md5",
                "Set rds.accepted_password_auth_method = scram to refuse md5 from now on.",
            )
        )

    # SEC004 certificate authority and server certificate
    if s.ca_identifier and s.ca_identifier not in CURRENT_CAS:
        out.append(
            Finding(
                "SEC004",
                Severity.FAIL,
                f"Certificate authority {s.ca_identifier} is not a current RDS CA",
                "Clients that validate the server certificate will fail, or already do. "
                "Rotate to rds-ca-rsa2048-g1 (the default) and update the trust bundle on "
                "ArcGIS Server machines and clients first.",
                {"ca": s.ca_identifier},
            )
        )
    if s.cert_valid_till:
        days = (s.cert_valid_till - now).total_seconds() / 86400
        if days < CERT_WARN_DAYS:
            out.append(
                Finding(
                    "SEC004",
                    Severity.FAIL if days < 0 else Severity.WARN,
                    "Server certificate "
                    + (
                        f"expired {abs(days):.0f} days ago"
                        if days < 0
                        else f"expires in {days:.0f} days"
                    ),
                    "Current CAs rotate the server certificate automatically on engine versions "
                    "that support it; otherwise rotate it in a maintenance window.",
                    {"valid_till": s.cert_valid_till.isoformat()},
                )
            )
    if s.ca_identifier in CURRENT_CAS and not any(x.code == "SEC004" for x in out):
        out.append(Finding("SEC004", Severity.OK, f"Certificate authority {s.ca_identifier}"))

    # SEC005 network exposure
    if s.ingress is not None:
        world = [r for r in s.ingress if r.cidr in OPEN]
        if world and f.publicly_accessible:
            out.append(
                Finding(
                    "SEC005",
                    Severity.FAIL,
                    f"Port {port} is open to the internet",
                    "The instance has a public address and "
                    + ", ".join(f"{r.group} allows {r.cidr}" for r in world)
                    + ". Remove the rule and turn off public access now; treat the credentials "
                    "as exposed (rdsops incident --kind exposure).",
                    {"rules": [r.__dict__ for r in world]},
                )
            )
        elif world:
            out.append(
                Finding(
                    "SEC005",
                    Severity.WARN,
                    f"A security group allows {world[0].cidr} to port {port}",
                    "The instance is private today, but one setting away from exposed. Limit "
                    "the rule to the ArcGIS Server subnets.",
                    {"rules": [r.__dict__ for r in world]},
                )
            )
        elif f.publicly_accessible:
            out.append(
                Finding(
                    "SEC005",
                    Severity.WARN,
                    "Public address, but no security group opens the port to everyone",
                    "Turn off public access; ArcGIS connects from inside the VPC.",
                )
            )
        else:
            out.append(Finding("SEC005", Severity.OK, "Not reachable from the internet"))

    # SEC006 snapshots
    if s.snapshots is not None:
        public = [x.identifier for x in s.snapshots if x.public]
        shared = [x for x in s.snapshots if x.accounts]
        plain = [x.identifier for x in s.snapshots if not x.encrypted]
        if public:
            out.append(
                Finding(
                    "SEC006",
                    Severity.FAIL,
                    f"{len(public)} snapshot(s) can be restored by any AWS account",
                    ", ".join(public)
                    + ". Anyone can copy the whole geodatabase. Remove 'all' from the restore "
                    "attribute now, then find out who set it (rdsops incident --kind exposure).",
                    {"snapshots": public},
                )
            )
        if shared:
            out.append(
                Finding(
                    "SEC006",
                    Severity.INFO,
                    f"{len(shared)} snapshot(s) shared with other accounts",
                    "; ".join(f"{x.identifier}: {', '.join(x.accounts)}" for x in shared)
                    + ". Confirm each account is yours.",
                )
            )
        if plain:
            out.append(
                Finding(
                    "SEC006",
                    Severity.WARN,
                    f"{len(plain)} unencrypted snapshot(s)",
                    ", ".join(plain[:10]) + ". Copy them with a KMS key and delete the originals.",
                )
            )
        if not (public or plain):
            out.append(
                Finding(
                    "SEC006",
                    Severity.OK,
                    f"{len(s.snapshots)} manual snapshot(s), none public or unencrypted",
                )
            )

    # SEC007 encryption and keys
    if not f.storage_encrypted:
        out.append(
            Finding(
                "SEC007",
                Severity.FAIL,
                "Storage is not encrypted",
                "Encryption cannot be turned on in place: copy a snapshot with a KMS key and "
                "restore from it.",
            )
        )
    elif s.kms_customer_managed and s.kms_rotation is False:
        out.append(
            Finding(
                "SEC007",
                Severity.WARN,
                "Automatic rotation is off for the customer-managed KMS key",
                "aws kms enable-key-rotation --key-id <key>.",
            )
        )
    elif s.kms_customer_managed is False:
        out.append(
            Finding(
                "SEC007",
                Severity.INFO,
                "Encrypted with the AWS managed key (aws/rds)",
                "Fine for most uses. A customer-managed key lets you control the key policy, "
                "and snapshots encrypted with aws/rds cannot be shared with other accounts.",
            )
        )
    else:
        out.append(Finding("SEC007", Severity.OK, "Encrypted at rest"))

    # SEC008 master credential
    if not f.managed_master_secret:
        out.append(
            Finding(
                "SEC008",
                Severity.WARN,
                "Master password is not managed by Secrets Manager",
                "Someone knows it, and it does not rotate. Switch with "
                "--manage-master-user-password (see ADR 0005 before a blue/green upgrade).",
            )
        )
    elif s.secret_rotation is False:
        out.append(
            Finding(
                "SEC008",
                Severity.WARN,
                "Master secret rotation is off",
                "Turn rotation back on for the RDS-managed secret.",
            )
        )
    elif s.secret_rotation:
        out.append(Finding("SEC008", Severity.OK, "Master secret is managed and rotates"))

    # SEC009 audit trail
    gaps = []
    if s.log_exports is not None and "postgresql" not in s.log_exports:
        gaps.append("the PostgreSQL log is not exported to CloudWatch Logs")
    libs = _p(s, "shared_preload_libraries")
    if libs is not None and "pgaudit" not in libs:
        gaps.append("pgaudit is not loaded")
    elif libs is not None and (_p(s, "pgaudit.log") or "none").lower() in ("none", ""):
        gaps.append("pgaudit.log is none")
    if _p(s, "log_connections") == "0":
        gaps.append("log_connections is off")
    if gaps:
        out.append(
            Finding(
                "SEC009",
                Severity.WARN,
                "Audit trail gaps: " + "; ".join(gaps),
                "After an incident these are what show who connected and what they ran. "
                "Without them the investigation starts blind.",
                {"gaps": gaps},
            )
        )
    elif s.log_exports is not None or libs is not None:
        out.append(Finding("SEC009", Severity.OK, "Logs exported and pgaudit on"))

    # SEC010 destructive-action guard rails
    if not f.deletion_protection:
        out.append(
            Finding(
                "SEC010",
                Severity.WARN,
                "Deletion protection is off",
                "One API call with stolen credentials deletes the instance.",
            )
        )
    if f.backup_retention_days < 7:
        out.append(
            Finding(
                "SEC010",
                Severity.WARN,
                f"Only {f.backup_retention_days} day(s) of point-in-time recovery",
                "Damage found late cannot be undone. Keep at least 7 days.",
            )
        )

    # SEC011 inside the database
    if s.non_ssl_connections:
        out.append(
            Finding(
                "SEC011",
                Severity.WARN,
                f"{s.non_ssl_connections} connection(s) without TLS right now",
                "pg_stat_ssl shows them. Find the clients before turning rds.force_ssl on.",
            )
        )
    if s.superuser_members:
        out.append(
            Finding(
                "SEC011",
                Severity.WARN,
                f"{len(s.superuser_members)} role(s) besides the master user hold rds_superuser",
                ", ".join(s.superuser_members)
                + ". The sde owner and ArcGIS connections do not need it after setup.",
                {"roles": s.superuser_members},
            )
        )
    if s.public_schema_create:
        out.append(
            Finding(
                "SEC011",
                Severity.WARN,
                "Any role can create objects in the public schema",
                "REVOKE CREATE ON SCHEMA public FROM PUBLIC; (the default from PostgreSQL 15).",
            )
        )

    for e in s.errors:
        out.append(Finding("SEC099", Severity.WARN, "Part of the check could not run", e))
    return out


# --------------------------------------------------------------- gathering


def gather(rds, ec2, kms, secrets, identifier: str, region: str = "") -> SecuritySnapshot:
    from .inventory import facts_from_api

    db = rds.describe_db_instances(DBInstanceIdentifier=identifier)["DBInstances"][0]
    s = SecuritySnapshot(facts=facts_from_api(db), region=region)
    cert = db.get("CertificateDetails") or {}
    s.ca_identifier = cert.get("CAIdentifier") or db.get("CACertificateIdentifier")
    s.cert_valid_till = cert.get("ValidTill")
    s.log_exports = list(db.get("EnabledCloudwatchLogsExports") or [])
    wanted = {
        "rds.force_ssl",
        "ssl_min_protocol_version",
        "password_encryption",
        "rds.accepted_password_auth_method",
        "shared_preload_libraries",
        "pgaudit.log",
        "log_connections",
    }
    try:
        group = db["DBParameterGroups"][0]["DBParameterGroupName"]
        for page in rds.get_paginator("describe_db_parameters").paginate(
            DBParameterGroupName=group
        ):
            for p in page["Parameters"]:
                if p["ParameterName"] in wanted:
                    s.params[p["ParameterName"]] = p.get("ParameterValue")
    except Exception as e:  # noqa: BLE001
        s.errors.append(f"parameter group: {e}")
    try:
        port = int((db.get("Endpoint") or {}).get("Port") or 5432)
        ids = [g["VpcSecurityGroupId"] for g in db.get("VpcSecurityGroups") or []]
        s.ingress = []
        if ids:
            for g in ec2.describe_security_groups(GroupIds=ids)["SecurityGroups"]:
                for perm in g.get("IpPermissions", []):
                    lo, hi = perm.get("FromPort", 0), perm.get("ToPort", 65535)
                    if perm.get("IpProtocol") not in ("-1", "tcp") or not (lo <= port <= hi):
                        continue
                    cidrs = [r["CidrIp"] for r in perm.get("IpRanges", [])]
                    cidrs += [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", [])]
                    s.ingress += [OpenRule(g["GroupId"], lo, hi, c) for c in cidrs]
    except Exception as e:  # noqa: BLE001
        s.ingress = None
        s.errors.append(f"security groups: {e}")
    try:
        s.snapshots = []
        snaps = rds.describe_db_snapshots(DBInstanceIdentifier=identifier, SnapshotType="manual")
        for snap in snaps["DBSnapshots"]:
            sid = snap["DBSnapshotIdentifier"]
            attrs = rds.describe_db_snapshot_attributes(DBSnapshotIdentifier=sid)
            restore = next(
                (
                    a.get("AttributeValues", [])
                    for a in attrs["DBSnapshotAttributesResult"]["DBSnapshotAttributes"]
                    if a["AttributeName"] == "restore"
                ),
                [],
            )
            s.snapshots.append(
                SnapshotShare(
                    sid,
                    bool(snap.get("Encrypted")),
                    "all" in restore,
                    tuple(a for a in restore if a != "all"),
                )
            )
    except Exception as e:  # noqa: BLE001
        s.snapshots = None
        s.errors.append(f"snapshots: {e}")
    key = db.get("KmsKeyId")
    if key and kms is not None:
        try:
            meta = kms.describe_key(KeyId=key)["KeyMetadata"]
            s.kms_customer_managed = meta.get("KeyManager") == "CUSTOMER"
            if s.kms_customer_managed:
                s.kms_rotation = bool(kms.get_key_rotation_status(KeyId=key)["KeyRotationEnabled"])
        except Exception as e:  # noqa: BLE001
            s.errors.append(f"KMS key: {e}")
    secret = (db.get("MasterUserSecret") or {}).get("SecretArn")
    if secret and secrets is not None:
        try:
            s.secret_rotation = bool(
                secrets.describe_secret(SecretId=secret).get("RotationEnabled")
            )
        except Exception as e:  # noqa: BLE001
            s.errors.append(f"master secret: {e}")
    return s


def gather_db(conn, s: SecuritySnapshot) -> SecuritySnapshot:
    """Database-side facts. Each query is independent; a failure is recorded, not raised."""

    def q(sql):
        return conn.execute(sql).fetchall()

    try:
        s.non_ssl_connections = q(
            "SELECT count(*) AS n FROM pg_stat_ssl s JOIN pg_stat_activity a USING (pid) "
            "WHERE a.backend_type = 'client backend' AND NOT s.ssl"
        )[0]["n"]
    except Exception as e:  # noqa: BLE001
        s.errors.append(f"pg_stat_ssl: {e}")
    try:
        s.superuser_members = [
            r["rolname"]
            for r in q(
                "SELECT m.rolname FROM pg_auth_members am JOIN pg_roles g ON g.oid = am.roleid "
                "JOIN pg_roles m ON m.oid = am.member WHERE g.rolname = 'rds_superuser' "
                "AND m.rolname <> current_user ORDER BY 1"
            )
        ]
    except Exception as e:  # noqa: BLE001
        s.errors.append(f"roles: {e}")
    try:
        s.public_schema_create = bool(
            q("SELECT has_schema_privilege('public', 'public', 'CREATE') AS c")[0]["c"]
        )
    except Exception as e:  # noqa: BLE001
        s.errors.append(f"public schema: {e}")
    try:
        rows = q("SELECT rolname, encryption_type FROM rds_tools.role_password_encryption_type()")
        s.md5_roles = [r["rolname"] for r in rows if r["encryption_type"] == "md5"]
    except Exception:  # noqa: BLE001 - rds_tools not installed is common
        s.md5_roles = None
    return s
