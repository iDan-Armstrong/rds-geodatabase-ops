"""Inventory: what the instance is, and whether its security posture matches the baseline.

Everything here reads from the RDS control plane (DescribeDBInstances), so it
needs IAM read access only, no database login.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from .findings import Finding, Severity


@dataclass(frozen=True)
class InstanceFacts:
    identifier: str
    engine: str
    engine_version: str
    instance_class: str
    status: str
    endpoint: str | None
    port: int | None
    multi_az: bool
    publicly_accessible: bool
    storage_encrypted: bool
    kms_key_id: str | None
    deletion_protection: bool
    backup_retention_days: int
    iam_auth: bool
    auto_minor_version_upgrade: bool
    performance_insights: bool
    parameter_groups: tuple[str, ...]
    ca_cert: str | None
    allocated_storage_gb: int
    max_allocated_storage_gb: int | None

    @property
    def engine_major(self) -> int:
        return int(self.engine_version.split(".")[0])

    def to_dict(self) -> dict:
        d = asdict(self)
        d["parameter_groups"] = list(self.parameter_groups)
        return d


def describe_instance(rds, identifier: str) -> InstanceFacts:
    """Read one instance from the RDS API into a flat, typed record."""
    resp = rds.describe_db_instances(DBInstanceIdentifier=identifier)
    db = resp["DBInstances"][0]
    endpoint = db.get("Endpoint") or {}
    return InstanceFacts(
        identifier=db["DBInstanceIdentifier"],
        engine=db["Engine"],
        engine_version=db["EngineVersion"],
        instance_class=db["DBInstanceClass"],
        status=db.get("DBInstanceStatus", "unknown"),
        endpoint=endpoint.get("Address"),
        port=endpoint.get("Port"),
        multi_az=bool(db.get("MultiAZ", False)),
        publicly_accessible=bool(db.get("PubliclyAccessible", False)),
        storage_encrypted=bool(db.get("StorageEncrypted", False)),
        kms_key_id=db.get("KmsKeyId"),
        deletion_protection=bool(db.get("DeletionProtection", False)),
        backup_retention_days=int(db.get("BackupRetentionPeriod", 0)),
        iam_auth=bool(db.get("IAMDatabaseAuthenticationEnabled", False)),
        auto_minor_version_upgrade=bool(db.get("AutoMinorVersionUpgrade", False)),
        performance_insights=bool(db.get("PerformanceInsightsEnabled", False)),
        parameter_groups=tuple(g["DBParameterGroupName"] for g in db.get("DBParameterGroups", [])),
        ca_cert=db.get("CACertificateIdentifier"),
        allocated_storage_gb=int(db.get("AllocatedStorage", 0)),
        max_allocated_storage_gb=db.get("MaxAllocatedStorage"),
    )


def posture_findings(facts: InstanceFacts, *, production: bool = False) -> list[Finding]:
    """Compare control-plane settings with the baseline the Terraform module sets.

    production=True turns availability gaps (single AZ, short retention) into
    failures instead of warnings.
    """
    out: list[Finding] = []
    gap = Severity.FAIL if production else Severity.WARN

    def add(code: str, ok: bool, bad: Severity, title: str, detail: str = "", **ev):
        out.append(Finding(code, Severity.OK if ok else bad, title, "" if ok else detail, ev))

    if facts.engine != "postgres":
        out.append(
            Finding(
                "INV000",
                Severity.FAIL,
                f"Engine is {facts.engine}, not postgres",
                "rdsops targets RDS for PostgreSQL. Aurora is out of scope (ADR 0002).",
            )
        )

    add(
        "INV001",
        facts.storage_encrypted,
        Severity.FAIL,
        "Storage encrypted at rest",
        "Encryption cannot be turned on in place: snapshot, copy with a KMS key, restore.",
        kms_key_id=facts.kms_key_id,
    )
    add(
        "INV002",
        not facts.publicly_accessible,
        Severity.FAIL,
        "No public endpoint",
        "ArcGIS clients belong in the same VPC; a public endpoint is never required.",
    )
    add(
        "INV003",
        facts.deletion_protection,
        gap,
        "Deletion protection on",
        "Turn on with modify-db-instance --deletion-protection.",
    )
    add(
        "INV004",
        facts.backup_retention_days >= 7,
        gap,
        f"Backup retention {facts.backup_retention_days} day(s) (baseline 7+)",
        "Retention also bounds how far back point-in-time restore can go.",
        backup_retention_days=facts.backup_retention_days,
    )
    add(
        "INV005",
        facts.iam_auth,
        Severity.WARN,
        "IAM database authentication available",
        "Lets admins and automation connect with short-lived tokens instead of stored passwords.",
    )
    add(
        "INV006",
        facts.multi_az,
        gap if production else Severity.INFO,
        "Multi-AZ standby",
        "Single AZ: an AZ outage or host failure means a restore, not a failover.",
    )
    add(
        "INV007",
        facts.performance_insights,
        Severity.INFO,
        "Performance Insights on",
        "rdsops health reads top waits from Performance Insights when it is available.",
    )

    if facts.auto_minor_version_upgrade:
        out.append(
            Finding(
                "INV008",
                Severity.WARN,
                "Auto minor version upgrade is on",
                "RDS may patch the engine before anyone checks the Esri support matrix. "
                "The baseline turns this off and patches through the upgrade runbook (ADR 0004).",
            )
        )
    else:
        out.append(Finding("INV008", Severity.OK, "Minor upgrades are manual (runbook-gated)"))

    if any(g.startswith("default.") for g in facts.parameter_groups):
        out.append(
            Finding(
                "INV009",
                Severity.WARN,
                "Using a default parameter group",
                "Default groups cannot be edited, so rds.force_ssl, pgaudit and "
                "pg_stat_statements cannot be set. Attach a custom group.",
                {"parameter_groups": list(facts.parameter_groups)},
            )
        )
    else:
        out.append(Finding("INV009", Severity.OK, "Custom parameter group attached"))

    return out
