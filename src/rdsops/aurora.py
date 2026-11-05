"""Aurora migration planning: move an RDS for PostgreSQL geodatabase to Aurora PostgreSQL.

``plan`` is pure. It takes what is known about the source instance and the Region
(``AuroraFacts``) and the choices made (``AuroraRequest``), and returns findings plus an
ordered runbook with the AWS CLI commands. ``gather`` reads the facts with boto3.

The rules come from AWS ("Migrating data from an RDS for PostgreSQL DB instance to an
Aurora PostgreSQL DB cluster by using an Aurora read replica", and the snapshot migration
page) and from Esri's Aurora support list in the compat matrix. Sources: docs/SCOPE.md and
docs/runbooks/aurora-migration.md.

Partition-aware: in AWS GovCloud (US) Regions every ARN uses ``aws-us-gov``, and the
Aurora versions on offer are read from the Region, not assumed from commercial Regions.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import compat
from .findings import Finding, Severity

METHODS = ("replica", "snapshot")
WAL_HEADROOM = 0.20  # free share of allocated storage to keep while WAL piles up


def partition(region: str) -> str:
    if region.startswith("us-gov-"):
        return "aws-us-gov"
    if region.startswith("cn-"):
        return "aws-cn"
    return "aws"


@dataclass
class AuroraFacts:
    source: str
    region: str
    engine_version: str
    account: str | None = None
    arn: str | None = None
    postgis_version: str | None = None
    encrypted: bool | None = None
    kms_key_id: str | None = None
    multi_az: bool | None = None
    aurora_replica_clusters: list[str] = field(default_factory=list)
    cross_region_replicas: list[str] = field(default_factory=list)
    allocated_gb: int | None = None
    free_bytes: int | None = None
    subnet_group: str | None = None
    security_groups: list[str] = field(default_factory=list)
    aurora_versions: list[str] | None = None  # offered in the Region; None when not read


@dataclass
class AuroraRequest:
    arcgis: str
    method: str = "replica"
    target_region: str | None = None  # None: same Region
    cluster: str | None = None
    writer_class: str = "db.r6g.large"


def source_arn(f: AuroraFacts) -> str:
    if f.arn:
        return f.arn
    return f"arn:{partition(f.region)}:rds:{f.region}:{f.account or '<account-id>'}:db:{f.source}"


def choose_target(facts: AuroraFacts, rel: compat.Release) -> tuple[str | None, str]:
    """Lowest Aurora version that AWS allows for this source (same major, same or higher
    minor), that the Region offers, and that Esri supports for the ArcGIS release."""
    src = compat.vtuple(facts.engine_version)
    major = str(src[0])
    esri_min = rel.aurora_postgresql.get(major)
    if esri_min is None:
        listed = ", ".join(sorted(rel.aurora_postgresql.values(), key=compat.vtuple))
        return None, (
            f"Esri lists no Aurora PostgreSQL {major} for ArcGIS Enterprise {rel.enterprise} "
            f"(Aurora versions listed: {listed or 'none'}). An Aurora read replica or snapshot "
            f"keeps the major version, so upgrade the RDS instance to a listed major first."
        )
    floor = max(src, compat.vtuple(esri_min))
    if facts.aurora_versions is None:
        return ".".join(map(str, floor[:2])), "Aurora versions in the Region were not read."
    offered = sorted(
        (v for v in facts.aurora_versions if compat.vtuple(v)[0] == src[0]), key=compat.vtuple
    )
    ok = [v for v in offered if compat.vtuple(v) >= floor]
    if not ok:
        return None, (
            f"{facts.region} offers Aurora PostgreSQL {major}: "
            f"{', '.join(offered) or 'none'}. None is at or above both the source "
            f"({facts.engine_version}) and Esri's minimum ({esri_min})."
        )
    return ok[0], ""


def plan(req: AuroraRequest, facts: AuroraFacts, matrix=None) -> tuple[list[Finding], list[str]]:
    out: list[Finding] = []
    steps: list[str] = []
    method = req.method if req.method in METHODS else "replica"
    region = facts.region
    target_region = req.target_region or region
    cluster = req.cluster or f"{facts.source}-aurora"
    gov = partition(region) == "aws-us-gov"
    matrix = matrix if matrix is not None else compat.load_matrix()
    rel = compat.find_release(matrix, req.arcgis)
    if rel is None:
        return compat.check(facts.engine_version, req.arcgis, matrix=matrix), steps

    # AUR001 target version
    target, why = choose_target(facts, rel)
    if target is None:
        out.append(Finding("AUR001", Severity.FAIL, "No Aurora version to migrate to", why))
    else:
        out.append(
            Finding(
                "AUR001",
                Severity.OK if not why else Severity.INFO,
                f"Target Aurora PostgreSQL {target}",
                why
                or f"The lowest version {region} offers that is at or above the source "
                f"({facts.engine_version}) and Esri's minimum for ArcGIS {rel.enterprise}.",
                {"target": target, "region": region},
            )
        )
        out += compat.check(
            target, req.arcgis, facts.postgis_version, matrix=matrix, platform="aurora"
        )

    # AUR002 method prerequisites
    if method == "replica":
        blockers = []
        if facts.aurora_replica_clusters:
            names = ", ".join(facts.aurora_replica_clusters)
            blockers.append(f"it already has an Aurora read replica ({names})")
        if facts.cross_region_replicas:
            blockers.append("it has a cross-Region read replica")
        if target_region != region:
            blockers.append(f"the target Region {target_region} is not the source Region {region}")
        if blockers:
            out.append(
                Finding(
                    "AUR002",
                    Severity.FAIL,
                    "An Aurora read replica cannot be created: " + "; ".join(blockers),
                    "AWS: the read replica option works only within the same Region and account, "
                    "and not when the instance already has an Aurora read replica or a "
                    "cross-Region read replica. Use --method snapshot, or remove the blocker.",
                )
            )
        else:
            out.append(
                Finding(
                    "AUR002",
                    Severity.OK,
                    "Aurora read replica method is available",
                    "Little downtime: the replica catches up while ArcGIS keeps working, and "
                    "writes stop only for the promotion.",
                )
            )
    else:
        out.append(
            Finding(
                "AUR002",
                Severity.INFO,
                "Snapshot method: writes stop for the whole migration",
                "Anything written after the snapshot is not in the cluster. Stop editing and "
                "services that write before taking it."
                + (
                    f" The snapshot must be copied to {target_region} first."
                    if target_region != region
                    else ""
                ),
            )
        )

    # AUR003 encryption
    if facts.encrypted is False:
        out.append(
            Finding(
                "AUR003",
                Severity.FAIL if gov else Severity.WARN,
                "Source is not encrypted at rest",
                "The migration is the moment to fix it: create the cluster with "
                "--storage-encrypted and a KMS key. An encrypted cluster cannot be made from "
                "this later without another migration."
                + (
                    " GovCloud workloads are normally required to encrypt data at rest."
                    if gov
                    else ""
                ),
            )
        )
    elif facts.encrypted:
        out.append(
            Finding(
                "AUR003",
                Severity.OK,
                "Source is encrypted; the cluster will be too",
                "AWS does not allow an unencrypted cluster from an encrypted source, so "
                "--storage-encrypted is required on create-db-cluster.",
            )
        )

    # AUR004 high availability during and after
    out.append(
        Finding(
            "AUR004",
            Severity.INFO,
            "No Multi-AZ during the migration"
            + (" (the source is Multi-AZ today)" if facts.multi_az else ""),
            "AWS: Multi-AZ is not available during the migration. After promotion, add an "
            "Aurora reader in a second Availability Zone for failover.",
        )
    )

    # AUR005 room for WAL while the replica catches up
    if method == "replica" and facts.allocated_gb and facts.free_bytes is not None:
        share = facts.free_bytes / (facts.allocated_gb * (1 << 30))
        out.append(
            Finding(
                "AUR005",
                Severity.WARN if share < WAL_HEADROOM else Severity.OK,
                f"{share:.0%} of storage free for WAL during replication",
                (
                    "WAL for the replica is kept on the source until Aurora applies it. "
                    "Add storage or turn on autoscaling first, and watch FreeStorageSpace "
                    "and OldestReplicationSlotLag."
                )
                if share < WAL_HEADROOM
                else "",
                {"free_bytes": facts.free_bytes},
            )
        )

    # AUR006 the ArcGIS side of the cutover
    out.append(
        Finding(
            "AUR006",
            Severity.INFO,
            "ArcGIS must be pointed at the cluster",
            "Registered data stores and .sde connection files name the RDS endpoint. After "
            "promotion, update each to the cluster writer endpoint, validate them, then check "
            "PostGIS on the cluster.",
        )
    )

    if target is None:
        return out, steps

    # Runbook
    reg = f"--region {region}"
    enc = (
        " --storage-encrypted" + (f" --kms-key-id {facts.kms_key_id}" if facts.kms_key_id else "")
        if facts.encrypted
        else " --storage-encrypted --kms-key-id <kms key arn>"
    )
    net = (f" --db-subnet-group-name {facts.subnet_group}" if facts.subnet_group else "") + (
        f" --vpc-security-group-ids {' '.join(facts.security_groups)}"
        if facts.security_groups
        else ""
    )
    steps.append(
        "Take a WebGISDR backup of ArcGIS Enterprise and a manual snapshot of "
        f"{facts.source}: aws rds create-db-snapshot {reg} --db-instance-identifier "
        f"{facts.source} --db-snapshot-identifier {facts.source}-pre-aurora"
    )
    if method == "replica":
        steps.append(
            f"aws rds create-db-cluster {reg} --db-cluster-identifier {cluster} "
            f"--engine aurora-postgresql --engine-version {target} "
            f"--replication-source-identifier {source_arn(facts)}{enc}{net}"
        )
        steps.append(
            f"aws rds create-db-instance {reg} --db-cluster-identifier {cluster} "
            f"--db-instance-identifier {cluster}-1 --db-instance-class {req.writer_class} "
            "--engine aurora-postgresql"
        )
        steps.append(
            "Watch RDSToAuroraPostgreSQLReplicaLag on the cluster, and FreeStorageSpace and "
            "OldestReplicationSlotLag on the source, until the replica is caught up"
        )
        steps.append(
            "Stop writes: stop ArcGIS services and edit sessions that write to the "
            "geodatabase. Check SELECT pg_current_wal_lsn() on the source is behind "
            "SELECT pg_last_wal_replay_lsn() on the cluster, and replica lag is 0"
        )
        steps.append(
            f"aws rds promote-read-replica-db-cluster {reg} --db-cluster-identifier {cluster}"
        )
    else:
        steps.append(
            "Stop writes: stop ArcGIS services and edit sessions that write to the geodatabase"
        )
        steps.append(
            f"aws rds create-db-snapshot {reg} --db-instance-identifier {facts.source} "
            f"--db-snapshot-identifier {facts.source}-to-aurora"
        )
        snap = f"{facts.source}-to-aurora"
        if target_region != region:
            steps.append(
                f"aws rds copy-db-snapshot --region {target_region} --source-region {region} "
                f"--source-db-snapshot-identifier "
                f"arn:{partition(region)}:rds:{region}:{facts.account or '<account-id>'}"
                f":snapshot:{snap} --target-db-snapshot-identifier {snap}"
                + (" --kms-key-id <kms key arn in the target Region>" if facts.encrypted else "")
            )
        kms = (
            ""
            if facts.encrypted
            else " --kms-key-id <kms key arn>"  # encrypts the cluster from an unencrypted snapshot
        )
        steps.append(
            f"aws rds restore-db-cluster-from-snapshot --region {target_region} "
            f"--db-cluster-identifier {cluster} --snapshot-identifier {snap} "
            f"--engine aurora-postgresql --engine-version {target}{kms}{net}"
        )
        steps.append(
            f"aws rds create-db-instance --region {target_region} --db-cluster-identifier "
            f"{cluster} --db-instance-identifier {cluster}-1 --db-instance-class "
            f"{req.writer_class} --engine aurora-postgresql"
        )
    steps.append(
        f"aws rds create-db-instance --region {target_region} --db-cluster-identifier {cluster} "
        f"--db-instance-identifier {cluster}-2 --db-instance-class {req.writer_class} "
        "--engine aurora-postgresql --availability-zone <a second AZ>  (reader for failover)"
    )
    steps.append(
        "Point ArcGIS at the cluster writer endpoint: update each registered data store "
        "(Server Manager > Site > Data Stores, or POST admin/data/items/<item>/edit) and the "
        ".sde connection files, then validate the data stores"
    )
    steps.append(
        "On the cluster: SELECT postgis_full_version(); then rdsops compat --platform aurora "
        f"--engine-version {target} --postgis <version> --arcgis {rel.enterprise}"
    )
    steps.append(
        "Start ArcGIS services and test editing. Keep the source instance stopped, not "
        "deleted, until the cluster has run cleanly for an agreed period (RDS starts a "
        "stopped instance again after seven days); delete it with a final snapshot"
    )
    return out, steps


# --------------------------------------------------------------- gathering


def free_storage_bytes(cloudwatch, identifier: str) -> int | None:
    from datetime import UTC, datetime, timedelta

    end = datetime.now(UTC) + timedelta(minutes=1)
    result = cloudwatch.get_metric_data(
        MetricDataQueries=[
            {
                "Id": "free",
                "MetricStat": {
                    "Metric": {
                        "Namespace": "AWS/RDS",
                        "MetricName": "FreeStorageSpace",
                        "Dimensions": [{"Name": "DBInstanceIdentifier", "Value": identifier}],
                    },
                    "Period": 300,
                    "Stat": "Minimum",
                },
            }
        ],
        StartTime=end - timedelta(minutes=30),
        EndTime=end,
    )["MetricDataResults"]
    points = result[0]["Values"] if result else []
    return int(min(points)) if points else None


def gather(rds, cloudwatch, source: str, region: str) -> AuroraFacts:
    db = rds.describe_db_instances(DBInstanceIdentifier=source)["DBInstances"][0]
    arn = db.get("DBInstanceArn")
    account = arn.split(":")[4] if arn and arn.count(":") >= 5 else None
    replicas = db.get("ReadReplicaDBInstanceIdentifiers") or []
    versions: list[str] = []
    for page in rds.get_paginator("describe_db_engine_versions").paginate(
        Engine="aurora-postgresql"
    ):
        versions += [v["EngineVersion"] for v in page["DBEngineVersions"]]
    return AuroraFacts(
        source=source,
        region=region,
        engine_version=db["EngineVersion"],
        account=account,
        arn=arn,
        encrypted=bool(db.get("StorageEncrypted")),
        kms_key_id=db.get("KmsKeyId"),
        multi_az=bool(db.get("MultiAZ")),
        aurora_replica_clusters=list(db.get("ReadReplicaDBClusterIdentifiers") or []),
        # same-Region replicas are listed by name; cross-Region ones by ARN
        cross_region_replicas=[r for r in replicas if r.startswith("arn:")],
        allocated_gb=int(db.get("AllocatedStorage") or 0) or None,
        free_bytes=free_storage_bytes(cloudwatch, source),
        subnet_group=(db.get("DBSubnetGroup") or {}).get("DBSubnetGroupName"),
        security_groups=[g["VpcSecurityGroupId"] for g in db.get("VpcSecurityGroups") or []],
        aurora_versions=sorted(set(versions), key=compat.vtuple),
    )
