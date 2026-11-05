# Runbook: move an RDS for PostgreSQL geodatabase to Aurora PostgreSQL

`rdsops aurora-plan` prints this runbook with the identifiers, Region and versions filled
in. This page explains the choices behind it.

## Pick the method

| | Aurora read replica | Snapshot |
| --- | --- | --- |
| Downtime | Only the promotion; writes stop briefly | Writes stop from the snapshot to the cutover |
| Region | Same Region and account only | Can be copied to another Region first |
| Blocked by | An existing Aurora read replica or a cross-Region read replica | Nothing above |
| Watch | `RDSToAuroraPostgreSQLReplicaLag`, `FreeStorageSpace`, `OldestReplicationSlotLag` on the source | Cluster status until `available` |

Both keep the PostgreSQL major version. The Aurora version must be the same as the
source or a higher minor in the same major, offered in the Region, and on Esri's Aurora
list for your ArcGIS release. If the major is not on that list, upgrade the RDS instance
first (`rdsops upgrade-plan`).

## Encryption

An encrypted source makes an encrypted cluster (`--storage-encrypted` is required). An
unencrypted source can be encrypted on the way with `--storage-encrypted --kms-key-id`.
AWS cannot make an unencrypted cluster from an encrypted source.

## GovCloud

ARNs use the `aws-us-gov` partition (`arn:aws-us-gov:rds:us-gov-west-1:...`), and every
command takes `--region us-gov-west-1` or `us-gov-east-1`. Aurora versions can arrive later
than in commercial Regions, which is why the planner reads them from the Region. Encrypt
at rest.

## ArcGIS cutover

1. Take a WebGISDR backup before anything else (`egisops backup-check` confirms it).
2. Stop the services and edit sessions that write to the geodatabase.
3. Promote (replica) or restore (snapshot), and add a reader in a second Availability Zone.
4. Update every registered data store and `.sde` connection file to the cluster writer
   endpoint, and validate the data stores.
5. Check PostGIS on the cluster and run `rdsops compat --platform aurora`.
6. Start services, test editing, and keep the old instance stopped until you are sure.

## Sources

- [AWS: migrating with an Aurora read replica](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/AuroraPostgreSQL.Migrating.RDSPostgreSQL.Replica.html)
- [AWS: migrating a snapshot](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/AuroraPostgreSQL.Migrating.RDSPostgreSQL.Import.Console.html)
- [Esri: databases in the cloud (12.1)](https://doc.esri.com/en/arcgis-enterprise/latest/plan/databases-in-the-cloud.html)
