# Enterprise geodatabase on RDS: what this module does and does not do

The module creates the PostgreSQL instance. The geodatabase is created afterward with
Esri's tools, because only they know how to lay down the sde schema for your ArcGIS
release.

## After `terraform apply`

1. Read the master password from the Secrets Manager secret in the
   `master_user_secret_arn` output. Use it only for the next step.
2. From a machine in the same VPC (an EC2 instance running ArcGIS Pro, or ArcGIS
   Server), connect as the master user and create the `sde` login with the privileges
   Esri documents for RDS, plus the PostGIS extension if it is not already there.
3. Run the **Enable Enterprise Geodatabase** geoprocessing tool as `sde`, or use Esri's
   AWS deployment tools, which create a database named `egdb` and the `sde` owner for
   you.
4. Register the database with ArcGIS Server if services will reference it.
5. Run `rdsops inventory` (and, from v0.3, `rdsops compat`) and keep the output with the
   change record.

## Facts to keep in mind

- Spatial type is PostGIS. ST_Geometry cannot be loaded on RDS.
- Clients must be in the same AWS region. Pro on a laptop talking to RDS works, but slowly
  enough that Esri does not support it.
- The `sde` user owns the geodatabase system tables. Treat it as an application owner,
  not a person: no interactive use, credentials in Secrets Manager.
- Versioned editing grows the state and lineage tables until a compress runs. v0.5 adds
  checks for that growth and for compress cadence.

Sources: see the table in [SCOPE.md](SCOPE.md).
