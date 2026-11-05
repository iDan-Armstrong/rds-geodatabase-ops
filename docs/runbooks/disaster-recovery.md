# Runbook: zone and Region loss for an RDS geodatabase

`rdsops resilience --instance <id> --region <r> --dr-region <dr> --rto-minutes N
--rpo-minutes N` scores the recovery paths you have. `rdsops failover-drill` plans the
rehearsal and scores it. Neither changes anything.

## The paths

| Loss | Path | Data loss | Time back | Notes |
| --- | --- | --- | --- | --- |
| Instance or zone | Multi-AZ DB instance | None: synchronous standby | AWS: typically 60 to 120 s, plus clients reconnecting | The standby cannot serve reads. The endpoint's DNS record moves; clients must reconnect. |
| Instance or zone | Point-in-time restore | Up to the latest restorable time (minutes) | Measure it with `rdsops restore-drill` | New endpoint: ArcGIS data stores and `.sde` files must be repointed. |
| Region | Cross-Region read replica | Replica lag (seconds to minutes) | Promotion plus repointing; measure it | Promotion is not reversible. RDS reports up to five minutes of lag when nothing is written. |
| Region | Cross-Region automated backup replication | Minutes behind the source | A point-in-time restore in the DR Region; measure it | Cheapest real DR. Started from the destination Region; GovCloud (US-East) and (US-West) replicate to each other. |
| Region | Manual snapshot copies | Everything since the copy | A snapshot restore; measure it | Fine for archives, weak for DR. |

Encrypted copies need a KMS key in the DR Region: keys belong to one Region. Create it
before you need it (RES005). The engine version must be offered there too (RES006).

## Drills

- **Zone (`--kind az`)**: reboot with failover during an announced window. Record when the
  database takes writes and when ArcGIS services answer. If ArcGIS lags by minutes, lower
  the JVM DNS TTL; AWS advises 60 seconds or less.
- **Region (`--kind region`)**: restore the replicated backups (or the newest copy) to a
  scratch instance in the DR Region, register it on a staging ArcGIS Server, validate,
  time it, delete it. Rehearse promotion of the replica as a tabletop: who decides, who
  repoints, who tells users.

Record the drill as JSON and score it:

```json
{"kind": "region", "started": "2026-11-05T12:00:00Z", "writable_at": "2026-11-05T12:40:00Z",
 "apps_ok_at": "2026-11-05T12:44:00Z", "data_loss_seconds": 300,
 "checks": [{"name": "PostGIS present", "ok": true}]}
```

```bash
rdsops failover-drill --kind region --instance egdb --region us-east-1 --dr-region us-west-2 \
    --result drill.json --report drills.jsonl
rdsops resilience --instance egdb --region us-east-1 --dr-region us-west-2 --report drills.jsonl
```

## ArcGIS

Multi-AZ keeps the endpoint, so ArcGIS only has to reconnect. Every other path gives a new
endpoint: update each registered data store and `.sde` connection file, validate them,
and restart the services that hold connections. Put those steps, and who runs them, in
the plan before the day you need them.

## Sources

- [AWS: Failing over a Multi-AZ DB instance](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.MultiAZ.Failover.html)
- [AWS: Amazon RDS Multi-AZ](https://aws.amazon.com/rds/features/multi-az/)
- [AWS: Replicating automated backups to another Region](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ReplicateBackups.html)
- [AWS API: StartDBInstanceAutomatedBackupsReplication](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_StartDBInstanceAutomatedBackupsReplication.html)
- [AWS API: CopyDBSnapshot](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CopyDBSnapshot.html)
- [AWS: PostgreSQL read replicas](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_PostgreSQL.Replication.ReadReplicas.html)
