# Runbook: restore drill

A backup you have never restored is a hope, not a backup. A drill restores the
production instance to a throwaway copy, times how long until the copy is usable,
checks the data is there, and deletes the copy. The source is never touched.

## Plan first (free, read-only)

```bash
rdsops restore-drill --instance egdb-prod --rto-minutes 60 --rpo-minutes 15
```

Prints what it would do and checks it can: backups on, restore point inside the
window, a snapshot to use in snapshot mode, and how much data a real restore at that
point would lose.

## Run it

```bash
rdsops restore-drill --instance egdb-prod --execute \
    --user ops --dbname egdb --iam \
    --verify-table gis.parcels --verify-table sewer.manholes \
    --report drills.jsonl
```

- `--mode pitr` (default) restores to the latest restorable time, or `--restore-time`.
  `--mode snapshot` restores the newest snapshot, or `--snapshot <id>`.
- The copy is private, single-AZ, has no deletion protection, and is tagged
  `rdsops-drill=true`. RDS would otherwise copy deletion protection from the source,
  and the cleanup would fail.
- Cleanup deletes only an instance that has that tag and is not the source.
- `--instance-class` restores to a smaller class to save money, but then the timing
  is not what production would get. Use the production class at least once a quarter.
- `--keep` leaves the copy running for manual checks. It bills until you delete it.
- `--report` appends each drill as a JSON line, which is the evidence an auditor asks for.

## What the findings mean

| Code | Meaning |
| --- | --- |
| DRL001 | Backups or a snapshot exist to restore from |
| DRL002 | The requested restore time is inside the restore window |
| DRL003 | Planned data loss (restore point age) against the RPO target |
| DRL004 | What the copy will look like |
| DRL010 | The restore completed, and how long RDS took |
| DRL011 | Time from start to a usable, verified copy, against the RTO target |
| DRL012 | Actual restore point age against the RPO target |
| DRL013 | Each verification check on the copy |
| DRL014 | The copy was deleted (or kept, and still billing) |

## Permissions

The identity running the drill needs `rds:DescribeDBInstances`,
`rds:DescribeDBSnapshots`, `rds:DescribeDBInstanceAutomatedBackups`,
`rds:RestoreDBInstanceToPointInTime`, `rds:RestoreDBInstanceFromDBSnapshot`,
`rds:AddTagsToResource`, `rds:ModifyDBInstance` and `rds:DeleteDBInstance`, plus
`rds-db:connect` for IAM verification. Scope the modify and delete permissions with
a condition on the `rdsops-drill` tag.

## Cost

A drill bills the copy's instance hours and storage for its lifetime, typically under
an hour. On a `db.t4g.micro` lab that is a few cents.

## Sources (checked 2026-11-04)

- [AWS: Restoring a DB instance to a specified time](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_PIT.html)
- [AWS: Introduction to backups](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html)
- [AWS CLI: restore-db-instance-to-point-in-time](https://docs.aws.amazon.com/cli/latest/reference/rds/restore-db-instance-to-point-in-time.html)
- [AWS: Deleting a DB instance](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_DeleteInstance.html)
