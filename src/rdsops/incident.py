"""Incident playbooks: contingency plans for an RDS geodatabase, filled in for the instance.

``playbook`` is pure. It takes the kind of incident and what is known (``IncidentContext``)
and returns readiness findings plus ordered steps, each tagged with its phase. It never
runs anything. The phases follow the incident handling practice in NIST SP 800-61 Rev. 3
(contain, eradicate, recover, with evidence kept and lessons fed back), and the federal
notification step follows CISA's Federal Incident Notification Guidelines. Sources and
the reasoning per step are in docs/runbooks/security-incidents.md.

Two rules run through every playbook:
- Preserve before you change. A snapshot of the instance as it is, and the logs, come
  before restoring, rotating or deleting anything, because those steps destroy evidence.
- Assume the blast radius is wider than it looks until the logs say otherwise.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from .findings import Finding, Severity

KINDS = {
    "credentials": "A database password or the master secret is exposed or in the wrong hands",
    "aws-keys": "AWS access keys that can manage RDS are exposed",
    "exposure": "The database or a snapshot was reachable from the internet",
    "destruction": "Data was deleted, overwritten or encrypted by someone",
    "exfiltration": "Data or a snapshot may have left the account",
    "certificate": "TLS failures: an expired or untrusted certificate",
}
PHASES = ("Triage", "Notify", "Contain", "Preserve", "Eradicate", "Recover", "Learn")


@dataclass
class IncidentContext:
    kind: str
    instance: str
    region: str
    federal: bool = False
    role: str | None = None  # the database role involved, if known
    access_key: str | None = None  # AWS access key id involved, if known
    since: datetime | None = None  # last known good time, or when it started
    now: datetime | None = None
    managed_secret: bool | None = None
    deletion_protection: bool | None = None
    publicly_accessible: bool | None = None
    backup_retention_days: int | None = None
    earliest_restorable: datetime | None = None
    snapshot: str | None = None  # a snapshot involved (exposure, exfiltration)
    group: str | None = None  # a security group involved
    cidr: str | None = None
    arcgis: bool = True  # ArcGIS clients connect to this database


@dataclass
class Step:
    phase: str
    title: str
    command: str = ""
    why: str = ""


COMMAND_STARTS = ("aws ", "rdsops ", "SELECT", "ALTER", "REVOKE", "SET ", "\\", "terraform ")


def is_command(text: str) -> bool:
    """True for something to run (shell or SQL), False for an instruction or a link."""
    return text.startswith(COMMAND_STARTS)


@dataclass
class Playbook:
    kind: str
    findings: list[Finding] = field(default_factory=list)
    steps: list[Step] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "findings": [f.to_dict() for f in self.findings],
            "steps": [s.__dict__ for s in self.steps],
        }


def _stamp(c: IncidentContext) -> str:
    return (c.now or datetime.now()).strftime("%Y%m%d%H%M")


def _r(c: IncidentContext) -> str:
    return f"--region {c.region}"


# --------------------------------------------------------------- shared steps


def _triage(c: IncidentContext) -> list[Step]:
    return [
        Step(
            "Triage",
            "Open an incident record and name one incident lead",
            "",
            "Start a timeline now (UTC). Every action from here on goes in it with who and when.",
        ),
        Step(
            "Triage",
            "Scope: what can this instance reach, and what can reach it",
            f"aws rds describe-db-instances {_r(c)} --db-instance-identifier {c.instance}",
            "Note the endpoint, security groups, snapshots and the ArcGIS sites that connect.",
        ),
    ]


def _notify(c: IncidentContext) -> list[Step]:
    if c.federal:
        return [
            Step(
                "Notify",
                "Report to CISA within one hour of identification",
                "https://www.cisa.gov/report",
                "CISA's Federal Incident Notification Guidelines: federal Executive Branch "
                "civilian agencies notify CISA within one hour of the incident being identified "
                "by the agency's top-level CSIRT, SOC or IT department. Report what is known; "
                "update later. Contractors and cloud providers report through the agency and "
                "their FedRAMP or contract terms.",
            ),
            Step(
                "Notify",
                "Tell the agency SOC and the system owner",
                "",
                "Follow the agency incident response plan for internal escalation and for "
                "privacy officials if personal data may be involved.",
            ),
        ]
    return [
        Step(
            "Notify",
            "Escalate under your incident response plan",
            "",
            "Security team, system owner, and legal or privacy if personal data may be "
            "involved. Regulated data can carry its own notification deadlines.",
        )
    ]


def _evidence(c: IncidentContext, why: str) -> list[Step]:
    snap = f"{c.instance}-incident-{_stamp(c)}"
    return [
        Step(
            "Preserve",
            "Snapshot the instance as it is now",
            f"aws rds create-db-snapshot {_r(c)} --db-instance-identifier {c.instance} "
            f"--db-snapshot-identifier {snap} --tags Key=incident,Value=true",
            why,
        ),
        Step(
            "Preserve",
            "Keep the database logs for the window",
            f"aws rds describe-db-log-files {_r(c)} --db-instance-identifier {c.instance}"
            + (f"  (since {c.since.isoformat()})" if c.since else "")
            + f"; aws logs create-export-task {_r(c)} --log-group-name "
            f"/aws/rds/instance/{c.instance}/postgresql --from <ms> --to <ms> "
            "--destination <evidence bucket>",
            "Log files on the instance rotate away. pgaudit lines show what each role ran.",
        ),
        Step(
            "Preserve",
            "Pull the CloudTrail record for the instance",
            f"aws cloudtrail lookup-events {_r(c)} --lookup-attributes "
            f"AttributeKey=ResourceName,AttributeValue={c.instance}"
            + (f" --start-time {c.since.isoformat()}" if c.since else ""),
            "Who changed what in the control plane: security groups, snapshots, parameters, "
            "passwords. CloudTrail event history keeps 90 days; trails keep what you configured.",
        ),
    ]


def _guard(c: IncidentContext) -> list[Step]:
    if c.deletion_protection is False:
        return [
            Step(
                "Contain",
                "Turn on deletion protection",
                f"aws rds modify-db-instance {_r(c)} --db-instance-identifier {c.instance} "
                "--deletion-protection --apply-immediately",
                "It is off. Whoever is in can delete the instance with one call.",
            )
        ]
    return []


def _arcgis_reconnect(c: IncidentContext, what: str) -> list[Step]:
    if not c.arcgis:
        return []
    return [
        Step(
            "Recover",
            f"Update ArcGIS: {what}",
            "Edit each registered data store (Server Manager, or POST admin/data/items/<item>/"
            "edit), replace .sde connection files, then validate the data stores",
            "Services keep failing, or keep using the old credentials, until this is done.",
        )
    ]


def _learn(c: IncidentContext) -> list[Step]:
    return [
        Step(
            "Learn",
            "Review within two weeks",
            f"rdsops security --instance {c.instance} --region {c.region}",
            "What let it happen, what found it, how long each phase took. Turn each answer "
            "into a change and a check, and run the security scan again.",
        )
    ]


# --------------------------------------------------------------- playbooks


def _credentials(c: IncidentContext, pb: Playbook) -> None:
    who = c.role or "<role>"
    pb.steps += _evidence(
        c,
        "Before passwords change and sessions end, so their activity is still on record.",
    )
    pb.steps += [
        Step(
            "Preserve",
            "Save who is connected right now",
            "\\copy (SELECT now(), pid, usename, client_addr, backend_start, state, query FROM "
            "pg_stat_activity) TO 'sessions.csv' CSV HEADER",
            "Ending sessions erases this. It is the quickest record of where the role came from.",
        ),
        Step(
            "Contain",
            f"Stop logins for {who} and end its sessions",
            f"ALTER ROLE {who} NOLOGIN; SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
            f"WHERE usename = '{who}';",
            "NOLOGIN first, or the attacker reconnects as soon as the session ends.",
        )
        if c.role
        else Step(
            "Contain",
            "Find which role it is, then stop its logins and end its sessions",
            "SELECT usename, client_addr, backend_start, state, query FROM pg_stat_activity "
            "ORDER BY backend_start;",
            "Unknown client addresses and odd hours point to the role in use.",
        ),
        Step(
            "Contain",
            "Rotate the master credential",
            f"aws rds modify-db-instance {_r(c)} --db-instance-identifier {c.instance} "
            "--rotate-master-user-password --apply-immediately"
            if c.managed_secret
            else f"aws rds modify-db-instance {_r(c)} --db-instance-identifier {c.instance} "
            "--manage-master-user-password --apply-immediately",
            "The master user can change every other role. Rotate it even if the leak looks "
            "smaller."
            + (
                ""
                if c.managed_secret
                else " Moving it into Secrets Manager also means no person knows it afterwards."
            ),
        ),
    ]
    pb.steps += _guard(c)
    pb.steps += [
        Step(
            "Eradicate",
            "Look for what the role left behind",
            "SELECT rolname, rolcanlogin, rolvaliduntil FROM pg_roles WHERE oid > 16384 ORDER BY "
            "rolname; and in the pgaudit log: CREATE ROLE, GRANT, ALTER ROLE, CREATE FUNCTION",
            "New roles, new grants and functions are how access survives a password change.",
        ),
        Step(
            "Eradicate",
            f"Set a new password for {who} and reset every role that shared it",
            f"SET password_encryption = 'scram-sha-256'; \\password {who}",
            "Passwords reused across roles or environments are all exposed.",
        ),
        Step(
            "Recover",
            f"Allow logins for {who} again",
            f"ALTER ROLE {who} LOGIN;",
            "Only after the new password is in place everywhere that needs it.",
        ),
    ]
    pb.steps += _arcgis_reconnect(c, "new credentials in every data store and connection file")


def _aws_keys(c: IncidentContext, pb: Playbook) -> None:
    key = c.access_key or "<access key id>"
    pb.steps += [
        Step(
            "Contain",
            f"Deactivate the key {key}",
            f"aws iam update-access-key --access-key-id {key} --status Inactive --user-name <user>",
            "Deactivate, do not delete: the key id is the thread through CloudTrail.",
        ),
        Step(
            "Contain",
            "Revoke the sessions it may have started",
            "Attach a deny policy with aws:TokenIssueTime before now to the user or role "
            "(the IAM console's Revoke active sessions does this for roles)",
            "Temporary credentials made with the key keep working until they expire.",
        ),
    ]
    pb.steps += _guard(c)
    pb.steps += _evidence(c, "The instance and its snapshots are what the key could reach.")
    pb.steps += [
        Step(
            "Preserve",
            "Everything the key did",
            f"aws cloudtrail lookup-events {_r(c)} --lookup-attributes "
            f"AttributeKey=AccessKeyId,AttributeValue={key}",
            "Look for ModifyDBInstance, ModifyDBSnapshotAttribute, CopyDBSnapshot, "
            "AuthorizeSecurityGroupIngress, CreateDBSnapshot and DeleteDBInstance. Repeat in "
            "every Region the key could use.",
        ),
        Step(
            "Eradicate",
            "Undo what it changed",
            "For each change found: remove snapshot shares, revoke added security group rules, "
            "restore parameter values, delete instances or snapshots it created after copying "
            "them as evidence",
            "Then decide from the findings whether this is also an exposure, exfiltration or "
            "destruction incident, and run that playbook too.",
        ),
        Step(
            "Recover",
            "Replace the key with a role",
            "Give the workload an IAM role (instance profile or IAM Identity Center) and delete "
            "the old key after the investigation",
            "Long-lived keys are what leaked. Roles hand out credentials that expire.",
        ),
    ]


def _exposure(c: IncidentContext, pb: Playbook) -> None:
    steps = []
    if c.snapshot:
        steps.append(
            Step(
                "Contain",
                f"Make snapshot {c.snapshot} private",
                f"aws rds modify-db-snapshot-attribute {_r(c)} --db-snapshot-identifier "
                f"{c.snapshot} --attribute-name restore --values-to-remove all",
                "Every minute it is public, any AWS account can copy the whole geodatabase.",
            )
        )
    if c.group and c.cidr:
        steps.append(
            Step(
                "Contain",
                f"Remove the {c.cidr} rule from {c.group}",
                f"aws ec2 revoke-security-group-ingress {_r(c)} --group-id {c.group} "
                f"--protocol tcp --port 5432 --cidr {c.cidr}",
                "Write the rule down first (Preserve below has the CloudTrail event).",
            )
        )
    if c.publicly_accessible is not False:
        steps.append(
            Step(
                "Contain",
                "Turn off public access",
                f"aws rds modify-db-instance {_r(c)} --db-instance-identifier {c.instance} "
                "--no-publicly-accessible --apply-immediately",
                "ArcGIS connects from inside the VPC and does not need it.",
            )
        )
    steps.append(
        Step(
            "Contain",
            "Find anything else that is open",
            f"aws rds describe-db-instances {_r(c)} --db-instance-identifier {c.instance} "
            "--query 'DBInstances[0].[PubliclyAccessible,VpcSecurityGroups]'; aws ec2 "
            f"describe-security-groups {_r(c)} --group-ids <groups>; for each manual snapshot: "
            f"aws rds describe-db-snapshot-attributes {_r(c)} --db-snapshot-identifier <snapshot>",
            "Public address, a 0.0.0.0/0 rule on the port, or a snapshot whose restore "
            "attribute includes all. Close each one the same way.",
        )
    )
    pb.steps += steps + _guard(c)
    pb.steps += _evidence(c, "The configuration and logs show how long it was open.")
    pb.steps += [
        Step(
            "Preserve",
            "Find who opened it and when",
            f"aws cloudtrail lookup-events {_r(c)} --lookup-attributes "
            "AttributeKey=EventName,AttributeValue=ModifyDBSnapshotAttribute (and "
            "AuthorizeSecurityGroupIngress, ModifyDBInstance)",
            "The exposure window runs from that event to the containment step.",
        ),
        Step(
            "Eradicate",
            "Check who connected during the window",
            "Search the PostgreSQL log for connection authorized lines from addresses outside "
            "your networks between the open and close times",
            "No log for the window means you cannot rule access out; plan as if it happened.",
        ),
        Step(
            "Eradicate",
            "Rotate credentials that were reachable",
            "Run rdsops incident --kind credentials for the master user and every login role",
            "Anything that could have been brute-forced or sniffed while exposed is suspect.",
        ),
        Step(
            "Recover",
            "Put a guard rail on it",
            "An AWS Config rule or SCP that denies public RDS instances and public snapshots",
            "The same mistake should be refused next time, not found.",
        ),
    ]


def _destruction(c: IncidentContext, pb: Playbook) -> None:
    before = c.since.isoformat() if c.since else "<a time before the damage>"
    target = f"{c.instance}-restored-{_stamp(c)}"
    pb.steps += [
        Step(
            "Contain",
            "Stop the writing",
            "Stop ArcGIS services and sync jobs that edit; REVOKE INSERT, UPDATE, DELETE ON ALL "
            "TABLES IN SCHEMA <schema> FROM <app roles>; or end the attacker's sessions "
            "(credentials playbook)",
            "Damage that keeps happening moves the restore point later and later.",
        ),
    ]
    pb.steps += _guard(c)
    pb.steps += _evidence(
        c,
        "Before any restore. The damaged state is the evidence, and a restore you do not "
        "keep separate can overwrite it.",
    )
    pb.steps += [
        Step(
            "Eradicate",
            "Close the way in before bringing data back",
            "Run the credentials or aws-keys playbook for how they got in",
            "Restoring into the same hole invites the same damage.",
        ),
        Step(
            "Recover",
            f"Restore to a new instance at {before}",
            f"aws rds restore-db-instance-to-point-in-time {_r(c)} --source-db-instance-identifier "
            f"{c.instance} --target-db-instance-identifier {target} --restore-time {before} "
            "--no-publicly-accessible --deletion-protection",
            "A new instance, not over the old one: compare them, and keep the damaged one.",
        ),
        Step(
            "Recover",
            "Verify the restored copy before anyone uses it",
            "rdsops restore-drill style checks: PostGIS present, geodatabase present, row "
            "counts of the damaged tables match what you expect",
            "Make sure the restore point is before the damage, not just before you noticed.",
        ),
    ]
    pb.steps += _arcgis_reconnect(c, "point data stores at the restored instance")


def _exfiltration(c: IncidentContext, pb: Playbook) -> None:
    pb.steps += _evidence(c, "The instance and snapshot state at the time you found it.")
    pb.steps += [
        Step(
            "Contain",
            "Cut every share",
            f"aws rds describe-db-snapshot-attributes {_r(c)} --db-snapshot-identifier "
            f"{c.snapshot or '<snapshot>'}; then --values-to-remove for every account that is "
            "not yours",
            "A snapshot already copied cannot be pulled back. Stop further copies.",
        ),
        Step(
            "Contain",
            "Check the KMS key policy and grants",
            f"aws kms list-grants {_r(c)} --key-id <key>; aws kms get-key-policy {_r(c)} "
            "--key-id <key> --policy-name default",
            "An encrypted snapshot is only useful elsewhere if the other account can use your "
            "key. Remove any grant or policy entry for an account that is not yours.",
        ),
        Step(
            "Preserve",
            "Trace the copies",
            f"aws cloudtrail lookup-events {_r(c)} --lookup-attributes "
            "AttributeKey=EventName,AttributeValue=CopyDBSnapshot (and "
            "ModifyDBSnapshotAttribute, StartExportTask)",
            "Snapshot exports to S3 count too. Note the destination accounts and buckets.",
        ),
        Step(
            "Eradicate",
            "Decide what was in it",
            "List the schemas and tables in the copied snapshot's time window, and whether any "
            "hold personal or sensitive data",
            "This decides who must be told. Geodatabases often hold owner names and addresses.",
        ),
    ]


def _certificate(c: IncidentContext, pb: Playbook) -> None:
    pb.steps += [
        Step(
            "Contain",
            "Confirm it is the certificate",
            f"aws rds describe-db-instances {_r(c)} --db-instance-identifier {c.instance} "
            "--query 'DBInstances[0].CertificateDetails'; aws rds describe-certificates",
            "Expired or untrusted, and which CA. Clients report SSL errors, not certificates.",
        ),
        Step(
            "Contain",
            "Update the trust bundle on every client first",
            "Download the current RDS CA bundle for the Region and install it on ArcGIS Server "
            "machines, ArcGIS Pro machines and anything else that verifies the server",
            "Rotating the server before clients trust the new CA moves the outage, not ends it.",
        ),
        Step(
            "Recover",
            "Rotate to a current CA",
            f"aws rds modify-db-instance {_r(c)} --db-instance-identifier {c.instance} "
            "--ca-certificate-identifier rds-ca-rsa2048-g1 --apply-immediately",
            "Some engine versions restart to apply it. Plan the window.",
        ),
        Step(
            "Recover",
            "Do not fix it by turning off TLS",
            "Keep rds.force_ssl = 1",
            "Turning off verification or TLS trades an outage for an exposure.",
        ),
    ]


BUILDERS = {
    "credentials": _credentials,
    "aws-keys": _aws_keys,
    "exposure": _exposure,
    "destruction": _destruction,
    "exfiltration": _exfiltration,
    "certificate": _certificate,
}


def readiness(c: IncidentContext) -> list[Finding]:
    """What already limits the response, before the first step."""
    out: list[Finding] = []
    if c.kind == "destruction":
        if c.backup_retention_days == 0:
            out.append(
                Finding(
                    "INC001",
                    Severity.FAIL,
                    "No point-in-time recovery: automated backups are off",
                    "The only way back is a manual snapshot or a WebGISDR backup taken before "
                    "the damage. Check for both now.",
                )
            )
        elif c.since and c.earliest_restorable and c.since < c.earliest_restorable:
            out.append(
                Finding(
                    "INC001",
                    Severity.FAIL,
                    "The damage is older than the earliest restorable time",
                    f"Earliest restorable: {c.earliest_restorable.isoformat()}. Look for a manual "
                    "snapshot or WebGISDR backup from before "
                    f"{c.since.isoformat()}.",
                )
            )
        elif c.since:
            out.append(
                Finding("INC001", Severity.OK, "The restore point is inside the backup window")
            )
    if c.deletion_protection is False:
        out.append(
            Finding(
                "INC002",
                Severity.WARN,
                "Deletion protection is off",
                "The playbook turns it on first; an attacker with access could delete it.",
            )
        )
    if c.kind == "credentials" and c.managed_secret is False:
        out.append(
            Finding(
                "INC003",
                Severity.WARN,
                "The master password is not in Secrets Manager",
                "Rotation means setting a new one by hand and getting it to everyone who needs "
                "it. The playbook moves it into Secrets Manager instead.",
            )
        )
    if c.kind in ("exposure", "exfiltration") and c.publicly_accessible:
        out.append(
            Finding("INC004", Severity.FAIL, "The instance is publicly accessible right now")
        )
    if c.federal:
        out.append(
            Finding(
                "INC005",
                Severity.INFO,
                "Federal: CISA notification within one hour of identification",
                "The Notify step comes right after triage for that reason.",
            )
        )
    return out


def playbook(c: IncidentContext) -> Playbook:
    if c.kind not in BUILDERS:
        raise ValueError(f"unknown incident kind {c.kind!r}; one of {', '.join(KINDS)}")
    pb = Playbook(c.kind, readiness(c))
    pb.steps += _triage(c) + _notify(c)
    BUILDERS[c.kind](c, pb)
    pb.steps += _learn(c)
    return pb
