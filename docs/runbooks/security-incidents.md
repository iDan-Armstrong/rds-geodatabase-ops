# Runbook: security incidents on an RDS geodatabase

`rdsops incident --kind <kind> --instance <id> --region <region>` prints the playbook for
the instance, with its identifiers and Region in every command. `rdsops security` is the
check to run before an incident (and again in the review after one).

## Principles

1. **Name a lead and start a timeline.** Every action, who did it and when, in UTC.
2. **Notify on time.** Federal Executive Branch civilian agencies notify CISA within one
   hour of the incident being identified by their top-level CSIRT, SOC or IT department.
   Contractors and cloud providers report through the agency and their FedRAMP or
   contract terms. Others follow their incident response plan and any regulatory clock.
3. **Contain, but preserve before you destroy.** Closing an exposure can come first; a
   restore, a password reset or ending sessions cannot come before the evidence is kept.
4. **Assume the blast radius is wider** until logs show otherwise. Exposure means rotate
   credentials. Leaked keys mean check every Region they could use.
5. **Fix the way in before bringing data back.**
6. **Turn on deletion protection** if it is off, before anything else changes.

## The playbooks

| Kind | When | First moves |
| --- | --- | --- |
| `credentials` | A database password or the master secret is in the wrong hands | Snapshot and save sessions, NOLOGIN and end sessions for the role, rotate the master credential |
| `aws-keys` | Access keys that can manage RDS leaked | Deactivate the key, revoke its sessions, list everything it did in CloudTrail |
| `exposure` | Public endpoint, open security group, or a public snapshot | Make the snapshot private, remove the rule, turn off public access, then find who opened it |
| `destruction` | Deleted, overwritten or encrypted data | Stop the writing, snapshot the damage, close the way in, restore to a new instance |
| `exfiltration` | A snapshot or data may have left the account | Snapshot, cut shares, check KMS grants, trace copies and exports |
| `certificate` | TLS failures | Confirm the certificate, update client trust bundles, then rotate the CA; never turn off TLS to fix it |

Each playbook ends with a review, and the readiness findings at the top say what already
limits the response (no point-in-time recovery, damage older than the backup window, no
managed secret, a public instance).

## ArcGIS

Credentials and endpoints live in ArcGIS too: registered data stores and `.sde`
connection files. Every playbook that changes credentials or restores to a new instance
includes updating and validating them; without that step services fail or keep using the
old credentials.

## Sources

- [NIST SP 800-61 Rev. 3, Incident Response Recommendations and Considerations for Cybersecurity Risk Management (April 2025)](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [CISA Federal Incident Notification Guidelines](https://www.cisa.gov/incident-notification-guidelines)
- [AWS: Using SCRAM for PostgreSQL password encryption](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/PostgreSQL_Password_Encryption_configuration.html)
- [AWS: Using SSL/TLS to encrypt a connection to a DB instance](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html)
