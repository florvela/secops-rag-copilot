---
documento: MITRE ATT&CK — Valid Accounts: Cloud Accounts
version: ATT&CK v15
fuente: mitre
tecnicas: T1078.004
---

# T1078.004 Valid Accounts: Cloud Accounts

Adversaries may obtain and abuse credentials of a cloud account as a means of gaining
initial access, persistence, privilege escalation, or defense evasion. Cloud accounts
are those created and configured by an organization for use by users, remote support,
services, or for administration of resources within a cloud service provider or SaaS
application. In some cases, cloud accounts may be federated with traditional identity
management systems.

Compromised cloud accounts are frequently used to access services through the management
console or programmatic interfaces. A successful console sign-in that does not use
multi-factor authentication (MFA) is a common signal worth investigating, because MFA
materially reduces the value of a stolen password.

## Detection

Monitor for unusual sign-in activity: logins from new source IP addresses, unfamiliar
user agents, impossible travel, or authentications that bypass MFA. In AWS, CloudTrail
`ConsoleLogin` events expose whether MFA was used through the `additional_event_data`
field (`MFAUsed`). Correlate the actor, the source IP and the time against the user's
baseline. A single successful console sign-in with `MFAUsed = No` on a human identity is
suspicious, especially for privileged roles.

## Mitigation

Enforce MFA for all human identities. Restrict the use of long-lived credentials and
prefer short-lived, role-based access. Apply conditional access policies that deny sign-ins
from untrusted networks and require re-authentication for sensitive actions.
