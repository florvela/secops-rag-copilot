---
documento: Playbook — Cloud Account Takeover Response
version: 1.0
fuente: playbook
---

# Cloud Account Takeover Response
Respond to cloud account takeover or unauthorized IAM activity. Disable compromised credentials, revoke suspicious keys, and audit what the attacker did.

# Triage
- Enrich the cloud principal: identity type, access keys, region, recent API calls, and last login IP.
- Investigate recent API activity for anomalous or high-impact actions.

# Containment
- Disable the compromised access key or credential involved.
- Revoke active cloud console and API sessions for the principal.

# Eradication and recovery
- Rotate the affected credentials and review for persistence (new keys, users, roles, or policy changes) and undo it.
- Restore any security controls the attacker disabled (logging, guard services).

# Notification and closure
- Notify the cloud security team and open an incident ticket.
- Close the case once credentials are rotated and the account is verified clean.
