---
documento: Playbook — DLP Policy Violation Response
version: 1.0
fuente: playbook
---

# DLP Policy Violation Response
Respond to a data loss prevention violation: unauthorized data transfer, sensitive uploads to personal storage, or PII/PHI exfiltration. Stop the transfer, preserve evidence, and involve compliance.

# Triage
- Enrich the event with the user, destination, data classification, and volume moved.
- Review the user's DLP history to tell a one-off mistake from a pattern.

# Containment
- Block the transfer and, for high-classification data, escalate immediately.
- Revoke the sharing link or access path used for the exfiltration.

# Notification and closure
- Notify compliance and legal, and the user's manager, preserving the audit trail.
- Open a violation ticket and close once reviewed and remediated.
