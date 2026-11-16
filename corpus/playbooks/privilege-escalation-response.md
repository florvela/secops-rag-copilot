---
documento: Playbook — Privilege Escalation Response
version: 1.0
fuente: playbook
---

# Privilege Escalation Response
Respond to a privilege escalation attempt: sudo abuse, SUID/SGID exploitation, token impersonation, or an anomalous role assignment. Revoke the elevated rights and preserve evidence.

# Triage
- Enrich the privileged session: user, host, how privileges were elevated, and the host's criticality.
- Review the user's privilege history for whether this elevation was expected.

# Containment
- If the host is business-critical, isolate it from the network.
- Revoke the escalated privileges and terminate the elevated session.

# Eradication and recovery
- Remove any persistence or accounts the elevation created.
- Reset affected credentials and confirm the escalation path is closed.

# Notification and closure
- Notify security operations and open a ticket.
- Close the case once privileges are revoked and the host is verified clean.
