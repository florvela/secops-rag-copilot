---
documento: Playbook — Business Email Compromise (BEC) Response
version: 1.0
fuente: playbook
---

# Business Email Compromise (BEC) Response
Respond to business email compromise: a spoofed or compromised (often executive) account used to request fraudulent wire transfers or sensitive data. Stop the fraud, contain the sender, and coordinate with finance and legal.

# Triage
- Enrich the email metadata and check sender authentication (SPF, DKIM, DMARC) for spoofing.
- Investigate whether the internal account was actually compromised (unusual sign-ins, new rules) or only impersonated.

# Containment
- Block the spoofed or malicious sender domain at the mail gateway.
- If an internal account is compromised, revoke its sessions and reset credentials.

# Notification and closure
- Alert the finance team to hold any pending or requested wire transfers.
- Notify the security team (and legal if funds moved), open an incident ticket, and close once resolved.
