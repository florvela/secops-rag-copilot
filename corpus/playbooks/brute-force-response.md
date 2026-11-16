---
documento: Playbook — Brute Force Attack Response
version: 1.0
fuente: playbook
---

# Brute Force Attack Response
Respond to brute force or credential-stuffing attacks against an authentication endpoint. Lock out the attacker, block the source, and confirm whether any login succeeded.

# Triage
- Enrich the event with the targeted account, source IP and ASN, attempt count, and time window.
- Investigate the attack source and determine whether a success followed the burst of failures.

# Containment
- If a login succeeded, treat the account as compromised: lock it and revoke its sessions.
- Block the attacking source IP at the firewall, and apply progressive lockout or CAPTCHA on the endpoint.

# Eradication and recovery
- Reset the affected credentials and enforce MFA.
- Review for any access-key or profile changes made during a successful intrusion.

# Notification and closure
- Notify the security team and open an incident ticket.
- Close the case once the source is blocked and the account is secured.
