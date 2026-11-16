---
documento: Playbook — Web Application Attack Response
version: 1.0
fuente: playbook
---

# Web Application Attack Response
Respond to a web application attack: SQL injection, XSS, remote code execution, or directory traversal. Block the source, check for data theft, and preserve evidence.

# Triage
- Enrich the request: source IP, target endpoint, payload, and the attack class.
- Investigate the source IP history and whether the attack succeeded in reaching data.

# Containment
- Block the attacking IP at the WAF or firewall.
- If exfiltration is suspected, flag it to security immediately and preserve request logs.

# Eradication and recovery
- Patch or add a WAF rule for the exploited weakness, and verify the fix.
- Review what the attacker accessed and rotate anything exposed.

# Notification and closure
- Notify the application security team and open a ticket.
- Close the case once the source is blocked and the weakness is fixed.
