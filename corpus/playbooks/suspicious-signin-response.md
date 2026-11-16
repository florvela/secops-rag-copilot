---
documento: Playbook — Suspicious Sign-In Response
version: 1.0
fuente: playbook
---

# Suspicious Sign-In Response
Respond to a suspicious sign-in: impossible travel, a new country, a known-bad IP, or a login outside business hours. Step up authentication or end the session based on risk.

# Triage
- Enrich the sign-in event: user, source IP and geolocation, device, and whether MFA was used.
- Investigate the source IP reputation and compare against the user's normal pattern.

# Containment
- For a high-risk sign-in, revoke the session and require a step-up MFA challenge before access resumes.
- Block the source IP if it is clearly malicious.

# Notification and closure
- Notify the user of the suspicious sign-in and open a ticket.
- Close the case once the session is handled and the account is confirmed secure.
