---
documento: Playbook — OAuth Application Abuse Response
version: 1.0
fuente: playbook
---

# OAuth Application Abuse Response
Respond to OAuth application abuse: consent phishing, malicious app grants, or unauthorized token usage. Revoke the app's access and audit what it reached.

# Triage
- Enrich the OAuth event with the application, the permissions (scopes) it was granted, and the users who consented.
- Investigate the app's reputation and whether its scopes are dangerous (mail, files, directory access).

# Containment
- Revoke the malicious application tenant-wide, and revoke individual user consents.
- Invalidate the app's active tokens.

# Eradication and recovery
- Audit all consented applications for other risky grants.
- Review what the app accessed and clean up any data it touched.

# Notification and closure
- Notify affected users and open a ticket.
- Close the case once the app is revoked and the grants are cleaned up.
