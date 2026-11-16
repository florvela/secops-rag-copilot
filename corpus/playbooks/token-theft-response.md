---
documento: Playbook — Authentication Token Theft Response
version: 1.0
fuente: playbook
---

# Authentication Token Theft Response
Respond to stolen authentication token usage: JWT hijacking, session-cookie theft, or bearer-token replay. Revoke the tokens, force re-authentication, and check for downstream access.

# Triage
- Enrich the token-usage event: user, token type, source, and the actions taken with it.
- Investigate replay activity and whether the token was used from more than one location.

# Containment
- Immediately revoke the stolen token and revoke all of the user's active sessions.
- Block the source IP replaying the token.

# Eradication and recovery
- Force re-authentication and rotate the signing keys or secrets if the token mechanism itself was exposed.
- Check downstream systems the token could reach for unauthorized access.

# Notification and closure
- Notify the affected user and open a ticket.
- Close the case once tokens are revoked and no further misuse is seen.
