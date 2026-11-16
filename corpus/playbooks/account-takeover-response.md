---
documento: Playbook — Account Takeover Response
version: 1.0
fuente: playbook
---

# Account Takeover Response
Respond to a suspected account takeover: confirm the compromise, lock the attacker out, restore the account to a trusted state, and inform the right people.

# Triage
- Gather context on the affected identity: recent sign-ins, source IPs and geolocations, device, and whether MFA was used.
- Review the login history for impossible travel, unfamiliar locations, or a burst of failures followed by a success.

# Containment
- Revoke all active sessions for the identity to invalidate any stolen tokens.
- Force a credential (password) reset and block the attacker's source IP if one stands out.

# Eradication and recovery
- Enforce MFA, or require MFA re-enrollment, before the account is used again.
- Review anything the attacker may have changed (keys, mail forwarding rules, grants) and revert it.

# Notification and closure
- Notify the affected user and their manager, and open an incident ticket.
- Close the case once the account is verified clean and secured.
