---
documento: Playbook — MFA Fatigue Attack Response
version: 1.0
fuente: playbook
---

# MFA Fatigue Attack Response
Respond to an MFA push-fatigue (push-bombing) attack, where an attacker spams approval prompts hoping the user accidentally accepts. Cut the prompts, block the source, and reset the second factor.

# Triage
- Enrich the event with the targeted user and the source IPs driving the prompts.
- Investigate the push frequency and whether any prompt was approved.

# Containment
- Temporarily disable push-based MFA for the user and switch to a phishing-resistant factor.
- Block the attacking IPs at the perimeter.

# Eradication and recovery
- Force MFA re-enrollment and reset the user's credentials if a prompt was approved.
- Confirm no session was established from the attacker.

# Notification and closure
- Notify the user about the attack and how to recognize it, and open a ticket.
- Close the case once the second factor is reset and prompts have stopped.
