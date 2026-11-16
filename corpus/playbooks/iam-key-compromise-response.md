---
documento: Playbook — IAM Key Compromise Response
version: 1.0
fuente: playbook
---

# IAM Key Compromise Response
Respond to a compromised or leaked cloud access key: a key exposed in a public repo, leaked in logs, or used from an unexpected location. Disable it, audit its use, and rotate.

# Triage
- Enrich the key event: owner, account, creation and last-used time, last-used region and service, and how it was exposed.
- Investigate the key's recent API usage for unauthorized or high-impact calls.

# Containment
- Immediately disable the compromised access key.
- If the key was used from an unexpected source, revoke the related sessions.

# Eradication and recovery
- Rotate the credential and issue a replacement; update any systems that used the old key.
- If exposed in a repository, have the owning team purge it from the history, not just the latest commit.

# Notification and closure
- Notify the cloud security team (and the VCS team if leaked in code), and open a ticket.
- Close the case once the key is rotated and no unauthorized use remains.
