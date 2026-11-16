---
documento: Playbook — Lateral Movement Response
version: 1.0
fuente: playbook
---

# Lateral Movement Response
Respond to lateral movement: pass-the-hash, pass-the-ticket, remote-service abuse, or admin-share enumeration. Isolate affected hosts, cut the credentials being reused, and map the blast radius.

# Triage
- Enrich the event with the source and destination hosts, the account used, and the technique observed.
- Map the blast radius: which hosts and accounts the movement has touched.

# Containment
- Isolate the source host from the network.
- If the destination is a sensitive system, isolate it too, and revoke the credentials being reused.

# Eradication and recovery
- Reset the compromised credentials across every host where they were used.
- Rebuild hosts that cannot be confirmed clean.

# Notification and closure
- Notify security operations and open an incident ticket.
- Close the case once movement is stopped and credentials are rotated.
