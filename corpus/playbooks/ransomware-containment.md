---
documento: Playbook — Ransomware Containment and Eradication
version: 1.0
fuente: playbook
---

# Ransomware Containment and Eradication
Contain and eradicate a ransomware incident. Isolate affected hosts fast, cut command-and-control, and preserve forensic state before recovery.

# Triage
- Enrich the affected host and confirm the severity and scope (which hosts and shares are affected).
- Identify the ransomware family and its command-and-control (C2) indicators.

# Containment
- Isolate affected hosts from the network immediately to stop encryption from spreading.
- Block the C2 IPs and domains at the perimeter.

# Eradication and recovery
- Snapshot disk state for forensics before wiping.
- Re-image affected hosts and restore data from known-good backups; rotate exposed credentials.

# Notification and closure
- Open an incident ticket and notify the incident response team.
- Mark the case contained once spread is stopped, and track recovery to closure.
