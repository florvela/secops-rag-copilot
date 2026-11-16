---
documento: Playbook — Host Containment Response
version: 1.0
fuente: playbook
---

# Host Containment Response
General-purpose containment for any threat that needs immediate endpoint isolation. Collect forensics first, isolate the host, and hand off to incident response.

# Triage
- Enrich the target host: owner, role, business criticality, and the threat that triggered containment.
- Collect pre-isolation forensic data (running processes, network connections, recent logins) while the host is still live.

# Containment
- For a business-critical host, notify change management before isolating to avoid an outage surprise.
- Isolate the host from the network so the threat cannot spread or exfiltrate.

# Notification and closure
- Notify the incident response team and open a containment ticket.
- Mark the case contained once the host is isolated and the investigation is under way.
