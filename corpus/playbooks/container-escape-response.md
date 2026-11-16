---
documento: Playbook — Container Escape Response
version: 1.0
fuente: playbook
---

# Container Escape Response
Respond to a container escape attempt or privileged-container misuse. Stop the offending workload, protect the node, and preserve forensics.

# Triage
- Enrich the container context: image, privileges, mounts, and the node it runs on.
- Investigate the suspicious process activity that triggered the alert and whether it reached the host.

# Containment
- Terminate the offending container immediately.
- Cordon the affected node so no new workloads schedule onto it while it is investigated.

# Eradication and recovery
- Capture runtime forensics before and after isolation.
- Rebuild the node from a known-good image and remove the offending image or privileged settings.

# Notification and closure
- Notify the platform security team and open an incident ticket.
- Close the case once the node is remediated and the escape path is fixed.
