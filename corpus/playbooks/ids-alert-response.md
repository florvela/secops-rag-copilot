---
documento: Playbook — IDS/IPS Alert Response
version: 1.0
fuente: playbook
---

# IDS/IPS Alert Response
Respond to an intrusion detection/prevention alert: network scans, exploitation attempts, or protocol anomalies. Block the source and preserve network evidence.

# Triage
- Enrich the alert with the signature, source and destination, and the targeted service.
- Investigate the attacking source IP and whether it is targeting a critical asset or port.

# Containment
- Block the attacking source IP, prioritizing attacks against critical ports or assets.
- Capture packet-level (PCAP) evidence around the event.

# Notification and closure
- Notify the network security team and open a ticket.
- Close the case once the source is blocked and the targeted asset is confirmed safe.
