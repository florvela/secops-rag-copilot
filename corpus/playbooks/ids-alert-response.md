---
documento: Playbook — IDS/IPS Alert Response
version: 1.0.0
fuente: playbook
---

# IDS/IPS Alert Response
Responds to Intrusion Detection/Prevention System alerts including network scans, exploitation attempts, and protocol anomalies. Blocks the attacking source, captures PCAP evidence, and notifies the network security team.

Applies to medium, high, critical severity alerts. Tags: ids, ips, network, intrusion-detection, nids.

# Step 1 — Enrich IDS Alert (Enrich context)
- source: ids_sensor
- fields: source_ip, destination_ip, destination_port, protocol, signature_id, signature_name, category, packet_count, bytes, interface, sensor_id

# Step 2 — Investigate Attack Source IP (Investigate)
- query: ip_threat source_ip={{ alert.source_ip }} threat_intel=true
- context fields: alert.source_ip, alert.signature_name, alert.category

# Step 3 — Check If Targeting Critical Asset (Decision)
- condition: field=alert.destination_port; operator=eq; value=22

# Step 4 — Block IP and Alert for Critical Port Attack (Containment — block source IP)
- ip field: alert.source_ip
- direction: inbound
- duration hours: 72
- comment: IDS critical port attack — {{ alert.signature_name }} — playbook {{ id }}

# Step 5 — Block Attacking Source IP (Containment — block source IP)
- ip field: alert.source_ip
- direction: inbound
- duration hours: 24
- comment: IDS alert — {{ alert.signature_name }} — playbook {{ id }}

# Step 6 — Notify Network Security Team (Notify)
- channel: #network-security
- message: 🛡️ *IDS Alert*
Signature: `{{ alert.signature_name }}`
Category: `{{ alert.category }}`
Source: `{{ alert.source_ip }}`
Target: `{{ alert.destination_ip }}:{{ alert.destination_port }}`
Protocol: `{{ alert.protocol }}`
Packets: {{ alert.packet_count }}
IP blocked: {{ steps.block-source.status }}


# Step 7 — Create IDS Alert Ticket (Create ticket)
- title: IDS: {{ alert.signature_name }} from {{ alert.source_ip }}
- severity: P2
- assignee group: network-security

# Step 8 — Close IDS Alert Case (Close case)
- status: remediated
- resolution: Source IP blocked; network security notified; evidence captured.
