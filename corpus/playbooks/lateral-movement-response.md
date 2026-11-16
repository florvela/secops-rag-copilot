---
documento: Playbook — Lateral Movement Response
version: 1.0.0
fuente: playbook
---

# Lateral Movement Response
Responds to detected lateral movement activity including pass-the-hash, pass-the-ticket, remote service abuse, and admin share enumeration. Isolates affected hosts, revokes lateral credentials, and maps the blast radius.

Applies to high, critical severity alerts. Tags: lateral-movement, endpoint, network, credential-abuse, active-directory.

# Step 1 — Enrich Lateral Movement Event (Enrich context)
- source: endpoint
- fields: source_host, destination_host, technique, account_used, protocol, destination_port, network_path

# Step 2 — Map Lateral Movement Blast Radius (Investigate)
- query: lateral_connections source={{ alert.source_host }} last_hours=6

- context fields: alert.source_host, alert.destination_host, alert.technique

# Step 3 — Isolate Source Host (Containment — isolate host)
- hostname: {{ alert.source_host }}
- reason: Lateral movement detected — playbook {{ id }}
- notify user: True

# Step 4 — Check If Destination Is Sensitive (Decision)
- condition: field=alert.destination_host; operator=contains; value=dc

# Step 5 — Isolate Sensitive Destination Host (Containment — isolate host)
- hostname: {{ alert.destination_host }}
- reason: Lateral movement target — possible DC compromise — playbook {{ id }}

# Step 6 — Notify Security Operations (Notify)
- channel: #ir-critical
- message: ↔️ *Lateral Movement Detected*
Technique: `{{ alert.technique }}`
Source: `{{ alert.source_host }}`
Destination: `{{ alert.destination_host }}`
Account: `{{ alert.account_used }}`
Protocol: `{{ alert.protocol }}`
Source isolated: {{ steps.isolate-source.status }}


# Step 7 — Create Lateral Movement Ticket (Create ticket)
- title: LATERAL: {{ alert.technique }} from {{ alert.source_host }} to {{ alert.destination_host }}
- severity: P1
- assignee group: ir-team

# Step 8 — Close Lateral Movement Case (Close case)
- status: contained
- resolution: Source isolated; blast radius mapped; IR ticket created.
