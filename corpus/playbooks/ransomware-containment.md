---
documento: Playbook — Ransomware Containment & Eradication
version: 1.0.0
fuente: playbook
---

# Ransomware Containment & Eradication
Automated containment and eradication playbook for ransomware incidents. Isolates affected hosts, blocks C2 IPs, snapshots disk state for forensics, and notifies the security team with remediation steps.

Applies to high, critical severity alerts. Tags: ransomware, malware, containment, endpoint, high-severity.

# Step 1 — Enrich Affected Host (Enrich context)
- source: endpoint
- fields: hostname, os, last_user, network_connections

# Step 2 — Check Alert Severity (Decision)
- condition: field=alert.severity; operator=eq; value=critical

# Step 3 — Isolate Host from Network (Containment — isolate host)
- reason: Ransomware detected — automated isolation
- notify user: True

# Step 4 — Block C2 IPs at Perimeter (Containment — block source IP)
- ip field: alert.external_ips
- direction: both
- duration hours: 72
- comment: Ransomware C2 block — playbook {{ id }}

# Step 5 — Create Incident Ticket (Create ticket)
- title: RANSOMWARE: {{ alert.hostname }} — {{ alert.created_at }}
- severity: P1
- assignee group: ir-team
- description: Ransomware alert triggered on {{ alert.hostname }}.
Alert ID: {{ alert.id }}
User: {{ alert.last_user }}
Isolation status: {{ steps.isolate-immediately.status }}


# Step 6 — Notify IR Team via Slack (Notify)
- channel: #ir-critical
- message: 🚨 *Ransomware Detected*
Host: `{{ alert.hostname }}`
Severity: `{{ alert.severity }}`
Ticket: {{ steps.create-ticket.ticket_url }}
Isolation: {{ steps.isolate-immediately.status }}


# Step 7 — Mark Case Contained (Close case)
- status: contained
- resolution: Host isolated; C2 blocked; IR ticket created.
