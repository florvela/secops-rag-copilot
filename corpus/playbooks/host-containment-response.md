---
documento: Playbook — Host Containment Response
version: 1.0.0
fuente: playbook
---

# Host Containment Response
General-purpose host containment playbook for any threat requiring immediate endpoint isolation. Performs pre-isolation forensic collection, isolates the host, notifies the IR team, and starts the investigation workflow.

Applies to high, critical severity alerts. Tags: containment, endpoint, isolation, edr, incident-response.

# Step 1 — Enrich Target Host (Enrich context)
- source: endpoint
- fields: hostname, ip_address, os, owner, department, criticality, running_processes, network_connections, last_user

# Step 2 — Collect Pre-Isolation Forensic Data (Investigate)
- query: host_forensics hostname={{ alert.hostname }} collect=processes,network,files last_minutes=60

- context fields: alert.hostname, alert.running_processes

# Step 3 — Check Host Business Criticality (Decision)
- condition: field=alert.criticality; operator=eq; value=critical

# Step 4 — Notify Change Management Before Critical Host Isolation (Notify)
- channel: #change-management
- message: ⚠️ *Emergency Isolation — Critical Asset*
Host: `{{ alert.hostname }}`
IP: `{{ alert.ip_address }}`
Owner: `{{ alert.owner }}` ({{ alert.department }})
Criticality: `{{ alert.criticality }}`
Proceeding with emergency isolation in 60 seconds.


# Step 5 — Isolate Host from Network (Containment — isolate host)
- reason: Threat containment — playbook {{ id }}
- notify user: True

# Step 6 — Notify IR Team (Notify)
- channel: #ir-critical
- message: 🔒 *Host Isolated — Containment Active*
Host: `{{ alert.hostname }}`
IP: `{{ alert.ip_address }}`
Owner: `{{ alert.owner }}`
Criticality: `{{ alert.criticality }}`
Alert: `{{ alert.id }}`
Isolation: {{ steps.isolate-host.status }}


# Step 7 — Create Containment Incident Ticket (Create ticket)
- title: CONTAIN: {{ alert.hostname }} isolated — {{ alert.id }}
- severity: P1
- assignee group: ir-team

# Step 8 — Mark Case as Contained (Close case)
- status: contained
- resolution: Host isolated; forensic data collected; IR team engaged.
