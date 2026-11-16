---
documento: Playbook — Privilege Escalation Response
version: 1.0.0
fuente: playbook
---

# Privilege Escalation Response
Responds to detected privilege escalation attempts including sudo abuse, SUID/SGID exploitation, token impersonation, or role assignment anomalies. Revokes elevated privileges, isolates the session, and logs forensic evidence.

Applies to high, critical severity alerts. Tags: privilege-escalation, endpoint, linux, windows, iam.

# Step 1 — Enrich Privileged Session (Enrich context)
- source: endpoint
- fields: username, hostname, process_name, parent_process, escalation_method, elevated_to, command_line, file_path

# Step 2 — Investigate User Privilege History (Investigate)
- query: privilege_events user={{ alert.username }} host={{ alert.hostname }} last_hours=24

- context fields: alert.username, alert.escalation_method

# Step 3 — Check If Critical Host (Decision)
- condition: field=alert.hostname; operator=contains; value=-prod-

# Step 4 — Isolate Production Host (Containment — isolate host)
- reason: Privilege escalation on production host — playbook {{ id }}
- notify user: False

# Step 5 — Revoke Escalated Privileges (Call external action)
- method: POST
- url: {{ env.IAM_API_URL }}/users/{{ alert.username }}/revoke-elevated
- body: host={{ alert.hostname }}; reason=Detected privilege escalation

# Step 6 — Notify Security Operations (Notify)
- channel: #security-alerts
- message: ⬆️ *Privilege Escalation Detected*
User: `{{ alert.username }}`
Host: `{{ alert.hostname }}`
Method: `{{ alert.escalation_method }}`
Escalated To: `{{ alert.elevated_to }}`
Process: `{{ alert.process_name }}`
Host isolated: {{ steps.isolate-host.status }}


# Step 7 — Create Privilege Escalation Ticket (Create ticket)
- title: PRIVESC: {{ alert.username }} via {{ alert.escalation_method }} on {{ alert.hostname }}
- severity: P1
- assignee group: ir-team

# Step 8 — Close Privilege Escalation Case (Close case)
- status: contained
- resolution: Elevated privileges revoked; host isolated if production; IR investigating.
