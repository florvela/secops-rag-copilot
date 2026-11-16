---
documento: Playbook — Insider Threat Response
version: 1.0.0
fuente: playbook
---

# Insider Threat Response
Responds to suspected insider threat activity including unauthorized data access, bulk downloads, privilege abuse, or off-hours anomalous activity. Escalates to HR and Legal with full audit trail.

Applies to medium, high, critical severity alerts. Tags: insider-threat, dlp, ueba, identity, data-exfiltration.

# Step 1 — Enrich Suspected Insider User (Enrich context)
- source: ueba
- fields: username, email, department, manager, role, risk_score, last_activity, anomaly_type, data_accessed, bytes_transferred

# Step 2 — Investigate User Activity Timeline (Investigate)
- query: user_activity user={{ alert.username }} risk=high last_days=30
- context fields: alert.username, alert.anomaly_type, alert.risk_score

# Step 3 — Check UEBA Risk Score Threshold (Decision)
- condition: field=alert.risk_score; operator=gt; value=80

# Step 4 — Escalate to HR and Legal (Notify)
- channel: email
- to: {{ env.HR_SECURITY_EMAIL }}
- subject: CONFIDENTIAL: Suspected Insider Threat — {{ alert.username }}
- message: This is a confidential security notification.

User: {{ alert.username }} ({{ alert.email }})
Department: {{ alert.department }}
Manager: {{ alert.manager }}
Risk Score: {{ alert.risk_score }}
Anomaly: {{ alert.anomaly_type }}
Data transferred: {{ alert.bytes_transferred }} bytes

Please review with Legal before any action.
IR Case ID: {{ alert.id }}


# Step 5 — Notify Security Manager (Notify)
- channel: #security-leadership
- message: 🔍 *Insider Threat Alert*
User: `{{ alert.username }}`
Risk Score: `{{ alert.risk_score }}`
Anomaly: `{{ alert.anomaly_type }}`
Data: {{ alert.bytes_transferred }} bytes
HR escalation: {{ steps.escalate-to-hr.status }}


# Step 6 — Create Insider Threat Ticket (Create ticket)
- title: INSIDER: {{ alert.username }} — {{ alert.anomaly_type }}
- severity: P1
- assignee group: ir-team
- tags: insider-threat, confidential

# Step 7 — Close Insider Threat Case (Close case)
- status: under-investigation
- resolution: HR/Legal escalated; IR case created; full audit trail preserved.
