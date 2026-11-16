---
documento: Playbook — ISO 27001 Control Violation Response
version: 1.0.0
fuente: playbook
---

# ISO 27001 Control Violation Response
Responds to ISO 27001 information security control violations including unauthorized access to sensitive information, policy breaches, and audit findings. Creates compliance records, notifies the CISO, and initiates corrective action procedures.

Applies to medium, high, critical severity alerts. Tags: iso27001, compliance, governance, policy-violation, audit.

# Step 1 — Enrich ISO Violation Event (Enrich context)
- source: compliance_engine
- fields: username, email, department, manager, control_id, control_name, violation_type, asset_affected, data_classification, timestamp

# Step 2 — Investigate Compliance Violation History (Investigate)
- query: compliance_violations user={{ alert.username }} control={{ alert.control_id }} last_days=90

- context fields: alert.username, alert.control_id, alert.violation_type

# Step 3 — Check Severity Requires CISO Notification (Decision)
- condition: field=alert.data_classification; operator=eq; value=confidential

# Step 4 — Notify CISO of Critical Compliance Violation (Notify)
- channel: email
- to: {{ env.CISO_EMAIL }}
- subject: ISO 27001 Violation: {{ alert.control_id }} — {{ alert.data_classification }} data
- message: A significant ISO 27001 control violation has been detected.

Control: {{ alert.control_id }} — {{ alert.control_name }}
User: {{ alert.username }} ({{ alert.department }})
Asset: {{ alert.asset_affected }}
Data Classification: {{ alert.data_classification }}
Violation: {{ alert.violation_type }}
Time: {{ alert.timestamp }}

Compliance team has been notified. Corrective action required within 24 hours.


# Step 5 — Notify Compliance Team (Notify)
- channel: #compliance-alerts
- message: 📋 *ISO 27001 Control Violation*
Control: `{{ alert.control_id }}` — {{ alert.control_name }}
User: `{{ alert.username }}` ({{ alert.department }})
Asset: `{{ alert.asset_affected }}`
Violation: `{{ alert.violation_type }}`
CISO notified: {{ steps.notify-ciso.status }}


# Step 6 — Create ISO Violation Compliance Ticket (Create ticket)
- title: ISO-27001: {{ alert.control_id }} violation by {{ alert.username }}
- severity: P2
- assignee group: compliance
- tags: iso27001, compliance, corrective-action

# Step 7 — Close ISO Violation Case (Close case)
- status: under-investigation
- resolution: CISO/compliance notified; corrective action ticket created; audit evidence preserved.
