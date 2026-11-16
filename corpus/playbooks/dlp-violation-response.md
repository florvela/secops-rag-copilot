---
documento: Playbook — DLP Policy Violation Response
version: 1.0.0
fuente: playbook
---

# DLP Policy Violation Response
Responds to data loss prevention (DLP) policy violations including unauthorized data transfers, sensitive document uploads to personal storage, or PII/PHI exfiltration attempts. Blocks the transfer, notifies compliance, and preserves audit evidence.

Applies to medium, high, critical severity alerts. Tags: dlp, data-loss-prevention, compliance, pii, phi, exfiltration.

# Step 1 — Enrich DLP Violation Event (Enrich context)
- source: dlp_engine
- fields: username, email, department, manager, data_classification, file_name, destination, destination_type, bytes_transferred, policy_violated

# Step 2 — Investigate User DLP History (Investigate)
- query: dlp_events user={{ alert.username }} last_days=30
- context fields: alert.username, alert.data_classification

# Step 3 — Check Data Classification Level (Decision)
- condition: field=alert.data_classification; operator=eq; value=restricted

# Step 4 — Block Transfer and Escalate (Call external action)
- method: POST
- url: {{ env.DLP_API_URL }}/violations/{{ alert.id }}/block
- body: action=block; reason=Restricted data DLP violation — playbook {{ id }}

# Step 5 — Notify Compliance and Legal (Notify)
- channel: email
- to: {{ env.COMPLIANCE_EMAIL }}
- subject: DLP Violation: Restricted Data Transfer — {{ alert.username }}
- message: A DLP violation has been detected and blocked.

User: {{ alert.username }} ({{ alert.email }})
Department: {{ alert.department }}
Data Classification: {{ alert.data_classification }}
File: {{ alert.file_name }}
Destination: {{ alert.destination }} ({{ alert.destination_type }})
Bytes: {{ alert.bytes_transferred }}
Policy: {{ alert.policy_violated }}

Transfer has been blocked. IR is investigating.


# Step 6 — Notify User's Manager (Notify)
- channel: email
- to: {{ alert.manager_email }}
- subject: Security Alert: DLP Policy Violation by {{ alert.username }}
- message: A DLP policy violation was detected on {{ alert.username }}'s account.
Security team is reviewing. Please contact security for details.


# Step 7 — Create DLP Violation Ticket (Create ticket)
- title: DLP: {{ alert.data_classification }} data — {{ alert.username }} to {{ alert.destination_type }}
- severity: P2
- assignee group: security-compliance

# Step 8 — Close DLP Case (Close case)
- status: remediated
- resolution: Transfer blocked; compliance notified; manager informed; audit evidence preserved.
