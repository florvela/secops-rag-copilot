---
documento: Playbook — Anomalous User Behavior Response
version: 1.0.0
fuente: playbook
---

# Anomalous User Behavior Response
Responds to anomalous user behavior flagged by UEBA systems including unusual access patterns, after-hours activity, mass data access, or deviation from behavioral baselines. Escalates based on risk score and enables adaptive authentication controls.

Applies to medium, high, critical severity alerts. Tags: anomalous, ueba, behavioral-analytics, identity, insider.

# Step 1 — Enrich Anomalous Behavior Event (Enrich context)
- source: ueba
- fields: username, email, department, risk_score, risk_delta, anomaly_categories, baseline_score, affected_assets, activity_summary, peer_group_comparison

# Step 2 — Investigate Behavioral History (Investigate)
- query: ueba_timeline user={{ alert.username }} anomaly_only=true last_days=30

- context fields: alert.username, alert.risk_score, alert.anomaly_categories

# Step 3 — Check If Risk Score Is Critical (Decision)
- condition: field=alert.risk_score; operator=gt; value=85

# Step 4 — Enforce Step-Up Authentication (Call external action)
- method: POST
- url: {{ env.IDP_API_URL }}/users/{{ alert.username }}/adaptive-auth
- body: level=enhanced; require_mfa=True; reason=UEBA high-risk score — anomalous behavior detected; duration_hours=48

# Step 5 — Notify Security Analyst for Review (Notify)
- channel: #ueba-alerts
- message: 📊 *Anomalous Behavior Alert*
User: `{{ alert.username }}` ({{ alert.department }})
Risk Score: `{{ alert.risk_score }}` (baseline: {{ alert.baseline_score }})
Delta: +{{ alert.risk_delta }}
Anomalies: {{ alert.anomaly_categories }}
Assets Affected: {{ alert.affected_assets }}
Step-up auth enforced: {{ steps.enforce-adaptive-auth.status }}


# Step 6 — Create Anomalous Behavior Ticket (Create ticket)
- title: UEBA: {{ alert.username }} — risk score {{ alert.risk_score }} ({{ alert.anomaly_categories }})
- severity: P2
- assignee group: security-ops

# Step 7 — Close Anomalous Behavior Case (Close case)
- status: under-investigation
- resolution: Step-up auth enforced; analyst notified; behavioral evidence preserved.
