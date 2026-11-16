---
documento: Playbook — Cloud Account Takeover Response
version: 1.0.0
fuente: playbook
---

# Cloud Account Takeover Response
Responds to cloud account takeover or unauthorized IAM activity. Disables compromised credentials, revokes suspicious API keys, audits recent API calls, and alerts the cloud security team.

Applies to high, critical severity alerts. Tags: cloud, account-takeover, iam, aws, gcp, azure.

# Step 1 — Enrich Cloud Principal (Enrich context)
- source: cloud_iam
- fields: principal_id, principal_type, cloud_provider, access_key_id, region, recent_api_calls, last_login_ip

# Step 2 — Investigate Recent API Activity (Investigate)
- query: cloud_api principal={{ alert.principal_id }} anomalous=true last_hours=24

- context fields: alert.principal_id, alert.access_key_id

# Step 3 — Check If Access Key Involved (Decision)
- condition: field=alert.access_key_id; operator=exists

# Step 4 — Disable Compromised Access Key (Call external action)
- method: POST
- url: {{ env.CLOUD_IAM_API_URL }}/keys/{{ alert.access_key_id }}/disable
- body: reason=Cloud account takeover — playbook {{ id }}

# Step 5 — Revoke Cloud Console Sessions (Call external action)
- method: POST
- url: {{ env.CLOUD_IAM_API_URL }}/users/{{ alert.principal_id }}/revoke-sessions
- body: reason=Suspected cloud account takeover

# Step 6 — Notify Cloud Security Team (Notify)
- channel: #cloud-security
- message: ☁️ *Cloud Account Takeover Detected*
Provider: `{{ alert.cloud_provider }}`
Principal: `{{ alert.principal_id }}`
Access Key: `{{ alert.access_key_id }}`
Source IP: `{{ alert.last_login_ip }}`
Key disabled: {{ steps.disable-key.status }}


# Step 7 — Create Cloud ATO Ticket (Create ticket)
- title: CLOUD-ATO: {{ alert.principal_id }} on {{ alert.cloud_provider }}
- severity: P1
- assignee group: cloud-security

# Step 8 — Close Cloud ATO Case (Close case)
- status: contained
- resolution: Access key disabled; sessions revoked; cloud security team notified.
