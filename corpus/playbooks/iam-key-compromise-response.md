---
documento: Playbook — IAM Key Compromise Response
version: 1.0.0
fuente: playbook
---

# IAM Key Compromise Response
Responds to compromised IAM access keys including keys exposed in public repositories, leaked in logs, or used from unexpected geolocations. Immediately disables the key, audits recent API usage, and rotates credentials.

Applies to high, critical severity alerts. Tags: iam, aws, cloud, key-compromise, credential-leak.

# Step 1 — Enrich IAM Key Event (Enrich context)
- source: cloud_iam
- fields: access_key_id, account_id, username, key_created_at, last_used_at, last_used_region, last_used_service, exposure_source, api_calls_24h

# Step 2 — Immediately Disable Compromised Key (Call external action)
- method: PUT
- url: {{ env.AWS_IAM_API_URL }}/users/{{ alert.username }}/keys/{{ alert.access_key_id }}
- body: Status=Inactive; reason=Key compromise detected — playbook {{ id }}

# Step 3 — Investigate Recent API Usage (Investigate)
- query: cloudtrail key={{ alert.access_key_id }} last_hours=48 service=all

- context fields: alert.access_key_id, alert.api_calls_24h

# Step 4 — Check Exposure Source Type (Decision)
- condition: field=alert.exposure_source; operator=eq; value=public_repo

# Step 5 — Notify VCS Team to Remove Key from Repo (Notify)
- channel: #devsecops-alerts
- message: 🔑 *IAM Key Exposed in Public Repository*
Key: `{{ alert.access_key_id }}`
Account: `{{ alert.account_id }}`
IAM User: `{{ alert.username }}`
Key has been disabled. Remove from VCS immediately and rotate.


# Step 6 — Notify Cloud Security Team (Notify)
- channel: #cloud-security
- message: 🔑 *IAM Key Compromise Detected*
Key: `{{ alert.access_key_id }}`
Account: `{{ alert.account_id }}`
IAM User: `{{ alert.username }}`
Exposure: `{{ alert.exposure_source }}`
API calls (24h): {{ alert.api_calls_24h }}
Key disabled: {{ steps.disable-key.status }}


# Step 7 — Create IAM Key Compromise Ticket (Create ticket)
- title: IAM-KEY: {{ alert.access_key_id }} compromised via {{ alert.exposure_source }}
- severity: P1
- assignee group: cloud-security

# Step 8 — Close IAM Key Compromise Case (Close case)
- status: contained
- resolution: Key disabled; API usage audited; VCS/cloud security notified; rotation in progress.
