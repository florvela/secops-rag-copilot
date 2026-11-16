---
documento: Playbook — OAuth Application Abuse Response
version: 1.0.0
fuente: playbook
---

# OAuth Application Abuse Response
Responds to OAuth application abuse including consent phishing, malicious app grants, and unauthorized OAuth token usage. Revokes malicious app access, audits all consented apps, and notifies affected users.

Applies to medium, high, critical severity alerts. Tags: oauth, identity, saas, consent-phishing, app-abuse.

# Step 1 — Enrich OAuth Application Event (Enrich context)
- source: identity_provider
- fields: username, email, app_id, app_name, app_publisher, permissions_granted, grant_time, data_accessed, tenant_id

# Step 2 — Investigate OAuth App Reputation (Investigate)
- query: oauth_app_reputation app_id={{ alert.app_id }} publisher={{ alert.app_publisher }}
- context fields: alert.app_id, alert.app_name, alert.permissions_granted

# Step 3 — Check Dangerous Permissions (Decision)
- condition: field=alert.permissions_granted; operator=contains; value=Mail.ReadWrite

# Step 4 — Revoke OAuth App Tenant-Wide (Call external action)
- method: DELETE
- url: {{ env.IDP_API_URL }}/tenants/{{ alert.tenant_id }}/apps/{{ alert.app_id }}/consent
- body: reason=Malicious OAuth app — dangerous permissions — playbook {{ id }}

# Step 5 — Revoke User OAuth Consent (Call external action)
- method: DELETE
- url: {{ env.IDP_API_URL }}/users/{{ alert.username }}/apps/{{ alert.app_id }}/consent

# Step 6 — Notify Affected User (Notify)
- channel: email
- to: {{ alert.email }}
- subject: Security Alert: Unauthorized app access revoked on your account
- message: An unauthorized application has been detected on your account.

App: {{ alert.app_name }} ({{ alert.app_publisher }})
Permissions: {{ alert.permissions_granted }}
Granted: {{ alert.grant_time }}

Access has been revoked. Review your connected apps at your account settings.
Contact security if you have questions: security@company.com


# Step 7 — Create OAuth Abuse Ticket (Create ticket)
- title: OAUTH-ABUSE: {{ alert.app_name }} — {{ alert.username }}
- severity: P2
- assignee group: security-ops

# Step 8 — Close OAuth Abuse Case (Close case)
- status: remediated
- resolution: App consent revoked; user notified; app reputation added to blocklist.
