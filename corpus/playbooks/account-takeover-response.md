---
documento: Playbook — Account Takeover Response
version: 1.0.0
fuente: playbook
---

# Account Takeover Response
Responds to suspected account takeover (ATO) events. Forces session termination, resets credentials, enables MFA enforcement, and notifies the user and security team.

Applies to medium, high, critical severity alerts. Tags: account-takeover, identity, iam, credential-compromise.

# Step 1 — Enrich Compromised User Account (Enrich context)
- source: identity_provider
- fields: username, email, department, manager, last_login_ip, mfa_enabled, active_sessions

# Step 2 — Investigate Login History (Investigate)
- query: logins user={{ alert.username }} last_days=7
- context fields: alert.username, alert.last_login_ip

# Step 3 — Check MFA Status (Decision)
- condition: field=alert.mfa_enabled; operator=eq; value=False

# Step 4 — Enforce MFA on Account (Call external action)
- method: POST
- url: {{ env.IDP_API_URL }}/users/{{ alert.username }}/enforce-mfa
- body: enforce=True; reason=ATO response — playbook {{ id }}

# Step 5 — Revoke All Active Sessions (Call external action)
- method: POST
- url: {{ env.IDP_API_URL }}/users/{{ alert.username }}/revoke-sessions
- body: reason=Suspected account takeover

# Step 6 — Notify Affected User (Notify)
- channel: email
- to: {{ alert.email }}
- subject: Security Alert: Unusual activity detected on your account
- message: We detected unusual login activity on your account.
Your sessions have been terminated as a precaution.
Please contact IT security immediately: security@company.com


# Step 7 — Notify User's Manager (Notify)
- channel: email
- to: {{ alert.manager_email }}
- subject: Security Alert: {{ alert.username }} account may be compromised
- message: The account {{ alert.username }} has been flagged for suspected compromise.
Sessions terminated. IR team has been notified.


# Step 8 — Create ATO Incident Ticket (Create ticket)
- title: ATO: {{ alert.username }} — suspicious login from {{ alert.last_login_ip }}
- severity: P1
- assignee group: ir-team

# Step 9 — Close ATO Case (Close case)
- status: contained
- resolution: Sessions revoked; MFA enforced; user and manager notified; IR ticket created.
