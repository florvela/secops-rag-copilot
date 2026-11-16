---
documento: Playbook — Suspicious Sign-In Response
version: 1.0.0
fuente: playbook
---

# Suspicious Sign-In Response
Responds to suspicious sign-in events including impossible travel, new country logins, known bad IP addresses, or sign-ins outside business hours. Triggers step-up authentication or session termination based on risk score.

Applies to medium, high, critical severity alerts. Tags: sign-in, identity, authentication, impossible-travel, conditional-access.

# Step 1 — Enrich Sign-In Event (Enrich context)
- source: identity_provider
- fields: username, email, source_ip, country, city, previous_country, previous_login_time, device_id, device_trust, risk_score, login_time

# Step 2 — Investigate Source IP Reputation (Investigate)
- query: ip_reputation ip={{ alert.source_ip }} threat_categories=true
- context fields: alert.source_ip, alert.country

# Step 3 — Check Risk Score Threshold (Decision)
- condition: field=alert.risk_score; operator=gt; value=70

# Step 4 — Revoke High-Risk Sign-In Session (Call external action)
- method: POST
- url: {{ env.IDP_API_URL }}/users/{{ alert.username }}/revoke-sessions
- body: session_id={{ alert.session_id }}; reason=Suspicious sign-in — high risk score

# Step 5 — Require Step-Up MFA Challenge (Call external action)
- method: POST
- url: {{ env.IDP_API_URL }}/users/{{ alert.username }}/require-mfa
- body: session_id={{ alert.session_id }}; challenge_type=totp

# Step 6 — Notify User of Suspicious Sign-In (Notify)
- channel: email
- to: {{ alert.email }}
- subject: Security Alert: Suspicious sign-in to your account
- message: We detected a suspicious sign-in to your account.

Location: {{ alert.city }}, {{ alert.country }}
IP: {{ alert.source_ip }}
Time: {{ alert.login_time }}

If this was you, no action is needed.
If not, contact security immediately: security@company.com


# Step 7 — Create Suspicious Sign-In Ticket (Create ticket)
- title: SUSPICIOUS-LOGIN: {{ alert.username }} from {{ alert.country }} ({{ alert.source_ip }})
- severity: P2
- assignee group: security-ops

# Step 8 — Close Suspicious Sign-In Case (Close case)
- status: remediated
- resolution: Session revoked or MFA required; user notified; ticket created.
