---
documento: Playbook — Authentication Token Theft Response
version: 1.0.0
fuente: playbook
---

# Authentication Token Theft Response
Responds to stolen authentication token usage including JWT hijacking, session cookie theft, and bearer token replay attacks. Revokes tokens, forces re-authentication, and checks for downstream unauthorized access.

Applies to high, critical severity alerts. Tags: token-theft, identity, jwt, session-hijacking, authentication.

# Step 1 — Enrich Token Usage Event (Enrich context)
- source: identity_provider
- fields: username, email, token_type, token_id, original_ip, replay_ip, user_agent, endpoints_accessed, data_accessed

# Step 2 — Investigate Token Replay Activity (Investigate)
- query: token_usage token_id={{ alert.token_id }} anomalous=true
- context fields: alert.token_id, alert.replay_ip, alert.endpoints_accessed

# Step 3 — Immediately Revoke Stolen Token (Call external action)
- method: POST
- url: {{ env.IDP_API_URL }}/tokens/{{ alert.token_id }}/revoke
- body: reason=Token theft detected — replay from different IP

# Step 4 — Revoke All User Sessions (Call external action)
- method: POST
- url: {{ env.IDP_API_URL }}/users/{{ alert.username }}/revoke-sessions
- body: reason=Token theft — full session revocation

# Step 5 — Block Token Replay Source IP (Containment — block source IP)
- ip field: alert.replay_ip
- direction: inbound
- duration hours: 48
- comment: Token theft replay IP — playbook {{ id }}

# Step 6 — Notify Affected User (Notify)
- channel: email
- to: {{ alert.email }}
- subject: Security Alert: Your authentication token was used from an unexpected location
- message: A stolen authentication token was detected being used from {{ alert.replay_ip }}.

Your {{ alert.token_type }} token has been revoked and all sessions terminated.
Please sign in again and contact security if you did not authorize this access.

Security contact: security@company.com


# Step 7 — Create Token Theft Ticket (Create ticket)
- title: TOKEN-THEFT: {{ alert.username }} — {{ alert.token_type }} replayed from {{ alert.replay_ip }}
- severity: P1
- assignee group: ir-team

# Step 8 — Close Token Theft Case (Close case)
- status: contained
- resolution: Token revoked; all sessions terminated; replay IP blocked; user notified.
