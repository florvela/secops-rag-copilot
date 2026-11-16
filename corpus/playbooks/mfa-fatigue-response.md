---
documento: Playbook — MFA Fatigue Attack Response
version: 1.0.0
fuente: playbook
---

# MFA Fatigue Attack Response
Responds to MFA push fatigue attacks where attackers spam authentication requests hoping the user accidentally approves. Detects rapid successive MFA prompts, temporarily blocks push notifications, and forces re-enrollment.

Applies to high, critical severity alerts. Tags: mfa-fatigue, identity, authentication, push-bombing, account-takeover.

# Step 1 — Enrich MFA Fatigue Event (Enrich context)
- source: identity_provider
- fields: username, email, phone_number, push_count, push_window_minutes, source_ips, device_enrolled, last_successful_mfa

# Step 2 — Investigate Attack Source IPs (Investigate)
- query: mfa_attempts user={{ alert.username }} last_hours=1
- context fields: alert.username, alert.push_count, alert.source_ips

# Step 3 — Check Push Frequency (Decision)
- condition: field=alert.push_count; operator=gt; value=10

# Step 4 — Temporarily Disable Push MFA (Call external action)
- method: POST
- url: {{ env.IDP_API_URL }}/users/{{ alert.username }}/mfa/push/disable
- body: reason=MFA fatigue attack — push bombing detected; duration_hours=24

# Step 5 — Block Attacking IPs at Perimeter (Containment — block source IP)
- ip field: alert.source_ips
- direction: inbound
- duration hours: 48
- comment: MFA fatigue attack IPs — playbook {{ id }}

# Step 6 — Notify User of MFA Fatigue Attack (Notify)
- channel: email
- to: {{ alert.email }}
- subject: SECURITY ALERT: Do not approve unexpected MFA requests
- message: IMPORTANT: Someone is attempting to access your account.

We have detected {{ alert.push_count }} MFA push requests in the last
{{ alert.push_window_minutes }} minutes directed at your account.

DO NOT approve any MFA requests you did not initiate.

Push MFA has been temporarily disabled as a precaution.
Contact security immediately: security@company.com


# Step 7 — Create MFA Fatigue Ticket (Create ticket)
- title: MFA-FATIGUE: {{ alert.username }} — {{ alert.push_count }} pushes in {{ alert.push_window_minutes }}min
- severity: P1
- assignee group: ir-team

# Step 8 — Close MFA Fatigue Case (Close case)
- status: contained
- resolution: Push MFA disabled; attacker IPs blocked; user notified; IR investigating.
