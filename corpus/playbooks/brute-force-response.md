---
documento: Playbook — Brute Force Attack Response
version: 1.0.0
fuente: playbook
---

# Brute Force Attack Response
Responds to brute force and credential stuffing attacks against authentication endpoints. Implements progressive lockout, blocks attacking IPs, enables CAPTCHA enforcement, and notifies the security team.

Applies to medium, high, critical severity alerts. Tags: brute-force, credential-stuffing, authentication, network, identity.

# Step 1 — Enrich Brute Force Attack Data (Enrich context)
- source: identity_provider
- fields: target_account, source_ip, country, attempt_count, success_count, time_window_minutes, targeted_endpoint, user_agent, ip_asn

# Step 2 — Investigate Attack Source (Investigate)
- query: auth_failures source_ip={{ alert.source_ip }} last_hours=24

- context fields: alert.source_ip, alert.attempt_count

# Step 3 — Check If Any Login Succeeded (Decision)
- condition: field=alert.success_count; operator=gt; value=0

# Step 4 — Lock Breached Account Immediately (Call external action)
- method: POST
- url: {{ env.IDP_API_URL }}/users/{{ alert.target_account }}/lock
- body: reason=Brute force succeeded — account locked for security review

# Step 5 — Block Attacking IP at Firewall (Containment — block source IP)
- ip field: alert.source_ip
- direction: inbound
- duration hours: 24
- comment: Brute force attack — {{ alert.attempt_count }} attempts — playbook {{ id }}

# Step 6 — Notify Security Team (Notify)
- channel: #security-alerts
- message: 🔨 *Brute Force Attack Detected*
Target: `{{ alert.target_account }}`
Source: `{{ alert.source_ip }}` ({{ alert.country }})
Attempts: {{ alert.attempt_count }} in {{ alert.time_window_minutes }}min
Successes: {{ alert.success_count }}
Endpoint: `{{ alert.targeted_endpoint }}`
Account locked: {{ steps.lock-account-and-alert.status }}
IP blocked: {{ steps.block-attacker.status }}


# Step 7 — Create Brute Force Incident Ticket (Create ticket)
- title: BRUTE-FORCE: {{ alert.target_account }} — {{ alert.attempt_count }} attempts from {{ alert.source_ip }}
- severity: P2
- assignee group: security-ops

# Step 8 — Close Brute Force Case (Close case)
- status: remediated
- resolution: Attacking IP blocked; account locked if successful; security team notified.
