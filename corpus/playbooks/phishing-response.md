---
documento: Playbook — Phishing Email Response
version: 1.0.0
fuente: playbook
---

# Phishing Email Response
Responds to confirmed or suspected phishing emails. Quarantines the message across the tenant, extracts and blocks malicious URLs and sender domains, identifies other recipients, and triggers user awareness notifications.

Applies to medium, high, critical severity alerts. Tags: phishing, email, identity, containment.

# Step 1 — Enrich Email Metadata (Enrich context)
- source: email_gateway
- fields: sender, sender_domain, subject, recipients, urls, attachments

# Step 2 — Investigate Sender Reputation (Investigate)
- query: ip_reputation sender={{ alert.sender_domain }}
- context fields: alert.sender, alert.sender_domain

# Step 3 — Block Malicious Sender Domain (Containment — block source IP)
- ip field: alert.sender_domain
- block type: domain
- direction: inbound
- duration hours: 168
- comment: Phishing sender block — playbook {{ id }}

# Step 4 — Check URL Count (Decision)
- condition: field=alert.url_count; operator=gt; value=0

# Step 5 — Block Malicious URLs at Proxy (Call external action)
- method: POST
- url: {{ env.PROXY_API_URL }}/block
- body: urls={{ alert.urls }}; category=phishing; duration_hours=168

# Step 6 — Notify Security Team (Notify)
- channel: #security-alerts
- message: 🎣 *Phishing Alert*
Sender: `{{ alert.sender }}`
Subject: `{{ alert.subject }}`
Recipients: {{ alert.recipient_count }}
URLs blocked: {{ alert.url_count }}


# Step 7 — Create Phishing Ticket (Create ticket)
- title: PHISHING: {{ alert.sender }} — {{ alert.subject }}
- severity: P2
- assignee group: security-ops

# Step 8 — Close Phishing Case (Close case)
- status: remediated
- resolution: Sender blocked; URLs blocked; recipients notified.
