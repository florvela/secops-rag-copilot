---
documento: Playbook — Business Email Compromise (BEC) Response
version: 1.0.0
fuente: playbook
---

# Business Email Compromise (BEC) Response
Responds to Business Email Compromise alerts. Identifies spoofed or compromised executive accounts used to initiate fraudulent wire transfers or sensitive data requests. Blocks sender, alerts finance/legal, and coordinates with email gateway.

Applies to high, critical severity alerts. Tags: bec, email, fraud, executive, financial-fraud.

# Step 1 — Enrich BEC Email Metadata (Enrich context)
- source: email_gateway
- fields: sender, reply_to, display_name, recipients, subject, body_snippet, spf_result, dkim_result, dmarc_result

# Step 2 — Check Email Authentication Failure (Decision)
- condition: field=alert.dmarc_result; operator=eq; value=fail

# Step 3 — Block Spoofed Sender Domain (Containment — block source IP)
- ip field: alert.sender_domain
- block type: domain
- direction: inbound
- duration hours: 720
- comment: BEC spoofed sender — playbook {{ id }}

# Step 4 — Investigate Potentially Compromised Account (Investigate)
- query: logins user={{ alert.sender }} anomalous=true last_days=14

# Step 5 — Alert Finance Team to Hold Wire Transfers (Notify)
- channel: #finance-alerts
- message: 🚨 *BEC Alert — HOLD ALL WIRE TRANSFERS*
Suspected fraudulent email from: `{{ alert.sender }}`
Display Name: `{{ alert.display_name }}`
Subject: `{{ alert.subject }}`
Recipients: {{ alert.recipients }}
DMARC: {{ alert.dmarc_result }}
Contact IR immediately: #ir-critical


# Step 6 — Notify Security Team (Notify)
- channel: #ir-critical
- message: 🎯 *Business Email Compromise Detected*
Sender: `{{ alert.sender }}`
Reply-To: `{{ alert.reply_to }}`
Finance team notified to hold transfers.


# Step 7 — Create BEC Incident Ticket (Create ticket)
- title: BEC: Fraudulent email from {{ alert.sender }} — {{ alert.subject }}
- severity: P1
- assignee group: ir-team

# Step 8 — Close BEC Case (Close case)
- status: contained
- resolution: Sender blocked; finance alerted to hold transfers; IR investigating.
