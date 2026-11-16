---
documento: Playbook — Web Application Attack Response
version: 1.0.0
fuente: playbook
---

# Web Application Attack Response
Responds to web application attacks including SQL injection, XSS, RCE, and directory traversal. Blocks attacking IPs, captures forensic evidence, checks for data exfiltration, and notifies the AppSec team.

Applies to medium, high, critical severity alerts. Tags: web, appsec, waf, sqli, xss, rce.

# Step 1 — Enrich Attack Request (Enrich context)
- source: waf
- fields: source_ip, user_agent, target_url, method, payload, attack_type, response_code, bytes_transferred

# Step 2 — Investigate Source IP History (Investigate)
- query: ip_activity ip={{ alert.source_ip }} last_hours=24
- context fields: alert.source_ip, alert.attack_type

# Step 3 — Check for Data Exfiltration (Decision)
- condition: field=alert.bytes_transferred; operator=gt; value=10000

# Step 4 — Notify Security — Possible Exfiltration (Notify)
- channel: #ir-critical
- message: ⚠️ *Web Attack with Possible Data Exfiltration*
Attack Type: `{{ alert.attack_type }}`
Source IP: `{{ alert.source_ip }}`
Target: `{{ alert.target_url }}`
Data transferred: {{ alert.bytes_transferred }} bytes


# Step 5 — Block Attacking IP at WAF/Firewall (Containment — block source IP)
- ip field: alert.source_ip
- direction: inbound
- duration hours: 48
- comment: Web attack — {{ alert.attack_type }} — playbook {{ id }}

# Step 6 — Notify AppSec Team (Notify)
- channel: #appsec-alerts
- message: 🌐 *Web Application Attack Detected*
Type: `{{ alert.attack_type }}`
Source: `{{ alert.source_ip }}`
Target: `{{ alert.target_url }}`
IP Blocked: {{ steps.block-ip.status }}


# Step 7 — Create Web Attack Ticket (Create ticket)
- title: WEB-ATTACK: {{ alert.attack_type }} from {{ alert.source_ip }}
- severity: P2
- assignee group: appsec

# Step 8 — Close Web Attack Case (Close case)
- status: remediated
- resolution: Attacking IP blocked; AppSec notified; evidence captured.
