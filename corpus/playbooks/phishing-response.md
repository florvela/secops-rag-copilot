---
documento: Playbook — Phishing Email Response
version: 1.0
fuente: playbook
---

# Phishing Email Response
Respond to a confirmed or suspected phishing email. Pull the message from mailboxes, block the malicious indicators, and warn other recipients.

# Triage
- Enrich the email metadata: sender, domain, URLs, attachments, and authentication results.
- Investigate the sender reputation and identify every recipient who received the message.

# Containment
- Quarantine the message across all affected mailboxes.
- Block the malicious sender domain and any malicious URLs at the mail gateway and web proxy.

# Eradication and recovery
- Reset credentials for any user who clicked or submitted data.
- Remove any mailbox rules or grants created from a compromised account.

# Notification and closure
- Notify the security team and send an awareness note to recipients.
- Open a ticket and close once the message is purged and indicators are blocked.
