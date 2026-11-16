---
documento: Playbook — Anomalous User Behavior Response
version: 1.0
fuente: playbook
---

# Anomalous User Behavior Response
Respond to anomalous user behavior flagged by behavioral analytics (UEBA): unusual access patterns, after-hours activity, mass data access, or deviation from a baseline. Escalate by risk score and tighten authentication.

# Triage
- Enrich the event with the user's role, normal working hours, usual locations, and the data they typically touch.
- Compare the flagged activity against the user's historical baseline to judge how far it deviates.

# Containment
- If the risk score is high, require step-up (re-)authentication before further access is allowed.
- Temporarily tighten the user's access until the behavior is explained.

# Notification and closure
- Send the case to a security analyst for review, and open a ticket.
- Close the case once the activity is confirmed benign or escalated to a full investigation.
