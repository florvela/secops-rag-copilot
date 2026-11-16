---
documento: Playbook — Object Storage Bucket Exposure Response
version: 1.0
fuente: playbook
---

# Object Storage Bucket Exposure Response
Respond to an object-storage (e.g. S3) bucket misconfiguration: public access enabled, ACL changes granting anonymous access, or unexpected exfiltration. Remove public access and audit the policy.

# Triage
- Enrich the bucket configuration: ownership, policy, ACLs, and whether it holds sensitive data.
- Investigate access logs for anonymous or unexpected reads, and when the exposure began.

# Containment
- Enable the public-access block and remove any anonymous or overly broad grants.
- If data was exfiltrated, preserve the access logs as evidence.

# Eradication and recovery
- Audit and correct the bucket policy and ACLs, and review other buckets for the same misconfiguration.
- Rotate anything sensitive that may have been exposed.

# Notification and closure
- Notify the cloud security team and open a ticket.
- Close the case once public access is removed and the policy is fixed.
