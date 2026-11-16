---
documento: Playbook — S3 Bucket Exposure Response
version: 1.0.0
fuente: playbook
---

# S3 Bucket Exposure Response
Responds to S3 bucket misconfigurations including public access enablement, ACL changes granting anonymous access, and unexpected data exfiltration from buckets. Remediates public access, audits bucket policy, and notifies cloud security.

Applies to medium, high, critical severity alerts. Tags: s3, cloud, aws, misconfiguration, data-exposure.

# Step 1 — Enrich S3 Bucket Configuration (Enrich context)
- source: cloud_iam
- fields: bucket_name, account_id, region, public_access_block, acl, bucket_policy, encryption_enabled, versioning_enabled, data_classification, estimated_size_gb

# Step 2 — Investigate Bucket Access Logs (Investigate)
- query: s3_access bucket={{ alert.bucket_name }} requester=anonymous last_hours=24
- context fields: alert.bucket_name, alert.acl

# Step 3 — Check If Bucket Is Publicly Accessible (Decision)
- condition: field=alert.public_access_block; operator=eq; value=False

# Step 4 — Enable S3 Public Access Block (Call external action)
- method: PUT
- url: {{ env.AWS_S3_API_URL }}/{{ alert.bucket_name }}/public-access-block
- body: BlockPublicAcls=True; IgnorePublicAcls=True; BlockPublicPolicy=True; RestrictPublicBuckets=True

# Step 5 — Request Bucket Policy Audit (Call external action)
- method: POST
- url: {{ env.CLOUD_SECURITY_API_URL }}/audit/s3
- body: bucket={{ alert.bucket_name }}; account={{ alert.account_id }}; check_types=['policy', 'acl', 'encryption', 'logging']

# Step 6 — Notify Cloud Security Team (Notify)
- channel: #cloud-security
- message: 🪣 *S3 Bucket Exposure Detected*
Bucket: `{{ alert.bucket_name }}`
Account: `{{ alert.account_id }}`
Region: `{{ alert.region }}`
Classification: `{{ alert.data_classification }}`
Size: {{ alert.estimated_size_gb }}GB
Public access blocked: {{ steps.block-public-access.status }}


# Step 7 — Create S3 Exposure Ticket (Create ticket)
- title: S3-EXPOSURE: {{ alert.bucket_name }} in {{ alert.account_id }}
- severity: P1
- assignee group: cloud-security

# Step 8 — Close S3 Exposure Case (Close case)
- status: remediated
- resolution: Public access blocked; bucket policy audited; cloud security notified.
