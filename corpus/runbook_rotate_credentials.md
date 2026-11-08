---
documento: Runbook — Rotate Compromised Cloud Credentials
version: 3.0
fuente: runbook
tecnicas: T1078.004, T1098
---

# Runbook: Rotate Compromised Cloud Credentials

Use when an identity is suspected or confirmed compromised. Supports the console sign-in and
brute-force playbooks.

## Steps

1. Disable the identity's console password to stop interactive access.
2. Deactivate, then delete, all access keys belonging to the identity. Deactivation first lets
   you confirm nothing legitimate breaks before deletion.
3. Enumerate and remove any MFA devices the attacker may have registered, then re-enroll a
   trusted device.
4. Rotate secrets the identity could read (for example, values in the secrets manager it had
   access to).
5. Review recent credential-creation events (`CreateAccessKey`, `UpdateLoginProfile`) to
   detect persistence set up during the intrusion.

## Verification

Confirm the identity has exactly one trusted MFA device, no stale access keys, and that the
password was reset through a trusted channel. Only then restore access.

## Notes

Rotating the password alone is insufficient if the attacker added their own access key: the
key keeps working after a password reset. Always check for added credentials.
