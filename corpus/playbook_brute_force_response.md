---
documento: Playbook — Brute Force / Password Guessing Response
version: 1.4
fuente: playbook
tecnicas: T1110.001
---

# Playbook: Brute Force / Password Guessing Response

Scope: repeated authentication failures against a single identity followed by a success.
Maps to MITRE T1110.001.

## Triage

1. Count failed authentication events for the identity within the lookback window and
   identify the source IP(s).
2. Determine whether a success followed the failures, and from which source.
3. Check if the source IP belongs to anonymizing infrastructure or a known-bad list.

## Containment

1. If a success followed the burst of failures from the same source, treat the account as
   compromised and revoke its sessions.
2. Temporarily block the offending source IP.
3. Apply or lower the account lockout threshold for the affected identity.

## Eradication and recovery

1. Force a password reset and enroll MFA if missing.
2. Review any actions performed after the successful sign-in.
3. Confirm no new credentials were added to the identity (see account manipulation guidance).

## Notes

Many failures with no success is usually a blocked attempt, not a breach. The success after
the failures is what turns this from noise into an incident.
