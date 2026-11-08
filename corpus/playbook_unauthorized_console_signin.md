---
documento: Playbook — Unauthorized Console Sign-in Without MFA
version: 2.1
fuente: playbook
tecnicas: T1078.004
---

# Playbook: Unauthorized Console Sign-in Without MFA

Scope: a successful cloud console sign-in where MFA was not used on a human identity.
Maps to MITRE T1078.004.

## Triage

1. Confirm the identity type. Service accounts and break-glass accounts may legitimately
   lack MFA; standard human users should not.
2. Review the source IP and user agent against the user's baseline. Flag new geographies,
   hosting-provider IP ranges, and unusual clients.
3. Check whether the sign-in was expected (recent travel, new device, password reset).

## Containment

1. If the sign-in is unexpected, treat the account as compromised.
2. Revoke active sessions for the identity.
3. Require MFA re-enrollment and block sign-ins from the suspicious source.

## Eradication and recovery

1. Rotate the password and any long-lived access keys (see the credential rotation runbook).
2. Review actions taken during the session for further manipulation.
3. Restore MFA enforcement and confirm the identity is clean before re-enabling access.

## Notes

A single sign-in with `MFAUsed = No` is enough to start triage, but not proof of compromise.
Contrast it with the user's history before escalating.
