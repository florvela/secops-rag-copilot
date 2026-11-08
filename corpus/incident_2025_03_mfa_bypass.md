---
documento: Incident Report — 2025-03 Console Sign-in Without MFA
version: final
fuente: incident
tecnicas: T1078.004
---

# Incident 2025-03: Console Sign-in Without MFA

## Summary

An IAM user signed in to the AWS console from an unfamiliar hosting-provider IP address with
`MFAUsed = No`. The user normally signs in from the corporate network with MFA. The alert
mapped to T1078.004.

## Timeline

- 02:14 UTC — Successful `ConsoleLogin` from a new source IP, no MFA, user agent not seen before.
- 02:19 UTC — The identity created a new access key on itself (T1098).
- 02:31 UTC — Listing of secrets in the secrets manager.
- 08:40 UTC — Alert triaged by the on-call analyst.

## Root cause

The user's password had been phished two days earlier. MFA was not enforced on this legacy
identity, so the stolen password was sufficient for console access.

## Response

Sessions revoked, password reset, the attacker-added access key deleted, and MFA enforced.
No data exfiltration was confirmed, but the added access key showed a persistence attempt.

## Lessons learned

MFA enforcement gaps on legacy identities are high risk. The added access key is why password
rotation alone would not have been enough.
