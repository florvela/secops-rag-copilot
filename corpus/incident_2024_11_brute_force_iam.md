---
documento: Incident Report — 2024-11 Brute Force Against IAM User
version: final
fuente: incident
tecnicas: T1110.001
---

# Incident 2024-11: Brute Force Against IAM User

## Summary

A single IAM user received hundreds of failed console sign-in attempts from one source IP over
twelve minutes, followed by a successful sign-in from the same IP. The pattern mapped to
T1110.001.

## Timeline

- 19:02 UTC — Burst of `ConsoleLogin` failures begins against one identity from a Tor exit node.
- 19:14 UTC — Successful `ConsoleLogin` from the same source IP.
- 19:15 UTC — Alert raised on failures-then-success correlation.
- 19:40 UTC — Analyst confirmed the success and revoked sessions.

## Root cause

The identity used a weak, reused password and had no MFA. Account lockout was not configured,
so the attacker could keep guessing until success.

## Response

Source IP blocked, sessions revoked, password reset, MFA enrolled, and an account lockout
policy applied. No credential additions were found after the successful sign-in.

## Lessons learned

A lockout threshold would have stopped the attack before success. The success event, not the
failures, is what made this an incident rather than noise.
