---
documento: MITRE ATT&CK — Brute Force: Password Guessing
version: ATT&CK v15
fuente: mitre
tecnicas: T1110.001
---

# T1110.001 Brute Force: Password Guessing

Adversaries with no prior knowledge of legitimate credentials may guess passwords to
attempt access to accounts. Without knowledge of the password for an account, an adversary
may opt to systematically guess the password using a repetitive or iterative mechanism.
Password guessing may or may not take into account the target's password policies and use
common username and password combinations.

Guessing is typically performed against a single account at a time with many password
attempts, which contrasts with password spraying, where one password is tried against many
accounts. Repeated authentication failures from a single source against a single identity
are a strong indicator of password guessing.

## Detection

Monitor authentication logs for high rates of failed logins followed by a success on the
same account. Look for bursts of `failure` events from one source IP, then a `success`.
Account lockout events and sign-ins from anonymizing infrastructure (VPNs, Tor exit nodes)
raise the confidence of the finding.

## Mitigation

Set account lockout policies after a threshold of failed attempts, balanced against
denial-of-service risk. Enforce strong password policies and MFA. Rate-limit authentication
endpoints and alert on anomalous failure volumes.
