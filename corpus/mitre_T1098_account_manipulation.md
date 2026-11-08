---
documento: MITRE ATT&CK — Account Manipulation
version: ATT&CK v15
fuente: mitre
tecnicas: T1098
---

# T1098 Account Manipulation

Adversaries may manipulate accounts to maintain and/or elevate access to victim systems.
Account manipulation may consist of any action that preserves or modifies adversary access
to a compromised account, such as modifying credentials or permission groups. These actions
could also include account activity designed to subvert security policies, such as
performing iterative password updates to bypass password duration policies.

In cloud environments, adversaries commonly add credentials (access keys, certificates, or
additional MFA devices) to an identity they already control, so that access survives a
password reset. Adding a new access key to an IAM user, or registering an attacker-controlled
MFA device, are high-value signals of persistence.

## Detection

Monitor for the creation of new credentials on existing identities: `CreateAccessKey`,
`UpdateLoginProfile`, and MFA device registration events. Correlate these against who
normally administers the account. Credential additions performed by the account on itself,
shortly after an anomalous sign-in, are especially suspicious.

## Mitigation

Apply least privilege so that identities cannot modify their own permissions or credentials.
Require approval workflows for credential creation. Rotate and audit access keys regularly.
