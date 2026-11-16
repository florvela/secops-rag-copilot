---
documento: Playbook — Supply Chain Compromise Response
version: 1.0
fuente: playbook
---

# Supply Chain Compromise Response
Respond to a suspected supply-chain attack: a malicious package update, a compromised third-party library, or a tampered build artifact. Stop the spread into builds and audit the software inventory.

# Triage
- Enrich the affected package or artifact: version, source, and where it is used.
- Investigate its provenance and check for a checksum or signature mismatch against the trusted source.

# Containment
- Halt the affected CI/CD pipelines so the compromised artifact is not built or shipped further.
- Pin or roll back to the last known-good version.

# Eradication and recovery
- Remove the malicious package from registries and caches, and rebuild from clean sources.
- Audit the software inventory for every system that pulled the bad artifact.

# Notification and closure
- Notify the DevSecOps team and open an incident ticket.
- Close the case once pipelines are clean and the inventory is verified.
