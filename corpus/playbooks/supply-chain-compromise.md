---
documento: Playbook — Supply Chain Compromise Response
version: 1.0.0
fuente: playbook
---

# Supply Chain Compromise Response
Responds to suspected supply chain attacks including malicious package updates, compromised third-party libraries, or tampered build artifacts. Quarantines affected builds, notifies DevSecOps, and triggers a software inventory audit.

Applies to high, critical severity alerts. Tags: supply-chain, devops, sca, build-security, oss.

# Step 1 — Enrich Affected Package (Enrich context)
- source: sca_scanner
- fields: package_name, package_version, ecosystem, cve_ids, affected_repos, build_jobs, pipeline_id, checksum_mismatch

# Step 2 — Investigate Package Provenance (Investigate)
- query: package_usage package={{ alert.package_name }} version={{ alert.package_version }}

- context fields: alert.package_name, alert.package_version, alert.cve_ids

# Step 3 — Check Checksum Mismatch (Decision)
- condition: field=alert.checksum_mismatch; operator=eq; value=True

# Step 4 — Halt Affected CI/CD Pipelines (Call external action)
- method: POST
- url: {{ env.CI_API_URL }}/pipelines/{{ alert.pipeline_id }}/cancel
- body: reason=Supply chain compromise — checksum mismatch — playbook {{ id }}

# Step 5 — Notify DevSecOps Team (Notify)
- channel: #devsecops-alerts
- message: 📦 *Supply Chain Compromise Detected*
Package: `{{ alert.package_name }}@{{ alert.package_version }}`
Ecosystem: `{{ alert.ecosystem }}`
CVEs: {{ alert.cve_ids }}
Affected Repos: {{ alert.affected_repos }}
Checksum mismatch: {{ alert.checksum_mismatch }}
Pipeline halted: {{ steps.halt-pipelines.status }}


# Step 6 — Create Supply Chain Incident Ticket (Create ticket)
- title: SUPPLY-CHAIN: {{ alert.package_name }}@{{ alert.package_version }} — {{ alert.ecosystem }}
- severity: P1
- assignee group: devsecops

# Step 7 — Close Supply Chain Case (Close case)
- status: under-investigation
- resolution: Pipelines halted; DevSecOps notified; package audit in progress.
