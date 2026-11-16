---
documento: Playbook — Container Escape Response
version: 1.0.0
fuente: playbook
---

# Container Escape Response
Responds to detected container escape attempts or privileged container misuse. Terminates the offending container, cordons the node, captures runtime forensics, and alerts the platform security team.

Applies to high, critical severity alerts. Tags: container, kubernetes, docker, escape, runtime-security.

# Step 1 — Enrich Container Context (Enrich context)
- source: container_runtime
- fields: container_id, container_name, image, namespace, node_name, pod_name, privileged, capabilities, process_tree, syscalls

# Step 2 — Investigate Suspicious Process Activity (Investigate)
- query: container_process container={{ alert.container_id }} anomalous=true last_minutes=30

- context fields: alert.container_id, alert.process_tree

# Step 3 — Check Privileged Container (Decision)
- condition: field=alert.privileged; operator=eq; value=True

# Step 4 — Terminate Offending Container Immediately (Call external action)
- method: DELETE
- url: {{ env.K8S_API_URL }}/namespaces/{{ alert.namespace }}/pods/{{ alert.pod_name }}
- headers: Authorization=Bearer {{ env.K8S_TOKEN }}

# Step 5 — Cordon Compromised Node (Call external action)
- method: PATCH
- url: {{ env.K8S_API_URL }}/nodes/{{ alert.node_name }}
- body: spec={'unschedulable': True}

# Step 6 — Notify Platform Security Team (Notify)
- channel: #platform-security
- message: 🐳 *Container Escape Detected*
Container: `{{ alert.container_name }}`
Image: `{{ alert.image }}`
Node: `{{ alert.node_name }}`
Namespace: `{{ alert.namespace }}`
Privileged: {{ alert.privileged }}
Container terminated: {{ steps.immediate-terminate.status }}
Node cordoned: {{ steps.cordon-node.status }}


# Step 7 — Create Container Escape Ticket (Create ticket)
- title: CONTAINER-ESCAPE: {{ alert.container_name }} on {{ alert.node_name }}
- severity: P1
- assignee group: platform-security

# Step 8 — Close Container Escape Case (Close case)
- status: contained
- resolution: Container terminated; node cordoned; forensics captured.
