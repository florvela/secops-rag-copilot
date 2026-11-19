# triage-copilot

A multi-agent security-alert investigation copilot with hybrid RAG over a security
knowledge corpus (MITRE ATT&CK prose, playbooks, runbooks, historical incidents).

Given a **structured alert** (simulated SIEM JSON: severity, description, resolution,
MITRE technique, matched event and the triggering query), the system builds retrieval
queries from the alert fields, retrieves grounded evidence via hybrid RAG
(BM25 + embeddings + RRF + cross-encoder re-ranking), and returns an investigation
report with citations. It then proposes a **response plan** and executes approved
actions through a mock MCP tool layer. It runs fully locally.

## Agents and flow

```
Alert → [MITRE enrichment] → Planner → Investigator (hybrid RAG) → Judge (grounding)
                                                                      │ grounded report
                                                                      ▼
                                                     report shown to the analyst first
                                                                      ▼
                                                         Remediator (3rd agent)
                                                         proposes response actions
                                                                      │
                                                                      ▼
                                                 Human-in-the-loop guardrail
                                                 destructive action → approval
                                                                      ▼
                                                 MCP tools (mock): disable_credential,
                                                 block_ip, revoke_sessions, isolate_host,
                                                 create_ticket, notify
                                                                      ▼
                                                        closure note (what was done)
```

The report is presented before any action so the analyst approves with the finding (and its
grounding status) in hand; a closure note at the end summarizes the actions actually taken.

- **Planner / Investigator / Judge / Remediator** — four agents; the Remediator turns the
  grounded report into a proposed response plan by selecting from the available tools.
- **MCP tools** — generic SOC response actions with a JSON schema and a `destructive` flag.
  The registry shape is library code (`triage_copilot/investigation/tools.py`); the **mocked**
  implementations (simulated results, no real systems) are a local adapter
  (`app/adapters/local/mock_tools.py`). They can optionally be served over a real MCP transport
  (`app/adapters/local/mcp_server.py`, FastMCP).
- **Human-in-the-loop** (`triage_copilot/investigation/approval.py`) — destructive actions require
  approval (interactive in the CLI; returned as `pending_approval` over the API), mitigating
  excessive agency. Every proposal and decision is written to the audit log.

## Requirements

- Python 3.13 (pinned in `.python-version`)
- [Ollama](https://ollama.com) for the local LLM agents — **required** to run the agents
  (CLI/API). If the `native` backend is unreachable the system automatically falls back to the
  `langchain` backend, and aborts with an error only if neither is available.

## Setup

Quick path (creates the venv, installs **both** LLM backends, prepares `.env` and
downloads the real MITRE ATT&CK data):

```bash
./setup.sh
source .venv/bin/activate
```

After setup you can run with either backend by setting `LLM_BACKEND` in `.env`
(`native` by default, or `langchain`) — nothing else to install.

Or do it manually:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .                 # installs the triage_copilot + app packages
pip install -e '.[langchain]'    # optional LangChain backend
cp .env.example .env
python scripts/fetch_mitre.py
```

The embedding and cross-encoder models are downloaded from Hugging Face on first run
and cached locally. After that, the pipeline runs offline.

## Configuration

Runtime settings live in `config/config.json` (chunking, models, retrieval depth,
thresholds). Secrets and environment-specific values live in `.env` (never hardcoded).

### LLM backend

The agents talk to the LLM through a small `LLMClient` interface with two interchangeable
backends, selected by `LLM_BACKEND` in `.env`:

- `native` (default) — talks to Ollama directly over HTTP. No extra dependencies.
- `langchain` — uses LangChain (`ChatOllama`). Installed by `setup.sh`, so just set
  `LLM_BACKEND=langchain`. Through LangChain the chat model can be swapped for other
  providers (OpenAI, Anthropic, Bedrock) by adding the matching package and key.

The rest of the system (agents, guardrails, API) is unchanged by the choice.

## Project layout

The code is split into a portable AI **library** (`triage_copilot/`) and a deployable
**app** layer (`app/`, wiring + adapters). The library never imports from the app.

```
src/
  triage_copilot/              portable AI library (no I/O, no app imports)
    rag/                       BM25, embeddings, RRF fusion, re-ranking, chunking, indexing
    investigation/             models, orchestrator, ports (Protocols), tools, approval, audit sink
    agents/                    planner, investigator, judge, remediator
    prompts/                   extracted system prompts
    llm/                       LLM client (native Ollama + LangChain backend)
    validation/                input validation, injection screening, grounding
    config.py                  Pydantic config schema (no loading)
    service.py                 public entry: investigate_alert(...)
  app/                         deployable layer (wiring + adapters)
    api/                       FastAPI endpoint
    cli.py                     CLI entrypoint
    config.py                  config/env loading (get_settings)
    logging_setup.py           colored per-module logging
    eval/                      metrics + golden set
    adapters/
      local/                   corpus loader, mock tools, cli approver, audit log, MCP server
      prod/                    (placeholder: pgvector retriever, real response tools)
config/         config.json, activity_mitre_map.json
corpus/         knowledge documents (MITRE, playbooks, runbooks)
  playbooks/    response playbooks (markdown; retrieved via `fuente: playbook`)
fixtures/       simulated input alerts (JSON)
scripts/        data builders (fetch MITRE, build MITRE map)
tests/          tests for the critical modules
docs/           deliverables (report, diagrams)
```

## Data builders

Two scripts derive data from the [AiSOC](https://github.com) detection/playbook repo
(MIT License). Their outputs are committed, so the runtime does not depend on that repo;
re-run them only to refresh from an updated checkout (adjust the source path constant at the
top of each script):

- `python scripts/build_mitre_map.py` → `config/activity_mitre_map.json`. Maps AWS
  `activity_name` (e.g. `DeleteTrail`) to MITRE techniques. Alerts that arrive without a
  technique are enriched from this map during input validation, so retrieval has an anchor.
- The AiSOC response playbooks were converted (YAML → corpus markdown, `fuente: playbook`) and
  the results are committed under `corpus/playbooks/*.md`; the remediation retrieval pass routes
  to these. The one-off conversion script is not included in the repo.

## Testing

See [docs/LOCAL_TESTING.md](docs/LOCAL_TESTING.md) for how to run the unit tests, the retrieval and
injection evaluations, the CLI and the API locally.

## License

Academic project — PLN III, MIA.
