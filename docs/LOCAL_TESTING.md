# Local testing guide

How to run and verify the whole system on your machine. Commands assume the repo root as the
working directory and the virtualenv active.

## 0. Prerequisites

- Python 3.13 (pinned in `.python-version`).
- Create and activate the virtualenv, then install dependencies (needs internet once):

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

The embedding and cross-encoder models download from Hugging Face on first use and are cached
locally; afterwards retrieval runs offline.

### Optional: local LLM (Ollama)

The agents (planner, judge, report writer) use a local LLM through Ollama. Without it the system
still runs, falling back to deterministic planning, a heuristic grounding check and an extractive
report. To enable the full LLM path:

```bash
# install Ollama from https://ollama.com, then:
ollama pull llama3.1:8b
```

Values are read from `.env` (`OLLAMA_BASE_URL`, `OLLAMA_MODEL`).

## 1. Unit tests

```bash
pytest -q
```

Covers RRF fusion, chunking (size + overlap), metadata filtering, retrieval metrics, the injection
guard and alert schema validation.

## 2. Configuration loads

```bash
python -m src.config
```

Prints the merged configuration (`config/config.json` + `.env`).

## 3. Retrieval evaluation

```bash
python -m src.eval.run
```

Runs the golden queries and reports precision@k, recall@k, nDCG@k (k=5,10) and MRR, both as a
baseline and with the MITRE technique filter applied. First run downloads the models.

## 4. Injection-detection evaluation

```bash
python -m src.eval.injection_eval
```

Scores the labelled adversarial/benign samples and reports detection rate and false-positive rate.
This one runs fully offline (no models needed).

## 5. End-to-end on a single alert (CLI)

```bash
python -m src.cli fixtures/alerts/mfa_console_signin.json
```

Validates the alert, runs the multi-agent investigation and prints the report, citations and run
metadata (`grounded`, `iterations`, `flagged_chunks`, `execution_id`).

To see the injection guard in action, use the adversarial fixture: the suspicious `matched_event`
is logged as `injection_suspected` in `logs/security.jsonl`.

```bash
python -m src.cli fixtures/alerts/mfa_console_signin_injection.json
```

## 6. API

```bash
uvicorn src.api.main:app --reload
```

In another terminal:

```bash
curl -s localhost:8000/health

curl -s -X POST localhost:8000/investigate \
  -H 'content-type: application/json' \
  -d @fixtures/alerts/mfa_console_signin.json | python -m json.tool
```

A malformed alert (missing field, oversized text) returns HTTP 422 with the validation errors.

## What runs offline vs. needs setup

| Step | Needs internet once | Needs Ollama |
| --- | --- | --- |
| Unit tests | no | no |
| Injection eval (step 4) | no | no |
| Retrieval eval (step 3) | yes (model download) | no |
| CLI / API (steps 5–6) | yes (model download) | optional (fallbacks otherwise) |

## Where things are written

- `logs/security.jsonl` — audit events (gitignored). Deleted safely between runs.
- Model weights — cached by Hugging Face outside the repo.
