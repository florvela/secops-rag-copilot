# Attack surface analysis (OWASP LLM)

Design-level analysis of the attack surface, referencing the OWASP Top 10 for LLM Applications
(2025). Not every control is implemented; the ones that are point to the module that enforces them.

| Surface | OWASP risk | Control | Implemented |
| --- | --- | --- | --- |
| API input (alert) | LLM01 Prompt Injection via event fields (`user_agent`, names); malformed/oversized input | Pydantic schema validation with length and range limits; the alert is treated as data | yes — `src/guardrails/input_validation.py` |
| Retrieved chunks | LLM01 indirect prompt injection; LLM04 data/model poisoning of the corpus | Heuristic injection screening of retrieved chunks before they reach the LLM | yes — `src/guardrails/injection_guard.py`, applied in `src/agents/investigator.py` |
| Untrusted event | LLM01 injection embedded in `matched_event` | The event is screened and flagged in the audit log; it is treated as data, not instructions | partial — `src/agents/orchestrator.py` (logs `injection_suspected`) |
| Agent-to-agent communication | Propagation of untrusted content between agents; LLM05 improper output handling | Retrieved content passes the injection screen before crossing to generation; structured results | partial — screening only |
| Tool use | LLM06 excessive agency | Read-only design: no tool mutates state, which removes the write-action risk class by construction | yes — by design (no write tools exist) |
| Report output | LLM02 sensitive info disclosure; LLM09 misinformation / hallucination | Grounding guard (judge) rejects ungrounded claims before returning the report | yes — `src/guardrails/grounding.py`, `src/agents/judge.py` |
| Secrets / config | credential exposure | API keys and environment values via `.env`, never hardcoded | yes — `src/config.py`, `.env.example` |
| Observability | lack of traceability on incident | Audit log in JSONL (event, source, decision), without dumping documents or credentials | yes — `src/security/audit.py` |

## Implemented controls (summary)

1. Input validation (schema + limits).
2. Indirect injection screening of retrieved chunks and the matched event.
3. Grounding guard on the output.
4. Read-only design (no state mutation).
5. Secrets via environment.
6. Audit logging.

## Not implemented (documented surface)

- Full agent-to-agent output sanitisation beyond injection screening.
- Redaction/pseudonymisation of entity names before sending to the LLM.
- A calibrated injection classifier (the current detector is heuristic; Meta Prompt Guard 2 is the
  intended drop-in, see notes).

These are identified as part of the surface but left out of scope, consistent with "implement some,
not all" from the course guidance.
