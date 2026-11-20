from __future__ import annotations

import json
import re
from typing import Protocol, runtime_checkable


class LLMUnavailable(RuntimeError):
    pass


@runtime_checkable
class LLMClient(Protocol):
    def generate(self, prompt: str, system: str | None = None, temperature: float = 0.2) -> str: ...

    def generate_json(self, prompt: str, system: str | None = None): ...


def _extract_json(raw: str):
    cleaned = re.sub(r"```(json)?|```", "", raw.strip()).strip()
    match = re.search(r"(\{.*\}|\[.*\])", cleaned, re.DOTALL)
    if not match:
        raise ValueError("no JSON found in LLM output")
    return json.loads(match.group(1))


class LocalLLM:
    def __init__(self, base_url: str, model: str, timeout: int = 120) -> None:
        self._url = base_url.rstrip("/") + "/api/generate"
        self._model = model
        self._timeout = timeout

    def generate(self, prompt: str, system: str | None = None, temperature: float = 0.2) -> str:
        try:
            import requests
        except ImportError as exc:
            raise LLMUnavailable("requests is not installed") from exc

        payload = {
            "model": self._model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": temperature},
        }
        if system:
            payload["system"] = system

        try:
            response = requests.post(self._url, json=payload, timeout=self._timeout)
            response.raise_for_status()
        except Exception as exc:
            raise LLMUnavailable(str(exc)) from exc

        return response.json().get("response", "").strip()

    def generate_json(self, prompt: str, system: str | None = None):
        return _extract_json(self.generate(prompt, system=system))


def _make_client(backend: str, settings, model: str) -> LLMClient:
    if backend == "langchain":
        from triage_copilot.llm.langchain_client import LangChainLLM

        return LangChainLLM(settings.llm.base_url, model)
    return LocalLLM(settings.llm.base_url, model)


def _build_bedrock(settings, model: str):
    from triage_copilot.llm.bedrock_client import BedrockLLM

    return BedrockLLM(
        model,
        region=getattr(settings.llm, "region", None),
        guardrail_id=getattr(settings.llm, "guardrail_id", None),
        guardrail_version=getattr(settings.llm, "guardrail_version", None),
        max_tokens=getattr(settings.llm, "max_tokens", 1024),
    )


def _probe(client: LLMClient) -> None:
    """Confirm the backend answers, so an unreachable model is caught at startup."""
    client.generate("ping", temperature=0.0)


def _resolve_model(settings, role: str | None) -> str:
    """Pick the model for a role from the optional per-role map, else the default."""
    models = getattr(settings.llm, "models", None) or {}
    if role and role in models:
        return models[role]
    return settings.llm.model


def build_llm(settings, role: str | None = None) -> LLMClient:
    """Return a working LLM client.

    With ``LLM_PROVIDER=bedrock`` a :class:`BedrockLLM` is returned (no live probe,
    to avoid a token call on every cold start). Otherwise the ``native``/``langchain``
    Ollama backends are tried in order and the reachable one is returned; if neither
    answers, ``LLMUnavailable`` is raised.

    ``role`` selects a per-role model from ``settings.llm.models`` when present
    (e.g. a cheap model for planner/judge, a larger one for the report), falling
    back to ``settings.llm.model``.
    """
    model = _resolve_model(settings, role)

    if getattr(settings.llm, "provider", "ollama").lower() == "bedrock":
        return _build_bedrock(settings, model)

    preferred = settings.llm.backend.lower()
    order = ["langchain", "native"] if preferred == "langchain" else ["native", "langchain"]

    errors: list[str] = []
    for backend in order:
        try:
            client = _make_client(backend, settings, model)
            _probe(client)
            return client
        except LLMUnavailable as exc:
            errors.append(f"{backend}: {exc}")

    raise LLMUnavailable(
        "No LLM backend is reachable. "
        f"Start Ollama (`ollama serve` and `ollama pull {settings.llm.model}`) "
        "or install the LangChain backend (requirements-langchain.txt). "
        "Tried -> " + " | ".join(errors)
    )
