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


def _make_client(backend: str, settings) -> LLMClient:
    if backend == "langchain":
        from src.agents.llm_langchain import LangChainLLM

        return LangChainLLM(settings.llm.base_url, settings.llm.model)
    return LocalLLM(settings.llm.base_url, settings.llm.model)


def _probe(client: LLMClient) -> None:
    """Confirm the backend answers, so an unreachable model is caught at startup."""
    client.generate("ping", temperature=0.0)


def build_llm(settings) -> LLMClient:
    """Return a working LLM client.

    The backend selected in ``.env`` (``native`` by default) is tried first; if it
    cannot be reached, the other backend is tried automatically. If neither answers,
    ``LLMUnavailable`` is raised.
    """
    preferred = settings.llm.backend.lower()
    order = ["langchain", "native"] if preferred == "langchain" else ["native", "langchain"]

    errors: list[str] = []
    for backend in order:
        try:
            client = _make_client(backend, settings)
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
