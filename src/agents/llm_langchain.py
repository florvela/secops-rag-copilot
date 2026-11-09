from __future__ import annotations

from src.agents.llm import LLMUnavailable, _extract_json


class LangChainLLM:
    """LLM backend built on LangChain. Uses ChatOllama by default so it stays local,
    but through LangChain the chat model can be swapped for any provider."""

    def __init__(self, base_url: str, model: str, temperature: float = 0.2) -> None:
        try:
            from langchain_ollama import ChatOllama
        except ImportError as exc:
            raise LLMUnavailable(
                "LangChain backend requires 'langchain-ollama' (see requirements-langchain.txt)"
            ) from exc
        self._model = ChatOllama(base_url=base_url, model=model, temperature=temperature)

    def generate(self, prompt: str, system: str | None = None, temperature: float = 0.2) -> str:
        from langchain_core.messages import HumanMessage, SystemMessage

        messages = []
        if system:
            messages.append(SystemMessage(content=system))
        messages.append(HumanMessage(content=prompt))
        try:
            result = self._model.invoke(messages)
        except Exception as exc:
            raise LLMUnavailable(str(exc)) from exc
        return (result.content or "").strip()

    def generate_json(self, prompt: str, system: str | None = None):
        return _extract_json(self.generate(prompt, system=system))
