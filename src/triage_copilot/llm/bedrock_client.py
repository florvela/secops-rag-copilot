from __future__ import annotations

from dataclasses import dataclass, field

from triage_copilot.llm.client import LLMUnavailable, _extract_json


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    total_tokens: int = 0

    def as_dict(self) -> dict:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cache_read_tokens": self.cache_read_tokens,
            "cache_write_tokens": self.cache_write_tokens,
            "total_tokens": self.total_tokens,
        }

    def add(self, other: "Usage") -> None:
        self.input_tokens += other.input_tokens
        self.output_tokens += other.output_tokens
        self.cache_read_tokens += other.cache_read_tokens
        self.cache_write_tokens += other.cache_write_tokens
        self.total_tokens += other.total_tokens


class BedrockLLM:
    """LLM backend on Amazon Bedrock (Converse).

    Mirrors the ``affinity_ai`` Bedrock wrapper: prompt caching on the static
    system prefix, optional Guardrails applied only to the user turn, and token
    usage exposed via ``last_usage`` so the cost layer can meter per request.

    The boto3 ``bedrock-runtime`` client can be injected (``client=``) so the
    adapter is unit-testable with a fake; otherwise it is created lazily.
    """

    def __init__(
        self,
        model: str,
        *,
        region: str | None = None,
        guardrail_id: str | None = None,
        guardrail_version: str | None = None,
        max_tokens: int = 1024,
        enable_prompt_cache: bool = True,
        client=None,
    ) -> None:
        self._model = model
        self._region = region
        self._guardrail_id = guardrail_id
        self._guardrail_version = guardrail_version
        self._max_tokens = max_tokens
        self._enable_prompt_cache = enable_prompt_cache
        self._client = client
        # last_usage holds the most recent call; total_usage accumulates across
        # the whole investigation (the orchestrator shares one client for many
        # calls), which is what the cost layer meters per request.
        self.last_usage = Usage()
        self.total_usage = Usage()

    def _runtime(self):
        if self._client is None:
            try:
                import boto3
            except ImportError as exc:
                raise LLMUnavailable("boto3 is not installed") from exc
            self._client = boto3.client("bedrock-runtime", region_name=self._region)
        return self._client

    def generate(self, prompt: str, system: str | None = None, temperature: float = 0.2) -> str:
        runtime = self._runtime()

        system_blocks: list[dict] = []
        if system:
            system_blocks.append({"text": system})
            if self._enable_prompt_cache:
                system_blocks.append({"cachePoint": {"type": "default"}})

        use_guardrail = bool(self._guardrail_id and self._guardrail_version)
        if use_guardrail:
            user_content = [{"guardContent": {"text": {"text": prompt}}}]
        else:
            user_content = [{"text": prompt}]

        kwargs: dict = {
            "modelId": self._model,
            "messages": [{"role": "user", "content": user_content}],
            "inferenceConfig": {
                "maxTokens": self._max_tokens,
                "temperature": temperature,
                "topP": 0.9,
            },
        }
        if system_blocks:
            kwargs["system"] = system_blocks
        if use_guardrail:
            kwargs["guardrailConfig"] = {
                "guardrailIdentifier": self._guardrail_id,
                "guardrailVersion": self._guardrail_version,
                "trace": "enabled",
            }

        try:
            response = runtime.converse(**kwargs)
        except Exception as exc:
            raise LLMUnavailable(str(exc)) from exc

        usage = response.get("usage", {}) or {}
        self.last_usage = Usage(
            input_tokens=usage.get("inputTokens", 0),
            output_tokens=usage.get("outputTokens", 0),
            cache_read_tokens=usage.get("cacheReadInputTokens", 0),
            cache_write_tokens=usage.get("cacheWriteInputTokens", 0),
            total_tokens=usage.get("totalTokens", 0),
        )
        self.total_usage.add(self.last_usage)

        message = response.get("output", {}).get("message", {})
        parts = [block["text"] for block in message.get("content", []) or [] if "text" in block]
        return "".join(parts).strip()

    def generate_json(self, prompt: str, system: str | None = None):
        return _extract_json(self.generate(prompt, system=system))
