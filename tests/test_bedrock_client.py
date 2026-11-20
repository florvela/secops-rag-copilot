import pytest

from triage_copilot.llm.bedrock_client import BedrockLLM
from triage_copilot.llm.client import LLMUnavailable


class FakeBedrock:
    """Records the last converse kwargs and returns a canned response."""

    def __init__(self, text: str, usage: dict | None = None) -> None:
        self._text = text
        self._usage = usage or {}
        self.last_kwargs: dict | None = None

    def converse(self, **kwargs):
        self.last_kwargs = kwargs
        return {
            "output": {"message": {"content": [{"text": self._text}]}},
            "usage": self._usage,
            "stopReason": "end_turn",
        }


class BoomBedrock:
    def converse(self, **kwargs):
        raise RuntimeError("no credentials")


def test_generate_returns_text_and_records_usage():
    fake = FakeBedrock(
        "hello",
        usage={
            "inputTokens": 10,
            "outputTokens": 3,
            "cacheReadInputTokens": 100,
            "cacheWriteInputTokens": 0,
            "totalTokens": 113,
        },
    )
    llm = BedrockLLM("amazon.nova-lite-v1:0", client=fake)
    assert llm.generate("hi", system="rules") == "hello"
    assert llm.last_usage.total_tokens == 113
    assert llm.last_usage.cache_read_tokens == 100


def test_prompt_cache_point_added_with_system():
    fake = FakeBedrock("x")
    BedrockLLM("m", client=fake).generate("hi", system="rules")
    system = fake.last_kwargs["system"]
    assert system[0] == {"text": "rules"}
    assert system[1] == {"cachePoint": {"type": "default"}}


def test_no_system_blocks_when_system_absent():
    fake = FakeBedrock("x")
    BedrockLLM("m", client=fake).generate("hi")
    assert "system" not in fake.last_kwargs


def test_guardrail_tags_only_user_turn():
    fake = FakeBedrock("x")
    llm = BedrockLLM("m", client=fake, guardrail_id="gr-1", guardrail_version="1")
    llm.generate("untrusted", system="rules")
    assert fake.last_kwargs["guardrailConfig"]["guardrailIdentifier"] == "gr-1"
    content = fake.last_kwargs["messages"][0]["content"]
    assert content == [{"guardContent": {"text": {"text": "untrusted"}}}]


def test_total_usage_accumulates_across_calls():
    fake = FakeBedrock("x", usage={"inputTokens": 5, "outputTokens": 2, "totalTokens": 7})
    llm = BedrockLLM("m", client=fake)
    llm.generate("a")
    llm.generate("b")
    assert llm.last_usage.total_tokens == 7
    assert llm.total_usage.total_tokens == 14
    assert llm.total_usage.input_tokens == 10


def test_generate_json_parses_fenced_output():
    fake = FakeBedrock('```json\n{"ok": true}\n```')
    assert BedrockLLM("m", client=fake).generate_json("hi") == {"ok": True}


def test_failure_raises_llm_unavailable():
    with pytest.raises(LLMUnavailable):
        BedrockLLM("m", client=BoomBedrock()).generate("hi")
