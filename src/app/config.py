from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv

from triage_copilot.config import LLMSettings, PipelineConfig, Settings


def _load_pipeline(config_path: Path) -> PipelineConfig:
    data = json.loads(config_path.read_text(encoding="utf-8"))
    return PipelineConfig.model_validate(data)


def _llm_model() -> str:
    """Default model per provider: Bedrock uses a cheap model, Ollama a local one."""
    if os.getenv("LLM_PROVIDER", "ollama").lower() == "bedrock":
        return os.getenv("BEDROCK_MODEL", "amazon.nova-lite-v1:0")
    return os.getenv("OLLAMA_MODEL", "llama3.1:8b")


def _role_models() -> dict[str, str]:
    """Optional per-role overrides (e.g. a larger model only for the final report)."""
    roles = ("planner", "judge", "remediator", "report")
    out: dict[str, str] = {}
    for role in roles:
        value = os.getenv(f"BEDROCK_MODEL_{role.upper()}")
        if value:
            out[role] = value
    return out


@lru_cache
def get_settings() -> Settings:
    load_dotenv()
    config_path = Path(os.getenv("CONFIG_PATH", "config/config.json"))
    return Settings(
        config_path=config_path,
        log_dir=Path(os.getenv("LOG_DIR", "logs")),
        llm=LLMSettings(
            backend=os.getenv("LLM_BACKEND", "native"),
            provider=os.getenv("LLM_PROVIDER", "ollama"),
            base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
            model=_llm_model(),
            region=os.getenv("AWS_REGION") or os.getenv("BEDROCK_REGION"),
            guardrail_id=os.getenv("BEDROCK_GUARDRAIL_ID") or None,
            guardrail_version=os.getenv("BEDROCK_GUARDRAIL_VERSION") or None,
            max_tokens=int(os.getenv("BEDROCK_MAX_TOKENS", "1024")),
            models=_role_models(),
        ),
        hf_token=os.getenv("HF_TOKEN") or None,
        pipeline=_load_pipeline(config_path),
    )


if __name__ == "__main__":
    print(get_settings().model_dump_json(indent=2))
