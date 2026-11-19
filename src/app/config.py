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
            model=os.getenv("OLLAMA_MODEL", "llama3.1:8b"),
        ),
        hf_token=os.getenv("HF_TOKEN") or None,
        pipeline=_load_pipeline(config_path),
    )


if __name__ == "__main__":
    print(get_settings().model_dump_json(indent=2))
