from __future__ import annotations

import json
from pathlib import Path

from src.guardrails.injection_guard import score_text

SAMPLES_PATH = "fixtures/injection_samples.json"
CONFIG_PATH = "config/config.json"


def evaluate() -> dict[str, float]:
    threshold = json.loads(Path(CONFIG_PATH).read_text(encoding="utf-8"))["injection_guard"][
        "threshold"
    ]
    samples = json.loads(Path(SAMPLES_PATH).read_text(encoding="utf-8"))

    tp = fp = tn = fn = 0
    for sample in samples:
        flagged = score_text(sample["text"]) >= threshold
        malicious = sample["label"] == "malicious"
        if malicious and flagged:
            tp += 1
        elif malicious and not flagged:
            fn += 1
        elif not malicious and flagged:
            fp += 1
        else:
            tn += 1

    detection = tp / (tp + fn) if (tp + fn) else 0.0
    false_positive = fp / (fp + tn) if (fp + tn) else 0.0
    return {
        "detection_rate": round(detection, 2),
        "false_positive_rate": round(false_positive, 2),
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "tn": tn,
    }


def main() -> None:
    for name, value in evaluate().items():
        print(f"{name}: {value}")


if __name__ == "__main__":
    main()
