"""Build an ``activity_name -> MITRE technique`` lookup from the AiSOC detections.

The AiSOC detection rules (MIT License) map AWS API calls (``event_name``) to MITRE
ATT&CK techniques via their ``tags``. We extract that mapping once and commit the
result to ``config/activity_mitre_map.json`` so the runtime never depends on the
external repo. Alerts that arrive without a technique are then enriched by looking up
the event's ``activity_name`` (see ``src/guardrails/input_validation.py``).

Re-run after updating the AiSOC checkout:

    python scripts/build_mitre_map.py
"""

from __future__ import annotations

import argparse
import json
import os
import re
from datetime import date
from pathlib import Path

import yaml

# Source: AiSOC detections (https://github.com — MIT License). The checkout location
# is configurable so this runs outside any one machine (env AISOC_DETECTIONS or --detections).
_DEFAULT_DETECTIONS = os.getenv("AISOC_DETECTIONS", "AiSOC/detections")
DOMAINS = ("cloud", "identity")
_DEFAULT_OUTPUT = os.getenv("MITRE_MAP_OUTPUT", "config/activity_mitre_map.json")

_EVENT_RE = re.compile(r'event_name\s*(?:==|IN)\s*(\[[^\]]*\]|"[^"]+")')
_NAME_RE = re.compile(r'"([A-Za-z0-9_:.-]+)"')
_TECH_RE = re.compile(r"^mitre\.attack\.(t\d+(?:\.\d+)?)$", re.IGNORECASE)


def _techniques(tags: object) -> list[str]:
    out: list[str] = []
    if not isinstance(tags, list):
        return out
    for tag in tags:
        if not isinstance(tag, str):
            continue
        match = _TECH_RE.match(tag.strip())
        if match:
            out.append(match.group(1).upper())
    return out


def _event_names(condition: str) -> list[str]:
    names: list[str] = []
    for chunk in _EVENT_RE.findall(condition or ""):
        names.extend(_NAME_RE.findall(chunk))
    return names


def build(detections: Path, output: Path) -> None:
    mapping: dict[str, set[str]] = {}
    rules = 0
    without_event = 0

    for domain in DOMAINS:
        for path in sorted((detections / domain).glob("*.yaml")):
            try:
                doc = yaml.safe_load(path.read_text(encoding="utf-8"))
            except yaml.YAMLError:
                continue
            if not isinstance(doc, dict):
                continue
            rules += 1
            techniques = _techniques(doc.get("tags"))
            condition = (doc.get("detection") or {}).get("condition", "")
            names = _event_names(condition)
            if not names:
                without_event += 1
                continue
            if not techniques:
                continue
            for name in names:
                mapping.setdefault(name, set()).update(techniques)

    result = {name: sorted(techs) for name, techs in sorted(mapping.items())}
    payload = {
        "_meta": {
            "source": "AiSOC detections (MIT License) — cloud + identity rules",
            "generated": date.today().isoformat(),
            "rules_processed": rules,
            "rules_without_event_name": without_event,
            "events_mapped": len(result),
        },
        **result,
    }

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(
        f"wrote {output} — {len(result)} events mapped from {rules} rules "
        f"({without_event} without a literal event_name)"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the activity -> MITRE technique map.")
    parser.add_argument("--detections", default=_DEFAULT_DETECTIONS,
                        help="path to the AiSOC detections checkout (env AISOC_DETECTIONS)")
    parser.add_argument("--output", default=_DEFAULT_OUTPUT,
                        help="output JSON path (env MITRE_MAP_OUTPUT)")
    args = parser.parse_args()
    build(Path(args.detections), Path(args.output))


if __name__ == "__main__":
    main()
