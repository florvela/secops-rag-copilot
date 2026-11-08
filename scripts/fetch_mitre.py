from __future__ import annotations

import json
import re
import urllib.request
from pathlib import Path

ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
CACHE = Path(".cache/enterprise-attack.json")

# MITRE technique id -> corpus filename stem (kept stable so goldens still match).
WANTED = {
    "T1078.004": "mitre_T1078_004_cloud_accounts",
    "T1110.001": "mitre_T1110_001_password_guessing",
    "T1098": "mitre_T1098_account_manipulation",
}

_CITATION = re.compile(r"\(Citation:.*?\)")


def _download() -> dict:
    if CACHE.exists():
        return json.loads(CACHE.read_text(encoding="utf-8"))
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    print("downloading ATT&CK STIX bundle (~40 MB, one time)...")
    with urllib.request.urlopen(ATTACK_URL) as response:
        data = response.read()
    CACHE.write_bytes(data)
    return json.loads(data)


def _attack_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _clean(text: str) -> str:
    return _CITATION.sub("", text or "").strip()


def _collection_version(bundle: dict) -> str:
    for obj in bundle["objects"]:
        if obj.get("type") == "x-mitre-collection":
            return obj.get("x_mitre_version", "")
    return ""


def _write_doc(path: Path, obj: dict, version: str) -> None:
    technique = _attack_id(obj)
    name = obj["name"]
    body = f"{_clean(obj.get('description', ''))}\n"
    detection = _clean(obj.get("x_mitre_detection", ""))
    if detection:
        body += f"\n## Detection\n\n{detection}\n"

    path.write_text(
        "---\n"
        f"documento: MITRE ATT&CK — {name}\n"
        f"version: ATT&CK v{version}\n"
        "fuente: mitre\n"
        f"tecnicas: {technique}\n"
        "---\n\n"
        f"# {technique} {name}\n\n"
        f"{body}",
        encoding="utf-8",
    )


def main() -> None:
    bundle = _download()
    version = _collection_version(bundle)

    index: dict[str, dict] = {}
    for obj in bundle["objects"]:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        technique = _attack_id(obj)
        if technique:
            index[technique] = obj

    for technique, stem in WANTED.items():
        obj = index.get(technique)
        if obj is None:
            print(f"WARNING: {technique} not found in the bundle")
            continue
        _write_doc(Path("corpus") / f"{stem}.md", obj, version)
        print(f"wrote corpus/{stem}.md  <-  {technique} {obj['name']}")


if __name__ == "__main__":
    main()
