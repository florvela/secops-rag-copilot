from __future__ import annotations

import argparse
import json
import re
import urllib.request
from pathlib import Path

ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
CACHE = Path(".cache/enterprise-attack.json")
OUT_DIR = Path("corpus/mitre")

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


def _doc_markdown(obj: dict, version: str) -> str:
    technique = _attack_id(obj)
    name = obj["name"]
    body = f"{_clean(obj.get('description', ''))}\n"
    detection = _clean(obj.get("x_mitre_detection", ""))
    if detection:
        body += f"\n## Detection\n\n{detection}\n"
    return (
        "---\n"
        f"documento: MITRE ATT&CK — {name}\n"
        f"version: ATT&CK v{version}\n"
        "fuente: mitre\n"
        f"tecnicas: {technique}\n"
        "---\n\n"
        f"# {technique} {name}\n\n"
        f"{body}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Download MITRE ATT&CK techniques into the corpus.")
    parser.add_argument("--out-dir", default=str(OUT_DIR))
    parser.add_argument("--limit", type=int, default=0, help="only the first N (for quick tests)")
    args = parser.parse_args()

    bundle = _download()
    version = _collection_version(bundle)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    techniques = []
    for obj in bundle["objects"]:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        if _attack_id(obj):
            techniques.append(obj)

    techniques.sort(key=lambda o: _attack_id(o))
    if args.limit:
        techniques = techniques[: args.limit]

    for obj in techniques:
        technique = _attack_id(obj)
        (out_dir / f"{technique}.md").write_text(_doc_markdown(obj, version), encoding="utf-8")

    print(f"wrote {len(techniques)} MITRE technique files to {out_dir}/ (ATT&CK v{version})")


if __name__ == "__main__":
    main()
