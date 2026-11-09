#!/usr/bin/env bash
# One-shot local setup for secops-rag-copilot.
# Creates the virtualenv, installs dependencies, prepares .env and downloads
# the real MITRE ATT&CK data. Safe to re-run (idempotent).

set -euo pipefail

# --- 1. Pick a Python 3.13 interpreter --------------------------------------
# torch / sentence-transformers do not ship wheels for Python 3.14 yet, so the
# project is pinned to 3.13 (see .python-version).
if [ -x "$HOME/.pyenv/versions/3.13.0/bin/python" ]; then
  PYTHON="$HOME/.pyenv/versions/3.13.0/bin/python"
elif command -v python3.13 >/dev/null 2>&1; then
  PYTHON="$(command -v python3.13)"
else
  echo "Python 3.13 not found. Install it (e.g. 'pyenv install 3.13.0') and re-run." >&2
  exit 1
fi
echo "Using $("$PYTHON" --version)"

# --- 2. Create the virtualenv (only if missing) -----------------------------
if [ ! -d .venv ]; then
  echo "Creating virtualenv in .venv ..."
  "$PYTHON" -m venv .venv
fi

# --- 3. Install dependencies ------------------------------------------------
echo "Installing dependencies ..."
./.venv/bin/python -m pip install --quiet --upgrade pip
./.venv/bin/python -m pip install -r requirements.txt

# --- 4. Prepare the local .env (only if missing) ----------------------------
# .env is gitignored; it holds paths and the local LLM (Ollama) settings.
if [ ! -f .env ]; then
  echo "Creating .env from .env.example ..."
  cp .env.example .env
fi

# --- 5. Download the real MITRE ATT&CK descriptions -------------------------
# Regenerates corpus/mitre_*.md from the official ATT&CK STIX bundle
# (cached under .cache/, gitignored).
echo "Fetching MITRE ATT&CK data ..."
./.venv/bin/python scripts/fetch_mitre.py

# --- 6. Done ----------------------------------------------------------------
echo ""
echo "Setup complete. Next steps:"
echo "  source .venv/bin/activate"
echo "  pytest -q"
echo "  python -m src.cli fixtures/alerts/mfa_console_signin.json"
