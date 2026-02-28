#!/usr/bin/env bash
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$APP_DIR"

if [[ ! -x ".venv/bin/waitress-serve" ]]; then
  echo "Missing waitress in .venv. Run: .venv/bin/pip install -r requirements.txt"
  exit 1
fi

exec .venv/bin/waitress-serve --host=0.0.0.0 --port=2026 wsgi:app
