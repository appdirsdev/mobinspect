#!/usr/bin/env bash
# Build the Tailwind CSS bundle in watch mode.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAILWIND="$ROOT/tools/tailwindcss"

if [[ ! -x "$TAILWIND" ]]; then
  echo "Tailwind CLI not found. Run ./scripts/install-tailwind.sh first." >&2
  exit 1
fi

cd "$ROOT"
exec "$TAILWIND" \
  --config tailwind.config.js \
  --input  mobsf/static/mobinspect/css/src/app.css \
  --output mobsf/static/mobinspect/css/dist/app.css \
  --watch
