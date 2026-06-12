#!/usr/bin/env bash
# Build the Tailwind CSS bundle once.
# Usage: ./scripts/tailwind-build.sh [--minify]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAILWIND="$ROOT/tools/tailwindcss"

if [[ ! -x "$TAILWIND" ]]; then
  echo "Tailwind CLI not found. Run ./scripts/install-tailwind.sh first." >&2
  exit 1
fi

MINIFY=""
if [[ "${1:-}" == "--minify" ]]; then
  MINIFY="--minify"
fi

cd "$ROOT"
"$TAILWIND" \
  --config tailwind.config.js \
  --input  mobsf/static/mobinspect/css/src/app.css \
  --output mobsf/static/mobinspect/css/dist/app.css \
  $MINIFY

echo "Built: mobsf/static/mobinspect/css/dist/app.css"
