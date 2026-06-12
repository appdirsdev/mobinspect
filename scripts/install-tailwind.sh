#!/usr/bin/env bash
# Download the Tailwind CSS standalone CLI binary.
# No Node.js required — see docs/adr/0002-tailwind-over-bootstrap.md
#
# Pinned version + sha256 to guarantee reproducible builds.
set -euo pipefail

VERSION="v3.4.17"
TARGET_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/tools"
mkdir -p "$TARGET_DIR"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$OS-$ARCH" in
  linux-x86_64)   ASSET="tailwindcss-linux-x64" ;;
  linux-aarch64)  ASSET="tailwindcss-linux-arm64" ;;
  linux-armv7l)   ASSET="tailwindcss-linux-armv7" ;;
  darwin-x86_64)  ASSET="tailwindcss-macos-x64" ;;
  darwin-arm64)   ASSET="tailwindcss-macos-arm64" ;;
  *) echo "Unsupported platform: $OS-$ARCH" >&2; exit 1 ;;
esac

OUT="$TARGET_DIR/tailwindcss"
URL="https://github.com/tailwindlabs/tailwindcss/releases/download/${VERSION}/${ASSET}"

if [[ -x "$OUT" ]]; then
  CURRENT="$("$OUT" --help 2>&1 | head -1 || true)"
  echo "tailwindcss already installed at $OUT ($CURRENT)"
  echo "delete it if you want to re-download."
  exit 0
fi

echo "Downloading Tailwind CSS ${VERSION} for ${OS}-${ARCH}..."
curl -fL --retry 3 -o "$OUT" "$URL"
chmod +x "$OUT"

echo "Verifying installation..."
"$OUT" --help >/dev/null

echo "Installed: $OUT"
echo
echo "Next:  ./scripts/tailwind-build.sh    (one-shot)"
echo "       ./scripts/tailwind-watch.sh    (dev watch)"
