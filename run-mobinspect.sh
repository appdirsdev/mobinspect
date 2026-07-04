#!/bin/bash
# Convenience launcher for the local MobInspect dev setup created during install.
# Usage:
#   ./run-mobinspect.sh emulator   # boot the Android AVD (for Dynamic Analysis)
#   ./run-mobinspect.sh server     # start MobInspect web server (uses PostgreSQL)
#   ./run-mobinspect.sh            # start the server (default)
set -e
cd "$(dirname "$0")"

PY="$HOME/.pyenv/versions/3.13.5/bin/python"
export ANDROID_HOME="$HOME/Library/Android/sdk"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export JAVA_HOME="/opt/homebrew/opt/openjdk@17"
export PATH="$JAVA_HOME/bin:$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH"

case "$1" in
  emulator)
    exec "$ANDROID_HOME/emulator/emulator" -avd MobInspect_API34 \
      -writable-system -no-snapshot -no-boot-anim
    ;;
  *)
    # Use PostgreSQL (falls back to SQLite automatically if these are unset)
    source ./.env.postgres
    exec "$PY" -m poetry run python manage.py runserver 127.0.0.1:8000
    ;;
esac
