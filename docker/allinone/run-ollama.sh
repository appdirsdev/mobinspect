#!/bin/bash
set -e
export OLLAMA_HOST=127.0.0.1:11434
export HOME=/usr/share/ollama
exec su ollama -s /bin/bash -c "/usr/local/bin/ollama serve"
