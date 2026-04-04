#!/usr/bin/env bash

set -euo pipefail

QUERY_CONSOLE=false
if [[ "${1:-}" == "--query-console" ]]; then
  QUERY_CONSOLE=true
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

OLLAMA_MODEL="${OLLAMA_MODEL:-tinyllama}"

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  COMPOSE_CMD=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE_CMD=(docker-compose)
else
  echo "Error: neither 'docker compose' nor 'docker-compose' is available."
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "Error: python3 is not installed or not in PATH."
  exit 1
fi

if $QUERY_CONSOLE; then
  echo "========================================"
  echo "  CCTV Event Query Console"
  echo "========================================"
  echo "Ask natural-language questions over recent events."
  echo "Examples:"
  echo "  - show suspicious events from last 10 minutes"
  echo "  - list high risk events in last 30 minutes"
  echo "  - any repeated person activity near entrance"
  echo "Type 'exit' to close this console."

  while true; do
    read -r -p $'\nQuery: ' query

    if [[ -z "${query// }" ]]; then
      continue
    fi

    if [[ "${query,,}" == "exit" ]]; then
      break
    fi

    read -r -p "Lookback minutes (default 10): " minutes_raw
    minutes=10
    if [[ -n "${minutes_raw// }" ]] && [[ "$minutes_raw" =~ ^[0-9]+$ ]] && [[ "$minutes_raw" -gt 0 ]]; then
      minutes="$minutes_raw"
    fi

    python3 query_events.py "$query" --minutes "$minutes"
  done

  exit 0
fi

open_terminal() {
  local cmd="$1"
  osascript <<EOF
 tell application "Terminal"
   activate
   do script "cd \"$ROOT_DIR\"; $cmd"
 end tell
EOF
}

echo "========================================"
echo "  Secure CCTV - Full Pipeline Launcher"
echo "========================================"

echo
echo "[1/6] Cleaning shared folders..."
rm -f shared/raw/* 2>/dev/null || true
rm -f shared/frames/* 2>/dev/null || true
rm -f shared/decrypted/* 2>/dev/null || true
rm -f shared/metadata/* 2>/dev/null || true

echo "[2/6] Building & starting Docker containers..."
"${COMPOSE_CMD[@]}" down >/dev/null 2>&1 || true
"${COMPOSE_CMD[@]}" up --build -d
sleep 8
echo "  Containers ready!"

echo "[3/6] Starting Ollama model ($OLLAMA_MODEL)..."
open_terminal "echo 'OLLAMA (HOST) - $OLLAMA_MODEL'; ollama run $OLLAMA_MODEL"

echo "[4/6] Launching YOLO detector..."
open_terminal "echo 'YOLO DETECTOR - Press ESC to stop'; python3 detect_and_send.py"

echo "[5/6] Launching Decrypted Stream Viewer..."
open_terminal "echo 'DECRYPTED STREAM VIEWER'; python3 display_host.py"

echo "[6/6] Launching Event Query Console..."
open_terminal "bash \"$ROOT_DIR/run_simulation.sh\" --query-console"

echo
echo "========================================"
echo "  ALL SYSTEMS LINKED & RUNNING!"
echo "  - Docker: Camera + Gateway + Cloud"
echo "  - Ollama: Host model server"
echo "  - YOLO: Host detection producer"
echo "  - Viewer: Host decrypted output"
echo "  - Query: Natural language event search"
echo "========================================"
echo
echo "Showing Docker logs below (Ctrl+C to stop):"
echo
"${COMPOSE_CMD[@]}" logs -f
