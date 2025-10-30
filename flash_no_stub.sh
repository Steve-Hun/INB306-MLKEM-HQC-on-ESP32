#!/usr/bin/env bash
set -euo pipefail

# Always flash via esptool without the RAM stub helper to avoid compressed-mode glitches.
PROJECT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${1:-/dev/tty.usbserial-0001}"

source /Users/stevie/Repos/INB306/esp-idf/export.sh
cd "${PROJECT_DIR}"

# Ensure ESP32 classic target
idf.py set-target esp32

# Build first so artifacts are fresh.
idf.py build

# Determine app bin path (fallback to project name 'mlkem-measurement')
APP_BIN="build/mlkem-measurement.bin"
if [[ -f build/project_description.json ]]; then
  # Try to extract app_bin path from JSON without jq
  maybe=$(sed -n 's/.*"app_bin"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' build/project_description.json | head -n1)
  if [[ -n "${maybe}" && -f "${maybe}" ]]; then
    APP_BIN="${maybe}"
  fi
fi

# Use esptool directly with --no-stub to avoid compressed-mode exit failures.
python -m esptool \
  --chip esp32 \
  --port "${PORT}" \
  --baud 115200 \
  --before default-reset \
  --after hard-reset \
  --no-stub \
  write-flash \
  --flash-mode dio \
  --flash-freq 40m \
    --flash-size 4MB \
  0x1000 build/bootloader/bootloader.bin \
  0x8000 build/partition_table/partition-table.bin \
  0x10000 "${APP_BIN}"
