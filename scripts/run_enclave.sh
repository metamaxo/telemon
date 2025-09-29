#!/usr/bin/env bash
# Terminates any running enclaves and launches a fresh instance from the built EIF.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_DEFAULTS="$SCRIPT_DIR/config.defaults.sh"
CONFIG_LOCAL="$SCRIPT_DIR/config.local.sh"

# shellcheck source=./config.defaults.sh
source "$CONFIG_DEFAULTS"
if [[ -f "$CONFIG_LOCAL" ]]; then
  # shellcheck source=./config.local.sh
  source "$CONFIG_LOCAL"
fi

RUNNER_ROOT="$ENCLAVE_WORKSPACE_ROOT"
OUT_DIR="$ENCLAVE_ARTIFACT_DIR"
EIF_PATH="$OUT_DIR/enclave-runner.eif"
RUN_INFO_PATH="$OUT_DIR/enclave-run.json"
CPU_COUNT="$ENCLAVE_CPU_COUNT"
MEMORY_MIB="$ENCLAVE_MEMORY_MIB"

if [[ ! -f "$EIF_PATH" ]]; then
  echo "Enclave EIF not found at $EIF_PATH. Run scripts/build_enclave.sh first." >&2
  exit 1
fi

sudo nitro-cli terminate-enclave --all >/dev/null 2>&1 || true

RUN_OUTPUT=$(sudo nitro-cli run-enclave \
  --eif-path "$EIF_PATH" \
  --cpu-count "$CPU_COUNT" \
  --memory "$MEMORY_MIB")

echo "$RUN_OUTPUT" | jq '.'

echo "$RUN_OUTPUT" > "$RUN_INFO_PATH"

ENCLAVE_ID=$(echo "$RUN_OUTPUT" | jq -r '.EnclaveID')
ENCLAVE_CID=$(echo "$RUN_OUTPUT" | jq -r '.EnclaveCID')

printf '\nEnclave started.\n  EnclaveID: %s\n  EnclaveCID: %s\n' "$ENCLAVE_ID" "$ENCLAVE_CID"
