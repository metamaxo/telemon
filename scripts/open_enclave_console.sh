#!/usr/bin/env bash
# Attach to the console of the most recently launched enclave.

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
RUN_INFO_PATH="$ENCLAVE_ARTIFACT_DIR/enclave-run.json"

if [[ ! -f "$RUN_INFO_PATH" ]]; then
  echo "Run info not found at $RUN_INFO_PATH. Start an enclave first." >&2
  exit 1
fi

ENCLAVE_ID=$(jq -r '.EnclaveID' "$RUN_INFO_PATH")

if [[ -z "$ENCLAVE_ID" || "$ENCLAVE_ID" == "null" ]]; then
  echo "Could not read EnclaveID from $RUN_INFO_PATH" >&2
  exit 1
fi

sudo nitro-cli console --enclave-id "$ENCLAVE_ID"
