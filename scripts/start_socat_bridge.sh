#!/usr/bin/env bash
# Forwards the configured attestation TCP port to the enclave's VSOCK port via socat.

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
PORT="$ATTESTATION_PORT"

if [[ ! -f "$RUN_INFO_PATH" ]]; then
  echo "Run info not found at $RUN_INFO_PATH. Start an enclave first." >&2
  exit 1
fi

CID=$(jq -r '.EnclaveCID' "$RUN_INFO_PATH")

if [[ -z "$CID" || "$CID" == "null" ]]; then
  echo "Could not read EnclaveCID from $RUN_INFO_PATH" >&2
  exit 1
fi

sudo socat -d -d -v TCP-LISTEN:${PORT},reuseaddr,fork VSOCK-CONNECT:${CID}:${PORT}
