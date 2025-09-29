#!/usr/bin/env bash
# Stops running enclaves, kills the socat bridge, and removes generated artifacts.

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
VERIFIER_ROOT="$ATTESTATION_VERIFIER_ROOT"
OUT_DIR="$ENCLAVE_ARTIFACT_DIR"
LOG_DIR="$(dirname "$SOCAT_LOG_PATH")"

step() {
  printf '\n==> %s\n' "$1"
}

stop_socat() {
  step "Stopping socat bridge if running"
  if pkill -f 'socat.*VSOCK-CONNECT' 2>/dev/null; then
    echo "Killed socat processes"
  else
    echo "No socat bridge detected"
  fi
}

stop_enclaves() {
  step "Terminating running enclaves"
  if nitro-cli terminate-enclave --all >/dev/null 2>&1; then
    echo "Terminated enclaves"
  else
    echo "No enclaves running or nitro-cli unavailable"
  fi
}

remove_generated() {
  step "Removing generated artifacts"
  rm -rf \
    "$OUT_DIR" \
    "$RUNNER_ROOT/target/debug" \
    "$RUNNER_ROOT/target/release" \
    "$VERIFIER_ROOT/target" \
    "$LOG_DIR"
}

stop_socat
stop_enclaves
remove_generated

step "Cleanup complete"
