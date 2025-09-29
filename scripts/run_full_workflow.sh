#!/usr/bin/env bash
# Orchestrates the full build → run → bridge → verify loop.

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

step() {
  printf '\n==> %s\n' "$1"
}

die() {
  echo "[error] $*" >&2
  exit 1
}

step "Building enclave artifacts"
"$SCRIPT_DIR/build_enclave.sh" || die "build failed"

step "Launching enclave"
"$SCRIPT_DIR/run_enclave.sh" || die "run failed"

step "Starting socat bridge"
SOCAT_LOG="$SOCAT_LOG_PATH"
mkdir -p "$(dirname "$SOCAT_LOG")"
# Run socat in the background so attestation can proceed
if "$SCRIPT_DIR/start_socat_bridge.sh" >>"$SOCAT_LOG" 2>&1 & then
  SOCAT_PID=$!
else
  die "failed to start socat bridge"
fi

cleanup() {
  if [[ -n "${SOCAT_PID:-}" ]] && kill -0 "$SOCAT_PID" >/dev/null 2>&1; then
    step "Stopping socat bridge"
    kill "$SOCAT_PID" >/dev/null 2>&1 || true
    wait "$SOCAT_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

# Give socat a moment to establish the listener
sleep 2

step "Verifying attestation"
"$SCRIPT_DIR/run_attestation_verifier.sh" || die "attestation verification failed"

step "Workflow completed successfully"
