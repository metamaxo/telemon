#!/usr/bin/env bash
# Forcefully remove the unpacked workspace plus generated artifacts, resetting to a pristine state.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

step() {
  printf '\n==> %s\n' "$1"
}

stop_socat() {
  step "Stopping socat bridge if running"
  pkill -f 'socat.*VSOCK-CONNECT' 2>/dev/null && echo "Killed socat" || echo "No socat bridge detected"
}

stop_enclaves() {
  step "Terminating running enclaves"
  nitro-cli terminate-enclave --all >/dev/null 2>&1 && echo "Terminated enclaves" || echo "No enclaves running or nitro-cli unavailable"
}

remove_workspace() {
  step "Purging workspace contents"
  rm -rf \
    "$REPO_ROOT/README.md" \
    "$REPO_ROOT/tg-client.tar.gz" \
    "$REPO_ROOT/attestation-verifier" \
    "$REPO_ROOT/nsm-enclave-runner" \
    "$REPO_ROOT/assets" \
    "$REPO_ROOT/scripts"
}

stop_socat
stop_enclaves
remove_workspace

echo "\nRemaining contents:"
ls -a "$REPO_ROOT"
