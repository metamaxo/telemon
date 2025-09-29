#!/usr/bin/env bash
# Runs the attestation verifier against the enclave's public endpoint.

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
ROOT_CERT_PATH="$NITRO_ROOT_CERT_PATH"

export NITRO_MEASUREMENTS_PATH="$OUT_DIR/enclave-runner-measurements.json"
export NITRO_EXPECTED_PCRS_PATH="$OUT_DIR/enclave-runner-expected-pcrs.json"

if [[ ! -f "$ROOT_CERT_PATH" ]]; then
  echo "Nitro root certificate missing at $ROOT_CERT_PATH. Adjust scripts/config.local.sh or restore the file." >&2
  exit 1
fi

unset NITRO_ROOT_PEM_PATH || true

cargo run --manifest-path "$VERIFIER_ROOT/Cargo.toml" -- "$ROOT_CERT_PATH"
