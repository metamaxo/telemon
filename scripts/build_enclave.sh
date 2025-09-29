#!/usr/bin/env bash
# Builds the enclave runner container image and corresponding EIF artifact.

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
DOCKERFILE="$RUNNER_ROOT/Dockerfile.enclave"
IMAGE_TAG="$ENCLAVE_IMAGE_TAG"
EIF_PATH="$OUT_DIR/enclave-runner.eif"
MEASUREMENTS_PATH="$OUT_DIR/enclave-runner-measurements.json"
PCRS_PATH="$OUT_DIR/enclave-runner-expected-pcrs.json"
BUNDLED_ROOT_CERT="$NITRO_ROOT_BUNDLE_PATH"
ROOT_CERT_DEST="$NITRO_ROOT_CERT_DEST"
EXPECTED_ROOT_FINGERPRINT="$NITRO_ROOT_EXPECTED_FINGERPRINT"

if [[ ! -f "$BUNDLED_ROOT_CERT" ]]; then
  echo "Bundled Nitro root certificate missing at $BUNDLED_ROOT_CERT" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

printf '==> Building enclave image (%s)\n' "$IMAGE_TAG"
docker build -f "$DOCKERFILE" -t "$IMAGE_TAG" "$RUNNER_ROOT"

printf '==> Building EIF (%s)\n' "$EIF_PATH"
sudo nitro-cli build-enclave \
  --docker-uri "$IMAGE_TAG" \
  --output-file "$EIF_PATH"

DESC_JSON="$(sudo nitro-cli describe-eif --eif-path "$EIF_PATH")"
printf '%s\n' "$DESC_JSON" | jq '.' > "$MEASUREMENTS_PATH"
printf '%s\n' "$DESC_JSON" | jq '{
  pcr0: .Measurements.PCR0,
  pcr1: .Measurements.PCR1,
  pcr2: .Measurements.PCR2,
  hash_algorithm: .Measurements.HashAlgorithm
}' > "$PCRS_PATH"

printf '==> Staging bundled Nitro root certificate to %s\n' "$ROOT_CERT_DEST"
cp "$BUNDLED_ROOT_CERT" "$ROOT_CERT_DEST"

fingerprint=$(openssl x509 -noout -fingerprint -sha256 -in "$ROOT_CERT_DEST" | cut -d'=' -f2)
printf '==> Nitro root SHA-256 fingerprint: %s\n' "$fingerprint"

if [[ -n "$EXPECTED_ROOT_FINGERPRINT" && "$fingerprint" != "$EXPECTED_ROOT_FINGERPRINT" ]]; then
  echo "Fingerprint mismatch! Expected $EXPECTED_ROOT_FINGERPRINT" >&2
  exit 1
fi

printf '\nArtifacts written to %s:\n' "$OUT_DIR"
ls -1 "$OUT_DIR"
