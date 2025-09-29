#!/usr/bin/env bash
# Fetches the Nitro attestation root certificate from the running enclave service.

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

OUTPUT_PATH="$NITRO_ROOT_BUNDLE_PATH"
ATTESTATION_URL="https://${ATTESTATION_HOST}:${ATTESTATION_PORT}${ATTESTATION_PATH}"

for bin in curl jq python3 base64 openssl; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "\"$bin\" is required but not installed" >&2
    exit 1
  fi
done

mkdir -p "$(dirname "$OUTPUT_PATH")"

nonce=$(python3 - <<'PY'
import os, base64
print(base64.b64encode(os.urandom(32)).decode())
PY
)

echo "Requesting attestation document from $ATTESTATION_URL"
response=$(curl -sS -k -X POST \
  -H 'content-type: application/json' \
  --data "{\"nonce_b64\": \"$nonce\"}" \
  "$ATTESTATION_URL")

if [[ -z "$response" ]]; then
  echo "Empty response from attestation endpoint" >&2
  exit 1
fi

root_b64=$(printf '%s' "$response" | jq -r '.attestation.cabundle_der_b64 | last // empty')

if [[ -z "$root_b64" ]]; then
  echo "Could not extract root certificate from attestation response" >&2
  exit 1
fi

tmp_cert=$(mktemp)
trap 'rm -f "$tmp_cert"' EXIT

printf '%s' "$root_b64" | base64 -d > "$tmp_cert"

openssl x509 -in "$tmp_cert" -noout >/dev/null 2>&1 || {
  echo "Downloaded data is not a valid X.509 certificate" >&2
  exit 1
}

mv "$tmp_cert" "$OUTPUT_PATH"

fingerprint=$(openssl x509 -in "$OUTPUT_PATH" -noout -fingerprint -sha256 | cut -d'=' -f2)

echo "Saved root certificate to $OUTPUT_PATH"
echo "SHA-256 fingerprint: $fingerprint"
