# shellcheck shell=bash
# Default configuration values for the helper scripts. Copy to config.local.sh
# and override as needed.

# Repository layout
: "${ENCLAVE_WORKSPACE_ROOT:=${REPO_ROOT}/nsm-enclave-runner}"
: "${ATTESTATION_VERIFIER_ROOT:=${REPO_ROOT}/attestation-verifier}"
: "${ENCLAVE_ARTIFACT_DIR:=${ENCLAVE_WORKSPACE_ROOT}/target/enclave}"

# Build settings
: "${ENCLAVE_IMAGE_TAG:=enclave-runner:enclave}"
: "${NITRO_ROOT_BUNDLE_PATH:=${REPO_ROOT}/assets/aws-nitro-root.pem}"
: "${NITRO_ROOT_CERT_PATH:=${NITRO_ROOT_BUNDLE_PATH}}"
: "${NITRO_ROOT_CERT_DEST:=${ENCLAVE_ARTIFACT_DIR}/nitro-root.pem}"
: "${NITRO_ROOT_EXPECTED_FINGERPRINT:=64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B}"

# Runtime settings
: "${ENCLAVE_CPU_COUNT:=1}"
: "${ENCLAVE_MEMORY_MIB:=1024}"
: "${ATTESTATION_HOST:=127.0.0.1}"
: "${ATTESTATION_PORT:=8443}"
: "${ATTESTATION_PATH:=/attestation}"
: "${SOCAT_LOG_PATH:=${REPO_ROOT}/logs/socat.log}"
