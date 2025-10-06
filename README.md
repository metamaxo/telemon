# Nitro Enclave Workflow

This repository contains two major pieces:

- `nsm-enclave-runner`: the enclave application that serves attestation material
  over HTTPS.
- `attestation-verifier` (`nitro_verifier` crate): a reusable library + CLI for
  validating AWS Nitro Enclave attestation responses.

The scripts under `scripts/` orchestrate the full build → run → verify loop with
opinionated defaults so you can iterate quickly on a workstation.

## Prerequisites

Install the following on the parent instance:

- Docker with Nitro Enclaves support
- `nitro-cli` and the Nitro kernel modules (`sudo nitro-cli configure-enclave`)
- `jq`, `socat`, `curl`, and `sudo`

## Typical Flow

```bash
# One-command path (build → run → bridge → verify)
./scripts/run_full_workflow.sh

# Or, invoke the individual steps:
./scripts/build_enclave.sh
./scripts/run_enclave.sh
./scripts/start_socat_bridge.sh
./scripts/run_attestation_verifier.sh
# Optional:
./scripts/open_enclave_console.sh     # watch enclave serial console
./scripts/cleanup_workspace.sh        # stop socat/enclaves, remove build outputs
./scripts/purge_workspace.sh          # stop helpers and delete unpacked repo contents
```

All generated artifacts (EIF, measurements, PCR policy JSON, Nitro root cert,
run metadata) live under `nsm-enclave-runner/target/enclave/` for easy archival
or external tooling.

## Configuration

The scripts load opinionated defaults from `scripts/config.defaults.sh`. To
customize them, copy the file to `scripts/config.local.sh` and adjust values
there (the local file is ignored by git). Any environment variable you export
before running a script also overrides the defaults.

Key script toggles include:

- `ENCLAVE_IMAGE_TAG`: Docker tag used when building the enclave image.
- `ENCLAVE_CPU_COUNT` / `ENCLAVE_MEMORY_MIB`: resources passed to `nitro-cli run-enclave`.
- `ATTESTATION_HOST`, `ATTESTATION_PORT`, `ATTESTATION_PATH`: where the host fetches attestation material.
- `SOCAT_LOG_PATH`: location for bridge logs.
- `NITRO_ROOT_EXPECTED_FINGERPRINT`, `NITRO_ROOT_CERT_PATH`: trust anchors used during attestation verification.

The enclave binary itself is configured via `RUNNER_*` variables (see
`nsm-enclave-runner/.env.example`). Relevant knobs:

- `RUNNER_PUBLIC_ADDR`: vsock port exposed for RA-TLS (IP portion is ignored inside the enclave).
- `RUNNER_LOG_LEVEL`: default tracing filter (falls back to `info`).

### RA-TLS workflow

- Each RA-TLS connection receives an ephemeral certificate containing a custom extension with the attestation payload.
- The helper scripts expose the same bundle at `/.well-known/ratls` so clients can staple attestation data observed during TLS setup.
- Legacy TLS listeners and mixed-mode fallbacks have been removed; every request is served over RA-TLS by default.

### Parent-instance bridge

The runner exposes RA-TLS over vsock inside the enclave. To make that reachable
from tooling on the parent instance:

1. Start an enclave (`./scripts/run_enclave.sh`) so `nitro-cli` reports the new
   CID in `nsm-enclave-runner/target/enclave/enclave-run.json`.
2. Forward TCP traffic from the parent to the enclave port using
   `./scripts/start_socat_bridge.sh`. The script reuses `ATTESTATION_PORT` and
   pipes TCP ↔ VSOCK for you.
3. Point verifiers at `https://127.0.0.1:${ATTESTATION_PORT}`. The helper will
   translate connections to the enclave's `RUNNER_PUBLIC_ADDR` port.

## Verifier Library Usage

The `attestation-verifier` crate exposes `nitro_verifier::attestation`, which you
can embed in other projects. Minimal example:

```rust
use nitro_verifier::attestation::{Verifier, VerifierConfig};
use std::time::Duration;

let mut cfg = VerifierConfig::default();
cfg.root_pem_paths.push("assets/aws-nitro-root.pem".into());
cfg.freshness = Duration::from_secs(300);
// populate cfg.expected_pcrs / expected_measurement as needed

let verifier = Verifier::new(cfg)?;
let response_body = /* JSON from /attestation */;
let expected_nonce = "...base64 nonce...";
let attn = verifier.verify_json(&response_body, expected_nonce)?;
println!("module {} attested with root {}", attn.module_id, attn.root_fingerprint_sha256);

// When performing RA-TLS verification, compare the attestation bundle against the
// observed peer certificate:
let peer_cert_der = /* DER bytes from the TLS handshake */;
let attn = verifier.verify_ratls(&peer_cert_der, &response_body, expected_nonce)?;
```

The CLI located in `attestation-verifier/src/main.rs` is built on top of this
API and remains the quickest way to validate responses produced by the helper
scripts.

## Project Layout

- `nsm-enclave-runner/`: enclave runtime, REST API, Docker context
- `attestation-verifier/`: verifier crate + CLI (exposes `nitro_verifier::attestation`)
- `scripts/`: orchestration helpers (`run_full_workflow`, cleanup/purge, etc.)
- `assets/`: bundled Nitro root certificate and related static assets
