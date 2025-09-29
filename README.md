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

Key toggles include:

- `ENCLAVE_IMAGE_TAG`: Docker tag used when building the enclave image.
- `ENCLAVE_CPU_COUNT` / `ENCLAVE_MEMORY_MIB`: resources passed to `nitro-cli run-enclave`.
- `ATTESTATION_HOST`, `ATTESTATION_PORT`, `ATTESTATION_PATH`: where the host fetches attestation material.
- `SOCAT_LOG_PATH`: location for bridge logs.
- `NITRO_ROOT_EXPECTED_FINGERPRINT`, `NITRO_ROOT_CERT_PATH`: trust anchors used during attestation verification.

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
```

The CLI located in `attestation-verifier/src/main.rs` is built on top of this
API and remains the quickest way to validate responses produced by the helper
scripts.

## Project Layout

- `nsm-enclave-runner/`: enclave runtime, REST API, Docker context
- `attestation-verifier/`: verifier crate + CLI (exposes `nitro_verifier::attestation`)
- `scripts/`: orchestration helpers (`run_full_workflow`, cleanup/purge, etc.)
- `assets/`: bundled Nitro root certificate and related static assets
# telemon
