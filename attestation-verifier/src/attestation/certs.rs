use crate::attestation::errors::AttnError;
use crate::attestation::util::{now_millis, sha256_fingerprint};
use anyhow::{anyhow, Context};
use ring::signature::{self, UnparsedPublicKey};
use rustls_pemfile as pemfile;
use std::collections::HashSet;
use std::io::Cursor;
use std::path::PathBuf;
use x509_parser::prelude::*;

/// Captured data for a single trusted root certificate.
pub struct RootMetadata {
    pub fingerprint: String,
    pub subject_raw: Vec<u8>,
    pub subject_display: String,
    pub der: Vec<u8>,
}

/// Trust store with metadata and quick fingerprint lookups.
pub struct RootStore {
    pub metadata: Vec<RootMetadata>,
    pub fingerprints: HashSet<String>,
}

/// Loads PEM-encoded roots from disk and filters them against an allow-list.
pub fn load_pinned_roots(
    paths: &[PathBuf],
    allow_fps: &HashSet<String>,
) -> anyhow::Result<RootStore> {
    let mut metadata = Vec::new();
    let mut fps = HashSet::new();

    for path in paths {
        let bytes = std::fs::read(path).with_context(|| format!("read {:?}", path))?;
        let mut cursor = Cursor::new(&bytes);
        let certs = pemfile::certs(&mut cursor)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow!("parse PEM in {:?}: {e:?}", path))?;
        for der in certs {
            let der_bytes = der.as_ref();
            let fp = sha256_fingerprint(der_bytes);
            if !allow_fps.is_empty() && !allow_fps.contains(&fp) {
                continue;
            }
            let (_, cert) = parse_x509_certificate(der_bytes)
                .map_err(|e| anyhow!("parse root certificate {:?}: {e}", path))?;
            metadata.push(RootMetadata {
                fingerprint: fp.clone(),
                subject_raw: cert.subject().as_raw().to_vec(),
                subject_display: format!("{}", cert.subject()),
                der: der_bytes.to_vec(),
            });
            fps.insert(fp);
        }
    }

    anyhow::ensure!(!metadata.is_empty(), "no roots loaded");

    Ok(RootStore {
        metadata,
        fingerprints: fps,
    })
}

/// Minimal certificate chain summary produced after validation.
pub struct ChainSummary {
    pub leaf_fingerprint: String,
    pub root_fingerprint: String,
    pub root_subject: String,
}

/// Validates the attestation leaf + intermediates against the pinned roots.
pub fn verify_chain(
    leaf_der: &[u8],
    intermediates: &[Vec<u8>],
    store: &RootStore,
) -> Result<ChainSummary, AttnError> {
    verify_manually(leaf_der, intermediates, store)
}

fn verify_manually(
    leaf_der: &[u8],
    intermediates: &[Vec<u8>],
    store: &RootStore,
) -> Result<ChainSummary, AttnError> {
    let (_, leaf_cert) = parse_x509_certificate(leaf_der)
        .map_err(|e| AttnError::ChainBuild(format!("parse leaf cert: {e}")))?;
    let now = (now_millis() / 1000) as i64;
    ensure_validity(&leaf_cert, now, "leaf")?;
    ensure_basic_constraints(&leaf_cert, false)?;

    let mut ordered: Vec<Vec<u8>> = Vec::with_capacity(1 + intermediates.len());
    ordered.push(leaf_der.to_vec());
    let mut remaining: Vec<Vec<u8>> = intermediates.to_vec();
    let mut issuer_raw = leaf_cert.tbs_certificate.issuer.as_raw().to_vec();

    for _ in 0..=remaining.len() {
        if let Some(root_meta) = find_root_by_subject(&issuer_raw, store) {
            return verify_signatures(ordered, remaining, store, root_meta, now);
        }

        let position = remaining.iter().position(|der| {
            parse_x509_certificate(der)
                .map(|(_, cert)| cert.tbs_certificate.subject.as_raw() == issuer_raw.as_slice())
                .unwrap_or(false)
        });

        let idx = match position {
            Some(i) => i,
            None => break,
        };

        let parent_der = remaining.swap_remove(idx);
        let (_, cert) = parse_x509_certificate(&parent_der).map_err(|e| {
            AttnError::ChainBuild(format!("parse intermediate certificate failed: {e}"))
        })?;
        ensure_validity(&cert, now, "intermediate")?;
        ensure_basic_constraints(&cert, true)?;
        issuer_raw = cert.tbs_certificate.issuer.as_raw().to_vec();
        ordered.push(parent_der);
    }

    let root_meta = find_root_by_subject(&issuer_raw, store).ok_or_else(|| {
        AttnError::ChainBuild("could not match attestation chain to trusted root".into())
    })?;

    verify_signatures(ordered, remaining, store, root_meta, now)
}

fn verify_signatures(
    ordered: Vec<Vec<u8>>,
    remaining: Vec<Vec<u8>>,
    store: &RootStore,
    root_meta: &RootMetadata,
    now: i64,
) -> Result<ChainSummary, AttnError> {
    if !remaining.is_empty() {
        return Err(AttnError::ChainBuild(
            "unused certificates left in cabundle".into(),
        ));
    }

    let (_, root_cert) = parse_x509_certificate(&root_meta.der)
        .map_err(|e| AttnError::ChainBuild(format!("parse root certificate: {e}")))?;

    let mut parent_subject_raw = root_cert.tbs_certificate.subject.as_raw().to_vec();
    let mut parent_pub_key = root_cert
        .tbs_certificate
        .subject_pki
        .subject_public_key
        .data
        .to_vec();

    for (idx, der) in ordered.iter().enumerate().rev() {
        let (_, cert) = parse_x509_certificate(der)
            .map_err(|e| AttnError::ChainBuild(format!("parse chain certificate: {e}")))?;
        let role = if idx == 0 { "leaf" } else { "intermediate" };
        ensure_validity(&cert, now, role)?;
        ensure_basic_constraints(&cert, idx != 0)?;

        if cert.tbs_certificate.issuer.as_raw() != parent_subject_raw.as_slice() {
            return Err(AttnError::ChainBuild(format!(
                "issuer mismatch (role={role})"
            )));
        }

        let algo_oid = &cert.signature_algorithm.algorithm;
        let alg = map_signature_oid(algo_oid).map_err(AttnError::ChainBuild)?;
        let verifier = UnparsedPublicKey::new(alg, &parent_pub_key);
        verifier
            .verify(
                cert.tbs_certificate.as_ref(),
                cert.signature_value.data.as_ref(),
            )
            .map_err(|_| {
                AttnError::ChainBuild(format!(
                    "certificate signature verification failed ({role})"
                ))
            })?;

        parent_subject_raw = cert.tbs_certificate.subject.as_raw().to_vec();
        parent_pub_key = cert
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .data
            .to_vec();
    }

    let leaf_fingerprint = sha256_fingerprint(ordered.first().expect("leaf exists").as_slice());

    if !store.fingerprints.contains(&root_meta.fingerprint) {
        return Err(AttnError::RootUntrusted);
    }

    Ok(ChainSummary {
        leaf_fingerprint,
        root_fingerprint: root_meta.fingerprint.clone(),
        root_subject: root_meta.subject_display.clone(),
    })
}

fn find_root_by_subject<'a>(subject_raw: &[u8], store: &'a RootStore) -> Option<&'a RootMetadata> {
    store
        .metadata
        .iter()
        .find(|meta| meta.subject_raw.as_slice() == subject_raw)
}

fn ensure_validity(cert: &X509Certificate<'_>, now: i64, label: &str) -> Result<(), AttnError> {
    let not_before = cert.validity().not_before.timestamp();
    let not_after = cert.validity().not_after.timestamp();
    if now < not_before || now > not_after {
        return Err(AttnError::ChainBuild(format!(
            "{label} certificate not valid at current time (nb={not_before} na={not_after} now={now})"
        )));
    }
    Ok(())
}

fn ensure_basic_constraints(cert: &X509Certificate<'_>, expect_ca: bool) -> Result<(), AttnError> {
    let bc = cert
        .basic_constraints()
        .map_err(|e| AttnError::ChainBuild(format!("basicConstraints parse error: {e}")))?;
    if expect_ca {
        let bc =
            bc.ok_or_else(|| AttnError::ChainBuild("missing basicConstraints on CA".into()))?;
        if !bc.value.ca {
            return Err(AttnError::ChainBuild(
                "certificate missing CA=true in basicConstraints".into(),
            ));
        }
    } else if let Some(bc) = bc {
        if bc.value.ca {
            return Err(AttnError::ChainBuild(
                "leaf certificate unexpectedly marked as CA".into(),
            ));
        }
    }

    let ku = cert
        .key_usage()
        .map_err(|e| AttnError::ChainBuild(format!("keyUsage parse error: {e}")))?;
    if expect_ca {
        let ku = ku.ok_or_else(|| AttnError::ChainBuild("missing keyUsage on CA".into()))?;
        if !ku.value.key_cert_sign() {
            return Err(AttnError::ChainBuild(
                "CA certificate missing keyCertSign usage".into(),
            ));
        }
    } else if let Some(ku) = ku {
        if ku.value.key_cert_sign() {
            return Err(AttnError::ChainBuild(
                "leaf certificate unexpectedly has keyCertSign usage".into(),
            ));
        }
    }

    Ok(())
}

fn map_signature_oid<'a>(
    oid: &x509_parser::der_parser::oid::Oid<'a>,
) -> Result<&'static dyn signature::VerificationAlgorithm, String> {
    let oid_str = oid.to_string();
    let alg: &'static dyn signature::VerificationAlgorithm = match oid_str.as_str() {
        "1.2.840.10045.4.3.2" => &signature::ECDSA_P256_SHA256_ASN1,
        "1.2.840.10045.4.3.3" => &signature::ECDSA_P384_SHA384_ASN1,
        "1.2.840.113549.1.1.11" => &signature::RSA_PKCS1_2048_8192_SHA256,
        "1.2.840.113549.1.1.12" => &signature::RSA_PKCS1_2048_8192_SHA384,
        "1.2.840.113549.1.1.13" => &signature::RSA_PKCS1_2048_8192_SHA512,
        other => {
            return Err(format!(
                "unsupported certificate signature algorithm OID {other}"
            ))
        }
    };
    Ok(alg)
}
