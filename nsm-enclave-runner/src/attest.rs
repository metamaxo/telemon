use anyhow::{anyhow, Result};
use aws_nitro_enclaves_nsm_api::api::{AttestationDoc, Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
use coset::{CborSerializable, CoseSign1, TaggedCborSerializable};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha512};
use std::collections::BTreeMap;

/// Material emitted by NSM plus derived metadata we expose to HTTP handlers.
pub struct NsmAttestationOut {
    /// Raw COSE_Sign1 document returned by the NSM driver.
    pub quote: Vec<u8>,
    /// Policy identifier for consumers (currently static).
    pub policy: String,
    /// Crate version embedded so verifiers know the producer.
    pub runner_version: String,
    /// Parsed representation of the attestation document.
    pub(crate) doc: internal::ParsedAttestationDoc,
}

/// Produces a fresh attestation document bound to the provided TLS SPKI and nonce.
///
/// This call must run inside an enclave (it talks to `/dev/nsm`). Validation is
/// performed on the inputs to avoid surprising driver errors, then the actual
/// driver interaction is moved onto a blocking thread to keep the async runtime
/// responsive.
pub async fn build_nsm_attestation(spki_der: &[u8], nonce: &[u8]) -> Result<NsmAttestationOut> {
    if !std::path::Path::new("/dev/nsm").exists() {
        return Err(anyhow!(
            "/dev/nsm not found — must run inside an AWS Nitro Enclave"
        ));
    }
    if spki_der.is_empty() {
        return Err(anyhow!("empty SPKI passed to build_nsm_attestation"));
    }
    if nonce.is_empty() || nonce.len() > 1024 {
        return Err(anyhow!("invalid nonce length"));
    }

    let spki = spki_der.to_vec();
    let nonce = nonce.to_vec();
    tokio::task::spawn_blocking(move || internal::get_doc_sync_driver(&spki, &nonce))
        .await
        .map_err(|e| anyhow!("spawn_blocking join error: {e}"))?
}

mod internal {
    use super::*;

    pub(crate) struct ParsedAttestationDoc {
        /// Module identifier expressed in the attestation payload.
        pub module_id: String,
        /// Digest algorithm used for the PCR bank (e.g. `SHA384`).
        pub digest: String,
        /// Timestamp emitted by NSM (milliseconds since Unix epoch).
        pub timestamp_ms: u64,
        /// Echoed nonce bound into the document.
        pub nonce: Vec<u8>,
        /// TLS SubjectPublicKeyInfo (DER) bound into the attestation.
        pub public_key: Vec<u8>,
        /// Optional user data blob returned by NSM.
        pub user_data: Option<Vec<u8>>,
        /// Attestation signing certificate DER.
        pub certificate: Vec<u8>,
        /// Intermediates/root certificates that complete the chain.
        pub cabundle: Vec<Vec<u8>>,
        /// PCR values keyed by PCR index.
        pub pcrs: BTreeMap<u32, Vec<u8>>,
    }

    /// Performs the synchronous NSM driver round-trip and parses the response.
    pub(super) fn get_doc_sync_driver(spki_der: &[u8], nonce: &[u8]) -> Result<NsmAttestationOut> {
        // Optional binding of SPKI+nonce in user_data for verifiers to recompute
        let mut h = Sha512::new();
        h.update(spki_der);
        h.update(nonce);
        let binding = h.finalize();

        let req = Request::Attestation {
            user_data: Some(ByteBuf::from(binding.to_vec())),
            nonce: Some(ByteBuf::from(nonce.to_vec())),
            public_key: Some(ByteBuf::from(spki_der.to_vec())),
        };

        let fd = nsm_init();
        if fd < 0 {
            return Err(anyhow!("nsm_init() failed (fd={fd})"));
        }

        let resp = nsm_process_request(fd, req);
        nsm_exit(fd);

        let quote = match resp {
            Response::Attestation { document } => document,
            Response::Error(e) => return Err(anyhow!("NSM returned error: {:?}", e)),
            other => return Err(anyhow!("unexpected NSM response: {:?}", other)),
        };

        if quote.is_empty() {
            return Err(anyhow!("attestation document is empty"));
        }

        let doc = parse_attestation_doc(&quote, spki_der, nonce)?;

        Ok(NsmAttestationOut {
            quote,
            policy: "aws-nitro-nsm".to_string(),
            runner_version: env!("CARGO_PKG_VERSION").to_string(),
            doc,
        })
    }

    /// Decodes the COSE/CBOR attestation payload and validates a few invariants.
    fn parse_attestation_doc(
        quote: &[u8],
        expected_spki: &[u8],
        expected_nonce: &[u8],
    ) -> Result<ParsedAttestationDoc> {
        let sign1 = CoseSign1::from_tagged_slice(quote)
            .or_else(|_| CoseSign1::from_slice(quote))
            .map_err(|e| anyhow!("parse NSM attestation as COSE_Sign1: {e:?}"))?;

        let payload = sign1
            .payload
            .as_ref()
            .ok_or_else(|| anyhow!("NSM attestation missing payload"))?
            .to_vec();

        let doc = AttestationDoc::from_binary(&payload)
            .map_err(|e| anyhow!("decode AttestationDoc payload: {e:?}"))?;

        let certificate = doc.certificate.to_vec();
        if certificate.is_empty() {
            return Err(anyhow!("attestation certificate missing"));
        }

        let cabundle: Vec<Vec<u8>> = doc.cabundle.iter().map(|c| c.to_vec()).collect();

        let nonce = doc
            .nonce
            .as_ref()
            .map(|n| n.to_vec())
            .ok_or_else(|| anyhow!("attestation nonce not present"))?;
        if nonce.as_slice() != expected_nonce {
            return Err(anyhow!("attestation nonce mismatch"));
        }

        let public_key = doc
            .public_key
            .as_ref()
            .map(|pk| pk.to_vec())
            .ok_or_else(|| anyhow!("attestation public_key field missing"))?;
        if public_key.as_slice() != expected_spki {
            return Err(anyhow!("attestation public_key mismatch"));
        }

        let mut pcrs = BTreeMap::new();
        for (idx, value) in doc.pcrs.iter() {
            pcrs.insert(*idx as u32, value.to_vec());
        }

        let digest = match doc.digest {
            aws_nitro_enclaves_nsm_api::api::Digest::SHA256 => "SHA256",
            aws_nitro_enclaves_nsm_api::api::Digest::SHA384 => "SHA384",
            aws_nitro_enclaves_nsm_api::api::Digest::SHA512 => "SHA512",
        };

        Ok(ParsedAttestationDoc {
            module_id: doc.module_id,
            digest: digest.to_string(),
            timestamp_ms: doc.timestamp,
            nonce,
            public_key,
            user_data: doc.user_data.as_ref().map(|u| u.to_vec()),
            certificate,
            cabundle,
            pcrs,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use aws_nitro_enclaves_nsm_api::api::Digest as AwsDigest;
        use coset::{CoseSign1Builder, HeaderBuilder};

        #[test]
        fn parse_attestation_doc_extracts_expected_fields() {
            let spki = vec![1u8, 2, 3, 4];
            let nonce = vec![5u8, 6, 7, 8];

            let mut pcrs = BTreeMap::new();
            pcrs.insert(0usize, vec![0xAB; 48]);
            pcrs.insert(1usize, vec![0xCD; 48]);

            let att_doc = AttestationDoc::new(
                "module-123".to_string(),
                AwsDigest::SHA384,
                1_700_000_000,
                pcrs.clone(),
                vec![0x01, 0x02, 0x03],
                vec![vec![0x04, 0x05]],
                Some(vec![0x99, 0x88]),
                Some(nonce.clone()),
                Some(spki.clone()),
            );
            let payload = att_doc.to_binary();

            let protected = HeaderBuilder::new()
                .algorithm(coset::iana::Algorithm::ES384)
                .build();

            let quote = CoseSign1Builder::new()
                .protected(protected)
                .payload(payload)
                .signature(vec![0u8; 96])
                .build()
                .to_tagged_vec()
                .expect("serialize cose");

            let parsed = parse_attestation_doc(&quote, &spki, &nonce).expect("parse doc");

            assert_eq!(parsed.module_id, "module-123");
            assert_eq!(parsed.digest, "SHA384");
            assert_eq!(parsed.timestamp_ms, 1_700_000_000);
            assert_eq!(parsed.nonce, nonce);
            assert_eq!(parsed.public_key, spki);
            assert_eq!(parsed.user_data.as_deref(), Some(&[0x99, 0x88][..]));
            assert_eq!(parsed.certificate, vec![0x01, 0x02, 0x03]);
            assert_eq!(parsed.cabundle, vec![vec![0x04, 0x05]]);
            assert_eq!(parsed.pcrs.get(&0), Some(&vec![0xAB; 48]));
            assert_eq!(parsed.pcrs.get(&1), Some(&vec![0xCD; 48]));
        }
    }
}
