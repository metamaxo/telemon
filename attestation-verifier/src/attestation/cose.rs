use crate::attestation::errors::AttnError;
use base64::engine::general_purpose::STANDARD as b64;
use base64::Engine;
use coset::{CborSerializable, CoseSign1, TaggedCborSerializable};
use hex;
use ring::signature::{self, UnparsedPublicKey};
use serde_cbor::Value as CborValue;
use std::collections::HashMap;

#[derive(Debug)]
/// Decoded payload extracted from the COSE_Sign1 attestation document.
pub struct ParsedCose {
    pub nonce: Vec<u8>,
    pub public_key: Vec<u8>,
    pub user_data: Option<Vec<u8>>,
    pub module_id: String,
    pub digest: String,
    pub timestamp_ms: u64,
    pub pcrs: HashMap<String, Vec<u8>>,
}

/// Validates the COSE signature using the attestation leaf public key and
/// returns the parsed CBOR payload.
pub fn verify_quote(quote_b64: &str, leaf_public_key: &[u8]) -> Result<ParsedCose, AttnError> {
    let quote = b64
        .decode(quote_b64.as_bytes())
        .map_err(|e| AttnError::Decode(format!("quote_b64: {e}")))?;

    let sign1 = CoseSign1::from_tagged_slice(&quote)
        .or_else(|_| CoseSign1::from_slice(&quote))
        .map_err(|e| AttnError::CoseInvalid(format!("parse COSE_Sign1: {e:?}")))?;

    let alg = sign1
        .protected
        .header
        .alg
        .as_ref()
        .ok_or_else(|| AttnError::CoseInvalid("missing COSE alg".into()))?;

    let (ring_alg, expected_sig_len) = match alg {
        coset::Algorithm::Assigned(coset::iana::Algorithm::ES256) => {
            (&signature::ECDSA_P256_SHA256_FIXED, 64)
        }
        coset::Algorithm::Assigned(coset::iana::Algorithm::ES384) => {
            (&signature::ECDSA_P384_SHA384_FIXED, 96)
        }
        other => {
            return Err(AttnError::CoseInvalid(format!(
                "unsupported COSE alg: {:?}",
                other
            )))
        }
    };

    let unparsed = UnparsedPublicKey::new(ring_alg, leaf_public_key);
    sign1
        .verify_signature(&[], |sig, data| {
            let raw = normalize_ecdsa_signature(sig, expected_sig_len)
                .map_err(|e| AttnError::CoseInvalid(e))?;
            unparsed
                .verify(data, &raw)
                .map_err(|_| AttnError::CoseInvalid("ring verification failed".into()))
        })
        .map_err(|e| {
            AttnError::CoseInvalid(format!("COSE signature verification failed: {e:?}"))
        })?;

    let payload_bytes = sign1
        .payload
        .as_ref()
        .ok_or_else(|| AttnError::CoseInvalid("missing COSE payload".into()))?;

    let payload: CborValue = serde_cbor::from_slice(payload_bytes)
        .map_err(|e| AttnError::CoseInvalid(format!("decode CBOR payload: {e}")))?;

    let fields = extract_fields(&payload)?;

    Ok(ParsedCose {
        nonce: fields.nonce,
        public_key: fields.public_key,
        user_data: fields.user_data,
        module_id: fields.module_id,
        digest: fields.digest,
        timestamp_ms: fields.timestamp_ms,
        pcrs: fields.pcrs,
    })
}

struct PayloadFields {
    nonce: Vec<u8>,
    public_key: Vec<u8>,
    user_data: Option<Vec<u8>>,
    module_id: String,
    digest: String,
    timestamp_ms: u64,
    pcrs: HashMap<String, Vec<u8>>,
}

fn extract_fields(payload: &CborValue) -> Result<PayloadFields, AttnError> {
    let map = match payload {
        CborValue::Map(m) => m,
        _ => return Err(AttnError::CoseInvalid("payload is not a map".into())),
    };

    let mut nonce = None;
    let mut public_key = None;
    let mut user_data = None;
    let mut module_id = None;
    let mut digest = None;
    let mut timestamp = None;
    let mut pcrs: HashMap<String, Vec<u8>> = HashMap::new();

    for (key, value) in map {
        if let Some(name) = key_as_string(key) {
            match name.as_str() {
                "nonce" => nonce = Some(bytes_from_value(value, "nonce")?),
                "public_key" => public_key = Some(bytes_from_value(value, "public_key")?),
                "user_data" => user_data = Some(bytes_from_value(value, "user_data")?),
                "module_id" => module_id = Some(string_from_value(value, "module_id")?),
                "digest" => digest = Some(string_from_value(value, "digest")?),
                "timestamp" => timestamp = Some(int_from_value(value, "timestamp")?),
                "pcrs" => {
                    pcrs = pcr_map_from_value(value)?;
                }
                _ => {}
            }
        }
    }

    Ok(PayloadFields {
        nonce: nonce.ok_or_else(|| AttnError::CoseInvalid("nonce missing".into()))?,
        public_key: public_key
            .ok_or_else(|| AttnError::CoseInvalid("public_key missing".into()))?,
        user_data,
        module_id: module_id.ok_or_else(|| AttnError::CoseInvalid("module_id missing".into()))?,
        digest: digest.ok_or_else(|| AttnError::CoseInvalid("digest missing".into()))?,
        timestamp_ms: timestamp
            .ok_or_else(|| AttnError::CoseInvalid("timestamp missing".into()))?,
        pcrs,
    })
}

fn key_as_string(key: &CborValue) -> Option<String> {
    match key {
        CborValue::Text(s) => Some(s.clone()),
        CborValue::Integer(i) => Some(i.to_string()),
        CborValue::Bytes(b) => Some(hex::encode(b)),
        _ => None,
    }
}

fn bytes_from_value(value: &CborValue, field: &str) -> Result<Vec<u8>, AttnError> {
    match value {
        CborValue::Bytes(b) => Ok(b.clone()),
        other => Err(AttnError::CoseInvalid(format!(
            "{field} expected bytes, got {:?}",
            other
        ))),
    }
}

fn string_from_value(value: &CborValue, field: &str) -> Result<String, AttnError> {
    match value {
        CborValue::Text(s) => Ok(s.clone()),
        other => Err(AttnError::CoseInvalid(format!(
            "{field} expected text, got {:?}",
            other
        ))),
    }
}

fn int_from_value(value: &CborValue, field: &str) -> Result<u64, AttnError> {
    match value {
        CborValue::Integer(i) if *i >= 0 => Ok(*i as u64),
        other => Err(AttnError::CoseInvalid(format!(
            "{field} expected non-negative integer, got {:?}",
            other
        ))),
    }
}

fn pcr_map_from_value(value: &CborValue) -> Result<HashMap<String, Vec<u8>>, AttnError> {
    let entries = match value {
        CborValue::Map(m) => m,
        other => {
            return Err(AttnError::CoseInvalid(format!(
                "pcrs expected map, got {:?}",
                other
            )))
        }
    };
    let mut out = HashMap::with_capacity(entries.len());
    for (k, v) in entries {
        let key = key_as_string(k)
            .ok_or_else(|| AttnError::CoseInvalid("pcrs key not convertible to string".into()))?;
        let value_bytes = bytes_from_value(v, "pcr value")?;
        out.insert(key, value_bytes);
    }
    Ok(out)
}

/// Accepts either raw fixed-width signatures or DER-encoded ones and normalises to raw.
fn normalize_ecdsa_signature(sig: &[u8], expected_len: usize) -> Result<Vec<u8>, String> {
    if sig.len() == expected_len {
        return Ok(sig.to_vec());
    }
    if sig.len() < 8 || sig.first() != Some(&0x30) {
        return Err(format!(
            "unexpected ECDSA signature format (len={})",
            sig.len()
        ));
    }
    let total_len = sig[1] as usize;
    if total_len + 2 != sig.len() {
        return Err(format!(
            "DER signature length mismatch (declared={}, actual={})",
            total_len,
            sig.len()
        ));
    }
    let mut idx = 2;
    let r = der_read_int(sig, &mut idx, expected_len / 2)?;
    let s = der_read_int(sig, &mut idx, expected_len / 2)?;
    if idx != sig.len() {
        return Err("unexpected trailing data in DER signature".into());
    }
    let mut out = Vec::with_capacity(expected_len);
    out.extend_from_slice(&r);
    out.extend_from_slice(&s);
    Ok(out)
}

fn der_read_int(sig: &[u8], idx: &mut usize, part_len: usize) -> Result<Vec<u8>, String> {
    if *idx >= sig.len() || sig[*idx] != 0x02 {
        return Err("expected INTEGER tag in DER signature".into());
    }
    *idx += 1;
    if *idx >= sig.len() {
        return Err("incomplete DER length".into());
    }
    let mut len = sig[*idx] as usize;
    *idx += 1;
    if len & 0x80 != 0 {
        let bytes = len & 0x7F;
        if bytes == 0 || bytes > 2 || *idx + bytes > sig.len() {
            return Err("unsupported DER length encoding".into());
        }
        len = 0;
        for _ in 0..bytes {
            len = (len << 8) | sig[*idx] as usize;
            *idx += 1;
        }
    }
    if *idx + len > sig.len() {
        return Err("DER INTEGER overruns signature buffer".into());
    }
    let mut value = &sig[*idx..*idx + len];
    *idx += len;
    while !value.is_empty() && value[0] == 0 {
        value = &value[1..];
    }
    if value.len() > part_len {
        return Err(format!(
            "DER INTEGER too large (len={}, expected <= {})",
            value.len(),
            part_len
        ));
    }
    let mut out = vec![0u8; part_len];
    let start = part_len - value.len();
    out[start..].copy_from_slice(value);
    Ok(out)
}
