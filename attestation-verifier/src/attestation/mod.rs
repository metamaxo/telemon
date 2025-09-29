pub mod config;
pub mod errors;
pub mod types;
pub mod verifier;

mod certs;
mod cose;
mod pcr;
mod util;

pub use config::VerifierConfig;
pub use errors::AttnError;
pub use types::{AttestationBlock, AttestationEnvelope, VerifiedAttestation};
pub use verifier::Verifier;
