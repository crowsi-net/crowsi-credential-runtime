use sha2::{Digest, Sha256};

use crate::{RuntimeError, RuntimeResult, UseRequestV1};

/// # Errors
///
/// Rejects a request that cannot be normalized as the closed v1 contract.
pub fn credential_use_body_sha256(request: &UseRequestV1) -> RuntimeResult<String> {
    let normalized = request.clone().validated()?;
    let encoded = serde_json::to_vec(&normalized).map_err(|_| RuntimeError::Contract)?;
    Ok(domain_digest(
        b"crowsi:credential-runtime-use-body:v1\0",
        &encoded,
    ))
}

pub(crate) fn operation_output_sha256(payload: &[u8]) -> String {
    domain_digest(b"crowsi:credential-runtime-output:v1\0", payload)
}

pub(crate) fn operation_input_sha256(payload: &[u8]) -> String {
    domain_digest(b"crowsi:credential-runtime-operation-input:v1\0", payload)
}

pub(crate) fn identity_digest(domain: &[u8], value: &str) -> String {
    domain_digest(domain, value.as_bytes())
}

fn domain_digest(domain: &[u8], value: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(value);
    format!("sha256:{:x}", hasher.finalize())
}
