use std::fmt;

use crowsi_credential_broker::CredentialReferenceV1;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{CredentialOperationV1, IdentityBindingV1};
use crate::{RuntimeError, RuntimeResult, validation};

pub const USE_REQUEST_SCHEMA: &str = "crowsi://credential-runtime/use-request/v1";

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UseRequestV1 {
    schema: String,
    request_id: String,
    binding: IdentityBindingV1,
    credential: CredentialReferenceV1,
    audience: String,
    host: String,
    ttl_seconds: u64,
    operation_input_schema: String,
    operation_input: Zeroizing<Vec<u8>>,
    operation_body_sha256: String,
    operation: CredentialOperationV1,
}

impl fmt::Debug for UseRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UseRequestV1([REDACTED])")
    }
}

impl UseRequestV1 {
    #[allow(clippy::too_many_arguments)]
    /// # Errors
    ///
    /// Rejects invalid scope, binding, host, input, operation, or lease fields.
    pub fn new(
        request_id: &str,
        binding: IdentityBindingV1,
        credential: CredentialReferenceV1,
        audience: &str,
        host: &str,
        ttl_seconds: u64,
        operation_input_schema: &str,
        operation_input: Vec<u8>,
        operation: CredentialOperationV1,
    ) -> RuntimeResult<Self> {
        Self {
            schema: USE_REQUEST_SCHEMA.into(),
            request_id: request_id.into(),
            binding,
            credential,
            audience: audience.into(),
            host: host.into(),
            ttl_seconds,
            operation_input_schema: operation_input_schema.into(),
            operation_body_sha256: crate::canonical::operation_input_sha256(&operation_input),
            operation_input: Zeroizing::new(operation_input),
            operation,
        }
        .validated()
    }

    pub(crate) fn validated(self) -> RuntimeResult<Self> {
        if self.schema != USE_REQUEST_SCHEMA || !(1..=300).contains(&self.ttl_seconds) {
            return Err(RuntimeError::Contract);
        }
        validation::component(&self.request_id, 96)?;
        validation::component(&self.audience, 96)?;
        validation::schema(&self.operation_input_schema)?;
        validation::digest(&self.operation_body_sha256)?;
        if self.operation_input.is_empty()
            || self.operation_input.len() > 32 * 1024
            || self.operation_body_sha256
                != crate::canonical::operation_input_sha256(&self.operation_input)
        {
            return Err(RuntimeError::Contract);
        }
        let reference = self
            .credential
            .to_secret_ref()
            .map_err(|_| RuntimeError::Contract)?;
        if reference.scope().audience() != self.audience {
            return Err(RuntimeError::AudienceMismatch);
        }
        crowsi_credential_broker::AccessRequest::new(
            reference,
            &self.audience,
            &self.host,
            self.ttl_seconds,
        )?;
        self.binding.clone().validated()?;
        self.operation.clone().validated()?;
        Ok(self)
    }

    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }
    #[must_use]
    pub fn binding(&self) -> &IdentityBindingV1 {
        &self.binding
    }
    #[must_use]
    pub fn credential(&self) -> &CredentialReferenceV1 {
        &self.credential
    }
    #[must_use]
    pub fn audience(&self) -> &str {
        &self.audience
    }
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }
    #[must_use]
    pub const fn ttl_seconds(&self) -> u64 {
        self.ttl_seconds
    }
    #[must_use]
    pub fn operation_input_schema(&self) -> &str {
        &self.operation_input_schema
    }
    #[must_use]
    pub fn operation_input(&self) -> &[u8] {
        &self.operation_input
    }
    #[must_use]
    pub fn operation_body_sha256(&self) -> &str {
        &self.operation_body_sha256
    }
    #[must_use]
    pub const fn operation(&self) -> &CredentialOperationV1 {
        &self.operation
    }
}
