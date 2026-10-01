use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{RuntimeError, RuntimeResult, executor::ExecutorOutput, validation};

pub const MAX_OPERATION_OUTPUT_BYTES: usize = 16 * 1024;

#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationOutputV1 {
    schema: String,
    content_type: String,
    payload: Zeroizing<Vec<u8>>,
    result_sha256: String,
    request_body_sha256: String,
    audience: String,
    expires_at_epoch_s: u64,
}

impl fmt::Debug for OperationOutputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperationOutputV1")
            .field("schema", &self.schema)
            .field("content_type", &self.content_type)
            .field("payload", &"[REDACTED]")
            .field("result_sha256", &self.result_sha256)
            .field("request_body_sha256", &self.request_body_sha256)
            .field("audience", &self.audience)
            .field("expires_at_epoch_s", &self.expires_at_epoch_s)
            .finish()
    }
}

impl OperationOutputV1 {
    pub(crate) fn bind(
        output: ExecutorOutput,
        body_sha256: &str,
        audience: &str,
        expires_at: u64,
        operation: &crate::CredentialOperationV1,
    ) -> RuntimeResult<Self> {
        let (schema, content_type, payload) = output.into_parts(operation)?;
        let result_sha256 = crate::canonical::operation_output_sha256(&payload);
        let value = Self {
            schema,
            content_type,
            payload,
            result_sha256,
            request_body_sha256: body_sha256.into(),
            audience: audience.into(),
            expires_at_epoch_s: expires_at,
        };
        value.validate()?;
        Ok(value)
    }

    pub(crate) fn validate(&self) -> RuntimeResult<()> {
        validation::schema(&self.schema)?;
        validation::content_type(&self.content_type)?;
        validation::digest(&self.result_sha256)?;
        validation::digest(&self.request_body_sha256)?;
        validation::component(&self.audience, 96)?;
        if self.payload.is_empty()
            || self.payload.len() > MAX_OPERATION_OUTPUT_BYTES
            || self.result_sha256 != crate::canonical::operation_output_sha256(&self.payload)
            || self.expires_at_epoch_s == 0
        {
            return Err(RuntimeError::Contract);
        }
        Ok(())
    }

    #[must_use]
    pub fn schema(&self) -> &str {
        &self.schema
    }
    #[must_use]
    pub fn content_type(&self) -> &str {
        &self.content_type
    }
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
    #[must_use]
    pub fn result_sha256(&self) -> &str {
        &self.result_sha256
    }
    #[must_use]
    pub fn request_body_sha256(&self) -> &str {
        &self.request_body_sha256
    }
    #[must_use]
    pub fn audience(&self) -> &str {
        &self.audience
    }
    #[must_use]
    pub const fn expires_at_epoch_s(&self) -> u64 {
        self.expires_at_epoch_s
    }
}
