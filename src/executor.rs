use crowsi_credential_broker::SecretValue;
use zeroize::Zeroizing;

use crate::{CredentialOperationV1, IdentityBindingV1, RuntimeError, RuntimeResult, validation};

pub struct ExecutorOutput {
    value: ExecutorOutputValue,
}

enum ExecutorOutputValue {
    Completed,
    Derived {
        schema: String,
        content_type: String,
        payload: Zeroizing<Vec<u8>>,
    },
}

impl ExecutorOutput {
    #[must_use]
    pub const fn completed() -> Self {
        Self {
            value: ExecutorOutputValue::Completed,
        }
    }

    /// # Errors
    ///
    /// Rejects an invalid schema, content type, or oversized/empty output.
    pub fn derived(schema: &str, content_type: &str, payload: Vec<u8>) -> RuntimeResult<Self> {
        validation::schema(schema)?;
        validation::content_type(content_type)?;
        if payload.is_empty() || payload.len() > crate::contract::MAX_OPERATION_OUTPUT_BYTES {
            return Err(RuntimeError::Contract);
        }
        Ok(Self {
            value: ExecutorOutputValue::Derived {
                schema: schema.into(),
                content_type: content_type.into(),
                payload: Zeroizing::new(payload),
            },
        })
    }

    pub(crate) fn into_parts(
        self,
        operation: &CredentialOperationV1,
    ) -> RuntimeResult<(String, String, Zeroizing<Vec<u8>>)> {
        match (self.value, operation) {
            (
                ExecutorOutputValue::Completed,
                CredentialOperationV1::BearerHeader { .. }
                | CredentialOperationV1::OpaqueSecret { .. },
            ) => Ok((
                "crowsi://credential-runtime/operation-completed/v1".into(),
                "application/json".into(),
                Zeroizing::new(br#"{"status":"applied"}"#.to_vec()),
            )),
            (
                ExecutorOutputValue::Derived {
                    schema,
                    content_type,
                    payload,
                },
                CredentialOperationV1::Sign { .. },
            ) if operation.expected_output_schema() == Some(schema.as_str()) => {
                Ok((schema, content_type, payload))
            }
            _ => Err(RuntimeError::OperationRejected),
        }
    }

    pub(crate) fn exposes(&self, secret: &[u8]) -> bool {
        match &self.value {
            ExecutorOutputValue::Completed => false,
            ExecutorOutputValue::Derived { payload, .. } => {
                !secret.is_empty() && payload.windows(secret.len()).any(|part| part == secret)
            }
        }
    }
}

/// Metadata available to one registered, trusted operation adapter.
pub struct CredentialOperationContext<'a> {
    pub(crate) request_id: &'a str,
    pub(crate) credential_ref: &'a str,
    pub(crate) audience: &'a str,
    pub(crate) host: &'a str,
    pub(crate) operation: &'a CredentialOperationV1,
    pub(crate) binding: &'a IdentityBindingV1,
    pub(crate) tenant: &'a str,
    pub(crate) service: &'a str,
    pub(crate) purpose: &'a str,
    pub(crate) operation_input_schema: &'a str,
    pub(crate) operation_input: &'a [u8],
    pub(crate) operation_body_sha256: &'a str,
    pub(crate) expires_at_epoch_s: u64,
}

impl CredentialOperationContext<'_> {
    #[must_use]
    pub fn request_id(&self) -> &str {
        self.request_id
    }
    #[must_use]
    pub fn credential_ref(&self) -> &str {
        self.credential_ref
    }
    #[must_use]
    pub fn audience(&self) -> &str {
        self.audience
    }
    #[must_use]
    pub fn host(&self) -> &str {
        self.host
    }
    #[must_use]
    pub const fn operation(&self) -> &CredentialOperationV1 {
        self.operation
    }
    #[must_use]
    pub const fn binding(&self) -> &IdentityBindingV1 {
        self.binding
    }
    #[must_use]
    pub fn tenant(&self) -> &str {
        self.tenant
    }
    #[must_use]
    pub fn service(&self) -> &str {
        self.service
    }
    #[must_use]
    pub fn purpose(&self) -> &str {
        self.purpose
    }
    #[must_use]
    pub fn operation_input_schema(&self) -> &str {
        self.operation_input_schema
    }
    #[must_use]
    pub const fn operation_input(&self) -> &[u8] {
        self.operation_input
    }
    #[must_use]
    pub fn operation_body_sha256(&self) -> &str {
        self.operation_body_sha256
    }
    #[must_use]
    pub const fn expires_at_epoch_s(&self) -> u64 {
        self.expires_at_epoch_s
    }
}

/// Implemented by a trusted provider adapter in the runtime process.
///
/// The borrowed secret must be consumed only during this call. It must never
/// be copied into logs, errors, audit metadata, or the returned output.
pub trait CredentialOperationExecutor {
    /// # Errors
    ///
    /// Returns a closed runtime error when the provider operation is denied.
    fn execute(
        &mut self,
        context: &CredentialOperationContext<'_>,
        secret: &SecretValue,
    ) -> RuntimeResult<ExecutorOutput>;
}
