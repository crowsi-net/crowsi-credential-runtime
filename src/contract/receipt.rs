use std::fmt;

use serde::{Deserialize, Serialize};

use super::OperationOutputV1;
use crate::{RuntimeError, RuntimeResult, validation};

pub const USE_RECEIPT_SCHEMA: &str = "crowsi://credential-runtime/use-receipt/v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UseReceiptMetadataV1 {
    request_id: String,
    event_id: String,
    credential_ref: String,
    operation: String,
    status: String,
    occurred_at_epoch_s: u64,
    expires_at_epoch_s: u64,
    contains_secret_values: bool,
}

impl UseReceiptMetadataV1 {
    pub(crate) fn completed(
        request_id: &str,
        event_id: &str,
        credential_ref: &str,
        operation: &str,
        occurred_at: u64,
        expires_at: u64,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            event_id: event_id.into(),
            credential_ref: credential_ref.into(),
            operation: operation.into(),
            status: "completed".into(),
            occurred_at_epoch_s: occurred_at,
            expires_at_epoch_s: expires_at,
            contains_secret_values: false,
        }
    }

    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }
    #[must_use]
    pub fn event_id(&self) -> &str {
        &self.event_id
    }
    #[must_use]
    pub fn credential_ref(&self) -> &str {
        &self.credential_ref
    }
    #[must_use]
    pub fn operation(&self) -> &str {
        &self.operation
    }
    #[must_use]
    pub fn status(&self) -> &str {
        &self.status
    }
    #[must_use]
    pub const fn occurred_at_epoch_s(&self) -> u64 {
        self.occurred_at_epoch_s
    }
    #[must_use]
    pub const fn expires_at_epoch_s(&self) -> u64 {
        self.expires_at_epoch_s
    }
    #[must_use]
    pub const fn contains_secret_values(&self) -> bool {
        self.contains_secret_values
    }
}

#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UseReceiptV1 {
    schema: String,
    metadata: UseReceiptMetadataV1,
    output: OperationOutputV1,
}

impl fmt::Debug for UseReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UseReceiptV1")
            .field("schema", &self.schema)
            .field("metadata", &self.metadata)
            .field("output", &self.output)
            .finish()
    }
}

impl UseReceiptV1 {
    pub(crate) fn completed(metadata: UseReceiptMetadataV1, output: OperationOutputV1) -> Self {
        Self {
            schema: USE_RECEIPT_SCHEMA.into(),
            metadata,
            output,
        }
    }

    pub(crate) fn validate_for(&self, request: &crate::UseRequestV1) -> RuntimeResult<()> {
        let body = crate::credential_use_body_sha256(request)?;
        let credential_ref = request
            .credential()
            .to_secret_ref()
            .map_err(|_| RuntimeError::Contract)?
            .canonical_id();
        let expected_output = request
            .operation()
            .expected_output_schema()
            .unwrap_or("crowsi://credential-runtime/operation-completed/v1");
        let exact = self.schema == USE_RECEIPT_SCHEMA
            && self.metadata.request_id == request.request_id()
            && self.metadata.credential_ref == credential_ref
            && self.metadata.operation == request.operation().kind()
            && self.metadata.status == "completed"
            && !self.metadata.contains_secret_values
            && self.metadata.expires_at_epoch_s == self.output.expires_at_epoch_s()
            && self.output.request_body_sha256() == body
            && self.output.audience() == request.audience()
            && self.output.schema() == expected_output;
        validation::component(&self.metadata.event_id, 96)?;
        self.output.validate()?;
        exact.then_some(()).ok_or(RuntimeError::Contract)
    }

    #[must_use]
    pub fn metadata(&self) -> &UseReceiptMetadataV1 {
        &self.metadata
    }
    #[must_use]
    pub const fn output(&self) -> &OperationOutputV1 {
        &self.output
    }
}
