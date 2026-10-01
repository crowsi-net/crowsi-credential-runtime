use serde::Serialize;

use crate::{RuntimeResult, UseReceiptMetadataV1, UseRequestV1, canonical::identity_digest};

pub const AUDIT_EVENT_SCHEMA: &str = "crowsi://credential-runtime/audit-event/v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CredentialUseAuditEventV1 {
    pub schema: &'static str,
    pub event_id: String,
    pub request_digest: String,
    pub subject_digest: String,
    pub device_digest: String,
    pub workload_digest: String,
    pub grant_digest: String,
    pub credential_ref_digest: String,
    pub operation: String,
    pub operation_input_schema: String,
    pub operation_body_sha256: String,
    pub output_schema: String,
    pub output_sha256: String,
    pub output_bytes: usize,
    pub occurred_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub contains_secret_values: bool,
}

impl CredentialUseAuditEventV1 {
    pub(crate) fn completed(
        request: &UseRequestV1,
        metadata: &UseReceiptMetadataV1,
        output: &crate::OperationOutputV1,
    ) -> Self {
        let binding = request.binding();
        Self {
            schema: AUDIT_EVENT_SCHEMA,
            event_id: metadata.event_id().into(),
            request_digest: identity_digest(b"crowsi:request-id:v1\0", request.request_id()),
            subject_digest: identity_digest(
                b"crowsi:pairwise-subject:v1\0",
                binding.pairwise_subject(),
            ),
            device_digest: identity_digest(b"crowsi:device-id:v1\0", binding.device_id()),
            workload_digest: identity_digest(b"crowsi:workload-id:v1\0", binding.workload_id()),
            grant_digest: identity_digest(b"crowsi:grant-id:v1\0", binding.grant_id()),
            credential_ref_digest: identity_digest(
                b"crowsi:credential-ref:v1\0",
                metadata.credential_ref(),
            ),
            operation: metadata.operation().into(),
            operation_input_schema: request.operation_input_schema().into(),
            operation_body_sha256: request.operation_body_sha256().into(),
            output_schema: output.schema().into(),
            output_sha256: output.result_sha256().into(),
            output_bytes: output.payload().len(),
            occurred_at_epoch_s: metadata.occurred_at_epoch_s(),
            expires_at_epoch_s: metadata.expires_at_epoch_s(),
            contains_secret_values: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditWriteError;

pub trait AuditSink {
    /// # Errors
    ///
    /// Returns an opaque failure when durable audit storage is unavailable.
    fn record(&mut self, event: &CredentialUseAuditEventV1) -> Result<(), AuditWriteError>;
}

pub(crate) fn write(
    sink: &mut impl AuditSink,
    event: &CredentialUseAuditEventV1,
) -> RuntimeResult<()> {
    sink.record(event)
        .map_err(|_| crate::RuntimeError::AuditUnavailable)
}
