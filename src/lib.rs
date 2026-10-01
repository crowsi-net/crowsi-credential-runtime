//! Authenticated, one-use credential execution for trusted local adapters.
//!
//! The client receives only an operation-derived output and a metadata receipt;
//! raw credentials and lease tokens never cross the runtime IPC boundary.
//!
//! ```compile_fail
//! use crowsi_credential_broker::SecretValue;
//! fn require_serializable<T: serde::Serialize>() {}
//! require_serializable::<SecretValue>();
//! ```

mod audit;
mod canonical;
mod client;
mod contract;
mod engine;
mod error;
mod executor;
mod handler;
mod transport;
mod validation;

#[cfg(test)]
mod schema_tests;

pub use audit::{AuditSink, AuditWriteError, CredentialUseAuditEventV1};
pub use canonical::credential_use_body_sha256;
pub use client::CredentialRuntimeClient;
pub use contract::{
    CredentialOperationV1, IdentityBindingV1, OperationOutputV1, USE_RECEIPT_SCHEMA,
    USE_REQUEST_SCHEMA, UseReceiptMetadataV1, UseReceiptV1, UseRequestV1,
};
pub use engine::CredentialUseEngine;
pub use error::{RuntimeError, RuntimeResult};
pub use executor::{CredentialOperationContext, CredentialOperationExecutor, ExecutorOutput};
pub use handler::CredentialRuntimeHandler;
pub use transport::{FrameTransport, UnixFrameTransport};

#[cfg(any(test, feature = "test-support"))]
pub use transport::MemoryFrameTransport;
