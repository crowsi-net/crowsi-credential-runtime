use std::os::unix::net::UnixStream;
use std::time::Duration;

use crowsi_credential_broker::credential_resource;
use crowsi_local_control_bridge::{BridgeAction, IpcAuthorizationEnvelopeV2};

use crate::engine::{USE_ACTION, USE_PURPOSE};
use crate::transport::{read_json, write_json};
use crate::{
    FrameTransport, RuntimeError, RuntimeResult, UnixFrameTransport, UseReceiptV1, UseRequestV1,
    credential_use_body_sha256,
};

pub struct CredentialRuntimeClient {
    timeout: Duration,
}

impl CredentialRuntimeClient {
    #[must_use]
    pub const fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// Sends an authorization and use request over one local stream.
    ///
    /// # Errors
    ///
    /// Rejects invalid bindings, framing, output, EOF, or transport failures.
    pub fn exchange(
        &self,
        stream: &mut UnixStream,
        authorization: &IpcAuthorizationEnvelopeV2,
        request: &UseRequestV1,
    ) -> RuntimeResult<UseReceiptV1> {
        let mut transport = UnixFrameTransport::new(stream, self.timeout)?;
        self.exchange_transport(&mut transport, authorization, request)
    }

    /// Exposes the same framing to test and purpose-specific transports.
    ///
    /// # Errors
    ///
    /// Rejects any authorization, contract, framing, or receipt mismatch.
    pub fn exchange_transport(
        &self,
        transport: &mut impl FrameTransport,
        authorization: &IpcAuthorizationEnvelopeV2,
        request: &UseRequestV1,
    ) -> RuntimeResult<UseReceiptV1> {
        let request = request.clone().validated()?;
        validate_authorization_request(authorization, &request)?;
        write_json(transport, authorization)?;
        write_json(transport, &request)?;
        transport.finish_writes()?;
        let receipt: UseReceiptV1 = read_json(transport)?;
        transport.expect_eof()?;
        receipt.validate_for(&request)?;
        Ok(receipt)
    }
}

fn validate_authorization_request(
    envelope: &IpcAuthorizationEnvelopeV2,
    request: &UseRequestV1,
) -> RuntimeResult<()> {
    let control = &envelope.request;
    let document = &envelope.authorization.document;
    let binding = request.binding();
    let resource = credential_resource(request.credential()).map_err(|_| RuntimeError::Contract)?;
    let body = credential_use_body_sha256(request)?;
    let exact = envelope.schema == "crowsi://local-control/ipc-envelope/v2"
        && control.action == BridgeAction::UseCredential
        && control.request_id == request.request_id()
        && control.resource == resource
        && control.purpose == USE_PURPOSE
        && control.body_sha256 == body
        && binding.resource() == resource
        && binding.action() == USE_ACTION
        && binding.proof_key_ref() == document.sender_public_key_hex
        && binding.grant_id() == document.reservation_id
        && document.service_id == "service:crowsi"
        && binding.pairwise_subject() == document.pairwise_subject
        && binding.device_id() == document.device_id
        && binding.workload_id() == document.workload_id;
    exact
        .then_some(())
        .ok_or(RuntimeError::AuthorizationRejected)
}

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;
