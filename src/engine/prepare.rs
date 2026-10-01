use crowsi_credential_broker::{
    AccessRequest, Broker, Clock, CredentialStore, LeaseBinding, LeaseGrant, credential_resource,
};
use crowsi_local_control_bridge::{BridgeAction, DispatchTicket};

use super::{USE_ACTION, USE_PURPOSE};
use crate::{RuntimeError, RuntimeResult, UseRequestV1, credential_use_body_sha256};

pub(super) struct PreparedUse {
    pub(super) request: UseRequestV1,
    pub(super) credential_ref: String,
    pub(super) body_sha256: String,
    pub(super) lease_binding: LeaseBinding,
    pub(super) lease: Option<LeaseGrant>,
}

impl PreparedUse {
    pub(super) fn new<S: CredentialStore, C: Clock>(
        broker: &Broker<S, C>,
        ticket: &DispatchTicket,
        request: UseRequestV1,
    ) -> RuntimeResult<Self> {
        let request = request.validated()?;
        let reference = request
            .credential()
            .to_secret_ref()
            .map_err(|_| RuntimeError::Contract)?;
        let credential_ref = reference.canonical_id();
        let resource =
            credential_resource(request.credential()).map_err(|_| RuntimeError::Contract)?;
        let body_sha256 = credential_use_body_sha256(&request)?;
        validate_ticket(ticket, &request, &resource, &body_sha256)?;
        let binding = request.binding();
        let lease_binding = LeaseBinding::new(
            binding.pairwise_subject(),
            binding.device_id(),
            binding.workload_id(),
            binding.grant_id(),
            binding.resource(),
            binding.action(),
            binding.proof_key_ref(),
        )?;
        let access = AccessRequest::new(
            reference,
            request.audience(),
            request.host(),
            request.ttl_seconds(),
        )?;
        let lease = broker.issue_bound(access, lease_binding.clone())?;
        Ok(Self {
            request,
            credential_ref,
            body_sha256,
            lease_binding,
            lease: Some(lease),
        })
    }
}

fn validate_ticket(
    ticket: &DispatchTicket,
    request: &UseRequestV1,
    resource: &str,
    body: &str,
) -> RuntimeResult<()> {
    let binding = request.binding();
    let exact = ticket.schema == "crowsi://local-control/dispatch-ticket/v2"
        && ticket.action == BridgeAction::UseCredential
        && ticket.purpose == USE_PURPOSE
        && ticket.request_id == request.request_id()
        && ticket.reservation_id == binding.grant_id()
        && ticket.service_id == "service:crowsi"
        && ticket.pairwise_subject == binding.pairwise_subject()
        && ticket.device_id == binding.device_id()
        && ticket.workload_id == binding.workload_id()
        && ticket.sender_public_key_hex == binding.proof_key_ref()
        && binding.resource() == resource
        && binding.action() == USE_ACTION
        && ticket.resource == resource
        && ticket.body_sha256 == body;
    exact
        .then_some(())
        .ok_or(RuntimeError::AuthorizationRejected)
}
