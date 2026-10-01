use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use crowsi_credential_broker::{
    Broker, CredentialEntry, CredentialReferenceV1, CredentialStore, MemoryStore, SecretValue,
    credential_resource,
};
use crowsi_local_control_bridge::{BridgeAction, DispatchTicket};

use super::super::{CredentialUseEngine, USE_ACTION, USE_PURPOSE};
use super::executor::{ExecutorMode, TestExecutor};
use super::support::{AUDIENCE, Engine, HOST, ManualClock, SECRET, SharedAudit};
use crate::{CredentialOperationV1, IdentityBindingV1, UseRequestV1, credential_use_body_sha256};

pub(super) fn fixture(
    mode: ExecutorMode,
    operation: CredentialOperationV1,
) -> (
    Engine,
    UseRequestV1,
    DispatchTicket,
    ManualClock,
    SharedAudit,
) {
    fixture_with_input(mode, operation, b"{\"method\":\"GET\"}".to_vec())
}

pub(super) fn fixture_with_input(
    mode: ExecutorMode,
    operation: CredentialOperationV1,
    input: Vec<u8>,
) -> (
    Engine,
    UseRequestV1,
    DispatchTicket,
    ManualClock,
    SharedAudit,
) {
    let reference =
        CredentialReferenceV1::new("primary", "tenant-a", "zixcel-aws", "sign", AUDIENCE)
            .expect("reference");
    let resource = credential_resource(&reference).expect("resource");
    let binding = IdentityBindingV1::new(
        "pairwise-crowsi-runtime-fixture",
        "device-runtime-workstation-a",
        "spiffe://crowsi/local/zixcel-aws",
        "grant-a",
        &resource,
        USE_ACTION,
        "abcd1234",
    )
    .expect("binding");
    let request = UseRequestV1::new(
        "request-a",
        binding,
        reference.clone(),
        AUDIENCE,
        HOST,
        10,
        "zixcel://aws/sign-request/v1",
        input,
        operation,
    )
    .expect("request");
    let ticket = ticket(&request, &resource);
    let store = Arc::new(MemoryStore::default());
    store
        .put(
            CredentialEntry::new(
                reference.to_secret_ref().expect("secret ref"),
                [HOST.to_owned()],
                SecretValue::new(SECRET.to_vec()).expect("secret"),
            )
            .expect("entry"),
        )
        .expect("store");
    let clock = ManualClock(Arc::new(AtomicU64::new(1_000)));
    let audit = SharedAudit::default();
    let engine = CredentialUseEngine::new(
        Broker::with_clock(store, clock.clone()),
        TestExecutor(mode),
        audit.clone(),
    );
    (engine, request, ticket, clock, audit)
}

fn ticket(request: &UseRequestV1, resource: &str) -> DispatchTicket {
    DispatchTicket {
        schema: "crowsi://local-control/dispatch-ticket/v2",
        request_id: request.request_id().into(),
        reservation_id: "grant-a".into(),
        action: BridgeAction::UseCredential,
        resource: resource.into(),
        purpose: USE_PURPOSE.into(),
        body_sha256: credential_use_body_sha256(request).expect("digest"),
        command_digest: "sha256:command".into(),
        service_id: "service:crowsi".into(),
        pairwise_subject: "pairwise-crowsi-runtime-fixture".into(),
        device_id: "device-runtime-workstation-a".into(),
        session_ref: "session-runtime-fixture".into(),
        device_proof_key_ref: "keyref-device-runtime-workstation-a".into(),
        workload_id: "spiffe://crowsi/local/zixcel-aws".into(),
        actor_profile_id: "profile-a".into(),
        sender_public_key_hex: "abcd1234".into(),
        device_posture_revision: 4,
        subject_revocation_epoch: 3,
        service_revocation_epoch: 2,
        device_revocation_epoch: 4,
        session_revocation_epoch: 5,
        authorized_at_epoch_s: 1_000,
    }
}

pub(super) fn sign() -> CredentialOperationV1 {
    CredentialOperationV1::sign(
        "zixcel-aws",
        "aws4-hmac-sha256",
        "ipc-response",
        "zixcel://aws/sign-response/v1",
    )
    .expect("operation")
}
