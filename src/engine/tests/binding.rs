use crowsi_credential_broker::{CredentialReferenceV1, credential_resource};

use super::super::USE_ACTION;
use super::executor::ExecutorMode;
use super::fixture::{fixture, sign};
use super::support::{AUDIENCE, HOST};
use crate::{IdentityBindingV1, RuntimeError, UseRequestV1};

#[test]
fn audience_and_ticket_body_mismatches_fail_closed() {
    let reference =
        CredentialReferenceV1::new("primary", "tenant-a", "zixcel-aws", "sign", AUDIENCE)
            .expect("reference");
    let resource = credential_resource(&reference).expect("resource");
    let binding = IdentityBindingV1::new(
        "subject-a",
        "device-a",
        "spiffe://crowsi/local/zixcel-aws",
        "grant-a",
        &resource,
        USE_ACTION,
        "abcd1234",
    )
    .expect("binding");
    let mismatch = UseRequestV1::new(
        "request-a",
        binding,
        reference,
        "other",
        HOST,
        10,
        "zixcel://aws/sign-request/v1",
        b"{}".to_vec(),
        sign(),
    );
    assert_eq!(mismatch, Err(RuntimeError::AudienceMismatch));

    let (mut engine, request, mut ticket, _, _) = fixture(ExecutorMode::Signed, sign());
    ticket.body_sha256 = format!("sha256:{}", "0".repeat(64));
    assert_eq!(
        engine.process(&ticket, request),
        Err(RuntimeError::AuthorizationRejected)
    );
}
