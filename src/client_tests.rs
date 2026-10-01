use crowsi_credential_broker::{CredentialReferenceV1, credential_resource};
use crowsi_local_control_bridge::{
    BridgeAction, ControlAuthorizationV2, ControlRequestV1, IpcAuthorizationEnvelopeV2,
    SenderProof, SignedAuthorization,
};

use super::validate_authorization_request;
use crate::engine::{USE_ACTION, USE_PURPOSE};
use crate::{
    CredentialOperationV1, IdentityBindingV1, RuntimeError, UseRequestV1,
    credential_use_body_sha256,
};

fn request() -> UseRequestV1 {
    let reference = CredentialReferenceV1::new("primary", "tenant-a", "zixcel-aws", "sign", "aws")
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
    UseRequestV1::new(
        "request-a",
        binding,
        reference,
        "aws",
        "sts.example.test",
        30,
        "zixcel://aws/sign-request/v1",
        b"{\"method\":\"GET\"}".to_vec(),
        CredentialOperationV1::sign(
            "zixcel-aws",
            "aws4-hmac-sha256",
            "ipc-response",
            "zixcel://aws/sign-response/v1",
        )
        .expect("operation"),
    )
    .expect("request")
}

fn envelope(request: &UseRequestV1) -> IpcAuthorizationEnvelopeV2 {
    let resource = credential_resource(request.credential()).expect("resource");
    let body = credential_use_body_sha256(request).expect("digest");
    let control = ControlRequestV1 {
        schema: "crowsi://local-control/request/v1".into(),
        request_id: "request-a".into(),
        action: BridgeAction::UseCredential,
        resource: resource.clone(),
        purpose: USE_PURPOSE.into(),
        body_sha256: body.clone(),
    };
    let document = ControlAuthorizationV2 {
        schema: "crowsi://local-control/authorization/v2".into(),
        issuer: "pa".into(),
        audience: "local-control".into(),
        service_id: "service:crowsi".into(),
        pairwise_subject: "pairwise-crowsi-runtime-fixture".into(),
        device_id: "device-runtime-workstation-a".into(),
        session_ref: "session-runtime-fixture".into(),
        device_proof_key_ref: "keyref-device-runtime-workstation-a".into(),
        device_posture: "compliant".into(),
        device_posture_revision: 4,
        subject_revocation_epoch: 3,
        service_revocation_epoch: 2,
        device_revocation_epoch: 4,
        session_revocation_epoch: 5,
        workload_id: "spiffe://crowsi/local/zixcel-aws".into(),
        actor_profile_id: "profile-a".into(),
        assurance: "phishing-resistant".into(),
        user_verification: true,
        sender_public_key_hex: "abcd1234".into(),
        request_id: "request-a".into(),
        action: BridgeAction::UseCredential,
        resource,
        purpose: USE_PURPOSE.into(),
        body_sha256: body,
        reservation_id: "grant-a".into(),
        issued_at_epoch_s: 1_000,
        expires_at_epoch_s: 1_030,
    };
    IpcAuthorizationEnvelopeV2 {
        schema: "crowsi://local-control/ipc-envelope/v2".into(),
        request: control,
        authorization: SignedAuthorization {
            document,
            signature_hex: "signature".into(),
        },
        sender_proof: SenderProof {
            signature_hex: "proof".into(),
        },
    }
}

#[test]
fn pa_request_body_and_runtime_body_are_exactly_the_same_digest() {
    let request = request();
    let mut envelope = envelope(&request);
    assert_eq!(validate_authorization_request(&envelope, &request), Ok(()));
    envelope.request.body_sha256 = format!("sha256:{}", "0".repeat(64));
    assert_eq!(
        validate_authorization_request(&envelope, &request),
        Err(RuntimeError::AuthorizationRejected)
    );
}

#[test]
fn published_aws_fixture_is_the_canonical_authorization_body() {
    let request: UseRequestV1 =
        serde_json::from_str(include_str!("../fixtures/aws-sign-use-request-v1.json"))
            .expect("fixture");
    assert_eq!(
        credential_use_body_sha256(&request).expect("digest"),
        "sha256:10b20c5e37801169dc6dcdc51ee9a956aa18fbe1b35ceac0e32968b61811cdc1"
    );
    let receipt: crate::UseReceiptV1 =
        serde_json::from_str(include_str!("../fixtures/aws-sign-use-receipt-v1.json"))
            .expect("receipt fixture");
    receipt.validate_for(&request).expect("bound receipt");
}
