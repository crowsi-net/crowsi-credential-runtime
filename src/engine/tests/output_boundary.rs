use super::executor::ExecutorMode;
use super::fixture::{fixture, fixture_with_input, sign};
use super::support::SECRET;
use crate::{CredentialOperationV1, RuntimeError};

#[test]
fn signed_output_is_bound_and_audit_has_no_secret() {
    let (mut engine, request, ticket, _, audit) = fixture(ExecutorMode::Signed, sign());
    let receipt = engine.process(&ticket, request).expect("use");
    assert_eq!(receipt.output().audience(), "aws");
    assert_eq!(receipt.output().schema(), "zixcel://aws/sign-response/v1");
    let audit = serde_json::to_string(&audit.0.lock().expect("audit")[0]).expect("json");
    assert!(!audit.contains(std::str::from_utf8(SECRET).expect("utf8")));
    assert!(!audit.contains("tenant-a/zixcel-aws/sign/aws/primary"));
    assert!(audit.contains("credential_ref_digest"));
}

#[test]
fn raw_secret_cannot_enter_input_or_output() {
    let (mut engine, request, ticket, _, _) = fixture(ExecutorMode::Leak, sign());
    assert_eq!(
        engine.process(&ticket, request),
        Err(RuntimeError::OperationRejected)
    );

    let (mut engine, request, ticket, _, _) =
        fixture_with_input(ExecutorMode::Completed, sign(), SECRET.to_vec());
    assert_eq!(
        engine.process(&ticket, request),
        Err(RuntimeError::OperationRejected)
    );
}

#[test]
fn opaque_operation_cannot_return_arbitrary_output() {
    let opaque = CredentialOperationV1::opaque("provider", "perform").expect("opaque");
    let (mut engine, request, ticket, _, _) = fixture(ExecutorMode::DerivedOpaque, opaque);
    assert_eq!(
        engine.process(&ticket, request),
        Err(RuntimeError::OperationRejected)
    );
}

#[test]
fn signed_output_schema_must_match_the_request() {
    let (mut engine, request, ticket, _, _) = fixture(ExecutorMode::WrongSchema, sign());
    assert_eq!(
        engine.process(&ticket, request),
        Err(RuntimeError::OperationRejected)
    );
}
