use crowsi_credential_broker::SecretValue;

use super::support::AUDIENCE;
use crate::{
    CredentialOperationContext, CredentialOperationExecutor, ExecutorOutput, RuntimeResult,
};

pub(super) enum ExecutorMode {
    Completed,
    Signed,
    Leak,
    WrongSchema,
    DerivedOpaque,
}

pub(super) struct TestExecutor(pub(super) ExecutorMode);

impl CredentialOperationExecutor for TestExecutor {
    fn execute(
        &mut self,
        context: &CredentialOperationContext<'_>,
        secret: &SecretValue,
    ) -> RuntimeResult<ExecutorOutput> {
        assert_eq!(context.audience(), AUDIENCE);
        assert_eq!(context.binding().grant_id(), "grant-a");
        assert_eq!(context.purpose(), "sign");
        assert_eq!(
            context.operation_input_schema(),
            "zixcel://aws/sign-request/v1"
        );
        match self.0 {
            ExecutorMode::Completed => Ok(ExecutorOutput::completed()),
            ExecutorMode::Signed => ExecutorOutput::derived(
                "zixcel://aws/sign-response/v1",
                "application/json",
                b"{\"signed\":true}".to_vec(),
            ),
            ExecutorMode::Leak => secret.expose(|value| {
                ExecutorOutput::derived(
                    "zixcel://aws/sign-response/v1",
                    "application/octet-stream",
                    value.to_vec(),
                )
            }),
            ExecutorMode::WrongSchema => ExecutorOutput::derived(
                "zixcel://aws/other-response/v1",
                "application/json",
                b"{}".to_vec(),
            ),
            ExecutorMode::DerivedOpaque => ExecutorOutput::derived(
                "zixcel://aws/sign-response/v1",
                "application/json",
                b"{}".to_vec(),
            ),
        }
    }
}
