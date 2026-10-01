mod prepare;

#[cfg(test)]
mod tests;

use crowsi_credential_broker::{Broker, Clock, CredentialStore};
use crowsi_local_control_bridge::DispatchTicket;

use crate::{
    AuditSink, CredentialOperationContext, CredentialOperationExecutor, CredentialUseAuditEventV1,
    OperationOutputV1, RuntimeError, RuntimeResult, UseReceiptMetadataV1, UseReceiptV1,
    UseRequestV1, audit,
};
use prepare::PreparedUse;

pub const USE_ACTION: &str = "use-credential";
pub const USE_PURPOSE: &str = "credential-runtime-use";

pub struct CredentialUseEngine<S, C, E, A> {
    broker: Broker<S, C>,
    executor: E,
    audit: A,
}

impl<S, C, E, A> CredentialUseEngine<S, C, E, A> {
    #[must_use]
    pub const fn new(broker: Broker<S, C>, executor: E, audit: A) -> Self {
        Self {
            broker,
            executor,
            audit,
        }
    }
}

impl<S, C, E, A> CredentialUseEngine<S, C, E, A>
where
    S: CredentialStore,
    C: Clock,
    E: CredentialOperationExecutor,
    A: AuditSink,
{
    /// Performs one authorized operation and returns only a bounded derived output.
    ///
    /// # Errors
    ///
    /// Fails closed on any authorization, binding, lease, adapter, or audit error.
    pub fn process(
        &mut self,
        ticket: &DispatchTicket,
        request: UseRequestV1,
    ) -> RuntimeResult<UseReceiptV1> {
        let mut prepared = PreparedUse::new(&self.broker, ticket, request)?;
        self.execute(&mut prepared)
    }

    fn execute(&mut self, prepared: &mut PreparedUse) -> RuntimeResult<UseReceiptV1> {
        let grant = prepared.lease.take().ok_or(RuntimeError::Replay)?;
        let used = self.broker.consume_bound(
            grant.token(),
            prepared.request.audience(),
            prepared.request.host(),
            &prepared.lease_binding,
        )?;
        let reference = prepared
            .request
            .credential()
            .to_secret_ref()
            .map_err(|_| RuntimeError::Contract)?;
        let context = CredentialOperationContext {
            request_id: prepared.request.request_id(),
            credential_ref: &prepared.credential_ref,
            audience: prepared.request.audience(),
            host: &used.receipt.host,
            operation: prepared.request.operation(),
            binding: prepared.request.binding(),
            tenant: reference.scope().tenant(),
            service: reference.scope().service(),
            purpose: reference.scope().purpose(),
            operation_input_schema: prepared.request.operation_input_schema(),
            operation_input: prepared.request.operation_input(),
            operation_body_sha256: prepared.request.operation_body_sha256(),
            expires_at_epoch_s: used.receipt.expires_at,
        };
        if used
            .secret
            .expose(|secret| contains(prepared.request.operation_input(), secret))
        {
            return Err(RuntimeError::OperationRejected);
        }
        let output = self.executor.execute(&context, &used.secret)?;
        if used.secret.expose(|secret| output.exposes(secret)) {
            return Err(RuntimeError::OperationRejected);
        }
        let output = OperationOutputV1::bind(
            output,
            &prepared.body_sha256,
            prepared.request.audience(),
            used.receipt.expires_at,
            prepared.request.operation(),
        )?;
        let metadata = UseReceiptMetadataV1::completed(
            prepared.request.request_id(),
            &used.receipt.event_id,
            &prepared.credential_ref,
            prepared.request.operation().kind(),
            used.receipt.occurred_at,
            used.receipt.expires_at,
        );
        let event = CredentialUseAuditEventV1::completed(&prepared.request, &metadata, &output);
        audit::write(&mut self.audit, &event)?;
        Ok(UseReceiptV1::completed(metadata, output))
    }
}

fn contains(value: &[u8], secret: &[u8]) -> bool {
    !secret.is_empty() && value.windows(secret.len()).any(|part| part == secret)
}
