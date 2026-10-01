use std::os::unix::net::UnixStream;
use std::time::Duration;

use crowsi_credential_broker::{Clock, CredentialStore};
use crowsi_local_control_bridge::{AuthorizedOperationHandler, BridgeError, DispatchTicket};

use crate::transport::{read_json, write_json};
use crate::{
    AuditSink, CredentialOperationExecutor, CredentialUseEngine, FrameTransport, RuntimeError,
    RuntimeResult, UnixFrameTransport, UseRequestV1,
};

pub struct CredentialRuntimeHandler<S, C, E, A> {
    engine: CredentialUseEngine<S, C, E, A>,
    timeout: Duration,
}

impl<S, C, E, A> CredentialRuntimeHandler<S, C, E, A> {
    #[must_use]
    pub const fn new(engine: CredentialUseEngine<S, C, E, A>, timeout: Duration) -> Self {
        Self { engine, timeout }
    }
}

impl<S, C, E, A> CredentialRuntimeHandler<S, C, E, A>
where
    S: CredentialStore,
    C: Clock,
    E: CredentialOperationExecutor,
    A: AuditSink,
{
    fn handle_transport(
        &mut self,
        ticket: &DispatchTicket,
        transport: &mut impl FrameTransport,
    ) -> RuntimeResult<()> {
        let request: UseRequestV1 = read_json(transport)?;
        transport.expect_eof()?;
        let receipt = self.engine.process(ticket, request)?;
        write_json(transport, &receipt)?;
        transport.finish_writes()
    }
}

impl<S, C, E, A> AuthorizedOperationHandler for CredentialRuntimeHandler<S, C, E, A>
where
    S: CredentialStore,
    C: Clock,
    E: CredentialOperationExecutor,
    A: AuditSink,
{
    fn handle(
        &mut self,
        ticket: DispatchTicket,
        stream: &mut UnixStream,
    ) -> Result<(), BridgeError> {
        let mut transport = UnixFrameTransport::new(stream, self.timeout).map_err(map_error)?;
        self.handle_transport(&ticket, &mut transport)
            .map_err(map_error)
    }
}

fn map_error(error: RuntimeError) -> BridgeError {
    match error {
        RuntimeError::Contract => BridgeError::Contract,
        RuntimeError::AuthorizationRejected | RuntimeError::AudienceMismatch => {
            BridgeError::Binding
        }
        RuntimeError::Replay => BridgeError::Replay,
        RuntimeError::Expired => BridgeError::Time,
        RuntimeError::CredentialUnavailable | RuntimeError::AuditUnavailable => {
            BridgeError::Storage
        }
        RuntimeError::OperationRejected => BridgeError::Binding,
        RuntimeError::TransportUnavailable | RuntimeError::Timeout => BridgeError::Transport,
    }
}
