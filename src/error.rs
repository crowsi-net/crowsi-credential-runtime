use crowsi_credential_broker::BrokerError;
use thiserror::Error;

pub type RuntimeResult<T> = Result<T, RuntimeError>;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RuntimeError {
    #[error("credential runtime contract rejected")]
    Contract,
    #[error("credential runtime authorization rejected")]
    AuthorizationRejected,
    #[error("credential runtime audience binding rejected")]
    AudienceMismatch,
    #[error("credential runtime operation replay rejected")]
    Replay,
    #[error("credential runtime lease expired")]
    Expired,
    #[error("credential runtime backend unavailable")]
    CredentialUnavailable,
    #[error("trusted credential operation rejected")]
    OperationRejected,
    #[error("credential runtime audit unavailable")]
    AuditUnavailable,
    #[error("credential runtime transport unavailable")]
    TransportUnavailable,
    #[error("credential runtime transport timed out")]
    Timeout,
}

impl From<BrokerError> for RuntimeError {
    fn from(value: BrokerError) -> Self {
        match value {
            BrokerError::Expired => Self::Expired,
            BrokerError::UnknownLease => Self::Replay,
            BrokerError::AccessDenied | BrokerError::Revoked => Self::AuthorizationRejected,
            BrokerError::InvalidField(_) => Self::Contract,
            _ => Self::CredentialUnavailable,
        }
    }
}
