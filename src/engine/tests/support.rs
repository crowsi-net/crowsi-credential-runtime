use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crowsi_credential_broker::{Clock, MemoryStore};

use super::super::CredentialUseEngine;
use super::executor::TestExecutor;
use crate::{AuditSink, AuditWriteError, CredentialUseAuditEventV1};

pub(super) const SECRET: &[u8] = b"long-lived-test-secret";
pub(super) const HOST: &str = "sts.example.test";
pub(super) const AUDIENCE: &str = "aws";

#[derive(Clone)]
pub(super) struct ManualClock(pub(super) Arc<AtomicU64>);

impl Clock for ManualClock {
    fn now(&self) -> crowsi_credential_broker::Result<u64> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

#[derive(Clone, Default)]
pub(super) struct SharedAudit(pub(super) Arc<Mutex<Vec<CredentialUseAuditEventV1>>>);

impl AuditSink for SharedAudit {
    fn record(&mut self, event: &CredentialUseAuditEventV1) -> Result<(), AuditWriteError> {
        self.0
            .lock()
            .map_err(|_| AuditWriteError)?
            .push(event.clone());
        Ok(())
    }
}

pub(super) type Engine = CredentialUseEngine<MemoryStore, ManualClock, TestExecutor, SharedAudit>;
