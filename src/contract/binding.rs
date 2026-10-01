use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{RuntimeResult, validation};

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityBindingV1 {
    pairwise_subject: String,
    device_id: String,
    workload_id: String,
    grant_id: String,
    resource: String,
    action: String,
    proof_key_ref: String,
}

impl fmt::Debug for IdentityBindingV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IdentityBindingV1([REDACTED])")
    }
}

impl IdentityBindingV1 {
    #[allow(clippy::too_many_arguments)]
    /// # Errors
    ///
    /// Rejects an invalid identity, grant, resource, action, or proof-key field.
    pub fn new(
        subject: &str,
        device: &str,
        workload: &str,
        grant: &str,
        resource: &str,
        action: &str,
        proof_key_ref: &str,
    ) -> RuntimeResult<Self> {
        let value = Self {
            pairwise_subject: subject.into(),
            device_id: device.into(),
            workload_id: workload.into(),
            grant_id: grant.into(),
            resource: resource.into(),
            action: action.into(),
            proof_key_ref: proof_key_ref.into(),
        };
        value.validated()
    }

    pub(crate) fn validated(self) -> RuntimeResult<Self> {
        validation::component(&self.pairwise_subject, 128)?;
        validation::component(&self.device_id, 128)?;
        validation::component(&self.grant_id, 128)?;
        validation::component(&self.resource, 128)?;
        validation::component(&self.action, 64)?;
        validation::component(&self.proof_key_ref, 128)?;
        if !self.workload_id.starts_with("spiffe://") || self.workload_id.len() > 255 {
            return Err(crate::RuntimeError::Contract);
        }
        Ok(self)
    }

    #[must_use]
    pub fn pairwise_subject(&self) -> &str {
        &self.pairwise_subject
    }

    #[must_use]
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    #[must_use]
    pub fn workload_id(&self) -> &str {
        &self.workload_id
    }

    #[must_use]
    pub fn grant_id(&self) -> &str {
        &self.grant_id
    }

    #[must_use]
    pub fn resource(&self) -> &str {
        &self.resource
    }
    #[must_use]
    pub fn action(&self) -> &str {
        &self.action
    }
    #[must_use]
    pub fn proof_key_ref(&self) -> &str {
        &self.proof_key_ref
    }
}
