use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{RuntimeResult, validation};

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CredentialOperationV1 {
    BearerHeader {
        adapter: String,
    },
    OpaqueSecret {
        adapter: String,
        operation: String,
    },
    Sign {
        adapter: String,
        algorithm: String,
        delivery: String,
        output_schema: String,
    },
}

impl fmt::Debug for CredentialOperationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CredentialOperationV1")
            .field(&self.kind())
            .finish()
    }
}

impl CredentialOperationV1 {
    /// # Errors
    ///
    /// Rejects an invalid adapter identifier.
    pub fn bearer_header(adapter: &str) -> RuntimeResult<Self> {
        Self::BearerHeader {
            adapter: adapter.into(),
        }
        .validated()
    }

    /// # Errors
    ///
    /// Rejects invalid adapter or operation identifiers.
    pub fn opaque(adapter: &str, operation: &str) -> RuntimeResult<Self> {
        Self::OpaqueSecret {
            adapter: adapter.into(),
            operation: operation.into(),
        }
        .validated()
    }

    /// # Errors
    ///
    /// Rejects invalid adapter, algorithm, delivery, or output schema values.
    pub fn sign(
        adapter: &str,
        algorithm: &str,
        delivery: &str,
        output_schema: &str,
    ) -> RuntimeResult<Self> {
        Self::Sign {
            adapter: adapter.into(),
            algorithm: algorithm.into(),
            delivery: delivery.into(),
            output_schema: output_schema.into(),
        }
        .validated()
    }

    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::BearerHeader { .. } => "bearer-header",
            Self::OpaqueSecret { .. } => "opaque-secret",
            Self::Sign { .. } => "sign",
        }
    }

    pub(crate) fn validated(self) -> RuntimeResult<Self> {
        match &self {
            Self::BearerHeader { adapter } => validation::component(adapter, 64)?,
            Self::OpaqueSecret { adapter, operation } => {
                validation::component(adapter, 64)?;
                validation::component(operation, 96)?;
            }
            Self::Sign {
                adapter,
                algorithm,
                delivery,
                output_schema,
            } => {
                validation::component(adapter, 64)?;
                validation::component(algorithm, 64)?;
                validation::component(delivery, 96)?;
                validation::schema(output_schema)?;
            }
        }
        Ok(self)
    }

    pub(crate) fn expected_output_schema(&self) -> Option<&str> {
        match self {
            Self::Sign { output_schema, .. } => Some(output_schema),
            _ => None,
        }
    }
}
