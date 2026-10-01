use serde::{Serialize, de::DeserializeOwned};
use zeroize::Zeroizing;

use super::FrameTransport;
use crate::{RuntimeError, RuntimeResult};

pub(crate) fn read_json<T: DeserializeOwned>(
    transport: &mut impl FrameTransport,
) -> RuntimeResult<T> {
    let frame = transport.read_frame()?;
    serde_json::from_slice(&frame).map_err(|_| RuntimeError::Contract)
}

pub(crate) fn write_json<T: Serialize>(
    transport: &mut impl FrameTransport,
    value: &T,
) -> RuntimeResult<()> {
    let frame = Zeroizing::new(serde_json::to_vec(value).map_err(|_| RuntimeError::Contract)?);
    transport.write_frame(&frame)
}
