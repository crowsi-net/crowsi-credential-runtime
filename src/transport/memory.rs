use std::collections::VecDeque;

use zeroize::Zeroizing;

use super::{FrameTransport, MAX_FRAME_BYTES};
use crate::{RuntimeError, RuntimeResult};

#[derive(Default)]
pub struct MemoryFrameTransport {
    inbound: VecDeque<Zeroizing<Vec<u8>>>,
    outbound: Vec<Zeroizing<Vec<u8>>>,
    writes_finished: bool,
}

impl MemoryFrameTransport {
    #[must_use]
    pub fn with_inbound(frames: impl IntoIterator<Item = Vec<u8>>) -> Self {
        Self {
            inbound: frames.into_iter().map(Zeroizing::new).collect(),
            ..Self::default()
        }
    }

    pub fn outbound(&self) -> impl Iterator<Item = &[u8]> {
        self.outbound.iter().map(AsRef::as_ref)
    }
}

impl FrameTransport for MemoryFrameTransport {
    fn read_frame(&mut self) -> RuntimeResult<Zeroizing<Vec<u8>>> {
        self.inbound
            .pop_front()
            .ok_or(RuntimeError::TransportUnavailable)
    }

    fn write_frame(&mut self, frame: &[u8]) -> RuntimeResult<()> {
        if self.writes_finished || frame.is_empty() || frame.len() > MAX_FRAME_BYTES {
            return Err(RuntimeError::Contract);
        }
        self.outbound.push(Zeroizing::new(frame.to_vec()));
        Ok(())
    }

    fn finish_writes(&mut self) -> RuntimeResult<()> {
        self.writes_finished = true;
        Ok(())
    }

    fn expect_eof(&mut self) -> RuntimeResult<()> {
        self.inbound
            .is_empty()
            .then_some(())
            .ok_or(RuntimeError::Contract)
    }
}

#[cfg(test)]
#[path = "memory_tests.rs"]
mod tests;
