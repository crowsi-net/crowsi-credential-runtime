mod codec;
mod unix;

#[cfg(any(test, feature = "test-support"))]
mod memory;

use zeroize::Zeroizing;

use crate::RuntimeResult;

pub use unix::UnixFrameTransport;

#[cfg(any(test, feature = "test-support"))]
pub use memory::MemoryFrameTransport;

pub const MAX_FRAME_BYTES: usize = 64 * 1024;

pub trait FrameTransport {
    /// # Errors
    ///
    /// Rejects invalid, oversized, partial, timed-out, or unavailable input.
    fn read_frame(&mut self) -> RuntimeResult<Zeroizing<Vec<u8>>>;
    /// # Errors
    ///
    /// Rejects invalid, oversized, closed, timed-out, or unavailable output.
    fn write_frame(&mut self, frame: &[u8]) -> RuntimeResult<()>;
    /// # Errors
    ///
    /// Returns an error if the transport cannot half-close its write side.
    fn finish_writes(&mut self) -> RuntimeResult<()>;
    /// # Errors
    ///
    /// Rejects trailing data, timeout, or an unavailable transport.
    fn expect_eof(&mut self) -> RuntimeResult<()>;
}

pub(crate) use codec::{read_json, write_json};
