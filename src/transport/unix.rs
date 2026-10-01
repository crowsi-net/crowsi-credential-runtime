use std::io::{ErrorKind, Read, Write};
use std::net::Shutdown;
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use nix::poll::{PollFd, PollFlags, poll};
use zeroize::Zeroizing;

use super::{FrameTransport, MAX_FRAME_BYTES};
use crate::{RuntimeError, RuntimeResult};

pub struct UnixFrameTransport<'a> {
    stream: &'a mut UnixStream,
    timeout: Duration,
}

impl<'a> UnixFrameTransport<'a> {
    /// # Errors
    ///
    /// Rejects zero or excessive deadlines and unavailable socket controls.
    pub fn new(stream: &'a mut UnixStream, timeout: Duration) -> RuntimeResult<Self> {
        if timeout.is_zero() || timeout > Duration::from_secs(30) {
            return Err(RuntimeError::Timeout);
        }
        stream
            .set_nonblocking(true)
            .map_err(|_| RuntimeError::TransportUnavailable)?;
        Ok(Self { stream, timeout })
    }

    fn read_exact(&mut self, mut value: &mut [u8], deadline: Instant) -> RuntimeResult<()> {
        while !value.is_empty() {
            match self.stream.read(value) {
                Ok(0) => return Err(RuntimeError::TransportUnavailable),
                Ok(count) => value = &mut value[count..],
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    wait(self.stream, PollFlags::POLLIN, deadline)?;
                }
                Err(_) => return Err(RuntimeError::TransportUnavailable),
            }
        }
        Ok(())
    }

    fn write_all(&mut self, mut value: &[u8], deadline: Instant) -> RuntimeResult<()> {
        while !value.is_empty() {
            match self.stream.write(value) {
                Ok(0) => return Err(RuntimeError::TransportUnavailable),
                Ok(count) => value = &value[count..],
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    wait(self.stream, PollFlags::POLLOUT, deadline)?;
                }
                Err(_) => return Err(RuntimeError::TransportUnavailable),
            }
        }
        Ok(())
    }
}

impl FrameTransport for UnixFrameTransport<'_> {
    fn read_frame(&mut self) -> RuntimeResult<Zeroizing<Vec<u8>>> {
        let deadline = Instant::now() + self.timeout;
        let mut length = [0_u8; 4];
        self.read_exact(&mut length, deadline)?;
        let length =
            usize::try_from(u32::from_be_bytes(length)).map_err(|_| RuntimeError::Contract)?;
        if length == 0 || length > MAX_FRAME_BYTES {
            return Err(RuntimeError::Contract);
        }
        let mut frame = Zeroizing::new(vec![0_u8; length]);
        self.read_exact(&mut frame, deadline)?;
        Ok(frame)
    }

    fn write_frame(&mut self, frame: &[u8]) -> RuntimeResult<()> {
        if frame.is_empty() || frame.len() > MAX_FRAME_BYTES {
            return Err(RuntimeError::Contract);
        }
        let length = u32::try_from(frame.len()).map_err(|_| RuntimeError::Contract)?;
        let deadline = Instant::now() + self.timeout;
        self.write_all(&length.to_be_bytes(), deadline)?;
        self.write_all(frame, deadline)
    }

    fn finish_writes(&mut self) -> RuntimeResult<()> {
        self.stream
            .shutdown(Shutdown::Write)
            .map_err(|_| RuntimeError::TransportUnavailable)
    }

    fn expect_eof(&mut self) -> RuntimeResult<()> {
        let mut trailing = [0_u8; 1];
        match self.stream.read(&mut trailing) {
            Ok(0) => Ok(()),
            Ok(_) => Err(RuntimeError::Contract),
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                let deadline = Instant::now() + self.timeout;
                wait(self.stream, PollFlags::POLLIN, deadline)?;
                match self.stream.read(&mut trailing) {
                    Ok(0) => Ok(()),
                    _ => Err(RuntimeError::Contract),
                }
            }
            Err(_) => Err(RuntimeError::TransportUnavailable),
        }
    }
}

fn wait(stream: &UnixStream, flags: PollFlags, deadline: Instant) -> RuntimeResult<()> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(RuntimeError::Timeout)?;
    let millis = remaining.as_millis().clamp(1, u128::from(u16::MAX));
    let timeout = u16::try_from(millis).map_err(|_| RuntimeError::Timeout)?;
    let mut descriptors = [PollFd::new(stream.as_fd(), flags)];
    let ready = poll(&mut descriptors, timeout).map_err(|_| RuntimeError::TransportUnavailable)?;
    if ready == 0 {
        return Err(RuntimeError::Timeout);
    }
    let events = descriptors[0].revents().unwrap_or(PollFlags::empty());
    if events.intersects(PollFlags::POLLERR | PollFlags::POLLNVAL) {
        return Err(RuntimeError::TransportUnavailable);
    }
    Ok(())
}

#[cfg(test)]
#[path = "unix_tests.rs"]
mod tests;
