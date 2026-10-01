use super::{FrameTransport, MemoryFrameTransport};
use crate::RuntimeError;

#[test]
fn frames_are_ordered_bounded_and_closed() {
    let mut transport = MemoryFrameTransport::with_inbound([b"request".to_vec()]);
    assert_eq!(
        transport.read_frame().expect("frame").as_slice(),
        b"request"
    );
    transport.expect_eof().expect("eof");
    transport.write_frame(b"receipt").expect("write");
    transport.finish_writes().expect("finish");
    assert_eq!(transport.outbound().next(), Some(b"receipt".as_slice()));
    assert_eq!(transport.write_frame(b"late"), Err(RuntimeError::Contract));
}
