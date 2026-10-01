use std::os::unix::net::UnixStream;
use std::thread;
use std::time::Duration;

use super::{FrameTransport, UnixFrameTransport};

#[test]
fn unix_transport_exchanges_closed_length_prefixed_frames() {
    let (mut client_stream, mut server_stream) = UnixStream::pair().expect("pair");
    let server = thread::spawn(move || {
        let mut transport = UnixFrameTransport::new(&mut server_stream, Duration::from_secs(1))
            .expect("server transport");
        assert_eq!(
            transport.read_frame().expect("request").as_slice(),
            b"request"
        );
        transport.expect_eof().expect("client eof");
        transport.write_frame(b"receipt").expect("receipt");
        transport.finish_writes().expect("server eof");
    });
    let mut transport = UnixFrameTransport::new(&mut client_stream, Duration::from_secs(1))
        .expect("client transport");
    transport.write_frame(b"request").expect("request");
    transport.finish_writes().expect("client eof");
    assert_eq!(
        transport.read_frame().expect("receipt").as_slice(),
        b"receipt"
    );
    transport.expect_eof().expect("server eof");
    server.join().expect("server");
}
