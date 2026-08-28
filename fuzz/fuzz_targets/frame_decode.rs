#![no_main]

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use rustgo_protocol::{FrameCodec, MAX_UDP_PAYLOAD_BYTES, UDP_METADATA_LEN};

const PRODUCTION_MAX_PAYLOAD: usize = UDP_METADATA_LEN + MAX_UDP_PAYLOAD_BYTES;

fuzz_target!(|data: &[u8]| {
    let codec = FrameCodec::new(PRODUCTION_MAX_PAYLOAD);

    // Exercise both the exact-frame and incremental decoder. Header limits are
    // inspected before either path waits for or copies a declared payload.
    let _ = codec.decode_exact(data);
    let mut streaming = BytesMut::from(data);
    let _ = codec.decode(&mut streaming);
});
