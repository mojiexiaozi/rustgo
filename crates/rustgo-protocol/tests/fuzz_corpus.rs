use std::{collections::BTreeSet, fs, path::PathBuf};

use rustgo_protocol::{FrameCodec, MAX_UDP_PAYLOAD_BYTES, MessageId, UDP_METADATA_LEN};

const PRODUCTION_MAX_PAYLOAD: usize = UDP_METADATA_LEN + MAX_UDP_PAYLOAD_BYTES;

#[test]
fn checked_in_fuzz_corpus_contains_one_valid_frame_per_message_family() {
    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("fuzz/corpus/frame_decode");
    let codec = FrameCodec::new(PRODUCTION_MAX_PAYLOAD);
    let mut decoded_ids = BTreeSet::new();

    for entry in fs::read_dir(&corpus).expect("frame decoder corpus directory must exist") {
        let path = entry.expect("corpus entry must be readable").path();
        if path.is_file() {
            let bytes = fs::read(&path).expect("corpus seed must be readable");
            let frame = codec
                .decode_exact(&bytes)
                .unwrap_or_else(|error| panic!("{} is not a valid frame: {error}", path.display()));
            decoded_ids.insert(frame.message.id().as_u16());
        }
    }

    let expected = [
        MessageId::CLIENT_HELLO,
        MessageId::SERVER_CHALLENGE,
        MessageId::CLIENT_AUTHENTICATE,
        MessageId::AUTH_RESULT,
        MessageId::REGISTER_TUNNELS,
        MessageId::TUNNEL_RESULTS,
        MessageId::OPEN_TCP_STREAM,
        MessageId::TCP_STREAM_READY,
        MessageId::UDP_DATAGRAM,
        MessageId::HEARTBEAT,
        MessageId::ERROR,
        MessageId::OPEN_UDP_CHANNEL,
        MessageId::DATA_CHANNEL_BIND,
        MessageId::UDP_SESSION_RETIRED,
    ]
    .map(MessageId::as_u16)
    .into_iter()
    .collect::<BTreeSet<_>>();

    assert_eq!(decoded_ids, expected);
}
