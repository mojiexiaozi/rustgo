#![forbid(unsafe_code)]

//! Transport interfaces for Rustgo.

mod backoff;
mod copy;
mod logging;
mod peer_tcp;
mod quic;
mod tls;

pub use backoff::{
    Backoff, BackoffClock, BackoffConfig, BackoffError, JitterSource, RandomJitter,
    SystemBackoffClock,
};
pub use copy::{COPY_BUFFER_SIZE, CopyError, CopyReport, copy_bidirectional_bounded};
pub use logging::{
    EventRateLimit, SafeDisplay, init as init_logging, safe_context, safe_display,
    short_fingerprint, short_id,
};
pub use peer_tcp::{
    EncryptedPeerTcp, MAX_PEER_TCP_PLAINTEXT_BYTES, PeerTcpAuthentication,
    PeerTcpAuthenticationFactory, PeerTcpError, TcpPathAttempt,
};
pub use quic::{
    MAX_PEER_DATAGRAM_BYTES, PeerAuthentication, PeerAuthenticationFactory, PeerDatagram,
    PeerStream, QuicPathAttempt, QuicPeerConfig, QuicPeerEndpoint, QuicPeerError,
    QuicPeerPathHandle, QuicPeerSession, QuicPunchConfig,
};
pub use tls::{
    BindingError, ChannelBinding, ChannelBindingStore, ChannelKind, TlsClient, TlsError, TlsServer,
};
