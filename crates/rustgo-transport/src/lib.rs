#![forbid(unsafe_code)]

//! Transport interfaces for Rustgo.

mod backoff;
mod copy;
mod tls;

pub use backoff::{
    Backoff, BackoffClock, BackoffConfig, BackoffError, JitterSource, RandomJitter,
    SystemBackoffClock,
};
pub use copy::{COPY_BUFFER_SIZE, CopyError, CopyReport, copy_bidirectional_bounded};
pub use tls::{
    BindingError, ChannelBinding, ChannelBindingStore, ChannelKind, TlsClient, TlsError, TlsServer,
};
