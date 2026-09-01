#![forbid(unsafe_code)]

//! Bounded, non-blocking observability events and immutable runtime snapshots.

mod model;
mod store;

pub use model::*;
pub use store::{
    EVENT_QUEUE_CAPACITY, MAX_TERMINAL_SESSIONS, ObservabilitySink, ObservabilityStore,
    ObservabilityWorker, ObservationEvent, PublishError,
};
