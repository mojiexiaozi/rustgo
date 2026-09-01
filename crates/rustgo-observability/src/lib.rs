#![forbid(unsafe_code)]

//! Bounded, non-blocking observability events and immutable runtime snapshots.

mod model;
mod store;

pub use model::*;
pub use store::{
    EVENT_QUEUE_CAPACITY, ObservabilitySink, ObservabilityStore, ObservabilityWorker,
    ObservationEvent, PublishError,
};
