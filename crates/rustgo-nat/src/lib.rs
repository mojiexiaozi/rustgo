#![forbid(unsafe_code)]

//! Pure, bounded candidate discovery inputs and NAT mapping evidence.

mod candidate;
mod observation;
mod predict;

pub use candidate::{CandidateGatherer, CandidateInput};
pub use observation::{MappingEvidence, Observation, analyze_mappings};
pub use predict::{PredictionPolicy, predicted_ports};
