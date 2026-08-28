#![forbid(unsafe_code)]

//! Pure, bounded candidate discovery inputs and NAT mapping evidence.

mod candidate;
mod observation;
mod predict;
mod tcp_punch;

pub use candidate::{CandidateGatherer, CandidateInput};
pub use observation::{MappingEvidence, Observation, analyze_mappings};
pub use predict::{PredictionPolicy, predicted_ports};
pub use tcp_punch::{
    MAX_TCP_PUNCH_CANDIDATES, TcpPunchCandidates, TcpPunchError, TcpPunchMode, TcpPuncher,
};
