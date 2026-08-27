#![forbid(unsafe_code)]

//! Rustgo private-network client runtime.

mod app;
mod control;
mod session;
mod tcp;

pub use app::{ActiveGeneration, ClientApp, ClientStatus, ReconnectBackoff};
pub use control::{CLIENT_VERSION, ClientError, ControlClient, ControlSession, RegisteredTunnel};
pub use session::{
    ChildSessionContext, ChildSessionRequest, ChildSessionSupervisor, NoopChildSessionSupervisor,
    SessionGeneration,
};
