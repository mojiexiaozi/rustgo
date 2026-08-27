#![forbid(unsafe_code)]

//! Rustgo public relay server runtime.

mod app;
mod auth;
mod control;
mod registry;
mod tcp;
mod udp;

pub use app::{ServerApp, ServerError, ServerRuntimeLimits};
pub use auth::AuthenticatedClient;
pub use registry::{AuthenticatedDataChannel, ClientRegistry, ControlSessionGuard, RegistryError};
