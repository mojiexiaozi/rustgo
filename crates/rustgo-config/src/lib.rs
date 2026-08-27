#![forbid(unsafe_code)]

//! Shared configuration support for Rustgo.

mod load;
mod model;
mod validate;

pub use load::{
    ConfigError, check_client_references, check_server_references, load_client,
    load_client_with_lookup, load_server, load_server_with_lookup,
};
pub use model::{
    AuthorizedClient, ClientConfig, ClientSection, Limits, ServerConfig, ServerSection,
    TunnelConfig, TunnelProtocol,
};
pub use validate::ValidationError;
