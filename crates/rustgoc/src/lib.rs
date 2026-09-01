#![forbid(unsafe_code)]

//! Rustgo private-network client runtime.

mod app;
mod control;
mod exports;
mod forwards;
mod orchestration;
mod peer;
mod session;
mod tcp;
mod telemetry;
mod udp;

pub use app::{ActiveGeneration, ClientApp, ClientStatus, ReconnectBackoff};
pub use control::{
    CLIENT_VERSION, ClientError, ControlClient, ControlEvent, ControlSession, RegisteredTunnel,
};
pub use exports::{AuthorizedExport, ExportError, ExportRegistry, PeerOpenRequest, PeerOpenResult};
pub use forwards::{
    BoxPeerDatagramSession, BoxPeerStream, ForwardConnector, ForwardError, ForwardRuntime,
    ForwardRuntimeOptions, PeerDatagramSession, PeerFuture, PeerIo,
};
pub use peer::{
    PeerRelayChannel, PeerRuntimeError, PeerSessionHandle, PeerSessionRuntime,
    PeerSessionRuntimeOptions,
};
pub use session::{
    ChildSessionContext, ChildSessionRequest, ChildSessionSupervisor, NoopChildSessionSupervisor,
    PeerGenerationHandler, SessionGeneration,
};
#[doc(hidden)]
pub use telemetry::{TelemetryControlWriteGate, TelemetryRuntimeHook};
