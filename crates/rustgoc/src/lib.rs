#![forbid(unsafe_code)]

//! Rustgo private-network client runtime.

pub use rustgo_protocol::EnrollmentErrorCode;

mod app;
mod control;
mod enrollment;
mod exports;
mod forwards;
mod orchestration;
mod path_status;
mod peer;
mod session;
mod tcp;
mod telemetry;
mod udp;

pub use app::{ActiveGeneration, ClientApp, ClientStatus, ReconnectBackoff};
pub use control::{
    CLIENT_VERSION, ClientError, ControlClient, ControlEvent, ControlSession, RegisteredTunnel,
    update_managed_configuration,
};
pub use enrollment::{
    EnrollmentCompletion, EnrollmentError, EnrollmentKey, EnrollmentPurpose, EnrollmentState,
    PendingEnrollment, classify_enrollment_state, client_config_path, enroll,
    recover_pending_enrollment, request_key_rotation, request_registration, run_managed_client,
    wait_for_registration,
};
pub use exports::{AuthorizedExport, ExportError, ExportRegistry, PeerOpenRequest, PeerOpenResult};
pub use forwards::{
    BoxPeerDatagramSession, BoxPeerStream, ForwardConnector, ForwardError, ForwardRuntime,
    ForwardRuntimeOptions, PeerDatagramSession, PeerFuture, PeerIo,
};
pub use path_status::{PathKindStatus, PathStatus, PathStatusStore};
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
pub use telemetry::{TrafficHandle, TrafficSnapshot};
