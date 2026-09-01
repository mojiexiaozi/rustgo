use serde::{Deserialize, Serialize};

use crate::ProtocolErrorCode;

/// A wire protocol version. Major versions must match; minor versions negotiate down.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl ProtocolVersion {
    pub const V0_1: Self = Self::new(1, 0);
    pub const V0_2: Self = Self::new(1, 1);
    pub const V0_3: Self = Self::new(1, 2);
    pub const SUPPORTED: Self = Self::V0_3;

    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    /// Negotiates the shared version, rejecting incompatible major versions.
    pub const fn negotiate(self, peer: Self) -> Result<Self, ProtocolErrorCode> {
        if self.major != peer.major {
            return Err(ProtocolErrorCode::UNSUPPORTED_VERSION);
        }
        Ok(Self::new(self.major, min_u16(self.minor, peer.minor)))
    }

    /// Returns whether a negotiated version includes the V0.3 telemetry
    /// message family.
    pub const fn supports_telemetry(self) -> bool {
        self.major == Self::V0_3.major && self.minor >= Self::V0_3.minor
    }
}

const fn min_u16(left: u16, right: u16) -> u16 {
    if left < right { left } else { right }
}
