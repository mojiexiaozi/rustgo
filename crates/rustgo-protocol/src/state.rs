use thiserror::Error;

use crate::{BoundedBytes, MAX_SESSION_ID_BYTES, Message, ProtocolErrorCode};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientHandshakeState {
    AwaitingHello,
    AwaitingChallenge,
    AwaitingAuthenticate {
        session_id: BoundedBytes<MAX_SESSION_ID_BYTES>,
    },
    AwaitingAuthResult {
        session_id: BoundedBytes<MAX_SESSION_ID_BYTES>,
    },
    AwaitingTunnelRegistration {
        session_id: BoundedBytes<MAX_SESSION_ID_BYTES>,
    },
    Active {
        session_id: BoundedBytes<MAX_SESSION_ID_BYTES>,
    },
    Rejected,
}

impl Default for ClientHandshakeState {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientHandshakeState {
    pub const fn new() -> Self {
        Self::AwaitingHello
    }

    /// Validates one control message and returns the next state without mutating this state.
    pub fn transition(&self, message: &Message) -> Result<Self, StateError> {
        match (self, message) {
            (Self::AwaitingHello, Message::ClientHello(_)) => Ok(Self::AwaitingChallenge),
            (Self::AwaitingChallenge, Message::ServerChallenge(challenge)) => {
                Ok(Self::AwaitingAuthenticate {
                    session_id: challenge.session_id.clone(),
                })
            }
            (Self::AwaitingAuthenticate { session_id }, Message::ClientAuthenticate(_)) => {
                Ok(Self::AwaitingAuthResult {
                    session_id: session_id.clone(),
                })
            }
            (Self::AwaitingAuthResult { session_id }, Message::AuthResult(result)) => {
                if result.accepted {
                    Ok(Self::AwaitingTunnelRegistration {
                        session_id: session_id.clone(),
                    })
                } else {
                    Ok(Self::Rejected)
                }
            }
            (Self::AwaitingTunnelRegistration { session_id }, Message::RegisterTunnels(_)) => {
                Ok(Self::Active {
                    session_id: session_id.clone(),
                })
            }
            (Self::Active { .. }, Message::Heartbeat(_)) => Ok(self.clone()),
            (Self::Active { .. }, Message::OpenTcpStream(_) | Message::OpenUdpChannel(_)) => {
                Ok(self.clone())
            }
            _ => Err(StateError::invalid_state()),
        }
    }

    pub const fn is_active(&self) -> bool {
        matches!(self, Self::Active { .. })
    }

    pub const fn is_rejected(&self) -> bool {
        matches!(self, Self::Rejected)
    }

    /// Checks that a data channel names the session established by this active control channel.
    pub fn validate_data_channel_session(&self, candidate: &[u8]) -> Result<(), StateError> {
        match self {
            Self::Active { session_id } if session_id.as_slice() == candidate => Ok(()),
            Self::Active { .. } => Err(StateError::unknown_session()),
            _ => Err(StateError::invalid_state()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("protocol state rejected operation with error code {code:?}")]
pub struct StateError {
    pub code: ProtocolErrorCode,
}

impl StateError {
    pub const fn invalid_state() -> Self {
        Self {
            code: ProtocolErrorCode::INVALID_STATE,
        }
    }

    pub const fn unknown_session() -> Self {
        Self {
            code: ProtocolErrorCode::UNKNOWN_SESSION,
        }
    }
}
