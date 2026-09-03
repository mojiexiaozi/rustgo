#![forbid(unsafe_code)]
#![allow(dead_code)]

use rustgoc::ClientStatus;
use tokio::sync::watch;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected { generation: u64 },
    Backoff { seconds: u64 },
}

pub struct ConnectionViewModel {
    status_rx: watch::Receiver<ClientStatus>,
    local_state: ConnectionState,
}

impl ConnectionViewModel {
    pub fn new(status_rx: watch::Receiver<ClientStatus>) -> Self {
        Self {
            status_rx,
            local_state: ConnectionState::Disconnected,
        }
    }

    pub fn update(&mut self) -> ConnectionState {
        if self.status_rx.has_changed().unwrap_or(false) {
            let status = self.status_rx.borrow_and_update();
            self.local_state = if let Some(active) = status.active() {
                ConnectionState::Connected {
                    generation: active.generation().get(),
                }
            } else {
                ConnectionState::Disconnected
            };
        }
        self.local_state.clone()
    }

    pub fn mark_connecting(&mut self) {
        self.local_state = ConnectionState::Connecting;
    }

    pub fn mark_backoff(&mut self, seconds: u64) {
        self.local_state = ConnectionState::Backoff { seconds };
    }

    pub fn current(&self) -> &ConnectionState {
        &self.local_state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_disconnected() {
        let (tx, rx) = watch::channel(ClientStatus::default());
        let vm = ConnectionViewModel::new(rx);
        assert_eq!(vm.current(), &ConnectionState::Disconnected);
        drop(tx);
    }

    #[test]
    fn test_mark_connecting() {
        let (_tx, rx) = watch::channel(ClientStatus::default());
        let mut vm = ConnectionViewModel::new(rx);
        vm.mark_connecting();
        assert_eq!(vm.current(), &ConnectionState::Connecting);
    }

    #[test]
    fn test_mark_backoff() {
        let (_tx, rx) = watch::channel(ClientStatus::default());
        let mut vm = ConnectionViewModel::new(rx);
        vm.mark_backoff(30);
        assert_eq!(vm.current(), &ConnectionState::Backoff { seconds: 30 });
    }
}
