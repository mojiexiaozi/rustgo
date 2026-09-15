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
    pub fn status(&self) -> watch::Ref<'_, ClientStatus> {
        self.status_rx.borrow()
    }
    pub fn authentication_rejected(&self) -> bool {
        self.status_rx.borrow().authentication_rejected()
    }
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

pub fn transition_message(
    previous: &ConnectionState,
    current: &ConnectionState,
    server: &str,
) -> Option<String> {
    if previous == current {
        return None;
    }
    match (previous, current) {
        (_, ConnectionState::Connected { .. }) => Some(format!("连接成功：{server}")),
        // A new ClientApp briefly publishes its default disconnected state before
        // registration completes. Waiting for Backoff avoids a false failure log.
        (ConnectionState::Connecting, ConnectionState::Disconnected) => None,
        (ConnectionState::Connected { .. }, ConnectionState::Disconnected) => {
            Some(format!("连接已断开：{server}，客户端将自动重试"))
        }
        (_, ConnectionState::Backoff { seconds }) => {
            Some(format!("连接失败：{server}，{seconds} 秒后重试"))
        }
        _ => None,
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

    #[test]
    fn transition_messages_cover_success_failure_and_disconnect() {
        assert!(
            super::transition_message(
                &ConnectionState::Connecting,
                &ConnectionState::Connected { generation: 1 },
                "server:8443"
            )
            .unwrap()
            .contains("连接成功")
        );
        assert_eq!(
            super::transition_message(
                &ConnectionState::Connecting,
                &ConnectionState::Disconnected,
                "server:8443"
            ),
            None
        );
        assert!(
            super::transition_message(
                &ConnectionState::Connecting,
                &ConnectionState::Backoff { seconds: 5 },
                "server:8443"
            )
            .unwrap()
            .contains("连接失败")
        );
        assert!(
            super::transition_message(
                &ConnectionState::Connected { generation: 1 },
                &ConnectionState::Disconnected,
                "server:8443"
            )
            .unwrap()
            .contains("连接已断开")
        );
    }
}
