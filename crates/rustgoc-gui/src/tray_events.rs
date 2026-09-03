#![forbid(unsafe_code)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayEvent {
    Show,
    Connect,
    Disconnect,
    Quit,
}

#[cfg(windows)]
pub fn decode_menu_id(id: u32) -> Option<TrayEvent> {
    match id {
        1 => Some(TrayEvent::Show),
        2 => Some(TrayEvent::Connect),
        3 => Some(TrayEvent::Disconnect),
        4 => Some(TrayEvent::Quit),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(windows)]
    fn test_decode_valid_menu_ids() {
        assert_eq!(decode_menu_id(1), Some(TrayEvent::Show));
        assert_eq!(decode_menu_id(2), Some(TrayEvent::Connect));
        assert_eq!(decode_menu_id(3), Some(TrayEvent::Disconnect));
        assert_eq!(decode_menu_id(4), Some(TrayEvent::Quit));
    }

    #[test]
    #[cfg(windows)]
    fn test_decode_invalid_menu_id() {
        assert_eq!(decode_menu_id(0), None);
        assert_eq!(decode_menu_id(5), None);
        assert_eq!(decode_menu_id(999), None);
    }

    #[test]
    fn test_event_equality() {
        assert_eq!(TrayEvent::Show, TrayEvent::Show);
        assert_ne!(TrayEvent::Show, TrayEvent::Quit);
    }
}
