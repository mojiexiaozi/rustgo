#![forbid(unsafe_code)]

use crate::tray_events::TrayEvent;
use std::sync::mpsc;

#[cfg(windows)]
pub mod platform {
    use super::*;
    use tray_icon::{
        TrayIcon as SystemTrayIcon, TrayIconBuilder,
        menu::{Menu, MenuEvent, MenuItem},
    };

    pub struct TrayIcon {
        _tray: SystemTrayIcon,
        _event_tx: mpsc::SyncSender<TrayEvent>,
        _show_item: MenuItem,
        _connect_item: MenuItem,
        _disconnect_item: MenuItem,
        _quit_item: MenuItem,
    }

    impl TrayIcon {
        pub fn new(event_tx: mpsc::SyncSender<TrayEvent>) -> anyhow::Result<Self> {
            let menu = Menu::new();

            let show_item = MenuItem::with_id("1", "Show", true, None);
            let connect_item = MenuItem::with_id("2", "Connect", true, None);
            let disconnect_item = MenuItem::with_id("3", "Disconnect", true, None);
            let quit_item = MenuItem::with_id("4", "Quit", true, None);

            menu.append(&show_item)?;
            menu.append(&connect_item)?;
            menu.append(&disconnect_item)?;
            menu.append(&quit_item)?;

            let tray = TrayIconBuilder::new()
                .with_menu(Box::new(menu))
                .with_tooltip("Rustgo Client")
                .build()?;

            let menu_rx = MenuEvent::receiver();
            let tx_clone = event_tx.clone();

            std::thread::spawn(move || {
                while let Ok(event) = menu_rx.recv() {
                    if let Ok(id_str) = event.id().0.parse::<u32>()
                        && let Some(tray_event) = crate::tray_events::decode_menu_id(id_str)
                    {
                        let _ = tx_clone.send(tray_event);
                    }
                }
            });

            Ok(Self {
                _tray: tray,
                _event_tx: event_tx,
                _show_item: show_item,
                _connect_item: connect_item,
                _disconnect_item: disconnect_item,
                _quit_item: quit_item,
            })
        }
    }
}

#[cfg(not(windows))]
pub mod platform {
    use super::*;

    pub struct TrayIcon;

    impl TrayIcon {
        pub fn new(_event_tx: mpsc::SyncSender<TrayEvent>) -> anyhow::Result<Self> {
            Ok(Self)
        }
    }
}
