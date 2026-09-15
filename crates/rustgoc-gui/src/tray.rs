#![forbid(unsafe_code)]

#[cfg(windows)]
pub mod platform {
    use crate::tray_events::TrayEvent;
    use std::sync::mpsc;
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
        pub fn new(
            event_tx: mpsc::SyncSender<TrayEvent>,
            ctx: eframe::egui::Context,
        ) -> anyhow::Result<Self> {
            let menu = Menu::new();

            let show_item = MenuItem::with_id("1", "显示", true, None);
            let connect_item = MenuItem::with_id("2", "连接", true, None);
            let disconnect_item = MenuItem::with_id("3", "断开", true, None);
            let quit_item = MenuItem::with_id("4", "退出", true, None);

            menu.append(&show_item)?;
            menu.append(&connect_item)?;
            menu.append(&disconnect_item)?;
            menu.append(&quit_item)?;

            let tray = TrayIconBuilder::new()
                .with_menu(Box::new(menu))
                .with_icon(rustgo_icon()?)
                .with_menu_on_left_click(false)
                .with_tooltip("Rustgo 客户端")
                .build()?;

            let tx_clone = event_tx.clone();
            let menu_ctx = ctx.clone();
            MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
                if let Ok(id) = event.id().0.parse::<u32>()
                    && let Some(event) = crate::tray_events::decode_menu_id(id)
                {
                    let _ = tx_clone.try_send(event);
                    menu_ctx.request_repaint();
                }
            }));
            let tx_clone = event_tx.clone();
            tray_icon::TrayIconEvent::set_event_handler(Some(move |event| {
                if matches!(
                    event,
                    tray_icon::TrayIconEvent::DoubleClick {
                        button: tray_icon::MouseButton::Left,
                        ..
                    } | tray_icon::TrayIconEvent::Click {
                        button: tray_icon::MouseButton::Left,
                        button_state: tray_icon::MouseButtonState::Up,
                        ..
                    }
                ) {
                    let _ = tx_clone.try_send(TrayEvent::Show);
                    ctx.request_repaint();
                }
            }));

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

    fn rustgo_icon() -> anyhow::Result<tray_icon::Icon> {
        Ok(tray_icon::Icon::from_rgba(
            crate::app_icon::rgba(32),
            32,
            32,
        )?)
    }
}

#[cfg(not(windows))]
pub mod platform {
    pub struct TrayIcon;
}
