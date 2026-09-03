#![forbid(unsafe_code)]

use crate::state::connection::{ConnectionState, ConnectionViewModel};
use crate::ui::formatting::format_bytes;
use eframe::egui::Ui;

pub struct ConnectionPanel {
    pub server_address: String,
}

impl ConnectionPanel {
    pub fn new(server_address: String) -> Self {
        Self { server_address }
    }

    pub fn show(
        &mut self,
        ui: &mut Ui,
        vm: &mut ConnectionViewModel,
        on_connect: &mut bool,
        on_disconnect: &mut bool,
        sent_bytes: Option<u64>,
        received_bytes: Option<u64>,
    ) {
        ui.heading("连接");
        ui.separator();

        ui.horizontal(|ui| {
            ui.label("服务器：");
            ui.add(
                eframe::egui::TextEdit::singleline(&mut self.server_address)
                    .desired_width(300.0)
                    .hint_text("例如: 127.0.0.1:8443"),
            );
        });

        ui.add_space(10.0);

        let state = vm.current();
        ui.horizontal(|ui| {
            ui.label("状态：");
            match state {
                ConnectionState::Disconnected => {
                    ui.label("已断开");
                }
                ConnectionState::Connecting => {
                    ui.label("连接中...");
                }
                ConnectionState::Connected { generation } => {
                    ui.label(format!("已连接 (代 {})", generation));
                }
                ConnectionState::Backoff { seconds } => {
                    ui.label(format!("重试中 ({}秒后重试)", seconds));
                }
            }
        });

        ui.add_space(10.0);

        ui.horizontal(|ui| {
            let can_connect = matches!(state, ConnectionState::Disconnected);
            let can_disconnect = matches!(state, ConnectionState::Connected { .. });

            if ui
                .add_enabled(can_connect, eframe::egui::Button::new("连接"))
                .clicked()
            {
                *on_connect = true;
            }

            if ui
                .add_enabled(can_disconnect, eframe::egui::Button::new("断开"))
                .clicked()
            {
                *on_disconnect = true;
            }
        });

        ui.add_space(10.0);

        ui.heading("流量");
        ui.separator();

        match (sent_bytes, received_bytes) {
            (Some(sent), Some(received)) => {
                ui.horizontal(|ui| {
                    ui.label("发送：");
                    ui.monospace(format_bytes(sent));
                });
                ui.horizontal(|ui| {
                    ui.label("接收：");
                    ui.monospace(format_bytes(received));
                });
            }
            _ => {
                ui.label("流量统计不可用");
            }
        }
    }
}
