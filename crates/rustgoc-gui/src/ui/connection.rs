#![forbid(unsafe_code)]

use crate::state::connection::{ConnectionState, ConnectionViewModel};
use crate::ui::formatting::format_bytes;
use eframe::egui::Ui;

pub struct ConnectionPanel {
    server_address: String,
}

impl ConnectionPanel {
    pub fn new(server_address: String) -> Self {
        Self { server_address }
    }

    pub fn set_server_address(&mut self, server_address: String) {
        self.server_address = server_address;
    }

    pub fn show(
        &mut self,
        ui: &mut Ui,
        vm: &mut ConnectionViewModel,
        sent_bytes: Option<u64>,
        received_bytes: Option<u64>,
    ) {
        ui.heading("连接");
        ui.separator();

        ui.horizontal(|ui| {
            ui.label("服务器：");
            ui.monospace(&self.server_address);
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
