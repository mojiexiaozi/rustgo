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

    pub fn show(
        &mut self,
        ui: &mut Ui,
        vm: &mut ConnectionViewModel,
        on_connect: &mut bool,
        on_disconnect: &mut bool,
        sent_bytes: Option<u64>,
        received_bytes: Option<u64>,
    ) {
        ui.heading("Connection");
        ui.separator();

        ui.horizontal(|ui| {
            ui.label("Server:");
            ui.monospace(&self.server_address);
        });

        ui.add_space(10.0);

        let state = vm.current();
        ui.horizontal(|ui| {
            ui.label("Status:");
            match state {
                ConnectionState::Disconnected => {
                    ui.label("Disconnected");
                }
                ConnectionState::Connecting => {
                    ui.label("Connecting...");
                }
                ConnectionState::Connected { generation } => {
                    ui.label(format!("Connected (generation {})", generation));
                }
                ConnectionState::Backoff { seconds } => {
                    ui.label(format!("Backoff (retry in {}s)", seconds));
                }
            }
        });

        ui.add_space(10.0);

        ui.horizontal(|ui| {
            let can_connect = matches!(state, ConnectionState::Disconnected);
            let can_disconnect = matches!(state, ConnectionState::Connected { .. });

            if ui
                .add_enabled(can_connect, eframe::egui::Button::new("Connect"))
                .clicked()
            {
                *on_connect = true;
            }

            if ui
                .add_enabled(can_disconnect, eframe::egui::Button::new("Disconnect"))
                .clicked()
            {
                *on_disconnect = true;
            }
        });

        ui.add_space(10.0);

        ui.heading("Traffic");
        ui.separator();

        match (sent_bytes, received_bytes) {
            (Some(sent), Some(received)) => {
                ui.horizontal(|ui| {
                    ui.label("Sent:");
                    ui.monospace(format_bytes(sent));
                });
                ui.horizontal(|ui| {
                    ui.label("Received:");
                    ui.monospace(format_bytes(received));
                });
            }
            _ => {
                ui.label("Traffic counters not available");
            }
        }
    }
}
