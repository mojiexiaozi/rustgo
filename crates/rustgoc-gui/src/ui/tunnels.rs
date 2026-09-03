#![forbid(unsafe_code)]

use crate::state::tunnels::TunnelRow;
use eframe::egui::Ui;

pub struct TunnelsPanel;

impl TunnelsPanel {
    pub fn new() -> Self {
        Self
    }

    pub fn show(&mut self, ui: &mut Ui, tunnels: &[TunnelRow]) {
        ui.heading("Tunnels");
        ui.separator();

        if tunnels.is_empty() {
            ui.label("No tunnels configured");
            return;
        }

        eframe::egui::Grid::new("tunnels_grid")
            .striped(true)
            .num_columns(6)
            .show(ui, |ui| {
                ui.label("ID");
                ui.label("Name");
                ui.label("Protocol");
                ui.label("Local");
                ui.label("Remote Port");
                ui.label("Status");
                ui.end_row();

                for tunnel in tunnels {
                    ui.monospace(tunnel.tunnel_id.to_string());
                    ui.label(&tunnel.name);
                    ui.label(&tunnel.protocol);
                    ui.monospace(&tunnel.local_addr);
                    ui.monospace(tunnel.remote_port.to_string());

                    if let Some(error) = &tunnel.error {
                        ui.colored_label(eframe::egui::Color32::RED, error);
                    } else if tunnel.accepted {
                        ui.colored_label(eframe::egui::Color32::GREEN, "Accepted");
                    } else {
                        ui.label("Pending");
                    }

                    ui.end_row();
                }
            });
    }
}

impl Default for TunnelsPanel {
    fn default() -> Self {
        Self::new()
    }
}
