#![forbid(unsafe_code)]

use crate::state::tunnels::TunnelRow;
use eframe::egui::Ui;

pub struct TunnelsPanel;

impl TunnelsPanel {
    pub fn new() -> Self {
        Self
    }

    pub fn show(&mut self, ui: &mut Ui, tunnels: &[TunnelRow]) {
        ui.heading("隧道");
        ui.separator();

        if tunnels.is_empty() {
            ui.label("未配置隧道");
            return;
        }

        eframe::egui::Grid::new("tunnels_grid")
            .striped(true)
            .num_columns(6)
            .show(ui, |ui| {
                ui.label("ID");
                ui.label("名称");
                ui.label("协议");
                ui.label("本地");
                ui.label("远程端口");
                ui.label("状态");
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
                        ui.colored_label(eframe::egui::Color32::GREEN, "已接受");
                    } else {
                        ui.label("等待中");
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
