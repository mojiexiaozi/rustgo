#![forbid(unsafe_code)]
use eframe::egui::{self, Ui};
use rustgo_config::{ClientConfig, P2pConfig, PortRange};
use std::path::PathBuf;

pub struct ConfigPanel {
    config: Option<ClientConfig>,
    config_path: PathBuf,
    error: Option<String>,
    success: Option<String>,
}

impl ConfigPanel {
    pub fn config(&self) -> Option<&ClientConfig> {
        self.config.as_ref()
    }

    pub fn new(config_path: PathBuf) -> Self {
        let mut panel = Self {
            config: None,
            config_path,
            error: None,
            success: None,
        };
        panel.reload();
        panel
    }
    pub fn config_mut(&mut self) -> Option<&mut ClientConfig> {
        self.config.as_mut()
    }
    pub fn server_address(&self) -> Option<&str> {
        self.config.as_ref().map(|c| c.client.server_addr.as_str())
    }
    pub fn reload(&mut self) {
        match crate::configuration::load_or_create(&self.config_path) {
            Ok(c) => {
                self.config = Some(c);
                self.error = None;
            }
            Err(e) => self.error = Some(format!("配置加载失败: {e}")),
        }
    }
    pub fn save(&mut self) -> anyhow::Result<()> {
        let c = self
            .config
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("配置尚未加载"))?;
        crate::configuration::save_validated(&self.config_path, c)?;
        self.success = Some("配置已保存并生效".into());
        self.error = None;
        Ok(())
    }
    pub fn set_save_error(&mut self, error: &anyhow::Error) {
        self.success = None;
        self.error = Some(format!("保存失败：{error:#}"));
    }
    pub fn show(&mut self, ui: &mut Ui, apply: &mut bool) {
        ui.heading("配置");
        ui.separator();
        if let Some(e) = &self.error {
            ui.colored_label(eframe::egui::Color32::RED, e);
        }
        if let Some(m) = &self.success {
            ui.colored_label(eframe::egui::Color32::DARK_GREEN, m);
        }
        let Some(c) = self.config.as_mut() else {
            ui.label("无法读取配置，请检查软件目录写入权限。");
            return;
        };
        eframe::egui::Grid::new("client-settings")
            .num_columns(2)
            .show(ui, |ui| {
                ui.label("客户端名称");
                ui.text_edit_singleline(&mut c.client.name);
                ui.end_row();
                ui.label("服务器地址");
                ui.text_edit_singleline(&mut c.client.server_addr);
                ui.end_row();
                ui.label("心跳间隔（秒）");
                ui.add(
                    eframe::egui::DragValue::new(&mut c.client.heartbeat_interval_secs)
                        .range(1..=3600),
                );
                ui.end_row();
            });
        ui.add_space(12.0);
        ui.collapsing("P2P 全局设置", |ui| {
            let p = c.p2p.get_or_insert_with(default_p2p);
            ui.checkbox(&mut p.enabled, "启用 P2P");
            ui.checkbox(&mut p.prefer_direct, "优先直连");
            ui.checkbox(&mut p.allow_relay_fallback, "允许中继回退");
            ui.horizontal(|ui| {
                ui.label("直连超时");
                ui.add(egui::DragValue::new(&mut p.direct_timeout_secs).range(1..=300));
                ui.label("秒");
            });
            ui.horizontal(|ui| {
                ui.label("重连超时");
                ui.add(egui::DragValue::new(&mut p.reconnect_timeout_secs).range(1..=3600));
                ui.label("秒");
            });
            ui.horizontal(|ui| {
                ui.label("UDP 端口范围");
                ui.add(egui::DragValue::new(&mut p.udp_port_range.start).range(1..=65535));
                ui.label("至");
                ui.add(egui::DragValue::new(&mut p.udp_port_range.end).range(1..=65535));
            });
            ui.horizontal(|ui| {
                ui.label("TCP 端口范围");
                ui.add(egui::DragValue::new(&mut p.tcp_port_range.start).range(1..=65535));
                ui.label("至");
                ui.add(egui::DragValue::new(&mut p.tcp_port_range.end).range(1..=65535));
            });
            optional_address(ui, "主观测地址", &mut p.observation_primary_addr);
            optional_address(ui, "备用观测地址", &mut p.observation_alternate_addr);
        });
        ui.add_space(12.0);
        if ui.button("保存并生效").clicked() {
            *apply = true;
        }
    }
}

fn optional_address(ui: &mut Ui, label: &str, value: &mut Option<String>) {
    let mut text = value.clone().unwrap_or_default();
    ui.horizontal(|ui| {
        ui.label(label);
        if ui
            .add_sized([210.0, 24.0], egui::TextEdit::singleline(&mut text))
            .changed()
        {
            let trimmed = text.trim();
            *value = (!trimmed.is_empty()).then(|| trimmed.to_owned());
        }
    });
}
pub(super) fn default_p2p() -> P2pConfig {
    P2pConfig {
        enabled: false,
        prefer_direct: true,
        direct_timeout_secs: 10,
        reconnect_timeout_secs: 30,
        allow_relay_fallback: true,
        udp_port_range: PortRange {
            start: 20000,
            end: 21023,
        },
        tcp_port_range: PortRange {
            start: 22000,
            end: 23023,
        },
        observation_primary_addr: None,
        observation_alternate_addr: None,
    }
}

#[cfg(test)]
mod tests {
    use super::ConfigPanel;
    use std::fs;
    #[test]
    fn save_preserves_dynamic_identity_and_p2p_collections() {
        let d = tempfile::TempDir::new().unwrap();
        let p = d.path().join("client.toml");
        fs::write(&p,"[client]\nname='device'\nidentity_mode='dynamic'\nserver_addr='host:8443'\nserver_name='host'\ncertificate_authority_file='ca.pem'\nprivate_key_file='device.key'\nheartbeat_interval_secs=30\n\n[p2p]\nenabled=true\nprefer_direct=true\ndirect_timeout_secs=10\nreconnect_timeout_secs=30\nallow_relay_fallback=true\nudp_port_range='20000-20010'\ntcp_port_range='21000-21010'\n\n[[exports]]\nname='ssh'\nprotocol='tcp'\nlocal_addr='127.0.0.1:22'\n\n[[forwards]]\nname='peer-ssh'\npeer='peer'\nexport='ssh'\nlisten_addr='127.0.0.1:10022'\n").unwrap();
        let mut panel = ConfigPanel::new(p.clone());
        panel.save().unwrap();
        let c = rustgo_config::load_client(&p).unwrap();
        assert_eq!(
            c.client.identity_mode,
            Some(rustgo_config::IdentityMode::Dynamic)
        );
        assert_eq!(c.exports.len(), 1);
        assert_eq!(c.forwards.len(), 1);
        assert!(c.p2p.unwrap().enabled);
    }
}
