#![forbid(unsafe_code)]

use eframe::egui::{self, Ui};
use rustgo_config::{ClientConfig, IdentityMode, TunnelConfig, TunnelProtocol};
use std::path::PathBuf;

pub struct ConfigPanel {
    // In-memory config being edited
    config: Option<ClientConfig>,
    config_path: PathBuf,

    // UI state
    error_message: Option<String>,
    success_message: Option<String>,
    #[allow(dead_code)]
    selected_tunnel_index: Option<usize>,

    // New tunnel form
    show_add_tunnel: bool,
    new_tunnel_name: String,
    new_tunnel_protocol: TunnelProtocol,
    new_tunnel_local_addr: String,
    new_tunnel_remote_port: String,

    // File picker state
    show_ca_picker: bool,
    show_key_picker: bool,
}

impl ConfigPanel {
    pub fn new(config_path: PathBuf) -> Self {
        Self {
            config: None,
            config_path,
            error_message: None,
            success_message: None,
            selected_tunnel_index: None,
            show_add_tunnel: false,
            new_tunnel_name: String::new(),
            new_tunnel_protocol: TunnelProtocol::Tcp,
            new_tunnel_local_addr: String::new(),
            new_tunnel_remote_port: String::new(),
            show_ca_picker: false,
            show_key_picker: false,
        }
    }

    pub fn load_config(&mut self) {
        self.clear_messages();
        match rustgo_config::load_client(&self.config_path) {
            Ok(config) => {
                self.config = Some(config);
                self.success_message = Some("配置加载成功".to_string());
            }
            Err(e) => {
                self.error_message = Some(format!("配置加载失败: {}", e));
            }
        }
    }

    fn clear_messages(&mut self) {
        self.error_message = None;
        self.success_message = None;
    }

    fn save_config(&mut self) -> anyhow::Result<()> {
        let config = self
            .config
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("没有配置需要保存"))?;

        // Validate config before saving
        config
            .validate()
            .map_err(|e| anyhow::anyhow!("配置验证失败: {}", e))?;

        // Serialize the entire config to TOML
        // Note: This will lose comments and formatting from original file
        let identity_mode = match config.client.identity_mode {
            Some(IdentityMode::Static) => "identity_mode = \"static\"\n",
            Some(IdentityMode::Dynamic) => "identity_mode = \"dynamic\"\n",
            None => "",
        };
        let toml_content = format!(
            "[client]\n\
            name = \"{}\"\n\
            {}\
            server_addr = \"{}\"\n\
            server_name = \"{}\"\n\
            certificate_authority_file = \"{}\"\n\
            private_key_file = \"{}\"\n\
            heartbeat_interval_secs = {}\n\n",
            config.client.name,
            identity_mode,
            config.client.server_addr,
            config.client.server_name,
            config.client.certificate_authority_file.display(),
            config.client.private_key_file.display(),
            config.client.heartbeat_interval_secs
        );

        let mut full_content = toml_content;

        // Add tunnels
        for tunnel in &config.tunnels {
            full_content.push_str(&format!(
                "[[tunnels]]\n\
                name = \"{}\"\n\
                protocol = \"{}\"\n\
                local_addr = \"{}\"\n\
                remote_port = {}\n\n",
                tunnel.name,
                match tunnel.protocol {
                    TunnelProtocol::Tcp => "tcp",
                    TunnelProtocol::Udp => "udp",
                },
                tunnel.local_addr,
                tunnel.remote_port
            ));
        }

        // Atomic write: temp file -> fsync -> rename
        let temp_path = self.config_path.with_extension("toml.tmp");

        {
            use std::io::Write;
            let mut file = std::fs::File::create(&temp_path)?;
            file.write_all(full_content.as_bytes())?;
            file.sync_all()?; // fsync
        }

        // Atomic rename
        std::fs::rename(&temp_path, &self.config_path)?;

        Ok(())
    }

    pub fn show(&mut self, ui: &mut Ui, on_save_and_reconnect: &mut bool) {
        ui.heading("配置");
        ui.separator();

        // Show messages
        if let Some(ref error) = self.error_message {
            ui.colored_label(egui::Color32::RED, error);
            ui.add_space(5.0);
        }
        if let Some(ref success) = self.success_message {
            ui.colored_label(egui::Color32::GREEN, success);
            ui.add_space(5.0);
        }

        // Load config button if not loaded
        if self.config.is_none() {
            if ui.button("加载配置").clicked() {
                self.load_config();
            }
            return;
        }

        // Clone necessary values to avoid borrow conflicts
        let mut generate_keypair = false;
        let mut show_ca_picker = self.show_ca_picker;
        let mut show_key_picker = self.show_key_picker;
        let mut new_ca_path: Option<PathBuf> = None;
        let mut new_key_path: Option<PathBuf> = None;

        egui::ScrollArea::vertical().show(ui, |ui| {
            let config = self.config.as_mut().unwrap();

            // Server Configuration
            ui.heading("服务器配置");
            ui.separator();
            ui.add_space(5.0);

            ui.horizontal(|ui| {
                ui.label("客户端名称：");
                ui.text_edit_singleline(&mut config.client.name);
            });

            ui.horizontal(|ui| {
                ui.label("服务器地址：");
                ui.text_edit_singleline(&mut config.client.server_addr);
            });

            ui.horizontal(|ui| {
                ui.label("服务器名称：");
                ui.text_edit_singleline(&mut config.client.server_name);
            });

            ui.horizontal(|ui| {
                ui.label("CA 证书：");
                let path_str = config
                    .client
                    .certificate_authority_file
                    .display()
                    .to_string();
                let mut path_edit = path_str.clone();
                ui.text_edit_singleline(&mut path_edit);
                if path_edit != path_str {
                    config.client.certificate_authority_file = PathBuf::from(path_edit);
                }
                if ui.button("浏览...").clicked() {
                    show_ca_picker = true;
                }
            });

            ui.horizontal(|ui| {
                ui.label("设备私钥：");
                let path_str = config.client.private_key_file.display().to_string();
                let mut path_edit = path_str.clone();
                ui.text_edit_singleline(&mut path_edit);
                if path_edit != path_str {
                    config.client.private_key_file = PathBuf::from(path_edit);
                }
                if ui.button("浏览...").clicked() {
                    show_key_picker = true;
                }
                if ui.button("生成...").clicked() {
                    generate_keypair = true;
                }
            });

            ui.horizontal(|ui| {
                ui.label("心跳间隔（秒）：");
                let mut interval = config.client.heartbeat_interval_secs.to_string();
                if ui.text_edit_singleline(&mut interval).changed()
                    && let Ok(val) = interval.parse::<u64>()
                {
                    config.client.heartbeat_interval_secs = val;
                }
            });

            ui.add_space(10.0);

            // Tunnel Configuration
            ui.heading("隧道配置");
            ui.separator();
            ui.add_space(5.0);

            // Tunnel table
            egui::Grid::new("tunnel_grid")
                .striped(true)
                .min_col_width(80.0)
                .show(ui, |ui| {
                    ui.label("名称");
                    ui.label("协议");
                    ui.label("本地地址");
                    ui.label("远程端口");
                    ui.label("操作");
                    ui.end_row();

                    let mut to_remove = None;
                    for (idx, tunnel) in config.tunnels.iter_mut().enumerate() {
                        ui.text_edit_singleline(&mut tunnel.name);

                        let protocol_str = match tunnel.protocol {
                            TunnelProtocol::Tcp => "TCP",
                            TunnelProtocol::Udp => "UDP",
                        };
                        egui::ComboBox::from_id_salt(format!("protocol_{}", idx))
                            .selected_text(protocol_str)
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut tunnel.protocol,
                                    TunnelProtocol::Tcp,
                                    "TCP",
                                );
                                ui.selectable_value(
                                    &mut tunnel.protocol,
                                    TunnelProtocol::Udp,
                                    "UDP",
                                );
                            });

                        ui.text_edit_singleline(&mut tunnel.local_addr);

                        let mut port_str = tunnel.remote_port.to_string();
                        if ui.text_edit_singleline(&mut port_str).changed()
                            && let Ok(port) = port_str.parse::<u32>()
                        {
                            tunnel.remote_port = port;
                        }

                        if ui.button("删除").clicked() {
                            to_remove = Some(idx);
                        }
                        ui.end_row();
                    }

                    if let Some(idx) = to_remove {
                        config.tunnels.remove(idx);
                    }
                });

            ui.add_space(5.0);

            // Add tunnel button
            if ui.button("添加隧道").clicked() {
                self.show_add_tunnel = true;
                self.new_tunnel_name.clear();
                self.new_tunnel_protocol = TunnelProtocol::Tcp;
                self.new_tunnel_local_addr.clear();
                self.new_tunnel_remote_port.clear();
            }

            ui.add_space(10.0);
        });

        // Handle file pickers outside the scroll area
        if show_ca_picker {
            if let Some(path) = rfd::FileDialog::new()
                .add_filter("PEM", &["pem"])
                .pick_file()
            {
                new_ca_path = Some(path);
            }
            self.show_ca_picker = false;
        } else {
            self.show_ca_picker = show_ca_picker;
        }

        if show_key_picker {
            if let Some(path) = rfd::FileDialog::new()
                .add_filter("Key", &["key", "pem"])
                .pick_file()
            {
                new_key_path = Some(path);
            }
            self.show_key_picker = false;
        } else {
            self.show_key_picker = show_key_picker;
        }

        // Apply file picker results
        if let Some(path) = new_ca_path
            && let Some(config) = self.config.as_mut()
        {
            config.client.certificate_authority_file = path;
        }

        if let Some(path) = new_key_path
            && let Some(config) = self.config.as_mut()
        {
            config.client.private_key_file = path;
        }

        // Handle keypair generation
        if generate_keypair {
            let key_dir = if let Some(config) = self.config.as_ref() {
                config
                    .client
                    .private_key_file
                    .parent()
                    .map(|p| p.to_path_buf())
            } else {
                None
            };

            if let Some(dir) = key_dir {
                match rustgo_crypto::generate_key_file(&dir) {
                    Ok(public_key) => {
                        let private_path = dir.join("device.key");
                        let public_path = dir.join("device.pub");

                        // Update config to use the generated key
                        if let Some(config) = self.config.as_mut() {
                            config.client.private_key_file = private_path.clone();
                        }

                        self.success_message = Some(format!(
                            "密钥对已生成:\n私钥: {}\n公钥: {}\n公钥指纹: {}",
                            private_path.display(),
                            public_path.display(),
                            public_key
                        ));
                    }
                    Err(e) => {
                        self.error_message = Some(format!("密钥生成失败: {}", e));
                    }
                }
            } else {
                self.error_message = Some("无法确定密钥目录".to_string());
            }
        }

        // Add tunnel dialog
        if self.show_add_tunnel {
            egui::Window::new("添加隧道")
                .collapsible(false)
                .resizable(false)
                .show(ui.ctx(), |ui| {
                    ui.horizontal(|ui| {
                        ui.label("名称：");
                        ui.text_edit_singleline(&mut self.new_tunnel_name);
                    });

                    ui.horizontal(|ui| {
                        ui.label("协议：");
                        egui::ComboBox::from_id_salt("new_protocol")
                            .selected_text(match self.new_tunnel_protocol {
                                TunnelProtocol::Tcp => "TCP",
                                TunnelProtocol::Udp => "UDP",
                            })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut self.new_tunnel_protocol,
                                    TunnelProtocol::Tcp,
                                    "TCP",
                                );
                                ui.selectable_value(
                                    &mut self.new_tunnel_protocol,
                                    TunnelProtocol::Udp,
                                    "UDP",
                                );
                            });
                    });

                    ui.horizontal(|ui| {
                        ui.label("本地地址：");
                        ui.text_edit_singleline(&mut self.new_tunnel_local_addr);
                    });

                    ui.horizontal(|ui| {
                        ui.label("远程端口：");
                        ui.text_edit_singleline(&mut self.new_tunnel_remote_port);
                    });

                    ui.horizontal(|ui| {
                        if ui.button("添加").clicked()
                            && let Ok(port) = self.new_tunnel_remote_port.parse::<u32>()
                            && let Some(config) = self.config.as_mut()
                        {
                            config.tunnels.push(TunnelConfig {
                                name: self.new_tunnel_name.clone(),
                                protocol: self.new_tunnel_protocol,
                                local_addr: self.new_tunnel_local_addr.clone(),
                                remote_port: port,
                            });
                            self.show_add_tunnel = false;
                        }
                        if ui.button("取消").clicked() {
                            self.show_add_tunnel = false;
                        }
                    });
                });
        }

        // Action buttons at the bottom
        ui.separator();
        ui.horizontal(|ui| {
            if ui.button("重新加载").clicked() {
                self.load_config();
            }

            if ui.button("保存").clicked() {
                self.clear_messages();
                match self.save_config() {
                    Ok(_) => {
                        self.success_message = Some("配置已保存".to_string());
                    }
                    Err(e) => {
                        self.error_message = Some(format!("保存失败: {}", e));
                    }
                }
            }

            if ui.button("保存并重新连接").clicked() {
                self.clear_messages();
                match self.save_config() {
                    Ok(_) => {
                        self.success_message = Some("配置已保存，正在重新连接...".to_string());
                        *on_save_and_reconnect = true;
                    }
                    Err(e) => {
                        self.error_message = Some(format!("保存失败: {}", e));
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use rustgo_config::{ClientConfig, ClientSection, IdentityMode};

    use super::ConfigPanel;

    #[test]
    fn saving_dynamic_configuration_preserves_identity_mode() {
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("client.toml");
        let mut panel = ConfigPanel::new(path.clone());
        panel.config = Some(ClientConfig {
            client: ClientSection {
                name: "dynamic-device".to_owned(),
                identity_mode: Some(IdentityMode::Dynamic),
                server_addr: "server.example:7443".to_owned(),
                server_name: "server.example".to_owned(),
                certificate_authority_file: "ca.pem".into(),
                trust_mode: None,
                server_certificate_fingerprint: None,
                private_key_file: "device.key".into(),
                heartbeat_interval_secs: 20,
            },
            p2p: None,
            telemetry: None,
            tunnels: Vec::new(),
            exports: Vec::new(),
            forwards: Vec::new(),
        });

        panel.save_config().unwrap();

        let saved = std::fs::read_to_string(path).unwrap();
        assert!(saved.contains("identity_mode = \"dynamic\""));
    }
}
