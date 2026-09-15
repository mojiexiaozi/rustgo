#![forbid(unsafe_code)]
use crate::state::{p2p::P2PViewModel, tunnels::TunnelRow};
use eframe::egui::{self, Ui};
use rustgo_config::{
    ClientConfig, ExportConfig, ForwardConfig, P2pConfig, PortRange, TunnelConfig, TunnelProtocol,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardEntryKind {
    TcpTunnel,
    UdpTunnel,
    P2pExport,
    P2pForward,
}
impl ForwardEntryKind {
    fn label(self) -> &'static str {
        match self {
            Self::TcpTunnel => "TCP 隧道",
            Self::UdpTunnel => "UDP 隧道",
            Self::P2pExport => "P2P 导出",
            Self::P2pForward => "P2P 转发",
        }
    }
}
pub struct ForwardingPanel {
    pub managed: crate::state::managed::ManagedViewModel,
    pub saving: bool,
    pub save_managed: bool,
    pub reload_managed: bool,
    kind: ForwardEntryKind,
    name: String,
    local: String,
    port: u32,
    protocol: TunnelProtocol,
    peers: String,
    peer: String,
    export: String,
    listen: String,
    message: Option<String>,
}

impl Default for ForwardingPanel {
    fn default() -> Self {
        Self::new()
    }
}

impl ForwardingPanel {
    pub fn new() -> Self {
        Self {
            managed: Default::default(),
            saving: false,
            save_managed: false,
            reload_managed: false,
            kind: ForwardEntryKind::TcpTunnel,
            name: String::new(),
            local: "127.0.0.1:22".into(),
            port: 10022,
            protocol: TunnelProtocol::Tcp,
            peers: String::new(),
            peer: String::new(),
            export: String::new(),
            listen: "127.0.0.1:10022".into(),
            message: None,
        }
    }
    pub fn set_message(&mut self, m: impl Into<String>) {
        self.message = Some(m.into());
    }
    pub fn show(
        &mut self,
        ui: &mut Ui,
        config: Option<&mut ClientConfig>,
        tunnels: &[TunnelRow],
        p2p: &P2PViewModel,
        save: &mut bool,
    ) {
        ui.heading("转发");
        ui.label(format!(
            "运行中隧道：{}　活跃 P2P 路径：{}",
            tunnels.len(),
            p2p.rows(now_millis()).len()
        ));
        ui.separator();
        let Some(c) = config else {
            ui.label("配置不可用");
            return;
        };
        ui.add_enabled_ui(!self.saving, |ui| {
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
        });
        ui.separator();
        ui.heading("隧道配置");
        let is_managed = self.managed.draft().is_some();
        if is_managed {
            ui.strong(format!(
                "客户端与服务器同步 · 配置版本 {}",
                self.managed.draft_revision().unwrap_or(0)
            ));
            if self.managed.dirty() {
                ui.label("有未保存的修改");
            }
            if self.managed.revision() != self.managed.draft_revision() {
                ui.colored_label(
                    egui::Color32::YELLOW,
                    format!(
                        "服务器已有新修订号 {}，请重新加载后合并修改",
                        self.managed.revision().unwrap_or(0)
                    ),
                );
            }
            if ui
                .add_enabled(
                    !self.saving,
                    egui::Button::new("重新加载服务器配置（丢弃草稿）"),
                )
                .clicked()
            {
                self.reload_managed = true;
            }
            if ui
                .add_enabled(!self.saving, egui::Button::new("保存本地 P2P 设置并生效"))
                .clicked()
            {
                *save = true;
            }
        }
        let mut remote = c.clone();
        if let Some(draft) = self.managed.draft() {
            remote.tunnels = draft.tunnels.clone();
            remote.exports = draft.exports.clone();
            remote.forwards = draft.forwards.clone();
        }
        let c = if is_managed { &mut remote } else { c };
        ui.add_enabled_ui(!self.saving, |ui| {
            let mut remove = None;
            ui.with_layout(
                egui::Layout::left_to_right(egui::Align::Min).with_main_wrap(true),
                |ui| {
                    ui.spacing_mut().item_spacing = egui::vec2(12.0, 12.0);
                    for (i, x) in c.tunnels.iter_mut().enumerate() {
                        compact_card(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.strong(if x.protocol == TunnelProtocol::Tcp {
                                    "TCP 隧道"
                                } else {
                                    "UDP 隧道"
                                });
                                ui.add_sized(
                                    [150.0, 24.0],
                                    egui::TextEdit::singleline(&mut x.name),
                                );
                                if ui.small_button("删除").clicked() {
                                    remove = Some(i);
                                }
                            });
                            ui.horizontal(|ui| {
                                ui.label("本地地址");
                                ui.add_sized(
                                    [165.0, 24.0],
                                    egui::TextEdit::singleline(&mut x.local_addr),
                                );
                            });
                            ui.horizontal(|ui| {
                                ui.label("远程端口");
                                ui.add(egui::DragValue::new(&mut x.remote_port).range(1..=65535));
                            });
                            let runtime = tunnels.iter().find(|row| row.name == x.name);
                            let (color, label, detail) = match runtime {
                                Some(row) if row.error.is_some() || !row.accepted => (
                                    egui::Color32::from_rgb(220, 65, 65),
                                    "转发失败",
                                    row.error.as_deref().unwrap_or("服务端拒绝该隧道"),
                                ),
                                Some(_) => (
                                    egui::Color32::from_rgb(45, 170, 95),
                                    "正常转发",
                                    "隧道已获服务端接受；此状态不代表实时连通性检测结果",
                                ),
                                None => {
                                    (ui.visuals().weak_text_color(), "未就绪", "暂无隧道运行状态")
                                }
                            };
                            egui::Frame::new()
                                .fill(color.gamma_multiply(0.12))
                                .stroke(egui::Stroke::new(1.0, color))
                                .corner_radius(4.0)
                                .inner_margin(egui::Margin::symmetric(8, 4))
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        let (rect, _) = ui.allocate_exact_size(
                                            egui::vec2(8.0, 8.0),
                                            egui::Sense::hover(),
                                        );
                                        ui.painter().circle_filled(rect.center(), 4.0, color);
                                        ui.label(egui::RichText::new(label).color(color).strong());
                                    });
                                })
                                .response
                                .on_hover_text(detail);
                            if runtime.is_some_and(|row| row.error.is_some() || !row.accepted) {
                                ui.colored_label(color, detail);
                            }
                        });
                    }
                },
            );
            if let Some(i) = remove {
                c.tunnels.remove(i);
            }
            let mut remove = None;
            ui.with_layout(
                egui::Layout::left_to_right(egui::Align::Min).with_main_wrap(true),
                |ui| {
                    ui.spacing_mut().item_spacing = egui::vec2(12.0, 12.0);
                    for (i, x) in c.exports.iter_mut().enumerate() {
                        compact_card(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.strong("P2P 导出");
                                ui.add_sized(
                                    [150.0, 24.0],
                                    egui::TextEdit::singleline(&mut x.name),
                                );
                                if ui.small_button("删除").clicked() {
                                    remove = Some(i);
                                }
                            });
                            ui.horizontal(|ui| {
                                egui::ComboBox::from_id_salt(("existing-export-protocol", i))
                                    .selected_text(protocol_label(x.protocol))
                                    .show_ui(ui, |ui| {
                                        ui.selectable_value(
                                            &mut x.protocol,
                                            TunnelProtocol::Tcp,
                                            "TCP",
                                        );
                                        ui.selectable_value(
                                            &mut x.protocol,
                                            TunnelProtocol::Udp,
                                            "UDP",
                                        );
                                    });
                            });
                            ui.horizontal(|ui| {
                                ui.label("本地地址");
                                ui.add_sized(
                                    [165.0, 24.0],
                                    egui::TextEdit::singleline(&mut x.local_addr),
                                );
                            });
                            let mut peers = x.allowed_peers.join(", ");
                            ui.horizontal(|ui| {
                                ui.label("允许客户端");
                                if ui
                                    .add_sized(
                                        [205.0, 24.0],
                                        egui::TextEdit::singleline(&mut peers),
                                    )
                                    .changed()
                                {
                                    x.allowed_peers = parse_peers(&peers);
                                }
                            });
                        });
                    }
                },
            );
            if let Some(i) = remove {
                c.exports.remove(i);
            }
            let mut remove = None;
            ui.with_layout(
                egui::Layout::left_to_right(egui::Align::Min).with_main_wrap(true),
                |ui| {
                    ui.spacing_mut().item_spacing = egui::vec2(12.0, 12.0);
                    for (i, x) in c.forwards.iter_mut().enumerate() {
                        compact_card(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.strong("P2P 转发");
                                ui.add_sized(
                                    [150.0, 24.0],
                                    egui::TextEdit::singleline(&mut x.name),
                                );
                                if ui.small_button("删除").clicked() {
                                    remove = Some(i);
                                }
                            });
                            ui.horizontal(|ui| {
                                ui.label("监听地址");
                                ui.add_sized(
                                    [165.0, 24.0],
                                    egui::TextEdit::singleline(&mut x.listen_addr),
                                );
                            });
                            ui.horizontal(|ui| {
                                ui.label("目标客户端");
                                ui.add_sized(
                                    [100.0, 24.0],
                                    egui::TextEdit::singleline(&mut x.peer),
                                );
                            });
                            ui.horizontal(|ui| {
                                ui.label("导出名称");
                                ui.add_sized(
                                    [100.0, 24.0],
                                    egui::TextEdit::singleline(&mut x.export),
                                );
                            });
                        });
                    }
                },
            );
            if let Some(i) = remove {
                c.forwards.remove(i);
            }
            ui.separator();
            ui.heading("添加配置");
            egui::ComboBox::from_id_salt("forward-kind")
                .selected_text(self.kind.label())
                .show_ui(ui, |ui| {
                    for k in [
                        ForwardEntryKind::TcpTunnel,
                        ForwardEntryKind::UdpTunnel,
                        ForwardEntryKind::P2pExport,
                        ForwardEntryKind::P2pForward,
                    ] {
                        ui.selectable_value(&mut self.kind, k, k.label());
                    }
                });
            ui.horizontal(|ui| {
                ui.label("名称");
                ui.add_sized([180.0, 24.0], egui::TextEdit::singleline(&mut self.name));
            });
            match self.kind {
                ForwardEntryKind::TcpTunnel | ForwardEntryKind::UdpTunnel => {
                    ui.horizontal(|ui| {
                        ui.label("本地地址");
                        ui.add_sized([210.0, 24.0], egui::TextEdit::singleline(&mut self.local));
                    });
                    ui.horizontal(|ui| {
                        ui.label("远程端口");
                        ui.add(egui::DragValue::new(&mut self.port).range(1..=65535));
                    });
                }
                ForwardEntryKind::P2pExport => {
                    egui::ComboBox::from_id_salt("export-protocol")
                        .selected_text(if self.protocol == TunnelProtocol::Tcp {
                            "TCP"
                        } else {
                            "UDP"
                        })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.protocol, TunnelProtocol::Tcp, "TCP");
                            ui.selectable_value(&mut self.protocol, TunnelProtocol::Udp, "UDP");
                        });
                    ui.horizontal(|ui| {
                        ui.label("本地地址");
                        ui.text_edit_singleline(&mut self.local);
                    });
                    ui.horizontal(|ui| {
                        ui.label("允许客户端（逗号分隔）");
                        ui.text_edit_singleline(&mut self.peers);
                    });
                }
                ForwardEntryKind::P2pForward => {
                    ui.horizontal(|ui| {
                        ui.label("目标客户端");
                        ui.text_edit_singleline(&mut self.peer);
                    });
                    ui.horizontal(|ui| {
                        ui.label("导出名称");
                        ui.text_edit_singleline(&mut self.export);
                    });
                    ui.horizontal(|ui| {
                        ui.label("监听地址");
                        ui.text_edit_singleline(&mut self.listen);
                    });
                }
            }
            if ui.button("添加").clicked() {
                match self.validated_candidate(c) {
                    Ok(candidate) => {
                        *c = candidate;
                        self.name.clear();
                        self.message = Some("已添加，点击保存并生效后应用".into());
                    }
                    Err(reason) => {
                        self.message = Some(format!("添加失败：{reason}"));
                    }
                }
            }
            if let Some(m) = &self.message {
                if m.starts_with("添加失败") || m.starts_with("保存失败") {
                    ui.colored_label(egui::Color32::RED, m);
                } else {
                    ui.label(m);
                }
            }
            ui.add_space(8.0);
            if ui
                .button(if is_managed {
                    "保存到服务器并生效"
                } else {
                    "保存并生效"
                })
                .clicked()
            {
                if is_managed {
                    self.save_managed = true;
                } else {
                    *save = true;
                }
            }
        });
        if is_managed {
            let mut draft = rustgo_config::ManagedConfiguration::from_client(c);
            draft.p2p_enabled = self.managed.draft().unwrap().p2p_enabled;
            self.managed.edit(draft);
        }
    }

    fn validated_candidate(&self, current: &ClientConfig) -> Result<ClientConfig, String> {
        let name = self.name.trim();
        if name.is_empty() {
            return Err("名称不能为空".into());
        }
        if current
            .tunnels
            .iter()
            .any(|x| x.name.eq_ignore_ascii_case(name))
            || current
                .exports
                .iter()
                .any(|x| x.name.eq_ignore_ascii_case(name))
            || current
                .forwards
                .iter()
                .any(|x| x.name.eq_ignore_ascii_case(name))
        {
            return Err(format!("名称“{name}”已存在"));
        }

        let mut candidate = current.clone();
        match self.kind {
            ForwardEntryKind::TcpTunnel | ForwardEntryKind::UdpTunnel => {
                let protocol = if self.kind == ForwardEntryKind::TcpTunnel {
                    TunnelProtocol::Tcp
                } else {
                    TunnelProtocol::Udp
                };
                if current
                    .tunnels
                    .iter()
                    .any(|x| x.protocol == protocol && x.remote_port == self.port)
                {
                    return Err(format!(
                        "{} 远程端口 {} 已被占用",
                        protocol_label(protocol),
                        self.port
                    ));
                }
                candidate.tunnels.push(TunnelConfig {
                    name: name.into(),
                    protocol,
                    local_addr: self.local.trim().into(),
                    remote_port: self.port,
                });
            }
            ForwardEntryKind::P2pExport => candidate.exports.push(ExportConfig {
                name: name.into(),
                protocol: self.protocol,
                local_addr: self.local.trim().into(),
                allowed_peers: parse_peers(&self.peers),
            }),
            ForwardEntryKind::P2pForward => {
                let listen = self.listen.trim();
                if current.forwards.iter().any(|x| x.listen_addr == listen) {
                    return Err(format!("监听地址“{listen}”已被其他转发占用"));
                }
                candidate.forwards.push(ForwardConfig {
                    name: name.into(),
                    peer: self.peer.trim().into(),
                    export: self.export.trim().into(),
                    listen_addr: listen.into(),
                });
            }
        }
        candidate
            .validate()
            .map_err(|error| format_validation_error(&error.to_string()))?;
        Ok(candidate)
    }
}

fn format_validation_error(error: &str) -> String {
    let detail = error
        .strip_prefix("invalid configuration: ")
        .unwrap_or(error);
    if detail.contains("must include a host and port") {
        "地址格式错误，应填写“IP或主机名:端口”".into()
    } else if detail.contains("must contain a valid host") {
        "地址中的 IP 或主机名不合法".into()
    } else if detail.contains("has an invalid port") || detail.contains("invalid remote port") {
        "端口不合法，应在 1 到 65535 之间".into()
    } else if detail.contains("must not target the local client") {
        "P2P 转发不能指向当前客户端".into()
    } else {
        detail.into()
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
fn compact_card(ui: &mut Ui, content: impl FnOnce(&mut Ui)) {
    ui.allocate_ui_with_layout(
        egui::vec2(320.0, 0.0),
        egui::Layout::top_down(egui::Align::Min),
        |ui| {
            egui::Frame::group(ui.style())
                .inner_margin(6)
                .show(ui, |ui| {
                    ui.set_width(306.0);
                    ui.spacing_mut().item_spacing.y = 3.0;
                    ui.vertical(content);
                });
        },
    );
}
fn parse_peers(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect()
}
fn protocol_label(protocol: TunnelProtocol) -> &'static str {
    match protocol {
        TunnelProtocol::Tcp => "TCP",
        TunnelProtocol::Udp => "UDP",
    }
}
fn default_p2p() -> P2pConfig {
    P2pConfig {
        enabled: true,
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
fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
#[cfg(test)]
mod tests {
    use super::{ForwardEntryKind, ForwardingPanel, parse_peers};
    #[test]
    fn managed_cards_allow_add_and_never_replace_saved_source() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("client.toml");
        let mut config_panel = crate::ui::config::ConfigPanel::new(path.clone());
        let config = config_panel.config_mut().unwrap();
        config.p2p = Some(super::default_p2p());
        config.tunnels.push(rustgo_config::TunnelConfig {
            name: "local-tunnel".into(),
            protocol: rustgo_config::TunnelProtocol::Tcp,
            local_addr: "127.0.0.1:22".into(),
            remote_port: 2222,
        });
        config.exports.push(rustgo_config::ExportConfig {
            name: "local-export".into(),
            protocol: rustgo_config::TunnelProtocol::Tcp,
            local_addr: "127.0.0.1:22".into(),
            allowed_peers: vec![],
        });
        config.forwards.push(rustgo_config::ForwardConfig {
            name: "local-forward".into(),
            peer: "other".into(),
            export: "ssh".into(),
            listen_addr: "127.0.0.1:10022".into(),
        });
        let local = config_panel.config().unwrap().clone();
        let mut panel = ForwardingPanel::new();
        panel.name = "new-tunnel".into();
        panel.managed.select_server("server:8443");
        panel.managed.observe(
            true,
            Some(3),
            Some(&rustgo_config::ManagedConfiguration {
                tunnels: vec![],
                exports: vec![],
                forwards: vec![],
                p2p_enabled: false,
            }),
        );
        let mut remote = local.clone();
        remote.tunnels.clear();
        remote.exports.clear();
        remote.forwards.clear();
        let added = panel.validated_candidate(&remote).unwrap();
        panel
            .managed
            .edit(rustgo_config::ManagedConfiguration::from_client(&added));
        assert_eq!(panel.managed.draft().unwrap().tunnels[0].name, "new-tunnel");
        assert!(panel.managed.dirty());
        let context = eframe::egui::Context::default();
        let p2p = crate::state::p2p::P2PViewModel::new(rustgoc::PathStatusStore::new());
        let mut save = false;
        let mut output = context.run_ui(Default::default(), |ui| {
            panel.show(ui, config_panel.config_mut(), &[], &p2p, &mut save);
        });
        output.textures_delta.clear();
        assert_eq!(panel.managed.draft().unwrap().tunnels[0].name, "new-tunnel");
        assert!(panel.managed.dirty());
        config_panel
            .config_mut()
            .unwrap()
            .client
            .heartbeat_interval_secs = 45;
        config_panel.save().unwrap();
        let saved = rustgo_config::load_client(&path).unwrap();
        assert_eq!(saved.tunnels, local.tunnels);
        assert_eq!(saved.exports, local.exports);
        assert_eq!(saved.forwards, local.forwards);
        assert_eq!(saved.client.heartbeat_interval_secs, 45);
    }
    #[test]
    fn selector_has_exactly_four_types() {
        let k = [
            ForwardEntryKind::TcpTunnel,
            ForwardEntryKind::UdpTunnel,
            ForwardEntryKind::P2pExport,
            ForwardEntryKind::P2pForward,
        ];
        assert_eq!(
            k.map(ForwardEntryKind::label),
            ["TCP 隧道", "UDP 隧道", "P2P 导出", "P2P 转发"]
        );
    }

    #[test]
    fn peer_editor_normalizes_comma_separated_names() {
        assert_eq!(
            parse_peers("alpha, beta, ,gamma"),
            ["alpha", "beta", "gamma"]
        );
    }

    #[test]
    fn invalid_or_conflicting_entry_does_not_change_configuration() {
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("client.toml");
        let mut config = crate::configuration::load_or_create(&path).unwrap();
        config.tunnels.push(rustgo_config::TunnelConfig {
            name: "ssh".into(),
            protocol: rustgo_config::TunnelProtocol::Tcp,
            local_addr: "127.0.0.1:22".into(),
            remote_port: 2222,
        });
        let before = config.clone();

        let mut panel = ForwardingPanel::new();
        panel.name = "ssh".into();
        assert_eq!(
            panel.validated_candidate(&config).unwrap_err(),
            "名称“ssh”已存在"
        );
        assert_eq!(config, before);

        panel.name = "bad-address".into();
        panel.local = "127.0.0.1".into();
        assert!(
            panel
                .validated_candidate(&config)
                .unwrap_err()
                .contains("地址格式错误")
        );
        assert_eq!(config, before);
    }

    #[test]
    fn duplicate_remote_port_is_rejected_before_add() {
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("client.toml");
        let mut config = crate::configuration::load_or_create(&path).unwrap();
        config.tunnels.push(rustgo_config::TunnelConfig {
            name: "ssh".into(),
            protocol: rustgo_config::TunnelProtocol::Tcp,
            local_addr: "127.0.0.1:22".into(),
            remote_port: 2222,
        });
        let mut panel = ForwardingPanel::new();
        panel.name = "other".into();
        panel.port = 2222;
        assert!(
            panel
                .validated_candidate(&config)
                .unwrap_err()
                .contains("远程端口 2222 已被占用")
        );
    }
}
