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
        });
        ui.separator();
        ui.heading("配置项");
        let mut remove = None;
        for (i, x) in c.tunnels.iter().enumerate() {
            ui.horizontal(|ui| {
                ui.strong(if x.protocol == TunnelProtocol::Tcp {
                    "TCP 隧道"
                } else {
                    "UDP 隧道"
                });
                ui.label(format!("{}　{} → :{}", x.name, x.local_addr, x.remote_port));
                if ui.small_button("删除").clicked() {
                    remove = Some(i);
                }
            });
        }
        if let Some(i) = remove {
            c.tunnels.remove(i);
        }
        let mut remove = None;
        for (i, x) in c.exports.iter().enumerate() {
            ui.horizontal(|ui| {
                ui.strong("P2P 导出");
                ui.label(format!("{}　{} ({:?})", x.name, x.local_addr, x.protocol));
                if ui.small_button("删除").clicked() {
                    remove = Some(i);
                }
            });
        }
        if let Some(i) = remove {
            c.exports.remove(i);
        }
        let mut remove = None;
        for (i, x) in c.forwards.iter().enumerate() {
            ui.horizontal(|ui| {
                ui.strong("P2P 转发");
                ui.label(format!(
                    "{}　{} → {}/{}",
                    x.name, x.listen_addr, x.peer, x.export
                ));
                if ui.small_button("删除").clicked() {
                    remove = Some(i);
                }
            });
        }
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
            ui.text_edit_singleline(&mut self.name);
        });
        match self.kind {
            ForwardEntryKind::TcpTunnel | ForwardEntryKind::UdpTunnel => {
                ui.horizontal(|ui| {
                    ui.label("本地地址");
                    ui.text_edit_singleline(&mut self.local);
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
            let name = self.name.trim().to_owned();
            if name.is_empty() {
                self.message = Some("名称不能为空".into());
            } else {
                match self.kind {
                    ForwardEntryKind::TcpTunnel | ForwardEntryKind::UdpTunnel => {
                        c.tunnels.push(TunnelConfig {
                            name,
                            protocol: if self.kind == ForwardEntryKind::TcpTunnel {
                                TunnelProtocol::Tcp
                            } else {
                                TunnelProtocol::Udp
                            },
                            local_addr: self.local.trim().into(),
                            remote_port: self.port,
                        })
                    }
                    ForwardEntryKind::P2pExport => c.exports.push(ExportConfig {
                        name,
                        protocol: self.protocol,
                        local_addr: self.local.trim().into(),
                        allowed_peers: self
                            .peers
                            .split(',')
                            .map(str::trim)
                            .filter(|v| !v.is_empty())
                            .map(str::to_owned)
                            .collect(),
                    }),
                    ForwardEntryKind::P2pForward => c.forwards.push(ForwardConfig {
                        name,
                        peer: self.peer.trim().into(),
                        export: self.export.trim().into(),
                        listen_addr: self.listen.trim().into(),
                    }),
                }
                self.name.clear();
                self.message = Some("已添加，点击保存并生效后应用".into());
            }
        }
        if let Some(m) = &self.message {
            ui.label(m);
        }
        ui.add_space(8.0);
        if ui.button("保存并生效").clicked() {
            *save = true;
        }
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
    use super::ForwardEntryKind;
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
}
