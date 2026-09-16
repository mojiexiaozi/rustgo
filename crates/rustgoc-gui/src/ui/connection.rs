#![forbid(unsafe_code)]

use crate::state::connection::ConnectionState;
use crate::state::p2p::{P2PPathRow, PathRowKind};
use crate::state::telemetry::{TelemetryHistory, TelemetryPoint};
use crate::state::tunnels::TunnelRow;
use crate::ui::formatting::{format_bytes, format_percent, format_rate};
use eframe::egui::{Color32, Frame, RichText, Stroke, Ui};
use egui_plot::{Line, Plot, PlotPoints};

pub struct ConnectionPanel {
    server_address: String,
}

pub struct OverviewData<'a> {
    pub state: &'a ConnectionState,
    pub client_name: &'a str,
    pub uid: Option<&'a str>,
    pub local_ip: Option<&'a str>,
    pub history: &'a TelemetryHistory,
    pub sent_bytes: Option<u64>,
    pub received_bytes: Option<u64>,
    pub tunnels: &'a [TunnelRow],
    pub configured_tunnels: usize,
    pub exports: usize,
    pub forwards: usize,
    pub p2p_rows: &'a [P2PPathRow],
}

impl ConnectionPanel {
    pub fn new(server_address: String) -> Self {
        Self { server_address }
    }
    pub fn set_server_address(&mut self, server_address: String) {
        self.server_address = server_address;
    }

    pub fn show(&mut self, ui: &mut Ui, data: OverviewData<'_>) {
        let points = data.history.snapshot();
        let latest = points.last();
        let age = latest.map(|p| now_millis().saturating_sub(p.timestamp) / 1000);
        let state = match data.state {
            ConnectionState::Disconnected => "离线".to_owned(),
            ConnectionState::Connecting => "连接中".to_owned(),
            ConnectionState::Connected { .. } => "在线".to_owned(),
            ConnectionState::Backoff { seconds } => format!("重试中（{seconds} 秒）"),
        };
        ui.heading(RichText::new(data.client_name).size(30.0));
        ui.label(format!("UID：{}", data.uid.unwrap_or("尚未分配")));
        ui.label(format!(
            "本地 IP：{}",
            data.local_ip.unwrap_or("连接后获取")
        ));
        ui.label(format!(
            "{state} · 心跳 {} · 0 个活跃会话",
            age.map(|v| format!("{v} 秒前"))
                .unwrap_or_else(|| "不可用".into())
        ));
        ui.add_space(10.0);

        let direct = data
            .p2p_rows
            .iter()
            .filter(|r| matches!(r.kind, PathRowKind::Direct { .. }))
            .count();
        let relay = data.p2p_rows.len().saturating_sub(direct);
        let tcp = data
            .tunnels
            .iter()
            .filter(|t| t.protocol.eq_ignore_ascii_case("tcp"))
            .count();
        let udp = data
            .tunnels
            .iter()
            .filter(|t| t.protocol.eq_ignore_ascii_case("udp"))
            .count();
        let active = data.tunnels.iter().filter(|t| t.accepted).count();
        ui.columns(3, |columns| {
            metric(
                &mut columns[0],
                "CPU",
                latest.map(|p| format_percent(p.cpu_basis_points)),
                sample_note(age),
            );
            metric(
                &mut columns[1],
                "内存",
                latest.map(|p| format_bytes(p.memory_bytes)),
                sample_note(age),
            );
            metric(
                &mut columns[2],
                "存储",
                latest.map(|p| format_bytes(p.disk_bytes)),
                sample_note(age),
            );
        });
        ui.add_space(8.0);
        ui.columns(3, |columns| {
            metric(
                &mut columns[0],
                "上传",
                latest.map(|p| format_rate(p.tx_bytes_per_sec)),
                format!(
                    "逻辑发送量 {}",
                    data.sent_bytes
                        .map(format_bytes)
                        .unwrap_or_else(|| "不可用".into())
                ),
            );
            metric(
                &mut columns[1],
                "下载",
                latest.map(|p| format_rate(p.rx_bytes_per_sec)),
                format!(
                    "逻辑接收量 {}",
                    data.received_bytes
                        .map(format_bytes)
                        .unwrap_or_else(|| "不可用".into())
                ),
            );
            metric(
                &mut columns[2],
                "路径",
                Some(if data.p2p_rows.is_empty() {
                    "无活跃路径".into()
                } else {
                    format!("{} 条活跃路径", data.p2p_rows.len())
                }),
                format!("直连 {direct} · 中继 {relay}"),
            );
        });
        ui.add_space(8.0);
        ui.columns(3, |columns| {
            list(
                &mut columns[0],
                "清单",
                &[
                    format!("导出                         {}", data.exports),
                    format!("转发                         {}", data.forwards),
                    format!(
                        "隧道                         {}（活跃 {active}）",
                        data.configured_tunnels
                    ),
                ],
            );
            list(
                &mut columns[1],
                "路径与会话",
                &[
                    format!("P2P 直连                    {direct}"),
                    format!("P2P 回退                    {relay}"),
                    format!(
                        "TCP / UDP / P2P       {tcp} / {udp} / {}",
                        data.p2p_rows.len()
                    ),
                ],
            );
            list(&mut columns[2], "最近会话", &["暂无会话".to_owned()]);
        });

        ui.add_space(8.0);
        ui.columns(2, |columns| {
            chart(
                &mut columns[0],
                "CPU 历史",
                "overview_cpu",
                cpu_points(&points),
                Color32::from_rgb(72, 210, 190),
            );
            chart(
                &mut columns[1],
                "流量历史",
                "overview_traffic",
                traffic_points(&points),
                Color32::from_rgb(250, 180, 20),
            );
        });
    }
}

fn frame(ui: &Ui) -> Frame {
    Frame::new()
        .inner_margin(12)
        .fill(ui.visuals().faint_bg_color)
        .stroke(Stroke::new(
            1.0,
            ui.visuals().widgets.noninteractive.bg_stroke.color,
        ))
        .corner_radius(12)
}
fn metric(ui: &mut Ui, title: &str, value: Option<String>, note: String) {
    frame(ui).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.set_min_height(72.0);
        ui.vertical(|ui| {
            ui.strong(RichText::new(title).size(18.0));
            ui.add_space(3.0);
            ui.label(
                RichText::new(value.unwrap_or_else(|| "不可用".into()))
                    .size(27.0)
                    .strong(),
            );
            ui.label(RichText::new(note).weak());
        });
    });
}
fn list(ui: &mut Ui, title: &str, rows: &[String]) {
    frame(ui).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.set_min_height(88.0);
        ui.vertical(|ui| {
            ui.strong(RichText::new(title).size(18.0));
            ui.add_space(3.0);
            for row in rows {
                ui.label(row);
            }
        });
    });
}
fn chart(ui: &mut Ui, title: &str, id: &str, points: PlotPoints<'_>, color: Color32) {
    frame(ui).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.vertical(|ui| {
            ui.strong(RichText::new(title).size(18.0));
            Plot::new(id)
                .height(145.0)
                .show_axes([false, false])
                .allow_drag(false)
                .allow_zoom(false)
                .show(ui, |p| {
                    p.line(Line::new(title, points).color(color).width(2.0))
                });
        });
    });
}
fn cpu_points(points: &[TelemetryPoint]) -> PlotPoints<'_> {
    PlotPoints::from_iter(
        points
            .iter()
            .map(|p| [p.timestamp as f64, p.cpu_basis_points as f64 / 100.0]),
    )
}
fn traffic_points(points: &[TelemetryPoint]) -> PlotPoints<'_> {
    PlotPoints::from_iter(points.iter().map(|p| {
        [
            p.timestamp as f64,
            (p.tx_bytes_per_sec + p.rx_bytes_per_sec) as f64,
        ]
    }))
}
fn sample_note(age: Option<u64>) -> String {
    age.map(|v| format!("采样于 {v} 秒前"))
        .unwrap_or_else(|| "暂无采样".into())
}
fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn overview_series_use_cpu_and_total_traffic() {
        let p = vec![TelemetryPoint {
            timestamp: 1,
            cpu_basis_points: 1370,
            memory_bytes: 2,
            disk_bytes: 3,
            tx_bytes_per_sec: 4,
            rx_bytes_per_sec: 6,
        }];
        assert_eq!(cpu_points(&p).points()[0].y, 13.7);
        assert_eq!(traffic_points(&p).points()[0].y, 10.0);
    }
}
