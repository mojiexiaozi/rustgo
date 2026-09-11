#![forbid(unsafe_code)]
#![allow(dead_code)]

use crate::state::telemetry::{TelemetryHistory, TelemetryPoint};
use crate::ui::formatting::{format_bytes, format_percent, format_rate};
use eframe::egui::{self, Align, Color32, Frame, Layout, RichText, Stroke, Ui};
use egui_plot::{Line, Plot, PlotPoints};

pub struct TelemetryPanel;

impl TelemetryPanel {
    pub fn new() -> Self {
        Self
    }

    pub fn show(&mut self, ui: &mut Ui, history: &TelemetryHistory) {
        ui.heading("遥测 Telemetry");
        ui.separator();

        let points = history.snapshot();
        if points.is_empty() {
            ui.label("正在采集本机遥测 Collecting local telemetry...");
            return;
        }

        if let Some(latest) = points.last() {
            show_latest_card(ui, latest, points.len());
        }

        ui.add_space(12.0);
        show_chart_card(ui, "CPU 使用率 CPU Usage", |ui| {
            Plot::new("cpu_plot")
                .height(120.0)
                .show_axes([true, true])
                .show(ui, |plot_ui| {
                    plot_ui.line(Line::new("CPU %", extract_cpu_points(&points)));
                });
        });

        ui.add_space(10.0);
        show_chart_card(ui, "内存使用 Memory Usage", |ui| {
            Plot::new("memory_plot")
                .height(120.0)
                .show_axes([true, true])
                .show(ui, |plot_ui| {
                    plot_ui.line(Line::new("Memory MiB", extract_memory_points(&points)));
                });
        });

        ui.add_space(10.0);
        show_chart_card(ui, "网络流量 Network Traffic", |ui| {
            Plot::new("network_plot")
                .height(120.0)
                .show_axes([true, true])
                .show(ui, |plot_ui| {
                    plot_ui.line(Line::new("Upload KiB/s", extract_tx_points(&points)));
                    plot_ui.line(Line::new("Download KiB/s", extract_rx_points(&points)));
                });
        });
    }
}

impl Default for TelemetryPanel {
    fn default() -> Self {
        Self::new()
    }
}

fn card_frame(ui: &Ui) -> Frame {
    Frame::new()
        .inner_margin(16)
        .fill(ui.visuals().faint_bg_color)
        .stroke(Stroke::new(
            1.0,
            ui.visuals().widgets.noninteractive.bg_stroke.color,
        ))
        .corner_radius(8)
}

fn show_latest_card(ui: &mut Ui, latest: &TelemetryPoint, sample_count: usize) {
    card_frame(ui).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            ui.strong("最新遥测 Latest telemetry");
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                Frame::new()
                    .inner_margin(egui::Margin::symmetric(8, 3))
                    .fill(Color32::from_rgb(28, 110, 65))
                    .corner_radius(8)
                    .show(ui, |ui| {
                        ui.label(RichText::new("实时 Live").color(Color32::WHITE).small());
                    });
            });
        });

        ui.add_space(8.0);
        ui.label(
            RichText::new(format!("{sample_count} 个历史采样 History samples"))
                .small()
                .weak(),
        );
        ui.add_space(8.0);

        egui::Grid::new("latest_telemetry_details")
            .num_columns(2)
            .spacing([24.0, 8.0])
            .show(ui, |ui| {
                detail_row(ui, "CPU", format_percent(latest.cpu_basis_points));
                detail_row(ui, "内存 Memory", format_bytes(latest.memory_bytes));
                detail_row(
                    ui,
                    "上传 / 下载 Upload / download",
                    format!(
                        "{} / {}",
                        format_rate(latest.tx_bytes_per_sec),
                        format_rate(latest.rx_bytes_per_sec)
                    ),
                );
            });
    });
}

fn detail_row(ui: &mut Ui, label: &str, value: String) {
    ui.label(RichText::new(label).weak());
    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
        ui.label(value);
    });
    ui.end_row();
}

fn show_chart_card(ui: &mut Ui, title: &str, add_plot: impl FnOnce(&mut Ui)) {
    card_frame(ui).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.strong(title);
        ui.add_space(6.0);
        add_plot(ui);
    });
}

fn extract_cpu_points(points: &[TelemetryPoint]) -> PlotPoints<'_> {
    PlotPoints::from_iter(points.iter().map(|p| {
        let x = p.timestamp as f64 / 1000.0;
        let y = p.cpu_basis_points as f64 / 100.0;
        [x, y]
    }))
}

fn extract_memory_points(points: &[TelemetryPoint]) -> PlotPoints<'_> {
    PlotPoints::from_iter(points.iter().map(|p| {
        let x = p.timestamp as f64 / 1000.0;
        let y = p.memory_bytes as f64 / (1024.0 * 1024.0);
        [x, y]
    }))
}

fn extract_tx_points(points: &[TelemetryPoint]) -> PlotPoints<'_> {
    PlotPoints::from_iter(points.iter().map(|p| {
        let x = p.timestamp as f64 / 1000.0;
        let y = p.tx_bytes_per_sec as f64 / 1024.0;
        [x, y]
    }))
}

fn extract_rx_points(points: &[TelemetryPoint]) -> PlotPoints<'_> {
    PlotPoints::from_iter(points.iter().map(|p| {
        let x = p.timestamp as f64 / 1000.0;
        let y = p.rx_bytes_per_sec as f64 / 1024.0;
        [x, y]
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_cpu_points() {
        let points = vec![
            TelemetryPoint {
                timestamp: 1000,
                cpu_basis_points: 5000,
                memory_bytes: 0,
                tx_bytes_per_sec: 0,
                rx_bytes_per_sec: 0,
            },
            TelemetryPoint {
                timestamp: 2000,
                cpu_basis_points: 10000,
                memory_bytes: 0,
                tx_bytes_per_sec: 0,
                rx_bytes_per_sec: 0,
            },
        ];

        let plot_points = extract_cpu_points(&points);
        let points_slice = plot_points.points();
        assert_eq!(points_slice.len(), 2);
        assert_eq!(points_slice[0].x, 1.0);
        assert_eq!(points_slice[0].y, 50.0);
        assert_eq!(points_slice[1].x, 2.0);
        assert_eq!(points_slice[1].y, 100.0);
    }

    #[test]
    fn test_extract_memory_points() {
        let points = vec![TelemetryPoint {
            timestamp: 1000,
            cpu_basis_points: 0,
            memory_bytes: 1024 * 1024 * 100,
            tx_bytes_per_sec: 0,
            rx_bytes_per_sec: 0,
        }];

        let plot_points = extract_memory_points(&points);
        let points_slice = plot_points.points();
        assert_eq!(points_slice.len(), 1);
        assert_eq!(points_slice[0].x, 1.0);
        assert_eq!(points_slice[0].y, 100.0);
    }

    #[test]
    fn test_extract_network_points() {
        let points = vec![TelemetryPoint {
            timestamp: 1000,
            cpu_basis_points: 0,
            memory_bytes: 0,
            tx_bytes_per_sec: 2048,
            rx_bytes_per_sec: 4096,
        }];

        let tx = extract_tx_points(&points);
        let rx = extract_rx_points(&points);

        let tx_slice = tx.points();
        let rx_slice = rx.points();

        assert_eq!(tx_slice[0].x, 1.0);
        assert_eq!(tx_slice[0].y, 2.0);
        assert_eq!(rx_slice[0].x, 1.0);
        assert_eq!(rx_slice[0].y, 4.0);
    }

    #[test]
    fn test_empty_points() {
        let points = vec![];
        let cpu = extract_cpu_points(&points);
        assert_eq!(cpu.points().len(), 0);
    }
}
