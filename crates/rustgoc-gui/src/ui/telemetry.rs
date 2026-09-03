#![forbid(unsafe_code)]
#![allow(dead_code)]

use crate::state::telemetry::{TelemetryHistory, TelemetryPoint};
use eframe::egui::Ui;
use egui_plot::{Line, Plot, PlotPoints};

pub struct TelemetryPanel;

impl TelemetryPanel {
    pub fn new() -> Self {
        Self
    }

    pub fn show(&mut self, ui: &mut Ui, history: &TelemetryHistory) {
        ui.heading("Telemetry");
        ui.separator();

        if !history.is_available() {
            ui.label("Telemetry not available");
            return;
        }

        let points = history.snapshot();
        if points.is_empty() {
            ui.label("No telemetry data yet");
            return;
        }

        ui.label("CPU Usage");
        Plot::new("cpu_plot").height(120.0).show(ui, |plot_ui| {
            let cpu_points = extract_cpu_points(&points);
            let line = Line::new("CPU %", cpu_points);
            plot_ui.line(line);
        });

        ui.add_space(10.0);
        ui.label("Memory Usage");
        Plot::new("memory_plot").height(120.0).show(ui, |plot_ui| {
            let memory_points = extract_memory_points(&points);
            let line = Line::new("Memory MB", memory_points);
            plot_ui.line(line);
        });

        ui.add_space(10.0);
        ui.label("Network Traffic");
        Plot::new("network_plot").height(120.0).show(ui, |plot_ui| {
            let tx_points = extract_tx_points(&points);
            let rx_points = extract_rx_points(&points);
            plot_ui.line(Line::new("TX KB/s", tx_points));
            plot_ui.line(Line::new("RX KB/s", rx_points));
        });
    }
}

impl Default for TelemetryPanel {
    fn default() -> Self {
        Self::new()
    }
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
