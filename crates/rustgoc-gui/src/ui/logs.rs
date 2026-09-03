#![forbid(unsafe_code)]

use eframe::egui::Ui;

pub struct LogsPanel;

impl LogsPanel {
    pub fn new() -> Self {
        Self
    }

    pub fn show(&mut self, ui: &mut Ui, log_lines: &[String]) {
        ui.heading("日志");
        ui.separator();

        if log_lines.is_empty() {
            ui.label("无日志条目");
            return;
        }

        eframe::egui::ScrollArea::vertical()
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                for line in log_lines {
                    ui.monospace(line);
                }
            });
    }
}

impl Default for LogsPanel {
    fn default() -> Self {
        Self::new()
    }
}
