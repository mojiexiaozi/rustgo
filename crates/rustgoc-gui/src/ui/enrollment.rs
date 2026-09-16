#![forbid(unsafe_code)]
use eframe::egui::{self, Ui};
#[derive(Default)]
pub struct EnrollmentPanel {
    error_message: Option<String>,
    fingerprint: Option<String>,
    progress: Option<String>,
}
impl EnrollmentPanel {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set_fingerprint(&mut self, value: String) {
        self.fingerprint = Some(value);
    }
    pub fn show(&mut self, ui: &mut Ui, replacing: bool, retry: &mut bool) {
        ui.heading(if replacing {
            "恢复连接申请"
        } else {
            "接入申请"
        });
        if let Some(error) = &self.error_message {
            ui.colored_label(egui::Color32::RED, error);
            *retry = ui.button("重新提交 / 查询申请").clicked();
        } else {
            ui.horizontal_wrapped(|ui| {
                ui.spinner();
                ui.label(
                    self.progress
                        .as_deref()
                        .unwrap_or("正在连接服务器并提交申请，尚未确认提交成功…"),
                );
            });
        }
        if let Some(fingerprint) = &self.fingerprint {
            ui.collapsing("客户端公钥指纹", |ui| {
                ui.monospace(fingerprint);
            });
        }
    }
    pub fn set_error(&mut self, message: String) {
        self.error_message = Some(message);
    }
    pub fn clear_error(&mut self) {
        self.error_message = None;
        self.progress = None;
    }
    pub fn set_progress(&mut self, message: String) {
        self.progress = Some(message);
    }
}
