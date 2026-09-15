#![forbid(unsafe_code)]
use eframe::egui::{self, Align, Layout, Ui};

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
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.add_space(32.0);
                ui.vertical_centered(|ui| {
                    let width = ui.available_width().min(480.0);
                    ui.allocate_ui_with_layout(
                        egui::vec2(width, 0.0),
                        Layout::top_down(Align::Min),
                        |ui| {
                            ui.set_width(width);
                            ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Wrap);
                            ui.heading(if replacing {
                                "恢复连接申请"
                            } else {
                                "接入申请"
                            });
                            ui.add_space(16.0);
                            ui.label("客户端自动提交申请；服务器收到后，可在管理端审批。");
                            ui.label("批准后自动连接，无需输入密钥或验证码。");
                            if let Some(fingerprint) = &self.fingerprint {
                                ui.add_space(12.0);
                                ui.label("请管理员核对公钥指纹：");
                                ui.monospace(fingerprint);
                            }
                            ui.add_space(20.0);
                            if let Some(error) = &self.error_message {
                                ui.colored_label(egui::Color32::RED, error);
                                ui.add_space(12.0);
                                *retry = ui.button("重新连接并查询审批").clicked();
                            } else {
                                ui.horizontal(|ui| {
                                    ui.spinner();
                                    ui.label(
                                        self.progress
                                            .as_deref()
                                            .unwrap_or("正在连接服务器并提交申请…"),
                                    );
                                });
                            }
                            ui.add_space(20.0);
                            ui.weak("申请和候选密钥会保存在本机，重启后可继续等待审批。");
                        },
                    );
                });
            });
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
