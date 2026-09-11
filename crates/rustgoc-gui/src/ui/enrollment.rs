#![forbid(unsafe_code)]

use eframe::egui::Ui;

/// Enrollment panel for first-time registration and re-registration
pub struct EnrollmentPanel {
    enrollment_key: String,
    error_message: Option<String>,
    replace_confirmed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnrollmentPreparationError {
    InvalidKey,
    PurposeMismatch,
}

impl EnrollmentPanel {
    pub fn new() -> Self {
        Self {
            enrollment_key: String::new(),
            error_message: None,
            replace_confirmed: false,
        }
    }

    pub fn show(&mut self, ui: &mut Ui, is_reregistration: bool, on_submit: &mut bool) {
        ui.vertical_centered(|ui| {
            ui.add_space(60.0);

            if is_reregistration {
                ui.heading("设备重新注册");
                ui.add_space(10.0);
                ui.label("设备私钥缺失或已损坏");
                ui.label("请从管理界面获取重新注册密钥以恢复连接");
            } else {
                ui.heading("设备首次注册");
                ui.add_space(10.0);
                ui.label("请从管理界面获取接入密钥以完成注册");
            }

            ui.add_space(30.0);

            ui.horizontal(|ui| {
                ui.label("接入密钥：");
                ui.add(
                    eframe::egui::TextEdit::singleline(&mut self.enrollment_key)
                        .password(true)
                        .desired_width(400.0)
                        .hint_text("粘贴接入密钥"),
                );
            });

            ui.add_space(20.0);

            if let Some(error) = &self.error_message {
                ui.colored_label(eframe::egui::Color32::RED, error);
                ui.add_space(10.0);
            }

            if is_reregistration {
                ui.checkbox(
                    &mut self.replace_confirmed,
                    "我确认替换现有设备私钥（此操作不可撤销）",
                );
            }

            if ui
                .add_enabled(
                    !self.enrollment_key.is_empty()
                        && (!is_reregistration || self.replace_confirmed),
                    eframe::egui::Button::new("提交注册"),
                )
                .clicked()
            {
                *on_submit = true;
            }

            ui.add_space(20.0);

            ui.label("注意：接入密钥只能使用一次，请妥善保管");
        });
    }

    pub fn take_key(
        &mut self,
        expected_purpose: rustgoc::EnrollmentPurpose,
    ) -> Result<String, EnrollmentPreparationError> {
        let value = self.enrollment_key.trim().to_owned();
        let parsed = rustgoc::EnrollmentKey::parse(&value).map_err(|_| {
            self.set_error("接入密钥无效，请重新复制后再试".to_owned());
            EnrollmentPreparationError::InvalidKey
        })?;
        if parsed.purpose() != expected_purpose {
            self.set_error("接入密钥用途与当前注册状态不符".to_owned());
            return Err(EnrollmentPreparationError::PurposeMismatch);
        }
        self.clear_key();
        self.clear_error();
        Ok(value)
    }

    pub fn clear_key(&mut self) {
        self.enrollment_key.clear();
    }

    pub fn set_error(&mut self, message: String) {
        self.error_message = Some(message);
    }

    pub fn clear_error(&mut self) {
        self.error_message = None;
    }
}

impl Default for EnrollmentPanel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest, Sha256};

    use super::EnrollmentPanel;

    fn valid_key() -> String {
        let address = b"server.example:7443";
        let mut payload = vec![1];
        payload.extend_from_slice(&(address.len() as u16).to_be_bytes());
        payload.extend_from_slice(address);
        payload.extend_from_slice(&[7; 32]);
        payload.extend_from_slice(&[8; 32]);
        let digest = Sha256::digest(&payload);
        format!(
            "rustgo-enroll-v1.{}.{:02x}{:02x}{:02x}{:02x}",
            URL_SAFE_NO_PAD.encode(payload),
            digest[0],
            digest[1],
            digest[2],
            digest[3]
        )
    }

    #[test]
    fn malformed_key_shows_stable_error_without_echoing_secret() {
        let mut panel = EnrollmentPanel::new();
        panel.enrollment_key = "do-not-echo-this-secret".to_owned();

        assert!(panel.take_key(rustgoc::EnrollmentPurpose::Enroll).is_err());
        assert_eq!(
            panel.error_message.as_deref(),
            Some("接入密钥无效，请重新复制后再试")
        );
        assert!(
            !panel
                .error_message
                .as_deref()
                .unwrap()
                .contains("do-not-echo")
        );
    }

    #[test]
    fn accepted_key_is_validated_and_cleared_before_async_submission() {
        let mut panel = EnrollmentPanel::new();
        panel.enrollment_key = valid_key();

        let key = panel.take_key(rustgoc::EnrollmentPurpose::Enroll).unwrap();

        assert!(panel.enrollment_key.is_empty());
        assert!(panel.error_message.is_none());
        assert!(key.starts_with("rustgo-enroll-v1."));
    }
}
