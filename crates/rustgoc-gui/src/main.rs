#![forbid(unsafe_code)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod configuration;
mod runtime;
mod selfcheck;
mod state;
mod tray;
mod tray_events;
mod ui;

use clap::Parser;
use rustgoc::EnrollmentState;
use state::connection::ConnectionViewModel;
use state::logs::LogRing;
use state::tunnels::TunnelRow;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;
use tokio::sync::watch;
use tray_events::TrayEvent;
use ui::config::ConfigPanel;
use ui::connection::ConnectionPanel;
use ui::enrollment::EnrollmentPanel;
use ui::forwarding::ForwardingPanel;
use ui::logs::LogsPanel;

#[cfg(windows)]
fn setup_fonts(ctx: &eframe::egui::Context) {
    let mut fonts = eframe::egui::FontDefinitions::default();

    fonts.font_data.insert(
        "msyh".to_owned(),
        std::sync::Arc::new(eframe::egui::FontData::from_static(include_bytes!(
            "C:\\Windows\\Fonts\\msyh.ttc"
        ))),
    );

    fonts
        .families
        .entry(eframe::egui::FontFamily::Proportional)
        .or_default()
        .insert(0, "msyh".to_owned());

    fonts
        .families
        .entry(eframe::egui::FontFamily::Monospace)
        .or_default()
        .insert(0, "msyh".to_owned());

    ctx.set_fonts(fonts);
}

#[cfg(not(windows))]
fn setup_fonts(_ctx: &eframe::egui::Context) {}

#[derive(Parser)]
#[command(name = "rustgoc-gui")]
#[command(about = "Rustgo GUI client")]
struct Cli {
    #[arg(long)]
    selfcheck: bool,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let executable = std::env::current_exe()?;
    let config_path = configuration::config_path_for_executable(&executable)?;
    if cli.selfcheck {
        return selfcheck::run(&config_path);
    }

    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 800.0])
            .with_title("Rustgo 图形界面"),
        ..Default::default()
    };

    eframe::run_native(
        "rustgoc-gui",
        options,
        Box::new(move |cc| {
            setup_fonts(&cc.egui_ctx);
            Ok(Box::new(GuiApp::new(config_path)))
        }),
    )
    .map_err(|e| anyhow::anyhow!("eframe error: {}", e))
}

enum Tab {
    Connection,
    Forwarding,
    Telemetry,
    Logs,
    Config,
}

struct GuiApp {
    active_tab: Tab,
    connection_panel: ConnectionPanel,
    enrollment_panel: EnrollmentPanel,
    forwarding_panel: ForwardingPanel,
    telemetry_panel: ui::telemetry::TelemetryPanel,
    logs_panel: LogsPanel,
    config_panel: ConfigPanel,
    connection_vm: ConnectionViewModel,
    tunnels: Vec<TunnelRow>,
    telemetry_history: state::telemetry::TelemetryHistory,
    p2p_vm: state::p2p::P2PViewModel,
    log_ring: LogRing,
    tray_rx: mpsc::Receiver<TrayEvent>,
    _tray: Option<tray::platform::TrayIcon>,
    should_quit: bool,
    runtime: Option<runtime::ClientRuntime>,
    config_path: PathBuf,
    _status_tx: watch::Sender<rustgoc::ClientStatus>,
    traffic_handle: Option<rustgoc::TrafficHandle>,
    path_status_store: rustgoc::PathStatusStore,
    enrollment_state: EnrollmentState,
    enrollment_rx: Option<mpsc::Receiver<Result<rustgoc::EnrollmentCompletion, String>>>,
    enrollment_recovery_rx: Option<mpsc::Receiver<Result<bool, String>>>,
    auto_connect_pending: bool,
    last_logged_connection_state: state::connection::ConnectionState,
}

impl GuiApp {
    fn new(config_path: PathBuf) -> Self {
        let (status_tx, status_rx) = watch::channel(rustgoc::ClientStatus::default());

        let (tray_tx, tray_rx) = mpsc::sync_channel(64);

        #[cfg(windows)]
        let tray = tray::platform::TrayIcon::new(tray_tx).ok();

        #[cfg(not(windows))]
        let tray = None;

        let log_ring = LogRing::new();
        let _ = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(log_ring.clone())
            .try_init();
        let telemetry_history = state::telemetry::TelemetryHistory::new();
        let runtime = runtime::ClientRuntime::new(telemetry_history.clone()).ok();
        let path_status_store = rustgoc::PathStatusStore::new();

        Self {
            active_tab: Tab::Connection,
            connection_panel: ConnectionPanel::new("8.133.176.172:8443".to_string()),
            enrollment_panel: EnrollmentPanel::new(),
            forwarding_panel: ForwardingPanel::new(),
            telemetry_panel: ui::telemetry::TelemetryPanel::new(),
            logs_panel: LogsPanel::new(),
            config_panel: ConfigPanel::new(config_path.clone()),
            connection_vm: ConnectionViewModel::new(status_rx),
            tunnels: Vec::new(),
            telemetry_history,
            p2p_vm: state::p2p::P2PViewModel::new(path_status_store.clone()),
            log_ring,
            tray_rx,
            _tray: tray,
            should_quit: false,
            runtime,
            config_path,
            _status_tx: status_tx,
            traffic_handle: None,
            path_status_store,
            enrollment_state: EnrollmentState::Ready,
            enrollment_rx: None,
            enrollment_recovery_rx: None,
            auto_connect_pending: true,
            last_logged_connection_state: state::connection::ConnectionState::Disconnected,
        }
    }
}

impl eframe::App for GuiApp {
    fn ui(&mut self, ui: &mut eframe::egui::Ui, _frame: &mut eframe::Frame) {
        if self.auto_connect_pending {
            self.auto_connect_pending = false;
            self.handle_connect();
        }
        if let Some(receiver) = &self.enrollment_rx
            && let Ok(result) = receiver.try_recv()
        {
            self.enrollment_rx = None;
            match result {
                Ok(completion) => {
                    self.enrollment_state = EnrollmentState::Ready;
                    self.enrollment_panel.clear_error();
                    self.config_panel.reload();
                    self.log_ring.push(state::logs::LogLine {
                        timestamp: time::OffsetDateTime::now_utc()
                            .format(&time::format_description::well_known::Rfc3339)
                            .unwrap_or_else(|_| "unknown".to_owned()),
                        level: "INFO".to_owned(),
                        target: "gui".to_owned(),
                        message: format!(
                            "客户端 {} 注册完成，修订号 {}",
                            completion.client_id, completion.revision
                        ),
                    });
                    self.handle_connect();
                }
                Err(error) => self
                    .enrollment_panel
                    .set_error(format!("注册失败：{error}")),
            }
        }
        let recovery = self
            .enrollment_recovery_rx
            .as_ref()
            .and_then(|receiver| receiver.try_recv().ok());
        if let Some(result) = recovery {
            self.enrollment_recovery_rx = None;
            match result {
                Ok(true) => {
                    self.enrollment_state = EnrollmentState::Ready;
                    self.handle_connect();
                }
                Ok(false) => self
                    .enrollment_panel
                    .set_error("候选密钥尚未在服务端绑定，请输入管理员重新签发的密钥".to_owned()),
                Err(error) => self
                    .enrollment_panel
                    .set_error(format!("注册恢复失败：{error}")),
            }
        }
        let state = self.connection_vm.update();
        if let Some(message) = state::connection::transition_message(
            &self.last_logged_connection_state,
            &state,
            self.config_panel.server_address().unwrap_or("未知服务器"),
        ) {
            let level = if message.starts_with("连接成功") {
                "INFO"
            } else {
                "WARN"
            };
            self.log_ring.push(state::logs::LogLine {
                timestamp: time::OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_else(|_| "unknown".to_owned()),
                level: level.to_owned(),
                target: "connection".to_owned(),
                message,
            });
        }
        self.last_logged_connection_state = state.clone();

        // Update tunnels from active generation
        if matches!(state, state::connection::ConnectionState::Connected { .. })
            && let Some(active) = self._status_tx.borrow().active()
        {
            let new_tunnels: Vec<TunnelRow> = active
                .registered_tunnels()
                .iter()
                .map(TunnelRow::from_registered)
                .collect();
            self.tunnels = new_tunnels;
        }

        // Update P2P paths
        self.p2p_vm.update();

        while let Ok(event) = self.tray_rx.try_recv() {
            match event {
                TrayEvent::Show => {}
                TrayEvent::Connect => {}
                TrayEvent::Disconnect => {}
                TrayEvent::Quit => {
                    self.should_quit = true;
                }
            }
        }

        if self.should_quit {
            std::process::exit(0);
        }

        eframe::egui::Panel::top("tabs").show(ui, |ui| {
            ui.horizontal(|ui| {
                if ui
                    .selectable_label(matches!(self.active_tab, Tab::Connection), "连接")
                    .clicked()
                {
                    self.active_tab = Tab::Connection;
                }
                if ui
                    .selectable_label(matches!(self.active_tab, Tab::Forwarding), "转发")
                    .clicked()
                {
                    self.active_tab = Tab::Forwarding;
                }
                if ui
                    .selectable_label(matches!(self.active_tab, Tab::Telemetry), "遥测")
                    .clicked()
                {
                    self.active_tab = Tab::Telemetry;
                }
                if ui
                    .selectable_label(matches!(self.active_tab, Tab::Logs), "日志")
                    .clicked()
                {
                    self.active_tab = Tab::Logs;
                }
                if ui
                    .selectable_label(matches!(self.active_tab, Tab::Config), "配置")
                    .clicked()
                {
                    self.active_tab = Tab::Config;
                }
            });
        });

        eframe::egui::CentralPanel::default().show(ui, |ui| match self.active_tab {
            Tab::Connection => {
                if matches!(
                    self.enrollment_state,
                    EnrollmentState::RegistrationRequired | EnrollmentState::ReRegistrationRequired
                ) {
                    let mut on_submit = false;
                    self.enrollment_panel.show(
                        ui,
                        matches!(
                            self.enrollment_state,
                            EnrollmentState::ReRegistrationRequired
                        ),
                        &mut on_submit,
                    );

                    if on_submit {
                        self.handle_enrollment_submit();
                    }
                } else if matches!(
                    self.enrollment_state,
                    EnrollmentState::EnrollmentPending | EnrollmentState::ReEnrollmentPending
                ) {
                    let mut on_submit = false;
                    ui.vertical_centered(|ui| {
                        ui.add_space(60.0);
                        ui.heading("正在恢复注册状态");
                        ui.label("候选设备密钥和恢复信息已保存，正在验证服务端绑定状态。");
                        ui.label("关闭并重新打开客户端不会丢失该状态。");
                    });
                    self.enrollment_panel.show(
                        ui,
                        matches!(self.enrollment_state, EnrollmentState::ReEnrollmentPending),
                        &mut on_submit,
                    );
                    if on_submit {
                        self.handle_enrollment_submit();
                    }
                } else {
                    let (sent_bytes, received_bytes) = self
                        .traffic_handle
                        .as_ref()
                        .map(|handle| {
                            let snapshot = handle.snapshot();
                            (snapshot.sent_bytes(), snapshot.received_bytes())
                        })
                        .unzip();

                    self.connection_panel.show(
                        ui,
                        &mut self.connection_vm,
                        sent_bytes,
                        received_bytes,
                    );
                }
            }
            Tab::Forwarding => {
                let mut save = false;
                self.forwarding_panel.show(
                    ui,
                    self.config_panel.config_mut(),
                    &self.tunnels,
                    &self.p2p_vm,
                    &mut save,
                );
                if save {
                    self.apply_configuration();
                }
            }
            Tab::Telemetry => {
                self.telemetry_panel.show(ui, &self.telemetry_history);
            }
            Tab::Logs => {
                let (log_lines, _dropped) = self.log_ring.snapshot();
                let log_strings: Vec<String> = log_lines
                    .iter()
                    .map(|line| {
                        format!(
                            "{} {} {} {}",
                            line.timestamp, line.level, line.target, line.message
                        )
                    })
                    .collect();
                self.logs_panel.show(ui, &log_strings);
            }
            Tab::Config => {
                let mut on_save_and_reconnect = false;
                self.config_panel.show(ui, &mut on_save_and_reconnect);

                if on_save_and_reconnect {
                    self.apply_configuration();
                }
            }
        });

        ui.ctx().request_repaint_after(Duration::from_millis(500));
    }
}

impl GuiApp {
    fn apply_configuration(&mut self) {
        match self.config_panel.save() {
            Ok(()) => {
                if let Some(address) = self.config_panel.server_address() {
                    self.connection_panel.set_server_address(address.to_owned());
                }
                self.forwarding_panel
                    .set_message("配置已保存，正在重新连接");
                self.handle_disconnect();
                self.handle_connect();
            }
            Err(error) => {
                self.forwarding_panel
                    .set_message(format!("保存失败: {error}"));
                self.config_panel.set_save_error(&error);
            }
        }
    }

    fn handle_connect(&mut self) {
        let config = match configuration::load_or_create(&self.config_path) {
            Ok(cfg) => cfg,
            Err(e) => {
                self.log_ring.push(state::logs::LogLine {
                    timestamp: time::OffsetDateTime::now_utc()
                        .format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_else(|_| "unknown".to_string()),
                    level: "ERROR".to_string(),
                    target: "gui".to_string(),
                    message: format!("配置文件准备失败: {e}"),
                });
                return;
            }
        };
        let server_address = config.client.server_addr.clone();
        self.connection_panel
            .set_server_address(server_address.clone());

        self.enrollment_state = match rustgoc::classify_enrollment_state(&config, &self.config_path)
        {
            Ok(EnrollmentState::Ready) => EnrollmentState::Ready,
            Ok(state) => {
                self.log_ring.push(state::logs::LogLine {
                    timestamp: time::OffsetDateTime::now_utc()
                        .format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_else(|_| "unknown".to_string()),
                    level: "WARN".to_string(),
                    target: "gui".to_string(),
                    message: "客户端当前需要完成设备注册".to_string(),
                });
                self.enrollment_state = state;
                if matches!(
                    state,
                    EnrollmentState::EnrollmentPending | EnrollmentState::ReEnrollmentPending
                ) && self.enrollment_recovery_rx.is_none()
                    && let Some(runtime) = &self.runtime
                {
                    self.enrollment_recovery_rx =
                        Some(runtime.recover_enrollment(config, self.config_path.clone()));
                }
                return;
            }
            Err(error) => {
                self.log_ring.push(state::logs::LogLine {
                    timestamp: time::OffsetDateTime::now_utc()
                        .format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_else(|_| "unknown".to_string()),
                    level: "ERROR".to_string(),
                    target: "gui".to_string(),
                    message: format!("身份配置检查失败: {error}"),
                });
                return;
            }
        };

        // 创建客户端应用
        match rustgoc::ClientApp::from_config(config) {
            Ok(app) => {
                self.enrollment_state = EnrollmentState::Ready;

                if let Some(runtime) = &self.runtime {
                    // 订阅状态并获取流量句柄和路径状态
                    self.connection_vm = ConnectionViewModel::new(app.subscribe());
                    self.traffic_handle = app.traffic_handle();
                    self.path_status_store = app.path_status_store().clone();
                    self.p2p_vm = state::p2p::P2PViewModel::new(self.path_status_store.clone());

                    self.connection_vm.mark_connecting();

                    runtime.connect(app, self.traffic_handle.clone());

                    self.log_ring.push(state::logs::LogLine {
                        timestamp: time::OffsetDateTime::now_utc()
                            .format(&time::format_description::well_known::Rfc3339)
                            .unwrap_or_else(|_| "unknown".to_string()),
                        level: "INFO".to_string(),
                        target: "gui".to_string(),
                        message: format!("正在连接到 {}", server_address),
                    });
                }
            }
            Err(e) => self.log_ring.push(state::logs::LogLine {
                timestamp: time::OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_else(|_| "unknown".to_string()),
                level: "ERROR".to_string(),
                target: "gui".to_string(),
                message: format!("客户端初始化失败: {}", e),
            }),
        }
    }

    fn handle_enrollment_submit(&mut self) {
        let Ok(config) = rustgo_config::load_client(&self.config_path) else {
            self.enrollment_panel
                .set_error("无法读取客户端配置".to_owned());
            return;
        };
        let purpose = if matches!(
            self.enrollment_state,
            EnrollmentState::ReRegistrationRequired | EnrollmentState::ReEnrollmentPending
        ) {
            rustgoc::EnrollmentPurpose::ReEnroll
        } else {
            rustgoc::EnrollmentPurpose::Enroll
        };
        if let Ok(key) = self.enrollment_panel.take_key(purpose)
            && let Some(runtime) = &self.runtime
        {
            self.enrollment_rx = Some(runtime.enroll(config, self.config_path.clone(), key));
            self.enrollment_state = match purpose {
                rustgoc::EnrollmentPurpose::Enroll => EnrollmentState::EnrollmentPending,
                rustgoc::EnrollmentPurpose::ReEnroll => EnrollmentState::ReEnrollmentPending,
            };
            self.log_ring.push(state::logs::LogLine {
                timestamp: time::OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_else(|_| "unknown".to_string()),
                level: "INFO".to_string(),
                target: "gui".to_string(),
                message: "正在安全保存候选密钥并提交注册请求".to_string(),
            });
        }
    }

    fn handle_disconnect(&mut self) {
        if let Some(runtime) = &self.runtime {
            runtime.disconnect();
            self.log_ring.push(state::logs::LogLine {
                timestamp: time::OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_else(|_| "unknown".to_string()),
                level: "INFO".to_string(),
                target: "gui".to_string(),
                message: "已断开连接".to_string(),
            });
        }
    }
}
