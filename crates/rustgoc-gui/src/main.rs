#![forbid(unsafe_code)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(windows)]
mod autostart;
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
            Ok(Box::new(GuiApp::new(config_path, cc.egui_ctx.clone())))
        }),
    )
    .map_err(|e| anyhow::anyhow!("eframe error: {}", e))
}

enum Tab {
    Connection,
    Forwarding,
    Logs,
    Config,
}

struct GuiApp {
    active_tab: Tab,
    connection_panel: ConnectionPanel,
    enrollment_panel: EnrollmentPanel,
    forwarding_panel: ForwardingPanel,
    logs_panel: LogsPanel,
    config_panel: ConfigPanel,
    connection_vm: ConnectionViewModel,
    tunnels: Vec<TunnelRow>,
    telemetry_history: state::telemetry::TelemetryHistory,
    p2p_vm: state::p2p::P2PViewModel,
    log_ring: LogRing,
    tray_rx: mpsc::Receiver<TrayEvent>,
    _tray: Option<tray::platform::TrayIcon>,
    window_lifecycle: tray_events::WindowLifecycle,
    #[cfg(windows)]
    autostart_enabled: bool,
    #[cfg(windows)]
    autostart_error: Option<String>,
    runtime: Option<runtime::ClientRuntime>,
    config_path: PathBuf,
    _status_tx: watch::Sender<rustgoc::ClientStatus>,
    traffic_handle: Option<rustgoc::TrafficHandle>,
    path_status_store: rustgoc::PathStatusStore,
    enrollment_state: EnrollmentState,
    enrollment_rx: Option<mpsc::Receiver<Result<rustgoc::EnrollmentCompletion, String>>>,
    managed_save_rx: Option<mpsc::Receiver<Result<u64, String>>>,
    connected_server: String,
    connected_name: String,
    auto_connect_pending: bool,
    last_logged_connection_state: state::connection::ConnectionState,
}

impl GuiApp {
    fn new(config_path: PathBuf, _ctx: eframe::egui::Context) -> Self {
        let (status_tx, status_rx) = watch::channel(rustgoc::ClientStatus::default());

        let (tray_tx, tray_rx) = mpsc::sync_channel(64);

        #[cfg(windows)]
        let tray_result = tray::platform::TrayIcon::new(tray_tx, _ctx);

        #[cfg(not(windows))]
        drop(tray_tx);

        #[cfg(not(windows))]
        let tray = None;

        let log_ring = LogRing::new();
        let _ = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_timer(state::logs::GuiTimer)
            .with_writer(log_ring.clone())
            .try_init();
        #[cfg(windows)]
        let tray = match tray_result {
            Ok(tray) => Some(tray),
            Err(error) => {
                tracing::error!("托盘初始化失败，关闭窗口将退出程序：{error:#}");
                None
            }
        };
        #[cfg(windows)]
        let (autostart_enabled, autostart_error) = match autostart::enabled() {
            Ok(enabled) => (enabled, None),
            Err(error) => (false, Some(format!("读取自启动设置失败：{error:#}"))),
        };
        let telemetry_history = state::telemetry::TelemetryHistory::new();
        let runtime = runtime::ClientRuntime::new(telemetry_history.clone()).ok();
        let path_status_store = rustgoc::PathStatusStore::new();

        Self {
            active_tab: Tab::Connection,
            connection_panel: ConnectionPanel::new("8.133.176.172:8443".to_string()),
            enrollment_panel: EnrollmentPanel::new(),
            forwarding_panel: ForwardingPanel::new(),
            logs_panel: LogsPanel::new(),
            config_panel: ConfigPanel::new(config_path.clone()),
            connection_vm: ConnectionViewModel::new(status_rx),
            tunnels: Vec::new(),
            telemetry_history,
            p2p_vm: state::p2p::P2PViewModel::new(path_status_store.clone()),
            log_ring,
            tray_rx,
            _tray: tray,
            window_lifecycle: tray_events::WindowLifecycle::default(),
            #[cfg(windows)]
            autostart_enabled,
            #[cfg(windows)]
            autostart_error,
            runtime,
            config_path,
            _status_tx: status_tx,
            traffic_handle: None,
            path_status_store,
            enrollment_state: EnrollmentState::Ready,
            enrollment_rx: None,
            managed_save_rx: None,
            connected_server: String::new(),
            connected_name: String::new(),
            auto_connect_pending: true,
            last_logged_connection_state: state::connection::ConnectionState::Disconnected,
        }
    }
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

impl eframe::App for GuiApp {
    fn logic(&mut self, ctx: &eframe::egui::Context, _frame: &mut eframe::Frame) {
        while let Ok(event) = self.tray_rx.try_recv() {
            match event {
                TrayEvent::Connect if !self.window_lifecycle.quitting => self.handle_connect(),
                TrayEvent::Disconnect => self.handle_disconnect(),
                TrayEvent::Quit => self.handle_disconnect(),
                _ => {}
            }
            self.window_lifecycle
                .update(ctx, self._tray.is_some(), Some(event));
        }
        self.window_lifecycle
            .update(ctx, self._tray.is_some(), None);
        if self.window_lifecycle.quitting {
            return;
        }
        // Logic also runs while hidden in the tray. Keep polling background work
        // so approval and authentication recovery never depend on painting.
        ctx.request_repaint_after(Duration::from_millis(500));
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
                        timestamp: state::logs::local_timestamp(),
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
        if let Some(receiver) = &self.managed_save_rx {
            let result = match receiver.try_recv() {
                Ok(result) => Some(result),
                Err(mpsc::TryRecvError::Disconnected) => Some(Err("保存任务已中断".into())),
                Err(mpsc::TryRecvError::Empty) => None,
            };
            if let Some(result) = result {
                self.managed_save_rx = None;
                self.forwarding_panel.saving = false;
                match result {
                    Ok(revision) => {
                        self.forwarding_panel.managed.saved(revision);
                        self.forwarding_panel.set_message(format!(
                            "服务器配置已保存（修订号 {revision}），正在重新连接"
                        ));
                    }
                    Err(error) => self.forwarding_panel.set_message(format!(
                        "保存失败：{error}；草稿已保留，可重新加载服务器配置后重试"
                    )),
                }
                self.handle_connect();
            }
        }
        let state = self.connection_vm.update();
        if self.connection_vm.authentication_rejected()
            && self.enrollment_state == EnrollmentState::Ready
            && self.enrollment_rx.is_none()
        {
            if let Some(runtime) = &self.runtime {
                runtime.disconnect();
            }
            self.enrollment_state = EnrollmentState::ReRegistrationRequired;
            self.handle_enrollment_submit();
        }
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
                timestamp: state::logs::local_timestamp(),
                level: level.to_owned(),
                target: "connection".to_owned(),
                message,
            });
        }
        self.last_logged_connection_state = state.clone();

        if let Some(address) = self.config_panel.server_address() {
            if self.managed_save_rx.is_none() {
                self.forwarding_panel.managed.select_server(address);
            }
        }
        if self.config_panel.server_address() == Some(self.connected_server.as_str()) {
            let status = self.connection_vm.status();
            self.forwarding_panel.managed.observe(
                status.active().is_some(),
                status.managed_revision(),
                status.effective_configuration(),
            );
        }

        // Update tunnels from active generation
        if matches!(state, state::connection::ConnectionState::Connected { .. })
            && let Some(active) = self.connection_vm.status().active()
        {
            let new_tunnels: Vec<TunnelRow> = active
                .registered_tunnels()
                .iter()
                .map(TunnelRow::from_registered)
                .collect();
            self.tunnels = new_tunnels;
        } else {
            self.tunnels.clear();
        }

        // Update P2P paths
        self.p2p_vm.update();
    }

    fn ui(&mut self, ui: &mut eframe::egui::Ui, _frame: &mut eframe::Frame) {
        eframe::egui::Panel::top("tabs").show(ui, |ui| {
            ui.horizontal(|ui| {
                if ui
                    .selectable_label(matches!(self.active_tab, Tab::Connection), "概要")
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
                    EnrollmentState::RegistrationRequired
                        | EnrollmentState::ReRegistrationRequired
                        | EnrollmentState::EnrollmentPending
                        | EnrollmentState::ReEnrollmentPending
                ) {
                    let mut on_submit = false;
                    if let Ok(pending) = rustgoc::PendingEnrollment::load(&self.config_path)
                        && let Ok(public) = pending
                            .public_key()
                            .parse::<rustgo_crypto::DevicePublicKey>()
                    {
                        self.enrollment_panel
                            .set_fingerprint(public.fingerprint().to_string());
                    }
                    self.enrollment_panel.show(
                        ui,
                        matches!(
                            self.enrollment_state,
                            EnrollmentState::ReRegistrationRequired
                                | EnrollmentState::ReEnrollmentPending
                        ),
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
                    let config = self.config_panel.config();
                    let managed = self.forwarding_panel.managed.snapshot();
                    let p2p_rows = self.p2p_vm.rows(now_millis());
                    self.connection_panel.show(
                        ui,
                        ui::connection::OverviewData {
                            state: self.connection_vm.current(),
                            client_name: config.map(|c| c.client.name.as_str()).unwrap_or("客户端"),
                            history: &self.telemetry_history,
                            sent_bytes,
                            received_bytes,
                            tunnels: &self.tunnels,
                            configured_tunnels: managed
                                .map(|c| c.tunnels.len())
                                .unwrap_or_else(|| config.map(|c| c.tunnels.len()).unwrap_or(0)),
                            exports: managed
                                .map(|c| c.exports.len())
                                .unwrap_or_else(|| config.map(|c| c.exports.len()).unwrap_or(0)),
                            forwards: managed
                                .map(|c| c.forwards.len())
                                .unwrap_or_else(|| config.map(|c| c.forwards.len()).unwrap_or(0)),
                            p2p_rows: &p2p_rows,
                        },
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
                if std::mem::take(&mut self.forwarding_panel.reload_managed) {
                    self.forwarding_panel.managed.reload();
                    self.forwarding_panel
                        .set_message("正在重新连接并加载服务器配置");
                    self.handle_disconnect();
                    self.handle_connect();
                }
                if std::mem::take(&mut self.forwarding_panel.save_managed) {
                    self.save_managed_configuration();
                }
                if save {
                    self.apply_configuration();
                }
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
                #[cfg(windows)]
                {
                    let mut enabled = self.autostart_enabled;
                    if ui.checkbox(&mut enabled, "开机自启动").changed() {
                        match autostart::set_enabled(enabled) {
                            Ok(()) => {
                                self.autostart_enabled = enabled;
                                self.autostart_error = None;
                            }
                            Err(error) => {
                                self.autostart_error = Some(format!("设置自启动失败：{error:#}"))
                            }
                        }
                    }
                    if let Some(error) = &self.autostart_error {
                        ui.colored_label(eframe::egui::Color32::RED, error);
                    }
                    ui.separator();
                }
                let mut on_save_and_reconnect = false;
                ui.add_enabled_ui(self.managed_save_rx.is_none(), |ui| {
                    self.config_panel.show(ui, &mut on_save_and_reconnect);
                });

                if on_save_and_reconnect {
                    self.apply_configuration();
                }
            }
        });
    }
}

impl GuiApp {
    fn apply_configuration(&mut self) {
        if self.managed_save_rx.is_some() {
            return;
        }
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
                    .set_message(format!("保存失败：{error:#}"));
                self.config_panel.set_save_error(&error);
            }
        }
    }

    fn save_managed_configuration(&mut self) {
        if self.managed_save_rx.is_some() {
            return;
        }
        let (Some(revision), Some(desired), Some(mut config)) = (
            self.forwarding_panel.managed.draft_revision(),
            self.forwarding_panel.managed.draft().cloned(),
            self.config_panel.config().cloned(),
        ) else {
            return;
        };
        if config.client.server_addr != self.connected_server
            || config.client.name != self.connected_name
        {
            self.forwarding_panel
                .set_message("保存失败：连接身份已修改，请先保存本地设置并重新连接以加载对应配置");
            return;
        }
        if let Err(error) = desired.validate() {
            self.forwarding_panel
                .set_message(format!("保存失败：{error}"));
            return;
        }
        if let Err(error) = self.config_panel.save() {
            self.forwarding_panel
                .set_message(format!("保存失败：本地设置无法保存：{error:#}"));
            return;
        }
        if let Some(directory) = self.config_path.parent() {
            config.client.private_key_file = directory.join(&config.client.private_key_file);
            config.client.certificate_authority_file =
                directory.join(&config.client.certificate_authority_file);
        }
        let Some(runtime) = &self.runtime else {
            self.forwarding_panel
                .set_message("保存失败：客户端运行时不可用");
            return;
        };
        self.managed_save_rx = Some(runtime.update_managed(config, revision, desired));
        self.forwarding_panel.saving = true;
        self.forwarding_panel.set_message("正在保存服务器配置…");
    }

    fn handle_connect(&mut self) {
        if self.managed_save_rx.is_some() {
            return;
        }
        let mut config = match configuration::load_or_create(&self.config_path) {
            Ok(cfg) => cfg,
            Err(e) => {
                self.log_ring.push(state::logs::LogLine {
                    timestamp: state::logs::local_timestamp(),
                    level: "ERROR".to_string(),
                    target: "gui".to_string(),
                    message: format!("配置文件准备失败: {e}"),
                });
                return;
            }
        };
        // The GUI fixes credential filenames; resolve them beside client.toml,
        // including when launched by Windows with a different working directory.
        if let Some(directory) = self.config_path.parent() {
            config.client.private_key_file = directory.join(&config.client.private_key_file);
            config.client.certificate_authority_file =
                directory.join(&config.client.certificate_authority_file);
        }
        let server_address = config.client.server_addr.clone();
        self.connected_server = server_address.clone();
        self.connected_name = config.client.name.clone();
        self.forwarding_panel.managed.select_server(&server_address);
        // Drop the prior subscription before any enrollment or initialization failure.
        let (_, status_rx) = watch::channel(rustgoc::ClientStatus::default());
        self.connection_vm = ConnectionViewModel::new(status_rx);
        self.tunnels.clear();
        self.connection_panel
            .set_server_address(server_address.clone());

        self.enrollment_state = match rustgoc::classify_enrollment_state(&config, &self.config_path)
        {
            Ok(EnrollmentState::Ready) => EnrollmentState::Ready,
            Ok(state) => {
                self.log_ring.push(state::logs::LogLine {
                    timestamp: state::logs::local_timestamp(),
                    level: "WARN".to_string(),
                    target: "gui".to_string(),
                    message: "客户端当前需要完成设备注册".to_string(),
                });
                self.enrollment_state = state;
                self.handle_enrollment_submit();
                return;
            }
            Err(error) => {
                self.log_ring.push(state::logs::LogLine {
                    timestamp: state::logs::local_timestamp(),
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
                        timestamp: state::logs::local_timestamp(),
                        level: "INFO".to_string(),
                        target: "gui".to_string(),
                        message: format!("正在连接到 {}", server_address),
                    });
                }
            }
            Err(e) => self.log_ring.push(state::logs::LogLine {
                timestamp: state::logs::local_timestamp(),
                level: "ERROR".to_string(),
                target: "gui".to_string(),
                message: format!("客户端初始化失败: {}", e),
            }),
        }
    }

    fn handle_enrollment_submit(&mut self) {
        if self.enrollment_rx.is_some() {
            return;
        }
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
        if let Some(runtime) = &self.runtime {
            self.enrollment_panel.clear_error();
            self.enrollment_rx =
                Some(runtime.enroll(config, self.config_path.clone(), purpose, false));
            self.enrollment_state = match purpose {
                rustgoc::EnrollmentPurpose::Enroll => EnrollmentState::EnrollmentPending,
                rustgoc::EnrollmentPurpose::ReEnroll => EnrollmentState::ReEnrollmentPending,
            };
            self.log_ring.push(state::logs::LogLine {
                timestamp: state::logs::local_timestamp(),
                level: "INFO".to_string(),
                target: "gui".to_string(),
                message: "正在安全保存候选密钥并提交注册请求".to_string(),
            });
        }
    }

    fn handle_disconnect(&mut self) {
        if self.enrollment_rx.take().is_some() {
            self.enrollment_panel
                .set_error("审批查询已暂停，可点击继续查询".to_owned());
        }
        if let Some(runtime) = &self.runtime {
            runtime.disconnect();
            self.log_ring.push(state::logs::LogLine {
                timestamp: state::logs::local_timestamp(),
                level: "INFO".to_string(),
                target: "gui".to_string(),
                message: "已断开连接".to_string(),
            });
        }
    }
}

#[cfg(test)]
mod approval_regression_tests {
    use super::*;
    use eframe::App;

    #[test]
    fn managed_save_persists_local_policy_without_remote_collections() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("client.toml");
        let mut app = headless_app(path.clone());
        app.runtime = None;
        let config = app.config_panel.config_mut().unwrap();
        app.connected_server = config.client.server_addr.clone();
        app.connected_name = config.client.name.clone();
        config.p2p = Some(rustgo_config::P2pConfig {
            enabled: true,
            prefer_direct: true,
            direct_timeout_secs: 10,
            reconnect_timeout_secs: 30,
            allow_relay_fallback: true,
            udp_port_range: rustgo_config::PortRange {
                start: 20000,
                end: 21000,
            },
            tcp_port_range: rustgo_config::PortRange {
                start: 22000,
                end: 23000,
            },
            observation_primary_addr: None,
            observation_alternate_addr: None,
        });
        let mut remote = rustgo_config::ManagedConfiguration::from_client(config);
        remote.tunnels.push(rustgo_config::TunnelConfig {
            name: "remote".into(),
            protocol: rustgo_config::TunnelProtocol::Tcp,
            local_addr: "127.0.0.1:22".into(),
            remote_port: 2222,
        });
        app.forwarding_panel
            .managed
            .observe(true, Some(4), Some(&remote));
        app.save_managed_configuration();
        let saved = rustgo_config::load_client(&path).unwrap();
        assert!(saved.p2p.unwrap().enabled);
        assert!(saved.tunnels.is_empty());
        assert_eq!(app.forwarding_panel.managed.draft_revision(), Some(4));
        assert_eq!(app.forwarding_panel.managed.draft(), Some(&remote));
    }

    fn headless_app(config_path: PathBuf) -> GuiApp {
        let (status_tx, status_rx) = watch::channel(rustgoc::ClientStatus::default());
        let (_, tray_rx) = mpsc::sync_channel(1);
        let telemetry_history = state::telemetry::TelemetryHistory::new();
        let path_status_store = rustgoc::PathStatusStore::new();
        GuiApp {
            active_tab: Tab::Connection,
            connection_panel: ConnectionPanel::new(String::new()),
            enrollment_panel: EnrollmentPanel::new(),
            forwarding_panel: ForwardingPanel::new(),
            logs_panel: LogsPanel::new(),
            config_panel: ConfigPanel::new(config_path.clone()),
            connection_vm: ConnectionViewModel::new(status_rx),
            tunnels: Vec::new(),
            runtime: Some(runtime::ClientRuntime::new(telemetry_history.clone()).unwrap()),
            telemetry_history,
            p2p_vm: state::p2p::P2PViewModel::new(path_status_store.clone()),
            log_ring: LogRing::new(),
            tray_rx,
            _tray: None,
            window_lifecycle: Default::default(),
            #[cfg(windows)]
            autostart_enabled: false,
            #[cfg(windows)]
            autostart_error: None,
            config_path,
            _status_tx: status_tx,
            traffic_handle: None,
            path_status_store,
            enrollment_state: EnrollmentState::Ready,
            enrollment_rx: None,
            managed_save_rx: None,
            connected_server: String::new(),
            connected_name: String::new(),
            auto_connect_pending: false,
            last_logged_connection_state: state::connection::ConnectionState::Disconnected,
        }
    }

    struct Fixture {
        directory: tempfile::TempDir,
        runtime: tokio::runtime::Runtime,
        shutdown: tokio_util::sync::CancellationToken,
        store: rustgos::enrollment::DynamicClientStore,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let pair = rcgen::KeyPair::generate().unwrap();
            let cert =
                rcgen::CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
                    .unwrap()
                    .self_signed(&pair)
                    .unwrap();
            std::fs::write(directory.path().join("server.pem"), cert.pem()).unwrap();
            std::fs::write(directory.path().join("server-cert.pem"), cert.pem()).unwrap();
            std::fs::write(directory.path().join("server.key"), pair.serialize_pem()).unwrap();
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            drop(listener);
            let server_path = directory.path().join("server.toml");
            std::fs::write(&server_path, format!("[server]\nbind_addr='{address}'\ncertificate_file='server.pem'\nprivate_key_file='server.key'\nheartbeat_timeout_secs=60\n[limits]\nmax_clients=8\nmax_tunnels_per_client=4\nmax_tcp_connections_per_tunnel=4\nmax_udp_sessions_per_tunnel=4\nmax_udp_payload_bytes=65507\n[enrollment]\nenabled=true\ndatabase_path='approval.db'\npublic_addr='{address}'\nmax_active_clients=8\nmax_tokens=8\n")).unwrap();
            std::fs::write(directory.path().join("client.toml"), format!("[client]\nname='Gui.Node'\nserver_addr='{address}'\nserver_name='localhost'\ncertificate_authority_file='server.pem'\nprivate_key_file='device.key'\nheartbeat_interval_secs=20\n[telemetry]\nenabled=false\n")).unwrap();
            let runtime = tokio::runtime::Runtime::new().unwrap();
            let server = runtime
                .block_on(rustgos::ServerApp::bind(
                    rustgo_config::load_server(&server_path).unwrap(),
                ))
                .unwrap();
            let shutdown = tokio_util::sync::CancellationToken::new();
            runtime.spawn(server.run_until(shutdown.clone()));
            let store = rustgos::enrollment::DynamicClientStore::open(
                directory.path().join("approval.db"),
                rustgos::enrollment::EnrollmentStoreLimits {
                    max_active_clients: 8,
                    max_tokens: 8,
                },
            )
            .unwrap();
            Self {
                directory,
                runtime,
                shutdown,
                store,
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            self.shutdown.cancel();
            self.runtime
                .block_on(async { tokio::task::yield_now().await });
        }
    }

    fn wait_until(timeout: Duration, mut condition: impl FnMut() -> bool) {
        let deadline = std::time::Instant::now() + timeout;
        while !condition() {
            assert!(
                std::time::Instant::now() < deadline,
                "GUI state did not advance before timeout"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    #[test]
    fn gui_retains_authentication_rejection_for_approval_recovery() {
        let fixture = Fixture::new();
        rustgo_crypto::generate_key_file(fixture.directory.path()).unwrap();
        let mut app = headless_app(fixture.directory.path().join("client.toml"));
        app.handle_connect();
        wait_until(Duration::from_secs(3), || {
            app.connection_vm.authentication_rejected()
        });
        std::thread::sleep(Duration::from_millis(100));
        assert!(app.connection_vm.authentication_rejected());
    }

    #[test]
    fn hidden_gui_connects_after_approval_without_painting() {
        let fixture = Fixture::new();
        let mut app = headless_app(fixture.directory.path().join("client.toml"));
        app.handle_connect();
        wait_until(Duration::from_secs(3), || {
            !fixture.store.pending_approvals().unwrap().is_empty()
        });
        let pending = fixture.store.pending_approvals().unwrap();
        fixture
            .store
            .review_approval(&pending[0].request_id, true)
            .unwrap();
        let ctx = eframe::egui::Context::default();
        let mut input = eframe::egui::RawInput::default();
        input
            .viewports
            .get_mut(&eframe::egui::ViewportId::ROOT)
            .unwrap()
            .minimized = Some(true);
        let mut frame = eframe::Frame::_new_kittest();
        wait_until(Duration::from_secs(10), || {
            let _ = ctx.run_logic(&input, |ctx| app.logic(ctx, &mut frame));
            matches!(
                app.connection_vm.current(),
                state::connection::ConnectionState::Connected { .. }
            )
        });
        assert!(app.enrollment_rx.is_none());
        assert!(rustgoc::PendingEnrollment::load(&app.config_path).is_err());
    }
}
