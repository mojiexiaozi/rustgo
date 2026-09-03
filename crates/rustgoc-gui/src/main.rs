#![forbid(unsafe_code)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod runtime;
mod selfcheck;
mod state;
mod tray;
mod tray_events;
mod ui;

use clap::Parser;
use state::connection::ConnectionViewModel;
use state::logs::LogRing;
use state::tunnels::TunnelRow;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;
use tokio::sync::watch;
use tray_events::TrayEvent;
use ui::connection::ConnectionPanel;
use ui::logs::LogsPanel;
use ui::tunnels::TunnelsPanel;

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
    #[arg(short = 'c', long, default_value = "client.toml")]
    config: PathBuf,

    #[arg(long)]
    selfcheck: bool,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if cli.selfcheck {
        return selfcheck::run(&cli.config);
    }

    let config_path = cli.config.clone();

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
    Tunnels,
    Logs,
}

struct GuiApp {
    active_tab: Tab,
    connection_panel: ConnectionPanel,
    tunnels_panel: TunnelsPanel,
    logs_panel: LogsPanel,
    connection_vm: ConnectionViewModel,
    tunnels: Vec<TunnelRow>,
    log_ring: LogRing,
    tray_rx: mpsc::Receiver<TrayEvent>,
    _tray: Option<tray::platform::TrayIcon>,
    should_quit: bool,
    runtime: Option<runtime::ClientRuntime>,
    config_path: PathBuf,
    _status_tx: watch::Sender<rustgoc::ClientStatus>,
}

impl GuiApp {
    fn new(config_path: PathBuf) -> Self {
        let (status_tx, status_rx) = watch::channel(rustgoc::ClientStatus::default());

        let (tray_tx, tray_rx) = mpsc::sync_channel(64);

        #[cfg(windows)]
        let tray = tray::platform::TrayIcon::new(tray_tx).ok();

        #[cfg(not(windows))]
        let tray = None;

        let runtime = runtime::ClientRuntime::new().ok();

        Self {
            active_tab: Tab::Connection,
            connection_panel: ConnectionPanel::new("8.133.176.172:8443".to_string()),
            tunnels_panel: TunnelsPanel::new(),
            logs_panel: LogsPanel::new(),
            connection_vm: ConnectionViewModel::new(status_rx),
            tunnels: Vec::new(),
            log_ring: LogRing::new(),
            tray_rx,
            _tray: tray,
            should_quit: false,
            runtime,
            config_path,
            _status_tx: status_tx,
        }
    }
}

impl eframe::App for GuiApp {
    fn ui(&mut self, ui: &mut eframe::egui::Ui, _frame: &mut eframe::Frame) {
        self.connection_vm.update();

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
                    .selectable_label(matches!(self.active_tab, Tab::Tunnels), "隧道")
                    .clicked()
                {
                    self.active_tab = Tab::Tunnels;
                }
                if ui
                    .selectable_label(matches!(self.active_tab, Tab::Logs), "日志")
                    .clicked()
                {
                    self.active_tab = Tab::Logs;
                }
            });
        });

        eframe::egui::CentralPanel::default().show(ui, |ui| match self.active_tab {
            Tab::Connection => {
                let mut on_connect = false;
                let mut on_disconnect = false;
                self.connection_panel.show(
                    ui,
                    &mut self.connection_vm,
                    &mut on_connect,
                    &mut on_disconnect,
                    None,
                    None,
                );

                // 处理连接/断开事件
                if on_connect {
                    self.handle_connect();
                }
                if on_disconnect {
                    self.handle_disconnect();
                }
            }
            Tab::Tunnels => {
                self.tunnels_panel.show(ui, &self.tunnels);
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
        });

        ui.ctx().request_repaint_after(Duration::from_millis(500));
    }
}

impl GuiApp {
    fn generate_default_config(&self) -> anyhow::Result<()> {
        use std::io::Write;

        let default_config = r#"[client]
name = "gui-client"
server_addr = "8.133.176.172:8443"
server_name = "rustgo-server"
certificate_authority_file = "ca.pem"
private_key_file = "client-key.pem"
heartbeat_interval_secs = 30

[[tunnels]]
name = "ssh"
protocol = "tcp"
local_addr = "127.0.0.1:22"
remote_port = 10022
"#;

        let mut file = std::fs::File::create(&self.config_path)?;
        file.write_all(default_config.as_bytes())?;
        Ok(())
    }

    fn handle_connect(&mut self) {
        let server_address = self.connection_panel.server_address.clone();

        // 加载配置，如果不存在则生成默认配置
        let config = match rustgo_config::load_client(&self.config_path) {
            Ok(cfg) => cfg,
            Err(_) => {
                // 尝试生成默认配置
                if let Err(gen_err) = self.generate_default_config() {
                    self.log_ring.push(state::logs::LogLine {
                        timestamp: time::OffsetDateTime::now_utc()
                            .format(&time::format_description::well_known::Rfc3339)
                            .unwrap_or_else(|_| "unknown".to_string()),
                        level: "ERROR".to_string(),
                        target: "gui".to_string(),
                        message: format!("配置文件生成失败: {}", gen_err),
                    });
                    return;
                }

                self.log_ring.push(state::logs::LogLine {
                    timestamp: time::OffsetDateTime::now_utc()
                        .format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_else(|_| "unknown".to_string()),
                    level: "INFO".to_string(),
                    target: "gui".to_string(),
                    message: format!("已生成默认配置文件: {}", self.config_path.display()),
                });

                // 重新加载配置
                match rustgo_config::load_client(&self.config_path) {
                    Ok(cfg) => cfg,
                    Err(e) => {
                        self.log_ring.push(state::logs::LogLine {
                            timestamp: time::OffsetDateTime::now_utc()
                                .format(&time::format_description::well_known::Rfc3339)
                                .unwrap_or_else(|_| "unknown".to_string()),
                            level: "ERROR".to_string(),
                            target: "gui".to_string(),
                            message: format!("配置文件读取失败: {}", e),
                        });
                        return;
                    }
                }
            }
        };

        // 创建客户端应用
        match rustgoc::ClientApp::from_config(config) {
            Ok(app) => {
                if let Some(runtime) = &self.runtime {
                    runtime.connect(app);
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
            Err(e) => {
                self.log_ring.push(state::logs::LogLine {
                    timestamp: time::OffsetDateTime::now_utc()
                        .format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_else(|_| "unknown".to_string()),
                    level: "ERROR".to_string(),
                    target: "gui".to_string(),
                    message: format!("客户端初始化失败: {}", e),
                });
            }
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
