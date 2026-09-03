#![forbid(unsafe_code)]

mod runtime;
mod selfcheck;
mod state;
mod tray;
mod ui;

use clap::Parser;
use state::connection::ConnectionViewModel;
use state::logs::LogRing;
use state::tunnels::TunnelRow;
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::watch;
use ui::connection::ConnectionPanel;
use ui::logs::LogsPanel;
use ui::tunnels::TunnelsPanel;

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

    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 800.0])
            .with_title("Rustgo GUI"),
        ..Default::default()
    };

    eframe::run_native(
        "rustgoc-gui",
        options,
        Box::new(|_cc| Ok(Box::new(GuiApp::new()))),
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
}

impl GuiApp {
    fn new() -> Self {
        let (status_tx, status_rx) = watch::channel(rustgoc::ClientStatus::default());
        drop(status_tx);

        Self {
            active_tab: Tab::Connection,
            connection_panel: ConnectionPanel::new("server:8443".to_string()),
            tunnels_panel: TunnelsPanel::new(),
            logs_panel: LogsPanel::new(),
            connection_vm: ConnectionViewModel::new(status_rx),
            tunnels: Vec::new(),
            log_ring: LogRing::new(),
        }
    }
}

impl eframe::App for GuiApp {
    fn ui(&mut self, ui: &mut eframe::egui::Ui, _frame: &mut eframe::Frame) {
        self.connection_vm.update();

        eframe::egui::Panel::top("tabs").show(ui, |ui| {
            ui.horizontal(|ui| {
                if ui
                    .selectable_label(matches!(self.active_tab, Tab::Connection), "Connection")
                    .clicked()
                {
                    self.active_tab = Tab::Connection;
                }
                if ui
                    .selectable_label(matches!(self.active_tab, Tab::Tunnels), "Tunnels")
                    .clicked()
                {
                    self.active_tab = Tab::Tunnels;
                }
                if ui
                    .selectable_label(matches!(self.active_tab, Tab::Logs), "Logs")
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
