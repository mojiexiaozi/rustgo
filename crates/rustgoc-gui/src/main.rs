#![forbid(unsafe_code)]

mod runtime;
mod selfcheck;
mod state;
mod tray;

use clap::Parser;
use std::path::PathBuf;

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

struct GuiApp;

impl GuiApp {
    fn new() -> Self {
        Self
    }
}

impl eframe::App for GuiApp {
    fn ui(&mut self, ui: &mut eframe::egui::Ui, _frame: &mut eframe::Frame) {
        ui.heading("Rustgo GUI Client");
        ui.label("Connection UI coming soon...");
    }
}
