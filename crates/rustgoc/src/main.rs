use std::{path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand};
use rustgo_config::{ClientConfig, check_client_references, load_client};
use rustgo_crypto::generate_key_file;
use rustgo_transport::{init_logging, safe_display};
use rustgoc::{ClientApp, ControlClient};

/// Rustgo private-network client.
#[derive(Debug, Parser)]
#[command(name = "rustgoc")]
struct Cli {
    /// Path to the client configuration file.
    #[arg(short, long, global = true, default_value = "client.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Parse, validate, and locally inspect the configuration without contacting the server.
    Check,
    /// Generate a device key pair in the selected directory.
    Keygen {
        #[arg(short, long, default_value = "./keys")]
        output: PathBuf,
    },
}

enum Action {
    Run,
    Check,
    Keygen { output: PathBuf },
}

trait CommandHandler {
    fn run(&self, config: ClientConfig) -> Result<(), String>;
    fn keygen(&self, output: PathBuf) -> Result<(), String>;
}

struct LocalCommandHandler;

impl CommandHandler for LocalCommandHandler {
    fn run(&self, config: ClientConfig) -> Result<(), String> {
        let app = ClientApp::from_config(config).map_err(|error| error.to_string())?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|error| format!("could not start client runtime: {error}"))?;
        runtime
            .block_on(app.run())
            .map_err(|error| error.to_string())
    }

    fn keygen(&self, output: PathBuf) -> Result<(), String> {
        generate_key_file(&output)
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

fn main() -> ExitCode {
    init_logging();
    let cli = Cli::parse();
    let show_config_hint = !matches!(&cli.command, Some(Command::Keygen { .. }));
    match execute(cli, &LocalCommandHandler) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rustgoc: {}", safe_display(&error));
            if show_config_hint {
                eprintln!("Use -c <path> to select a client configuration file.");
            }
            ExitCode::FAILURE
        }
    }
}

fn execute<H: CommandHandler>(cli: Cli, handler: &H) -> Result<(), String> {
    let action = match cli.command {
        None => Action::Run,
        Some(Command::Check) => Action::Check,
        Some(Command::Keygen { output }) => Action::Keygen { output },
    };
    if let Action::Keygen { output } = action {
        return handler.keygen(output);
    }

    let config = load_client(&cli.config).map_err(|error| error.to_string())?;
    for warning in config.validation_warnings() {
        tracing::warn!(
            code = warning.code(),
            message = warning.message(),
            "configuration warning"
        );
    }
    check_client_references(&cli.config, &config).map_err(|error| error.to_string())?;
    match action {
        Action::Run => handler.run(config),
        Action::Check => {
            ControlClient::validate_credentials(&config).map_err(|error| error.to_string())
        }
        Action::Keygen { .. } => unreachable!("keygen actions return before configuration loading"),
    }
}
