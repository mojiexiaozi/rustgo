use std::{path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand};
use rustgo_config::{ConfigError, check_server_references, load_server};
use rustgo_transport::{init_logging, safe_display};
use rustgos::{ServerApp, ServerError};
use thiserror::Error;

/// Rustgo public relay server.
#[derive(Debug, Parser)]
#[command(name = "rustgos")]
struct Cli {
    /// Path to the server configuration file.
    #[arg(short, long, global = true, default_value = "server.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Parse, validate, and locally inspect the configuration without starting listeners.
    Check,
}

enum Action {
    Run,
    Check,
}

#[tokio::main]
async fn main() -> ExitCode {
    init_logging();
    match execute(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rustgos: {}", safe_display(&error));
            eprintln!("Use -c <path> to select a server configuration file.");
            ExitCode::FAILURE
        }
    }
}

async fn execute(cli: Cli) -> Result<(), CommandError> {
    let action = match cli.command {
        None => Action::Run,
        Some(Command::Check) => Action::Check,
    };
    let config = load_server(&cli.config)?;
    check_server_references(&cli.config, &config)?;

    match action {
        Action::Run => ServerApp::bind(config)
            .await?
            .run()
            .await
            .map_err(Into::into),
        Action::Check => Ok(()),
    }
}

#[derive(Debug, Error)]
enum CommandError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Server(#[from] ServerError),
}
