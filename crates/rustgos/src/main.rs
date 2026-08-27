use std::{path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand};
use rustgo_config::{ConfigError, ServerConfig, check_server_references, load_server};

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

trait CommandHandler {
    fn run(&self, config: ServerConfig) -> Result<(), ConfigError>;
}

struct LocalCommandHandler;

impl CommandHandler for LocalCommandHandler {
    fn run(&self, _config: ServerConfig) -> Result<(), ConfigError> {
        // Runtime startup is supplied by the server application task. Keeping it behind
        // this handler preserves this parser and validation contract for that task.
        Ok(())
    }
}

fn main() -> ExitCode {
    match execute(Cli::parse(), &LocalCommandHandler) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rustgos: {error}");
            eprintln!("Use -c <path> to select a server configuration file.");
            ExitCode::FAILURE
        }
    }
}

fn execute<H: CommandHandler>(cli: Cli, handler: &H) -> Result<(), ConfigError> {
    let action = match cli.command {
        None => Action::Run,
        Some(Command::Check) => Action::Check,
    };
    let config = load_server(&cli.config)?;
    check_server_references(&cli.config, &config)?;

    match action {
        Action::Run => handler.run(config),
        Action::Check => Ok(()),
    }
}
