use std::{
    io::{self, IsTerminal, Read},
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::{Parser, Subcommand};
use rustgo_config::{ClientConfig, check_client_references, load_client};
use rustgo_crypto::generate_key_file;
use rustgo_transport::{init_logging, safe_display};
use rustgoc::{ClientApp, ControlClient, EnrollmentKey, EnrollmentPurpose};

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
    /// Register a new dynamic identity. The key is read securely from the terminal,
    /// stdin, or RUSTGO_ENROLLMENT_KEY; it is never accepted as an argument.
    Enroll,
    /// Replace an existing dynamic private key using a re-enrollment key.
    ReEnroll {
        /// Confirm deletion and replacement of the existing private key.
        #[arg(long)]
        confirm_replace_key: bool,
    },
}

enum Action {
    Run,
    Check,
    Keygen { output: PathBuf },
    Enroll,
    ReEnroll { confirm_replace_key: bool },
}

trait CommandHandler {
    fn run(&self, config: ClientConfig) -> Result<(), String>;
    fn keygen(&self, output: PathBuf) -> Result<(), String>;
    fn enroll(
        &self,
        config: ClientConfig,
        config_path: &Path,
        reenroll: bool,
    ) -> Result<(), String>;
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

    fn enroll(
        &self,
        mut config: ClientConfig,
        config_path: &Path,
        reenroll: bool,
    ) -> Result<(), String> {
        let key = read_enrollment_key()?;
        let parsed = EnrollmentKey::parse(&key).map_err(|error| error.to_string())?;
        let expected = if reenroll {
            EnrollmentPurpose::ReEnroll
        } else {
            EnrollmentPurpose::Enroll
        };
        if parsed.purpose() != expected {
            return Err("enrollment key purpose does not match the requested operation".to_owned());
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| format!("could not start enrollment runtime: {error}"))?;
        let completion = runtime
            .block_on(rustgoc::enroll(&mut config, config_path, key.trim()))
            .map_err(|error| error.to_string())?;
        println!(
            "Dynamic enrollment completed for {} at revision {}.",
            completion.client_id, completion.revision
        );
        Ok(())
    }
}

fn read_enrollment_key() -> Result<String, String> {
    if let Ok(value) = std::env::var("RUSTGO_ENROLLMENT_KEY")
        && !value.trim().is_empty()
    {
        return Ok(value);
    }
    if !io::stdin().is_terminal() {
        let mut value = String::new();
        io::stdin()
            .read_to_string(&mut value)
            .map_err(|_| "could not read enrollment key from stdin".to_owned())?;
        if !value.trim().is_empty() {
            return Ok(value);
        }
        return Err("enrollment key input is empty".to_owned());
    }
    rpassword::prompt_password("Enrollment key: ")
        .map_err(|_| "could not read enrollment key securely".to_owned())
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
        Some(Command::Enroll) => Action::Enroll,
        Some(Command::ReEnroll {
            confirm_replace_key,
        }) => Action::ReEnroll {
            confirm_replace_key,
        },
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
    if matches!(action, Action::Run | Action::Check) {
        check_client_references(&cli.config, &config).map_err(|error| error.to_string())?;
    }
    match action {
        Action::Run => handler.run(config),
        Action::Check => {
            ControlClient::validate_credentials(&config).map_err(|error| error.to_string())
        }
        Action::Enroll => handler.enroll(config, &cli.config, false),
        Action::ReEnroll { confirm_replace_key: false } => Err(
            "re-enrollment replaces the existing private key; pass --confirm-replace-key to continue".to_owned(),
        ),
        Action::ReEnroll { confirm_replace_key: true } => handler.enroll(config, &cli.config, true),
        Action::Keygen { .. } => unreachable!("keygen actions return before configuration loading"),
    }
}
