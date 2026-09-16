use std::{path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand};
use rustgo_config::{ConfigError, check_server_references, load_server};
use rustgo_transport::{init_logging, safe_display};
use rustgos::{
    IdentityProvisioning, ServerApp, ServerError, ServerIdentityError, ensure_server_identity,
};
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
            eprintln!("使用 -c <path> 指定服务端配置文件。");
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
    if matches!(action, Action::Run)
        && ensure_server_identity(&config)? == IdentityProvisioning::Generated
    {
        let fingerprint = rustgo_transport::TlsServer::leaf_certificate_fingerprint(
            &config.server.certificate_file,
        )
        .map_err(ServerError::from)?;
        let fingerprint = fingerprint
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        tracing::info!(
            certificate = %config.server.certificate_file.display(),
            private_key = %config.server.private_key_file.display(),
            fingerprint = %fingerprint,
            event = %"server_identity_generated",
            "已生成并保存服务端 TLS 身份"
        );
    }
    let reference_check = check_server_references(&cli.config, &config)?;
    for warning in reference_check.warnings() {
        tracing::warn!(
            code = warning.code(),
            message = warning.message(),
            "配置警告"
        );
    }

    match action {
        Action::Run => {
            let server = ServerApp::bind(config).await?;
            let address = server.local_addr().map_err(ServerError::from)?;
            let web_address = server.web_local_addr();
            tracing::info!(
                address = %safe_display(address),
                web_enabled = web_address.is_some(),
                event = %"server_listening",
                "服务端 TLS 监听器已就绪"
            );
            if let Some(address) = web_address {
                tracing::info!(
                    address = %safe_display(address),
                    event = %"web_listening",
                    "Web 管理面板监听器已就绪"
                );
            }
            server.run().await.map_err(Into::into)
        }
        Action::Check => ServerApp::validate_configuration(&config).map_err(Into::into),
    }
}

#[derive(Debug, Error)]
enum CommandError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Identity(#[from] ServerIdentityError),
    #[error(transparent)]
    Server(#[from] ServerError),
}
