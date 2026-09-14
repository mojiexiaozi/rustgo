use clap::{Parser, Subcommand};
use rustgo_transport::{init_logging, safe_display};
use std::{path::PathBuf, process::ExitCode};
use tokio_util::sync::CancellationToken;

/// Rustgo 客户端，固定读取程序同目录 client.toml，自动申请接入并等待审批。
#[derive(Debug, Parser)]
#[command(name = "rustgoc")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// 检查同目录配置和已有凭据，不连接服务器。
    Check,
    /// 单独生成设备密钥；正常启动无需执行此命令。
    Keygen {
        #[arg(short, long, default_value = "./keys")]
        output: PathBuf,
    },
    /// 复用已有密钥申请接入，缺失时自动生成，等待管理员批准。
    Enroll,
    /// 复用当前密钥申请重新接入。
    ReEnroll {
        /// 明确生成新密钥；批准前保留当前密钥。
        #[arg(long)]
        confirm_replace_key: bool,
    },
}

fn main() -> ExitCode {
    init_logging();
    match execute(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rustgoc: {}", safe_display(&error));
            ExitCode::FAILURE
        }
    }
}

fn execute(cli: Cli) -> Result<(), String> {
    if let Some(Command::Keygen { output }) = cli.command {
        return rustgo_crypto::generate_key_file(&output)
            .map(|_| ())
            .map_err(|e| e.to_string());
    }
    let executable = std::env::current_exe().map_err(|e| format!("无法确定程序路径：{e}"))?;
    let path = rustgoc::client_config_path(&executable)?;
    let mut config = rustgo_config::load_client(&path)
        .map_err(|e| format!("读取 {} 失败：{e}", path.display()))?;
    for warning in config.validation_warnings() {
        tracing::warn!(
            code = warning.code(),
            message = warning.message(),
            "配置警告"
        );
    }
    if matches!(cli.command, Some(Command::Check)) {
        rustgo_config::check_client_references(&path, &config).map_err(|e| e.to_string())?;
        return rustgoc::ControlClient::validate_credentials(&config).map_err(|e| e.to_string());
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(async move {
        let shutdown = CancellationToken::new();
        let worker = async {
            match cli.command {
                Some(Command::Enroll) => {
                    rustgoc::wait_for_registration(
                        &mut config,
                        &path,
                        rustgoc::EnrollmentPurpose::Enroll,
                        false,
                        &shutdown,
                    )
                    .await;
                    Ok(())
                }
                Some(Command::ReEnroll {
                    confirm_replace_key,
                }) => {
                    rustgoc::wait_for_registration(
                        &mut config,
                        &path,
                        rustgoc::EnrollmentPurpose::ReEnroll,
                        confirm_replace_key,
                        &shutdown,
                    )
                    .await;
                    Ok(())
                }
                _ => rustgoc::run_managed_client(config.clone(), &path, shutdown.clone()).await,
            }
        };
        tokio::pin!(worker);
        tokio::select! {
            result=&mut worker=>result,
            signal=tokio::signal::ctrl_c()=>{
                signal.map_err(|e|e.to_string())?;
                shutdown.cancel();
                worker.await
            }
        }
    })
}
