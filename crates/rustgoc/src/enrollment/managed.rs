use super::{EnrollmentPurpose, PendingEnrollment, request_key_rotation, request_registration};
use rustgo_config::{ClientConfig, IdentityMode};
use rustgo_crypto::DeviceKeypair;
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

pub fn client_config_path(executable: &Path) -> Result<PathBuf, String> {
    executable
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| p.join("client.toml"))
        .ok_or_else(|| "无法确定程序所在目录".to_owned())
}

/// Returns false only when the user stops the process; errors keep the client waiting.
pub async fn wait_for_registration(
    config: &mut ClientConfig,
    path: &Path,
    purpose: EnrollmentPurpose,
    rotate: bool,
    shutdown: &CancellationToken,
) -> bool {
    let mut previous = String::new();
    loop {
        let result = tokio::select! {
            biased;
            () = shutdown.cancelled() => return false,
            result = async {
                if rotate { request_key_rotation(config,path).await }
                else { request_registration(config,path,purpose).await }
            } => result,
        };
        match result {
            Ok(result) => {
                tracing::info!(client=%result.client_id,revision=result.revision,"审批完成，开始连接");
                return true;
            }
            Err(error) => {
                let message = error.to_string();
                if message != previous {
                    tracing::warn!(error=%message,"申请尚未完成，客户端保持运行等待审批");
                    if let Ok(pending) = PendingEnrollment::load(path)
                        && let Ok(public) = pending
                            .public_key()
                            .parse::<rustgo_crypto::DevicePublicKey>()
                    {
                        tracing::info!(fingerprint=%public.fingerprint(),"请在管理端核对公钥指纹后批准");
                    }
                    previous = message;
                }
            }
        }
        tokio::select! { biased; ()=shutdown.cancelled()=>return false, ()=tokio::time::sleep(Duration::from_secs(5))=>{} }
    }
}

pub async fn run_managed_client(
    mut config: ClientConfig,
    path: &Path,
    shutdown: CancellationToken,
) -> Result<(), String> {
    let mut purpose = if PendingEnrollment::exists(path) {
        Some(
            PendingEnrollment::load(path)
                .map_err(|e| e.to_string())?
                .purpose(),
        )
    } else if DeviceKeypair::load_private_file(&config.client.private_key_file).is_err() {
        Some(
            if config.client.identity_mode == Some(IdentityMode::Dynamic) {
                EnrollmentPurpose::ReEnroll
            } else {
                EnrollmentPurpose::Enroll
            },
        )
    } else {
        None
    };
    loop {
        if let Some(requested) = purpose.take()
            && !wait_for_registration(&mut config, path, requested, false, &shutdown).await
        {
            return Ok(());
        }
        if shutdown.is_cancelled() {
            return Ok(());
        }
        let app = crate::ClientApp::from_config(config.clone())
            .map_err(|e| e.to_string())?
            .with_approval_recovery();
        match app.run_until(shutdown.clone()).await {
            Err(crate::ClientError::AuthenticationRejected) => {
                purpose = Some(EnrollmentPurpose::ReEnroll)
            }
            result => return result.map_err(|e| e.to_string()),
        }
    }
}
