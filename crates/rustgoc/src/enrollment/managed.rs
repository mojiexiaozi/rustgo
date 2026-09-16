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
        let mut status = app.subscribe();
        let run = app.run_until(shutdown.clone());
        tokio::pin!(run);
        let result = loop {
            tokio::select! {
                result = &mut run => break result,
                changed = status.changed() => {
                    if changed.is_err() { continue; }
                    let profile = status.borrow().client_profile().cloned();
                    if let Some(profile) = profile {
                        match persist_client_profile(path, &profile) {
                            Ok(profile) => config.client.profile = Some(profile),
                            Err(error) => tracing::warn!(%error, "保存客户端资料失败"),
                        }
                    }
                }
            }
        };
        match result {
            Err(crate::ClientError::AuthenticationRejected) => {
                purpose = Some(EnrollmentPurpose::ReEnroll)
            }
            result => return result.map_err(|e| e.to_string()),
        }
    }
}

fn persist_client_profile(
    path: &Path,
    profile: &rustgo_config::ClientProfile,
) -> Result<rustgo_config::ClientProfile, String> {
    use std::io::Write;
    let contents = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let mut document: toml::Value = toml::from_str(&contents).map_err(|e| e.to_string())?;
    let client = document
        .get_mut("client")
        .and_then(toml::Value::as_table_mut)
        .ok_or("缺少客户端配置")?;
    let mut profile = profile.clone();
    if let Some(label) = client
        .get("profile")
        .and_then(|p| p.get("display_name"))
        .and_then(toml::Value::as_str)
    {
        profile.display_name = label.to_owned();
    }
    client.insert(
        "profile".into(),
        toml::Value::try_from(&profile).map_err(|e| e.to_string())?,
    );
    let encoded = toml::to_string_pretty(&document).map_err(|e| e.to_string())?;
    atomicwrites::AtomicFile::new(path, atomicwrites::AllowOverwrite)
        .write(|file| file.write_all(encoded.as_bytes()))
        .map_err(|e| e.to_string())?;
    Ok(profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_persistence_preserves_routing_identity_and_current_settings() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.toml");
        std::fs::write(&path, "[client]\nname='legacy-alias'\nserver_addr='edited:7443'\n[client.profile]\ndisplay_name='Unsaved label edit'\nuid='old'\n").unwrap();
        let profile = rustgo_config::ClientProfile {
            display_name: "Previous label".into(),
            uid: Some("server-uid".into()),
            local_ip: Some("127.0.0.1".into()),
        };
        let saved = persist_client_profile(&path, &profile).unwrap();
        assert_eq!(saved.display_name, "Unsaved label edit");
        let document: toml::Value =
            toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(document["client"]["name"].as_str(), Some("legacy-alias"));
        assert_eq!(
            document["client"]["server_addr"].as_str(),
            Some("edited:7443")
        );
        assert_eq!(
            document["client"]["profile"]["uid"].as_str(),
            Some("server-uid")
        );
    }
}
