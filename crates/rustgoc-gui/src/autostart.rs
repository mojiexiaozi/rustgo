#![forbid(unsafe_code)]

use anyhow::Context;
use std::path::Path;
use winreg::RegKey;

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const VALUE_NAME: &str = "RustgoGui";

pub fn enabled() -> anyhow::Result<bool> {
    let hkcu = RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
    let key = match hkcu.open_subkey(RUN_KEY) {
        Ok(key) => key,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    enabled_at(&key, &std::env::current_exe()?)
}

pub fn set_enabled(enabled: bool) -> anyhow::Result<()> {
    let hkcu = RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
    let (key, _) = hkcu
        .create_subkey(RUN_KEY)
        .context("无法打开当前用户启动项")?;
    set_at(&key, &std::env::current_exe()?, enabled)
}

fn command(executable: &Path) -> anyhow::Result<String> {
    let path = executable.to_str().context("程序路径包含无效 Unicode")?;
    anyhow::ensure!(
        executable.is_absolute() && !path.contains('"'),
        "程序路径无效"
    );
    Ok(format!("\"{path}\""))
}

fn enabled_at(key: &RegKey, executable: &Path) -> anyhow::Result<bool> {
    match key.get_value::<String, _>(VALUE_NAME) {
        Ok(value) => Ok(value == command(executable)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn set_at(key: &RegKey, executable: &Path, enabled: bool) -> anyhow::Result<()> {
    if enabled {
        key.set_value(VALUE_NAME, &command(executable)?)?;
    } else {
        match key.delete_value(VALUE_NAME) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_toggle_persists_quoted_path_and_preserves_other_entries() {
        let hkcu = RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
        let path = format!(r"Software\RustgoAutostartTest-{}", std::process::id());
        let (key, _) = hkcu.create_subkey(&path).unwrap();
        let outcome = std::panic::catch_unwind(|| {
            let executable = Path::new(r"C:\测试 software\rustgoc-gui.exe");
            key.set_value("OtherApp", &"keep").unwrap();
            assert!(!enabled_at(&key, executable).unwrap());
            set_at(&key, executable, true).unwrap();
            assert!(enabled_at(&key, executable).unwrap());
            assert_eq!(
                key.get_value::<String, _>("RustgoGui").unwrap(),
                "\"C:\\测试 software\\rustgoc-gui.exe\""
            );
            assert!(!enabled_at(&key, Path::new(r"C:\other\rustgoc-gui.exe")).unwrap());
            set_at(&key, executable, false).unwrap();
            set_at(&key, executable, false).unwrap();
            assert!(!enabled_at(&key, executable).unwrap());
            assert_eq!(key.get_value::<String, _>("OtherApp").unwrap(), "keep");
        });
        drop(key);
        hkcu.delete_subkey(&path).unwrap();
        if let Err(error) = outcome {
            std::panic::resume_unwind(error);
        }
    }
}
