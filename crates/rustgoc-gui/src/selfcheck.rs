#![forbid(unsafe_code)]

use std::path::Path;

pub fn run(config_path: &Path) -> anyhow::Result<()> {
    let config = rustgo_config::load_client(config_path)?;

    let _control = rustgoc::ControlClient::from_config(config)?;

    println!("Selfcheck passed: configuration valid");
    Ok(())
}
