use std::{
    env, fs,
    path::{Path, PathBuf},
};

use thiserror::Error;

use crate::{ClientConfig, ServerConfig, ValidationError};

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("cannot read configuration `{path}` ({kind:?})")]
    Read {
        path: PathBuf,
        kind: std::io::ErrorKind,
    },
    #[error("environment variable `{variable}` is required by configuration `{path}`")]
    Interpolation { path: PathBuf, variable: String },
    #[error("invalid TOML configuration `{path}`")]
    TomlParse { path: PathBuf },
    #[error("invalid configuration `{path}`: {error}")]
    Validation {
        path: PathBuf,
        error: ValidationError,
    },
    #[error("configuration `{config_path}` references a missing {field} file `{referenced_path}`")]
    MissingReference {
        config_path: PathBuf,
        field: &'static str,
        referenced_path: PathBuf,
    },
}

pub fn load_server(path: &Path) -> Result<ServerConfig, ConfigError> {
    let mut config: ServerConfig = load(path)?;
    resolve_path(path, &mut config.server.certificate_file);
    resolve_path(path, &mut config.server.private_key_file);
    config.validate().map_err(|error| ConfigError::Validation {
        path: path.to_path_buf(),
        error,
    })?;
    Ok(config)
}

pub fn load_client(path: &Path) -> Result<ClientConfig, ConfigError> {
    let mut config: ClientConfig = load(path)?;
    resolve_path(path, &mut config.client.private_key_file);
    config.validate().map_err(|error| ConfigError::Validation {
        path: path.to_path_buf(),
        error,
    })?;
    Ok(config)
}

pub fn check_server_references(
    config_path: &Path,
    config: &ServerConfig,
) -> Result<(), ConfigError> {
    check_reference(config_path, "certificate", &config.server.certificate_file)?;
    check_reference(config_path, "private key", &config.server.private_key_file)
}

pub fn check_client_references(
    config_path: &Path,
    config: &ClientConfig,
) -> Result<(), ConfigError> {
    check_reference(config_path, "private key", &config.client.private_key_file)
}

fn load<T>(path: &Path) -> Result<T, ConfigError>
where
    T: serde::de::DeserializeOwned,
{
    let contents = fs::read_to_string(path).map_err(|error| ConfigError::Read {
        path: path.to_path_buf(),
        kind: error.kind(),
    })?;
    let expanded = interpolate(path, &contents)?;
    toml::from_str(&expanded).map_err(|_| ConfigError::TomlParse {
        path: path.to_path_buf(),
    })
}

fn resolve_path(config_path: &Path, reference: &mut PathBuf) {
    if reference.is_relative() {
        let directory = config_path.parent().unwrap_or_else(|| Path::new("."));
        *reference = directory.join(&reference);
    }
}

fn check_reference(
    config_path: &Path,
    field: &'static str,
    reference: &Path,
) -> Result<(), ConfigError> {
    if reference.is_file() {
        Ok(())
    } else {
        Err(ConfigError::MissingReference {
            config_path: config_path.to_path_buf(),
            field,
            referenced_path: reference.to_path_buf(),
        })
    }
}

fn interpolate(path: &Path, source: &str) -> Result<String, ConfigError> {
    let mut expanded = String::with_capacity(source.len());
    let mut remaining = source;
    while let Some(start) = remaining.find("${") {
        expanded.push_str(&remaining[..start]);
        let after_open = &remaining[start + 2..];
        let Some(end) = after_open.find('}') else {
            return Err(interpolation_error(path, "invalid placeholder"));
        };
        let variable = &after_open[..end];
        if !is_environment_variable_name(variable) {
            return Err(interpolation_error(path, "invalid placeholder"));
        }
        let value = env::var(variable).map_err(|_| interpolation_error(path, variable))?;
        expanded.push_str(&value);
        remaining = &after_open[end + 1..];
    }
    expanded.push_str(remaining);
    Ok(expanded)
}

fn interpolation_error(path: &Path, variable: &str) -> ConfigError {
    ConfigError::Interpolation {
        path: path.to_path_buf(),
        variable: variable.to_owned(),
    }
}

fn is_environment_variable_name(variable: &str) -> bool {
    let mut bytes = variable.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'_'))
        && bytes.all(|byte| matches!(byte, b'A'..=b'Z' | b'0'..=b'9' | b'_'))
}
