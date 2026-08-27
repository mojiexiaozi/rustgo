use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use atomicwrites::move_atomic;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rand::{TryRngCore, rngs::OsRng};
use tempfile::Builder;
use zeroize::Zeroizing;

use crate::{CryptoError, DeviceKeypair, DevicePublicKey};

const PRIVATE_KEY_PREFIX: &str = "rustgo-ed25519-private-v1:";
const PRIVATE_FILE_NAME: &str = "device.key";
const PUBLIC_FILE_NAME: &str = "device.pub";

pub fn generate_key_file(directory: &Path) -> Result<DevicePublicKey, CryptoError> {
    fs::create_dir_all(directory)
        .map_err(|error| io_error("create directory for", directory, error))?;

    let private_path = directory.join(PRIVATE_FILE_NAME);
    let public_path = directory.join(PUBLIC_FILE_NAME);
    ensure_absent(&private_path)?;
    ensure_absent(&public_path)?;

    let mut secret = Zeroizing::new([0_u8; 32]);
    OsRng
        .try_fill_bytes(secret.as_mut())
        .map_err(|error| CryptoError::KeyFileIo {
            operation: "obtain operating-system randomness for",
            path: private_path.clone(),
            kind: io::Error::other(error).kind(),
        })?;
    let keypair = DeviceKeypair::from_secret_bytes_ref(&secret);
    let public_key = keypair.public_key();

    let mut private_temp = new_temp(directory, PRIVATE_FILE_NAME, &private_path)?;
    write_private_key(&mut private_temp, &keypair, &private_path)?;
    persist_without_overwrite(private_temp, &private_path)?;

    let mut public_temp = new_temp(directory, PUBLIC_FILE_NAME, &public_path)?;
    write_and_sync(
        &mut public_temp,
        format!("{public_key}\n").as_bytes(),
        &public_path,
    )?;
    persist_without_overwrite(public_temp, &public_path)?;

    Ok(public_key)
}

impl DeviceKeypair {
    pub fn load_private_file(path: &Path) -> Result<Self, CryptoError> {
        let encoded =
            Zeroizing::new(fs::read(path).map_err(|error| io_error("read", path, error))?);
        let encoded = std::str::from_utf8(&encoded).map_err(|_| CryptoError::InvalidPrivateKey)?;
        let encoded = encoded.strip_suffix('\n').unwrap_or(encoded);
        let encoded = encoded.strip_suffix('\r').unwrap_or(encoded);
        let payload = encoded
            .strip_prefix(PRIVATE_KEY_PREFIX)
            .ok_or(CryptoError::InvalidPrivateKey)?;
        let secret = Zeroizing::new(
            STANDARD
                .decode(payload)
                .map_err(|_| CryptoError::InvalidPrivateKey)?,
        );
        if secret.len() != 32 {
            return Err(CryptoError::InvalidPrivateKey);
        }
        let mut secret_bytes = Zeroizing::new([0_u8; 32]);
        secret_bytes.copy_from_slice(&secret);
        Ok(Self::from_secret_bytes_ref(&secret_bytes))
    }
}

fn ensure_absent(path: &Path) -> Result<(), CryptoError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(CryptoError::KeyDestinationExists {
            path: path.to_path_buf(),
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error("inspect", path, error)),
    }
}

fn new_temp(directory: &Path, name: &str, destination: &Path) -> Result<KeyTempFile, CryptoError> {
    let temporary = Builder::new()
        .prefix(&format!(".{name}."))
        .suffix(".tmp")
        .tempfile_in(directory)
        .map_err(|error| io_error("create temporary", destination, error))?;
    let (file, path) = temporary
        .keep()
        .map_err(|error| io_error("prepare temporary", destination, error.error))?;
    Ok(KeyTempFile { file, path })
}

fn write_private_key(
    file: &mut KeyTempFile,
    keypair: &DeviceKeypair,
    destination: &Path,
) -> Result<(), CryptoError> {
    let mut encoded = Zeroizing::new([0_u8; 44]);
    let encoded_length = STANDARD
        .encode_slice(keypair.secret_bytes(), encoded.as_mut_slice())
        .map_err(|_| CryptoError::InvalidPrivateKey)?;

    file.file
        .write_all(PRIVATE_KEY_PREFIX.as_bytes())
        .and_then(|()| file.file.write_all(&encoded[..encoded_length]))
        .and_then(|()| file.file.write_all(b"\n"))
        .and_then(|()| file.file.flush())
        .and_then(|()| file.file.sync_all())
        .map_err(|error| io_error("write", destination, error))
}

fn write_and_sync(
    file: &mut KeyTempFile,
    contents: &[u8],
    destination: &Path,
) -> Result<(), CryptoError> {
    file.file
        .write_all(contents)
        .and_then(|()| file.file.flush())
        .and_then(|()| file.file.sync_all())
        .map_err(|error| io_error("write", destination, error))
}

fn persist_without_overwrite(file: KeyTempFile, destination: &Path) -> Result<(), CryptoError> {
    move_atomic(&file.path, destination).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            CryptoError::KeyDestinationExists {
                path: destination.to_path_buf(),
            }
        } else {
            io_error("persist and synchronize", destination, error)
        }
    })
}

struct KeyTempFile {
    file: fs::File,
    path: PathBuf,
}

impl Drop for KeyTempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn io_error(operation: &'static str, path: &Path, error: io::Error) -> CryptoError {
    CryptoError::KeyFileIo {
        operation,
        path: path.to_path_buf(),
        kind: error.kind(),
    }
}
