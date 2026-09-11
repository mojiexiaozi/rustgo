use std::path::Path;

use rustgo_config::{ClientConfig, IdentityMode};
use rustgo_crypto::DeviceKeypair;

use super::{EnrollmentError, EnrollmentPurpose, PendingEnrollment};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnrollmentState {
    Ready,
    RegistrationRequired,
    ReRegistrationRequired,
    EnrollmentPending,
    ReEnrollmentPending,
}

pub fn classify_enrollment_state(
    config: &ClientConfig,
    config_path: &Path,
) -> Result<EnrollmentState, EnrollmentError> {
    if PendingEnrollment::exists(config_path) {
        return match PendingEnrollment::load(config_path)?.purpose() {
            EnrollmentPurpose::Enroll => Ok(EnrollmentState::EnrollmentPending),
            EnrollmentPurpose::ReEnroll => Ok(EnrollmentState::ReEnrollmentPending),
        };
    }
    let private_key = &config.client.private_key_file;
    let key_exists = private_key.is_file();

    match config.client.identity_mode {
        Some(IdentityMode::Static) => {
            if !key_exists {
                return Err(EnrollmentError::MissingStaticPrivateKey);
            }
            DeviceKeypair::load_private_file(private_key)
                .map_err(|_| EnrollmentError::InvalidStaticPrivateKey)?;
            Ok(EnrollmentState::Ready)
        }
        Some(IdentityMode::Dynamic) => {
            if !key_exists || DeviceKeypair::load_private_file(private_key).is_err() {
                Ok(EnrollmentState::ReRegistrationRequired)
            } else {
                Ok(EnrollmentState::Ready)
            }
        }
        None => {
            if !key_exists {
                return Ok(EnrollmentState::RegistrationRequired);
            }
            DeviceKeypair::load_private_file(private_key)
                .map_err(|_| EnrollmentError::InvalidStaticPrivateKey)?;
            Ok(EnrollmentState::Ready)
        }
    }
}
