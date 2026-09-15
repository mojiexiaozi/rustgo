use std::fmt;

pub use rustgo_protocol::EnrollmentPurpose;
use rustgo_protocol::{EnrollmentKeyError, EnrollmentKeyMaterial};
use thiserror::Error;

pub struct EnrollmentKey(EnrollmentKeyMaterial);

impl EnrollmentKey {
    pub(crate) fn for_verified_server(
        purpose: EnrollmentPurpose,
        address: &str,
        fingerprint: [u8; 32],
    ) -> Result<Self, EnrollmentError> {
        EnrollmentKeyMaterial::new(purpose, address, fingerprint, [0; 32])
            .map(Self)
            .map_err(EnrollmentError::from)
    }
    pub fn parse(encoded: &str) -> Result<Self, EnrollmentError> {
        EnrollmentKeyMaterial::decode(encoded)
            .map(Self)
            .map_err(EnrollmentError::from)
    }

    pub fn server_addr(&self) -> &str {
        self.0.server_addr()
    }
    pub fn certificate_fingerprint(&self) -> &[u8; 32] {
        self.0.certificate_fingerprint()
    }
    pub fn purpose(&self) -> EnrollmentPurpose {
        self.0.purpose()
    }
    pub fn token(&self) -> &[u8; 32] {
        self.0.token()
    }
}

impl fmt::Debug for EnrollmentKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EnrollmentError {
    #[error("invalid enrollment key format")]
    InvalidFormat,
    #[error("unsupported enrollment key version")]
    UnsupportedVersion,
    #[error("invalid enrollment key checksum")]
    InvalidChecksum,
    #[error("invalid enrollment key purpose")]
    InvalidPurpose,
    #[error("invalid enrollment server address")]
    InvalidAddress,
    #[error("static identity private key is missing")]
    MissingStaticPrivateKey,
    #[error("static identity private key is invalid")]
    InvalidStaticPrivateKey,
    #[error("enrollment pending state is invalid")]
    InvalidPendingState,
    #[error("cannot {operation} enrollment pending state ({kind:?})")]
    PendingIo {
        operation: &'static str,
        kind: std::io::ErrorKind,
    },
    #[error("enrollment destination already exists")]
    DestinationExists,
    #[error("enrollment network protocol failed")]
    Network,
    #[error("本地证书配置不可用，申请尚未提交：{0}")]
    LocalCertificate(String),
    #[error("{}", rejection_message(.0))]
    Rejected(rustgo_protocol::EnrollmentErrorCode),
    #[error("cannot update client configuration ({0:?})")]
    ConfigurationIo(std::io::ErrorKind),
}

fn rejection_message(code: &rustgo_protocol::EnrollmentErrorCode) -> &'static str {
    use rustgo_protocol::EnrollmentErrorCode::*;
    match code {
        AlreadyBound => {
            "客户端名称或密钥已被服务器静态配置占用，请更换客户端名称，或由管理员修改原配置后重新申请"
        }
        PublicKeyConflict => {
            "客户端名称或公钥与服务器已有配置冲突，请管理员检查同名客户端及密钥配置"
        }
        PurposeMismatch => "客户端名称已存在，当前申请类型不匹配，请使用密钥更换申请",
        ReplacementApprovalPending => "服务器已存在同名客户端，等待管理员批准更换密钥",
        PendingApproval => "申请已提交，等待管理员审批",
        ApprovalRejected => "管理员已拒绝此次接入申请",
        Disabled => "客户端已被服务器禁用，请联系管理员",
        CapacityReached => "服务器客户端或申请数量已达上限，请稍后重试",
        Unavailable => "服务器暂时无法处理申请，请稍后重试",
        InvalidKey => "申请信息无效，请检查客户端名称及接入配置",
        Expired => "接入申请已过期，请重新申请",
        AlreadyUsed => "接入凭据已使用，请重新申请",
        UnsupportedVersion => "服务器不支持此接入协议，请更新客户端或服务器",
    }
}

impl From<EnrollmentKeyError> for EnrollmentError {
    fn from(error: EnrollmentKeyError) -> Self {
        match error {
            EnrollmentKeyError::InvalidFormat => Self::InvalidFormat,
            EnrollmentKeyError::UnsupportedVersion => Self::UnsupportedVersion,
            EnrollmentKeyError::InvalidChecksum => Self::InvalidChecksum,
            EnrollmentKeyError::InvalidPurpose => Self::InvalidPurpose,
            EnrollmentKeyError::InvalidAddress => Self::InvalidAddress,
        }
    }
}
