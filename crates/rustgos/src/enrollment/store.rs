use std::{
    fmt,
    path::Path,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rand::RngCore;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use rustgo_config::AuthorizedClient;
use rustgo_crypto::DevicePublicKey;
use rustgo_protocol::{EnrollmentKeyMaterial, EnrollmentPurpose};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;

const MAX_AUDIT_RECORDS: usize = 10_000;

mod approval;
pub use approval::RegistrationRequest;

#[derive(Clone, Copy, Debug)]
pub struct EnrollmentStoreLimits {
    pub max_active_clients: usize,
    pub max_tokens: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DynamicClient {
    internal_id: String,
    display_id: String,
    enabled: bool,
    revision: u64,
    public_key: Option<String>,
    tombstoned: bool,
}

impl DynamicClient {
    pub fn internal_id(&self) -> &str {
        &self.internal_id
    }
    pub fn display_id(&self) -> &str {
        &self.display_id
    }
    pub fn enabled(&self) -> bool {
        self.enabled
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn is_bound(&self) -> bool {
        self.public_key.is_some()
    }
    pub fn is_deleted(&self) -> bool {
        self.tombstoned
    }
}

pub struct DynamicClientStore {
    connection: Mutex<Connection>,
    limits: EnrollmentStoreLimits,
    static_identities: Mutex<Vec<(String, String)>>,
}

pub struct IssuedEnrollmentKey(String);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrollmentResult {
    display_id: String,
    revision: u64,
}

impl EnrollmentResult {
    pub fn display_id(&self) -> &str {
        &self.display_id
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
}

impl IssuedEnrollmentKey {
    pub fn into_encoded(self) -> String {
        self.0
    }
}

impl fmt::Debug for IssuedEnrollmentKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("IssuedEnrollmentKey")
            .field(&"[REDACTED]")
            .finish()
    }
}

impl DynamicClientStore {
    pub fn open(
        path: impl AsRef<Path>,
        limits: EnrollmentStoreLimits,
    ) -> Result<Self, EnrollmentStoreError> {
        let mut connection = Connection::open(path).map_err(database_error)?;
        connection
            .execute_batch("PRAGMA foreign_keys = ON;")
            .map_err(database_error)?;
        migrate_schema(&mut connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
            limits,
            static_identities: Mutex::new(Vec::new()),
        })
    }

    fn create_schema(connection: &Connection) -> Result<(), EnrollmentStoreError> {
        connection
            .execute_batch(
                "CREATE TABLE dynamic_clients (
               internal_id TEXT PRIMARY KEY,
               display_id TEXT NOT NULL,
               normalized_id TEXT NOT NULL UNIQUE,
               public_key TEXT UNIQUE,
               enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)),
               revision INTEGER NOT NULL CHECK(revision > 0),
               tombstoned INTEGER NOT NULL DEFAULT 0 CHECK(tombstoned IN (0, 1)),
               created_at INTEGER NOT NULL,
               updated_at INTEGER NOT NULL,
               deleted_at INTEGER
             );
             CREATE TABLE enrollment_tokens (
               selector BLOB PRIMARY KEY,
               token_hash BLOB NOT NULL,
               salt BLOB NOT NULL,
               purpose INTEGER NOT NULL,
               target_id TEXT NOT NULL REFERENCES dynamic_clients(internal_id),
               issued_revision INTEGER NOT NULL,
               expires_at INTEGER NOT NULL,
               consumed_at INTEGER,
               request_id TEXT,
               result_public_key TEXT,
               result_revision INTEGER,
               revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0, 1))
             );
             CREATE UNIQUE INDEX dynamic_clients_public_key
               ON dynamic_clients(public_key) WHERE public_key IS NOT NULL;
             CREATE TABLE enrollment_audit (
               sequence INTEGER PRIMARY KEY AUTOINCREMENT,
               event TEXT NOT NULL,
               target_id TEXT NOT NULL,
               created_at INTEGER NOT NULL
             );",
            )
            .map_err(database_error)
    }

    pub fn create_client(&self, display_id: &str) -> Result<DynamicClient, EnrollmentStoreError> {
        let display_id = validate_display_id(display_id)?;
        let normalized_id = display_id.to_ascii_lowercase();
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| EnrollmentStoreError::Database("connection lock poisoned".into()))?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let active: usize = transaction
            .query_row(
                "SELECT COUNT(*) FROM dynamic_clients WHERE enabled = 1",
                [],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if active >= self.limits.max_active_clients {
            return Err(EnrollmentStoreError::ClientCapacity);
        }

        let internal_id = random_id();
        let result = transaction.execute(
            "INSERT INTO dynamic_clients (internal_id, display_id, normalized_id, enabled, revision, created_at, updated_at)
             VALUES (?1, ?2, ?3, 1, 1, ?4, ?4)",
            params![internal_id, display_id, normalized_id, unix_now()?],
        );
        if let Err(error) = result {
            if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
                return Err(EnrollmentStoreError::DuplicateDisplayId);
            }
            return Err(database_error(error));
        }
        audit(&transaction, "client_created", &internal_id)?;
        transaction.commit().map_err(database_error)?;
        Ok(DynamicClient {
            internal_id,
            display_id: display_id.to_owned(),
            enabled: true,
            revision: 1,
            public_key: None,
            tombstoned: false,
        })
    }

    pub fn create_client_with_token(
        &self,
        display_id: &str,
        server_addr: &str,
        certificate_fingerprint: [u8; 32],
        ttl: Duration,
    ) -> Result<(DynamicClient, IssuedEnrollmentKey), EnrollmentStoreError> {
        let display_id = validate_display_id(display_id)?;
        let prepared = prepare_token(
            EnrollmentPurpose::Enroll,
            server_addr,
            certificate_fingerprint,
            ttl,
        )?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| EnrollmentStoreError::Database("connection lock poisoned".into()))?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let active_clients: usize = transaction
            .query_row(
                "SELECT COUNT(*) FROM dynamic_clients WHERE enabled = 1 AND tombstoned = 0",
                [],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if active_clients >= self.limits.max_active_clients {
            return Err(EnrollmentStoreError::ClientCapacity);
        }
        let active_tokens: usize = transaction
            .query_row(
                "SELECT COUNT(*) FROM enrollment_tokens WHERE consumed_at IS NULL AND revoked = 0",
                [],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if active_tokens >= self.limits.max_tokens {
            return Err(EnrollmentStoreError::TokenCapacity);
        }

        let internal_id = random_id();
        let now = unix_now()?;
        let inserted = transaction.execute(
            "INSERT INTO dynamic_clients
             (internal_id, display_id, normalized_id, enabled, revision, created_at, updated_at)
             VALUES (?1, ?2, ?3, 1, 1, ?4, ?4)",
            params![
                internal_id,
                display_id,
                display_id.to_ascii_lowercase(),
                now
            ],
        );
        if let Err(error) = inserted {
            if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
                return Err(EnrollmentStoreError::DuplicateDisplayId);
            }
            return Err(database_error(error));
        }
        transaction
            .execute(
                "INSERT INTO enrollment_tokens
             (selector, token_hash, salt, purpose, target_id, issued_revision, expires_at)
             VALUES (?1, ?2, ?3, 1, ?4, 1, ?5)",
                params![
                    prepared.selector.as_slice(),
                    prepared.hash.as_slice(),
                    prepared.salt,
                    internal_id,
                    prepared.expires_at
                ],
            )
            .map_err(database_error)?;
        audit(&transaction, "client_created_with_token", &internal_id)?;
        transaction.commit().map_err(database_error)?;
        Ok((
            DynamicClient {
                internal_id,
                display_id: display_id.to_owned(),
                enabled: true,
                revision: 1,
                public_key: None,
                tombstoned: false,
            },
            IssuedEnrollmentKey(prepared.encoded),
        ))
    }

    pub fn client(&self, internal_id: &str) -> Result<Option<DynamicClient>, EnrollmentStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| EnrollmentStoreError::Database("connection lock poisoned".into()))?;
        connection.query_row(
            "SELECT internal_id, display_id, enabled, revision, public_key, tombstoned FROM dynamic_clients WHERE internal_id = ?1",
            [internal_id], client_from_row,
        ).optional().map_err(database_error)
    }

    pub fn client_by_display_id(
        &self,
        display_id: &str,
    ) -> Result<Option<DynamicClient>, EnrollmentStoreError> {
        let display_id = validate_display_id(display_id)?;
        let connection = self
            .connection
            .lock()
            .map_err(|_| EnrollmentStoreError::Database("connection lock poisoned".into()))?;
        connection
            .query_row(
                "SELECT internal_id, display_id, enabled, revision, public_key, tombstoned
             FROM dynamic_clients WHERE normalized_id = ?1 AND tombstoned = 0",
                [display_id.to_ascii_lowercase()],
                client_from_row,
            )
            .optional()
            .map_err(database_error)
    }

    pub fn client_by_public_key(
        &self,
        public_key: &DevicePublicKey,
    ) -> Result<Option<DynamicClient>, EnrollmentStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| EnrollmentStoreError::Database("connection lock poisoned".into()))?;
        connection
            .query_row(
                "SELECT internal_id, display_id, enabled, revision, public_key, tombstoned
                 FROM dynamic_clients WHERE public_key = ?1 LIMIT 1",
                [public_key.to_string()],
                client_from_row,
            )
            .optional()
            .map_err(database_error)
    }

    pub fn list_clients(&self) -> Result<Vec<DynamicClient>, EnrollmentStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| EnrollmentStoreError::Database("connection lock poisoned".into()))?;
        let mut statement = connection
            .prepare(
                "SELECT internal_id, display_id, enabled, revision, public_key, tombstoned
             FROM dynamic_clients WHERE tombstoned = 0 ORDER BY normalized_id",
            )
            .map_err(database_error)?;
        statement
            .query_map([], client_from_row)
            .map_err(database_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(database_error)
    }

    pub fn rename_client(
        &self,
        internal_id: &str,
        display_id: &str,
        expected_revision: u64,
    ) -> Result<DynamicClient, EnrollmentStoreError> {
        let display_id = validate_display_id(display_id)?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| EnrollmentStoreError::Database("connection lock poisoned".into()))?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let result = transaction.execute(
            "UPDATE dynamic_clients SET display_id = ?1, normalized_id = ?2, revision = revision + 1, updated_at = ?3
             WHERE internal_id = ?4 AND revision = ?5 AND tombstoned = 0",
            params![display_id, display_id.to_ascii_lowercase(), unix_now()?, internal_id, expected_revision],
        );
        let changed = match result {
            Ok(changed) => changed,
            Err(error)
                if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) =>
            {
                return Err(EnrollmentStoreError::DuplicateDisplayId);
            }
            Err(error) => return Err(database_error(error)),
        };
        if changed == 0 {
            return mutation_miss(&transaction, internal_id);
        }
        let client =
            query_client(&transaction, internal_id)?.ok_or(EnrollmentStoreError::ClientNotFound)?;
        audit(&transaction, "client_renamed", internal_id)?;
        transaction.commit().map_err(database_error)?;
        Ok(client)
    }

    pub fn issue_token(
        &self,
        internal_id: &str,
        purpose: EnrollmentPurpose,
        server_addr: &str,
        certificate_fingerprint: [u8; 32],
        ttl: Duration,
        expected_revision: u64,
    ) -> Result<IssuedEnrollmentKey, EnrollmentStoreError> {
        if ttl.is_zero() {
            return Err(EnrollmentStoreError::InvalidTokenLifetime);
        }
        let mut token = [0_u8; 32];
        rand::rng().fill_bytes(&mut token);
        let material =
            EnrollmentKeyMaterial::new(purpose, server_addr, certificate_fingerprint, token)
                .map_err(|_| EnrollmentStoreError::InvalidKeyMaterial)?;
        let encoded = material.encode();
        let selector = Sha256::digest(encoded.as_bytes());
        let mut salt = [0_u8; 16];
        rand::rng().fill_bytes(&mut salt);
        let mut hasher = Sha256::new();
        hasher.update(salt);
        hasher.update(encoded.as_bytes());
        let token_hash = hasher.finalize();
        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| EnrollmentStoreError::InvalidTokenLifetime)?
            .checked_add(ttl)
            .ok_or(EnrollmentStoreError::InvalidTokenLifetime)?
            .as_secs();
        let purpose_code = match purpose {
            EnrollmentPurpose::Enroll => 1,
            EnrollmentPurpose::ReEnroll => 2,
        };

        let mut connection = self
            .connection
            .lock()
            .map_err(|_| EnrollmentStoreError::Database("connection lock poisoned".into()))?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let client_state: Option<(u64, Option<String>)> = transaction
            .query_row(
                "SELECT revision, public_key FROM dynamic_clients WHERE internal_id = ?1 AND enabled = 1 AND tombstoned = 0",
                [internal_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(database_error)?;
        let (revision, public_key) = client_state.ok_or(EnrollmentStoreError::ClientNotFound)?;
        if revision != expected_revision {
            return Err(EnrollmentStoreError::RevisionConflict);
        }
        match purpose {
            EnrollmentPurpose::Enroll if public_key.is_some() => {
                return Err(EnrollmentStoreError::PurposeMismatch);
            }
            EnrollmentPurpose::ReEnroll if public_key.is_none() => {
                return Err(EnrollmentStoreError::PurposeMismatch);
            }
            _ => {}
        }
        transaction
            .execute(
                "UPDATE enrollment_tokens SET revoked = 1
             WHERE target_id = ?1 AND purpose = ?2 AND consumed_at IS NULL AND revoked = 0",
                params![internal_id, purpose_code],
            )
            .map_err(database_error)?;
        let active_tokens: usize = transaction
            .query_row(
                "SELECT COUNT(*) FROM enrollment_tokens WHERE consumed_at IS NULL AND revoked = 0",
                [],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if active_tokens >= self.limits.max_tokens {
            return Err(EnrollmentStoreError::TokenCapacity);
        }
        transaction
            .execute(
                "INSERT INTO enrollment_tokens
             (selector, token_hash, salt, purpose, target_id, issued_revision, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    selector.as_slice(),
                    token_hash.as_slice(),
                    salt,
                    purpose_code,
                    internal_id,
                    revision,
                    expires_at
                ],
            )
            .map_err(database_error)?;
        audit(&transaction, "token_issued", internal_id)?;
        transaction.commit().map_err(database_error)?;
        Ok(IssuedEnrollmentKey(encoded))
    }

    pub fn set_client_enabled(
        &self,
        internal_id: &str,
        enabled: bool,
        expected_revision: u64,
    ) -> Result<DynamicClient, EnrollmentStoreError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| EnrollmentStoreError::Database("connection lock poisoned".into()))?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        if enabled {
            let active: usize = transaction
                .query_row(
                    "SELECT COUNT(*) FROM dynamic_clients WHERE enabled = 1 AND tombstoned = 0",
                    [],
                    |row| row.get(0),
                )
                .map_err(database_error)?;
            if active >= self.limits.max_active_clients {
                return Err(EnrollmentStoreError::ClientCapacity);
            }
        }
        let changed = transaction
            .execute(
                "UPDATE dynamic_clients SET enabled = ?1, revision = revision + 1, updated_at = ?2
             WHERE internal_id = ?3 AND revision = ?4 AND tombstoned = 0",
                params![enabled, unix_now()?, internal_id, expected_revision],
            )
            .map_err(database_error)?;
        if changed == 0 {
            return mutation_miss(&transaction, internal_id);
        }
        if !enabled {
            transaction
                .execute(
                    "UPDATE enrollment_tokens SET revoked = 1 WHERE target_id = ?1 AND consumed_at IS NULL",
                    [internal_id],
                )
                .map_err(database_error)?;
        }
        let client =
            query_client(&transaction, internal_id)?.ok_or(EnrollmentStoreError::ClientNotFound)?;
        audit(
            &transaction,
            if enabled {
                "client_enabled"
            } else {
                "client_disabled"
            },
            internal_id,
        )?;
        transaction.commit().map_err(database_error)?;
        Ok(client)
    }

    pub fn delete_client(
        &self,
        internal_id: &str,
        expected_revision: u64,
    ) -> Result<DynamicClient, EnrollmentStoreError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| EnrollmentStoreError::Database("connection lock poisoned".into()))?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let now = unix_now()?;
        let changed = transaction
            .execute(
                "UPDATE dynamic_clients SET enabled = 0, tombstoned = 1, revision = revision + 1,
                    updated_at = ?1, deleted_at = ?1
             WHERE internal_id = ?2 AND revision = ?3 AND tombstoned = 0",
                params![now, internal_id, expected_revision],
            )
            .map_err(database_error)?;
        if changed == 0 {
            return mutation_miss(&transaction, internal_id);
        }
        transaction.execute(
            "UPDATE enrollment_tokens SET revoked = 1 WHERE target_id = ?1 AND consumed_at IS NULL",
            [internal_id],
        ).map_err(database_error)?;
        let client =
            query_client(&transaction, internal_id)?.ok_or(EnrollmentStoreError::ClientNotFound)?;
        audit(&transaction, "client_deleted", internal_id)?;
        transaction.commit().map_err(database_error)?;
        Ok(client)
    }

    pub fn consume_token(
        &self,
        encoded_key: &str,
        public_key: &DevicePublicKey,
        request_id: &str,
        now: SystemTime,
    ) -> Result<EnrollmentResult, EnrollmentStoreError> {
        if request_id.is_empty() || request_id.len() > 128 {
            return Err(EnrollmentStoreError::InvalidRequestId);
        }
        let material = EnrollmentKeyMaterial::decode(encoded_key)
            .map_err(|_| EnrollmentStoreError::InvalidToken)?;
        let selector = Sha256::digest(encoded_key.as_bytes());
        let now = now
            .duration_since(UNIX_EPOCH)
            .map_err(|_| EnrollmentStoreError::InvalidToken)?
            .as_secs();
        let public_key = public_key.to_string();
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| EnrollmentStoreError::Database("connection lock poisoned".into()))?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let row = transaction
            .query_row(
                "SELECT t.token_hash, t.salt, t.purpose, t.target_id, t.issued_revision,
                    t.expires_at, t.consumed_at, t.request_id, t.result_public_key,
                    t.result_revision, t.revoked, c.display_id, c.enabled, c.revision,
                    c.public_key, c.tombstoned
             FROM enrollment_tokens t JOIN dynamic_clients c ON c.internal_id = t.target_id
             WHERE t.selector = ?1",
                [selector.as_slice()],
                |row| {
                    Ok(TokenCandidate {
                        hash: row.get(0)?,
                        salt: row.get(1)?,
                        purpose: row.get(2)?,
                        target_id: row.get(3)?,
                        issued_revision: row.get(4)?,
                        expires_at: row.get(5)?,
                        consumed_at: row.get(6)?,
                        request_id: row.get(7)?,
                        result_public_key: row.get(8)?,
                        result_revision: row.get(9)?,
                        revoked: row.get(10)?,
                        display_id: row.get(11)?,
                        enabled: row.get(12)?,
                        client_revision: row.get(13)?,
                        current_public_key: row.get(14)?,
                        tombstoned: row.get(15)?,
                    })
                },
            )
            .optional()
            .map_err(database_error)?
            .ok_or(EnrollmentStoreError::InvalidToken)?;

        let mut hasher = Sha256::new();
        hasher.update(&row.salt);
        hasher.update(encoded_key.as_bytes());
        let calculated = hasher.finalize();
        if calculated.as_slice().ct_eq(row.hash.as_slice()).unwrap_u8() != 1 {
            return Err(EnrollmentStoreError::InvalidToken);
        }
        if row.consumed_at.is_some() {
            if row.request_id.as_deref() == Some(request_id)
                && row.result_public_key.as_deref() == Some(public_key.as_str())
            {
                return Ok(EnrollmentResult {
                    display_id: row.display_id,
                    revision: row.result_revision.ok_or_else(|| {
                        EnrollmentStoreError::Database(
                            "consumed token has no result revision".into(),
                        )
                    })?,
                });
            }
            return Err(EnrollmentStoreError::TokenAlreadyUsed);
        }
        if now > row.expires_at {
            return Err(EnrollmentStoreError::TokenExpired);
        }
        if row.tombstoned {
            return Err(EnrollmentStoreError::ClientNotFound);
        }
        if !row.enabled {
            return Err(EnrollmentStoreError::ClientDisabled);
        }
        if row.revoked {
            return Err(EnrollmentStoreError::InvalidToken);
        }
        if row.client_revision != row.issued_revision {
            return Err(EnrollmentStoreError::RevisionConflict);
        }
        let expected_purpose = match material.purpose() {
            EnrollmentPurpose::Enroll => 1,
            EnrollmentPurpose::ReEnroll => 2,
        };
        if row.purpose != expected_purpose {
            return Err(EnrollmentStoreError::InvalidToken);
        }
        match material.purpose() {
            EnrollmentPurpose::Enroll if row.current_public_key.is_some() => {
                return Err(EnrollmentStoreError::PurposeMismatch);
            }
            EnrollmentPurpose::ReEnroll if row.current_public_key.is_none() => {
                return Err(EnrollmentStoreError::PurposeMismatch);
            }
            _ => {}
        }
        let new_revision = row
            .client_revision
            .checked_add(1)
            .ok_or(EnrollmentStoreError::RevisionConflict)?;
        let updated = transaction.execute(
            "UPDATE dynamic_clients SET public_key = ?1, revision = ?2
             WHERE internal_id = ?3 AND revision = ?4 AND enabled = 1",
            params![public_key, new_revision, row.target_id, row.client_revision],
        );
        if let Err(error) = updated {
            if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
                return Err(EnrollmentStoreError::PublicKeyConflict);
            }
            return Err(database_error(error));
        }
        transaction
            .execute(
                "UPDATE enrollment_tokens SET consumed_at = ?1, request_id = ?2,
                    result_public_key = ?3, result_revision = ?4
             WHERE selector = ?5 AND consumed_at IS NULL",
                params![
                    now,
                    request_id,
                    public_key,
                    new_revision,
                    selector.as_slice()
                ],
            )
            .map_err(database_error)?;
        audit(
            &transaction,
            if material.purpose() == EnrollmentPurpose::ReEnroll {
                "client_reenrolled"
            } else {
                "client_enrolled"
            },
            &row.target_id,
        )?;
        transaction.commit().map_err(database_error)?;
        Ok(EnrollmentResult {
            display_id: row.display_id,
            revision: new_revision,
        })
    }

    pub fn validate_static_collisions(
        &self,
        static_clients: &[AuthorizedClient],
    ) -> Result<(), EnrollmentStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| EnrollmentStoreError::Database("connection lock poisoned".into()))?;
        for client in static_clients {
            let collision: bool = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM dynamic_clients
                     WHERE tombstoned = 0 AND (normalized_id = ?1 OR public_key = ?2))",
                    params![client.name.to_ascii_lowercase(), client.public_key],
                    |row| row.get(0),
                )
                .map_err(database_error)?;
            if collision {
                return Err(EnrollmentStoreError::StaticIdentityConflict);
            }
        }
        *self
            .static_identities
            .lock()
            .map_err(|_| EnrollmentStoreError::Database("identity lock poisoned".into()))? =
            static_clients
                .iter()
                .map(|c| (c.name.to_ascii_lowercase(), c.public_key.clone()))
                .collect();
        Ok(())
    }

    pub fn health_check(&self) -> Result<(), EnrollmentStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| EnrollmentStoreError::Database("connection lock poisoned".into()))?;
        let result: String = connection
            .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
            .map_err(database_error)?;
        if result == "ok" {
            Ok(())
        } else {
            Err(EnrollmentStoreError::Database(
                "integrity check failed".into(),
            ))
        }
    }

    pub fn audit_count(&self) -> Result<usize, EnrollmentStoreError> {
        self.connection
            .lock()
            .map_err(|_| EnrollmentStoreError::Database("connection lock poisoned".into()))?
            .query_row("SELECT COUNT(*) FROM enrollment_audit", [], |row| {
                row.get(0)
            })
            .map_err(database_error)
    }

    pub fn purge_tombstones(
        &self,
        older_than: SystemTime,
        batch_limit: usize,
    ) -> Result<usize, EnrollmentStoreError> {
        if batch_limit == 0 || batch_limit > 1_000 {
            return Err(EnrollmentStoreError::InvalidPurgeLimit);
        }
        let cutoff = older_than
            .duration_since(UNIX_EPOCH)
            .map_err(|_| EnrollmentStoreError::InvalidPurgeLimit)?
            .as_secs();
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| EnrollmentStoreError::Database("connection lock poisoned".into()))?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let targets = {
            let mut statement = transaction
                .prepare("SELECT internal_id FROM dynamic_clients WHERE tombstoned = 1 AND deleted_at <= ?1 ORDER BY deleted_at LIMIT ?2")
                .map_err(database_error)?;
            statement
                .query_map(params![cutoff, batch_limit], |row| row.get::<_, String>(0))
                .map_err(database_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(database_error)?
        };
        for target in &targets {
            transaction
                .execute(
                    "DELETE FROM enrollment_tokens WHERE target_id = ?1",
                    [target],
                )
                .map_err(database_error)?;
            transaction
                .execute(
                    "DELETE FROM dynamic_clients WHERE internal_id = ?1",
                    [target],
                )
                .map_err(database_error)?;
            audit(&transaction, "tombstone_purged", target)?;
        }
        transaction.commit().map_err(database_error)?;
        Ok(targets.len())
    }
}

struct PreparedToken {
    encoded: String,
    selector: [u8; 32],
    hash: [u8; 32],
    salt: [u8; 16],
    expires_at: u64,
}

fn prepare_token(
    purpose: EnrollmentPurpose,
    server_addr: &str,
    certificate_fingerprint: [u8; 32],
    ttl: Duration,
) -> Result<PreparedToken, EnrollmentStoreError> {
    if ttl.is_zero() {
        return Err(EnrollmentStoreError::InvalidTokenLifetime);
    }
    let mut token = [0_u8; 32];
    rand::rng().fill_bytes(&mut token);
    let encoded = EnrollmentKeyMaterial::new(purpose, server_addr, certificate_fingerprint, token)
        .map_err(|_| EnrollmentStoreError::InvalidKeyMaterial)?
        .encode();
    let selector = Sha256::digest(encoded.as_bytes()).into();
    let mut salt = [0_u8; 16];
    rand::rng().fill_bytes(&mut salt);
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(encoded.as_bytes());
    let hash = hasher.finalize().into();
    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| EnrollmentStoreError::InvalidTokenLifetime)?
        .checked_add(ttl)
        .ok_or(EnrollmentStoreError::InvalidTokenLifetime)?
        .as_secs();
    Ok(PreparedToken {
        encoded,
        selector,
        hash,
        salt,
        expires_at,
    })
}

struct TokenCandidate {
    hash: Vec<u8>,
    salt: Vec<u8>,
    purpose: i64,
    target_id: String,
    issued_revision: u64,
    expires_at: u64,
    consumed_at: Option<u64>,
    request_id: Option<String>,
    result_public_key: Option<String>,
    result_revision: Option<u64>,
    revoked: bool,
    display_id: String,
    enabled: bool,
    client_revision: u64,
    current_public_key: Option<String>,
    tombstoned: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EnrollmentStoreError {
    #[error("waiting for administrator approval")]
    ApprovalPending,
    #[error("registration request rejected by administrator")]
    ApprovalRejected,
    #[error("invalid dynamic client display ID")]
    InvalidDisplayId,
    #[error("dynamic client display ID already exists")]
    DuplicateDisplayId,
    #[error("active dynamic client capacity reached")]
    ClientCapacity,
    #[error("dynamic client does not exist")]
    ClientNotFound,
    #[error("dynamic client is disabled")]
    ClientDisabled,
    #[error("dynamic client revision changed")]
    RevisionConflict,
    #[error("active enrollment token capacity reached")]
    TokenCapacity,
    #[error("invalid enrollment token lifetime")]
    InvalidTokenLifetime,
    #[error("invalid enrollment key material")]
    InvalidKeyMaterial,
    #[error("invalid enrollment token")]
    InvalidToken,
    #[error("enrollment token expired")]
    TokenExpired,
    #[error("enrollment token was already used")]
    TokenAlreadyUsed,
    #[error("enrollment token purpose does not match client state")]
    PurposeMismatch,
    #[error("device public key is already bound")]
    PublicKeyConflict,
    #[error("dynamic identity conflicts with a configured static client")]
    StaticIdentityConflict,
    #[error("invalid tombstone purge limit")]
    InvalidPurgeLimit,
    #[error("invalid enrollment request ID")]
    InvalidRequestId,
    #[error("enrollment database error: {0}")]
    Database(String),
    #[error("unsupported enrollment database schema version {0}")]
    UnsupportedSchema(u32),
}

fn validate_display_id(value: &str) -> Result<&str, EnrollmentStoreError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(EnrollmentStoreError::InvalidDisplayId);
    }
    Ok(value)
}

fn random_id() -> String {
    let mut bytes = [0_u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn database_error(error: rusqlite::Error) -> EnrollmentStoreError {
    EnrollmentStoreError::Database(error.to_string())
}

fn audit(
    transaction: &rusqlite::Transaction<'_>,
    event: &str,
    target_id: &str,
) -> Result<(), EnrollmentStoreError> {
    transaction
        .execute(
            "DELETE FROM enrollment_audit WHERE sequence IN (
               SELECT sequence FROM enrollment_audit ORDER BY sequence ASC
               LIMIT MAX(0, (SELECT COUNT(*) FROM enrollment_audit) - ?1 + 1)
             )",
            [MAX_AUDIT_RECORDS],
        )
        .map_err(database_error)?;
    transaction
        .execute(
            "INSERT INTO enrollment_audit (event, target_id, created_at) VALUES (?1, ?2, ?3)",
            params![event, target_id, unix_now()?],
        )
        .map_err(database_error)?;
    Ok(())
}

fn query_client(
    connection: &Connection,
    internal_id: &str,
) -> Result<Option<DynamicClient>, EnrollmentStoreError> {
    connection.query_row(
        "SELECT internal_id, display_id, enabled, revision, public_key, tombstoned FROM dynamic_clients WHERE internal_id = ?1",
        [internal_id],
        client_from_row,
    ).optional().map_err(database_error)
}

fn client_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<DynamicClient> {
    Ok(DynamicClient {
        internal_id: row.get(0)?,
        display_id: row.get(1)?,
        enabled: row.get(2)?,
        revision: row.get(3)?,
        public_key: row.get(4)?,
        tombstoned: row.get(5)?,
    })
}

fn mutation_miss(
    connection: &Connection,
    internal_id: &str,
) -> Result<DynamicClient, EnrollmentStoreError> {
    match query_client(connection, internal_id)? {
        Some(client) if !client.tombstoned => Err(EnrollmentStoreError::RevisionConflict),
        _ => Err(EnrollmentStoreError::ClientNotFound),
    }
}

fn unix_now() -> Result<u64, EnrollmentStoreError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| EnrollmentStoreError::Database("system clock predates Unix epoch".into()))
}

fn migrate_schema(connection: &mut Connection) -> Result<(), EnrollmentStoreError> {
    let version: u32 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(database_error)?;
    if version > 4 {
        return Err(EnrollmentStoreError::UnsupportedSchema(version));
    }
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(database_error)?;
    if version == 0 {
        DynamicClientStore::create_schema(&transaction)?;
    } else if version == 1 {
        transaction.execute_batch(
            "ALTER TABLE dynamic_clients ADD COLUMN tombstoned INTEGER NOT NULL DEFAULT 0 CHECK(tombstoned IN (0, 1));
             ALTER TABLE dynamic_clients ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0;
             ALTER TABLE dynamic_clients ADD COLUMN updated_at INTEGER NOT NULL DEFAULT 0;
             ALTER TABLE dynamic_clients ADD COLUMN deleted_at INTEGER;"
        ).map_err(database_error)?;
    }
    if version < 3 {
        transaction
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS enrollment_audit (
                   sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                   event TEXT NOT NULL,
                   target_id TEXT NOT NULL,
                   created_at INTEGER NOT NULL
                 );",
            )
            .map_err(database_error)?;
    }
    transaction
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS registration_requests (
          request_id TEXT PRIMARY KEY, display_id TEXT NOT NULL,
          public_key TEXT NOT NULL, purpose INTEGER NOT NULL,
          target_id TEXT, expected_revision INTEGER, created_at INTEGER NOT NULL,
          expires_at INTEGER NOT NULL, status INTEGER NOT NULL DEFAULT 0,
          result_revision INTEGER
        );",
        )
        .map_err(database_error)?;
    transaction
        .pragma_update(None, "user_version", 4)
        .map_err(database_error)?;
    transaction.commit().map_err(database_error)
}
