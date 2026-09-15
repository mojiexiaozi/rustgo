use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use rustgo_config::ManagedConfiguration;
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::HashSet,
    path::Path,
    sync::{Mutex, MutexGuard},
    time::Duration,
};

#[derive(Clone, Debug, Serialize)]
pub struct ManagedSnapshot {
    #[serde(skip_serializing)]
    pub identity: String,
    pub name: String,
    pub revision: u64,
    pub configuration: ManagedConfiguration,
    pub applied_revision: Option<u64>,
    pub results: Value,
}

#[derive(Debug, thiserror::Error)]
pub enum ManagedError {
    #[error("invalid managed configuration: {0}")]
    Invalid(String),
    #[error("managed revision conflict")]
    Conflict,
    #[error("managed client not found")]
    NotFound,
    #[error("managed storage failure: {0}")]
    Storage(String),
}

const MAX_JSON_BYTES: usize = 65_536;
const MAX_SNAPSHOTS: usize = 10_000;

pub struct ManagedStore {
    connection: Mutex<Connection>,
}
impl ManagedStore {
    pub fn open(path: &Path) -> Result<Self, ManagedError> {
        // Set the mode before SQLite creates journals; never expose an initial public file.
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(path)
                .map_err(storage)?;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(storage)?;
        }
        let mut connection = Connection::open(path).map_err(storage)?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(storage)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let version: u32 = transaction
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(storage)?;
        match version {
            0 => transaction
                .execute_batch(
                    "CREATE TABLE managed_snapshots (
                    identity TEXT PRIMARY KEY NOT NULL,
                    name TEXT NOT NULL,
                    mapped_name TEXT UNIQUE,
                    revision INTEGER NOT NULL CHECK(revision > 0),
                    configuration TEXT NOT NULL CHECK(length(CAST(configuration AS BLOB)) <= 65536),
                    applied_revision INTEGER,
                    results TEXT NOT NULL CHECK(length(CAST(results AS BLOB)) <= 65536)
                ); PRAGMA user_version = 1;",
                )
                .map_err(storage)?,
            1 => {}
            _ => {
                return Err(ManagedError::Storage(
                    "unsupported managed database schema".into(),
                ));
            }
        }
        transaction.commit().map_err(storage)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    /// Import only once per stable, authenticated identity. The caller owns name authorization.
    pub fn sync(
        &self,
        identity: &str,
        name: &str,
        configuration: &ManagedConfiguration,
    ) -> Result<ManagedSnapshot, ManagedError> {
        validate_identity_name(identity, name)?;
        let json = configuration_json(configuration)?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        if read_snapshot(&transaction, "identity", identity)?.is_none() {
            let count: usize = transaction
                .query_row("SELECT COUNT(*) FROM managed_snapshots", [], |row| {
                    row.get(0)
                })
                .map_err(storage)?;
            if count >= MAX_SNAPSHOTS {
                return Err(ManagedError::Invalid(
                    "managed snapshot capacity reached".into(),
                ));
            }
            transaction.execute("INSERT INTO managed_snapshots (identity,name,revision,configuration,results) VALUES (?1,?2,1,?3,'[]')", params![identity,name,json]).map_err(storage)?;
        }
        bind_name(&transaction, identity, name)?;
        transaction
            .execute(
                "UPDATE managed_snapshots SET applied_revision=NULL,results='[]' WHERE identity=?1",
                [identity],
            )
            .map_err(storage)?;
        let snapshot =
            read_snapshot(&transaction, "identity", identity)?.ok_or(ManagedError::NotFound)?;
        transaction.commit().map_err(storage)?;
        Ok(snapshot)
    }

    pub fn get(&self, name: &str) -> Result<Option<ManagedSnapshot>, ManagedError> {
        read_snapshot(&*self.lock()?, "mapped_name", name)
    }

    pub fn get_for_identity(
        &self,
        identity: &str,
    ) -> Result<Option<ManagedSnapshot>, ManagedError> {
        read_snapshot(&*self.lock()?, "identity", identity)
    }

    /// The identity and canonical name must be resolved by the authenticated server registry.
    pub fn replace_for_identity(
        &self,
        identity: &str,
        name: &str,
        expected_revision: u64,
        configuration: &ManagedConfiguration,
    ) -> Result<ManagedSnapshot, ManagedError> {
        validate_identity_name(identity, name)?;
        self.replace_inner(
            "identity",
            identity,
            Some(name),
            expected_revision,
            configuration,
        )
    }

    pub fn replace(
        &self,
        name: &str,
        expected_revision: u64,
        configuration: &ManagedConfiguration,
    ) -> Result<ManagedSnapshot, ManagedError> {
        self.replace_inner("mapped_name", name, None, expected_revision, configuration)
    }

    fn replace_inner(
        &self,
        column: &str,
        key: &str,
        new_name: Option<&str>,
        expected_revision: u64,
        configuration: &ManagedConfiguration,
    ) -> Result<ManagedSnapshot, ManagedError> {
        let json = configuration_json(configuration)?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let old = read_snapshot(&transaction, column, key)?.ok_or(ManagedError::NotFound)?;
        if old.revision != expected_revision {
            return Err(ManagedError::Conflict);
        }
        let revision = old
            .revision
            .checked_add(1)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or_else(|| ManagedError::Storage("revision exhausted".into()))?;
        transaction.execute("UPDATE managed_snapshots SET revision=?2,configuration=?3,applied_revision=NULL,results='[]' WHERE identity=?1", params![old.identity,revision,json]).map_err(storage)?;
        if let Some(name) = new_name {
            bind_name(&transaction, &old.identity, name)?;
        }
        let snapshot = read_snapshot(&transaction, "identity", &old.identity)?
            .ok_or(ManagedError::NotFound)?;
        transaction.commit().map_err(storage)?;
        Ok(snapshot)
    }

    pub fn report(
        &self,
        identity: &str,
        revision: u64,
        results: Value,
    ) -> Result<(), ManagedError> {
        let json = bounded_json(&results)?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let snapshot =
            read_snapshot(&transaction, "identity", identity)?.ok_or(ManagedError::NotFound)?;
        if snapshot.revision != revision {
            return Err(ManagedError::Conflict);
        }
        validate_report(&snapshot.configuration, &results)?;
        transaction
            .execute(
                "UPDATE managed_snapshots SET applied_revision=?2,results=?3 WHERE identity=?1",
                params![identity, revision, json],
            )
            .map_err(storage)?;
        transaction.commit().map_err(storage)
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>, ManagedError> {
        self.connection
            .lock()
            .map_err(|_| ManagedError::Storage("connection lock poisoned".into()))
    }
}

fn storage(error: impl std::fmt::Display) -> ManagedError {
    ManagedError::Storage(error.to_string())
}

fn validate_identity_name(identity: &str, name: &str) -> Result<(), ManagedError> {
    if identity.trim().is_empty() || identity.len() > 256 {
        return Err(ManagedError::Invalid("invalid stable identity".into()));
    }
    rustgo_config::validate_client_name(name)
        .map_err(|error| ManagedError::Invalid(error.to_string()))
}

fn bounded_json(value: &impl Serialize) -> Result<String, ManagedError> {
    let json =
        serde_json::to_string(value).map_err(|error| ManagedError::Invalid(error.to_string()))?;
    if json.len() > MAX_JSON_BYTES {
        return Err(ManagedError::Invalid(
            "managed JSON exceeds 65536 bytes".into(),
        ));
    }
    Ok(json)
}

fn configuration_json(configuration: &ManagedConfiguration) -> Result<String, ManagedError> {
    configuration
        .validate()
        .map_err(|error| ManagedError::Invalid(error.to_string()))?;
    bounded_json(configuration)
}

fn bind_name(connection: &Connection, identity: &str, name: &str) -> Result<(), ManagedError> {
    connection
        .execute(
            "UPDATE managed_snapshots SET mapped_name=NULL WHERE mapped_name=?1 AND identity<>?2",
            params![name, identity],
        )
        .map_err(storage)?;
    connection
        .execute(
            "UPDATE managed_snapshots SET name=?2,mapped_name=?2 WHERE identity=?1",
            params![identity, name],
        )
        .map_err(storage)?;
    Ok(())
}

fn read_snapshot(
    connection: &Connection,
    column: &str,
    key: &str,
) -> Result<Option<ManagedSnapshot>, ManagedError> {
    // Column names are internal constants, never caller-controlled SQL.
    let row = connection.query_row(&format!("SELECT identity,name,revision,configuration,applied_revision,results FROM managed_snapshots WHERE {column}=?1"), [key], |row| {
        Ok((row.get::<_, String>(0)?,row.get::<_, String>(1)?,row.get::<_, u64>(2)?,row.get::<_, String>(3)?,row.get::<_, Option<u64>>(4)?,row.get::<_, String>(5)?))
    }).optional().map_err(storage)?;
    row.map(
        |(identity, name, revision, configuration, applied_revision, results)| {
            if configuration.len() > MAX_JSON_BYTES || results.len() > MAX_JSON_BYTES {
                return Err(ManagedError::Storage("oversized stored JSON".into()));
            }
            Ok(ManagedSnapshot {
                identity,
                name,
                revision,
                configuration: serde_json::from_str(&configuration).map_err(storage)?,
                applied_revision,
                results: serde_json::from_str(&results).map_err(storage)?,
            })
        },
    )
    .transpose()
}

fn validate_report(
    configuration: &ManagedConfiguration,
    results: &Value,
) -> Result<(), ManagedError> {
    let invalid = || {
        ManagedError::Invalid("report must contain each configured kind/name once with a valid state and bounded error".into())
    };
    let mut expected: HashSet<(&str, &str)> = configuration
        .tunnels
        .iter()
        .map(|item| ("tunnel", item.name.as_str()))
        .chain(
            configuration
                .exports
                .iter()
                .map(|item| ("export", item.name.as_str())),
        )
        .chain(
            configuration
                .forwards
                .iter()
                .map(|item| ("forward", item.name.as_str())),
        )
        .collect();
    let items = results.as_array().ok_or_else(invalid)?;
    if items.len() != expected.len() {
        return Err(invalid());
    }
    for item in items {
        let object = item.as_object().ok_or_else(invalid)?;
        if object
            .keys()
            .any(|key| !matches!(key.as_str(), "kind" | "name" | "state" | "error"))
        {
            return Err(invalid());
        }
        let kind = item
            .get("kind")
            .and_then(Value::as_str)
            .ok_or_else(invalid)?;
        let name = item
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(invalid)?;
        if !expected.remove(&(kind, name))
            || !matches!(
                item.get("state").and_then(Value::as_str),
                Some("ready" | "failed" | "pending")
            )
        {
            return Err(invalid());
        }
        if let Some(error) = item.get("error")
            && !error.is_null()
            && !error.as_str().is_some_and(|error| error.len() <= 2048)
        {
            return Err(invalid());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
