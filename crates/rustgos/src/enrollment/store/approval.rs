use super::*;

#[derive(Clone, Debug, serde::Serialize)]
pub struct RegistrationRequest {
    pub request_id: String,
    pub client_id: String,
    pub public_key: String,
    pub fingerprint: String,
    pub replacing: bool,
    pub created_at: u64,
}

impl DynamicClientStore {
    fn ensure_not_static(&self, name: &str, key: &str) -> Result<(), EnrollmentStoreError> {
        let identities = self
            .static_identities
            .lock()
            .map_err(|_| EnrollmentStoreError::Database("identity lock poisoned".into()))?;
        if identities
            .iter()
            .any(|(n, k)| n == &name.to_ascii_lowercase() || k == key)
        {
            return Err(EnrollmentStoreError::StaticIdentityConflict);
        }
        Ok(())
    }
    pub fn request_approval(
        &self,
        name: &str,
        purpose: EnrollmentPurpose,
        key: &DevicePublicKey,
        request_id: &str,
        now: SystemTime,
    ) -> Result<EnrollmentResult, EnrollmentStoreError> {
        let name = validate_display_id(name)?;
        if request_id.is_empty()
            || request_id.len() > 128
            || !request_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(EnrollmentStoreError::InvalidRequestId);
        }
        let now = now
            .duration_since(UNIX_EPOCH)
            .map_err(|_| EnrollmentStoreError::InvalidToken)?
            .as_secs();
        let public_key = key.to_string();
        self.ensure_not_static(name, &public_key)?;
        let purpose = if purpose == EnrollmentPurpose::ReEnroll {
            2i64
        } else {
            1
        };
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| EnrollmentStoreError::Database("connection lock poisoned".into()))?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let existing = tx.query_row(
            "SELECT display_id, public_key, purpose, status, expires_at, result_revision FROM registration_requests WHERE request_id=?1",
            [request_id], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,i64>(2)?,r.get::<_,i64>(3)?,r.get::<_,u64>(4)?,r.get::<_,Option<u64>>(5)?))
        ).optional().map_err(database_error)?;
        if let Some((stored_name, stored_key, stored_purpose, status, expires, revision)) = existing
        {
            if stored_name != name || stored_key != public_key || stored_purpose != purpose {
                return Err(EnrollmentStoreError::InvalidRequestId);
            }
            if status == 2 {
                return Err(EnrollmentStoreError::ApprovalRejected);
            }
            if status == 1 {
                let current = tx.query_row("SELECT revision, public_key, enabled, tombstoned FROM dynamic_clients WHERE normalized_id=?1", [name.to_ascii_lowercase()],
                    |r| Ok((r.get::<_,u64>(0)?,r.get::<_,Option<String>>(1)?,r.get::<_,bool>(2)?,r.get::<_,bool>(3)?))).optional().map_err(database_error)?;
                if current.is_some_and(|(rev, k, enabled, deleted)| {
                    Some(rev) == revision
                        && k.as_deref() == Some(&public_key)
                        && enabled
                        && !deleted
                }) {
                    return Ok(EnrollmentResult {
                        display_id: stored_name,
                        revision: revision.ok_or(EnrollmentStoreError::RevisionConflict)?,
                    });
                }
                return Err(EnrollmentStoreError::RevisionConflict);
            }
            if now >= expires {
                let active:usize=tx.query_row("SELECT COUNT(*) FROM registration_requests WHERE status=0 AND expires_at>?1",[now],|r|r.get(0)).map_err(database_error)?;
                if active >= self.limits.max_tokens.min(256) {
                    return Err(EnrollmentStoreError::TokenCapacity);
                }
                // A signed retry revives the same request and key after an offline interval.
                tx.execute(
                    "UPDATE registration_requests SET expires_at=?1 WHERE request_id=?2",
                    params![now.saturating_add(86400), request_id],
                )
                .map_err(database_error)?;
                tx.commit().map_err(database_error)?;
            }
            return Err(EnrollmentStoreError::ApprovalPending);
        }
        tx.execute(
            "DELETE FROM registration_requests WHERE expires_at < ?1",
            [now.saturating_sub(7 * 86400)],
        )
        .map_err(database_error)?;
        let (pending, total): (usize,usize) = tx.query_row("SELECT COALESCE(SUM(status=0 AND expires_at>?1),0), COUNT(*) FROM registration_requests", [now], |r| Ok((r.get(0)?,r.get(1)?))).map_err(database_error)?;
        if pending >= self.limits.max_tokens.min(256) || total >= 4096 {
            return Err(EnrollmentStoreError::TokenCapacity);
        }
        let target = tx.query_row("SELECT internal_id, revision, public_key, enabled, tombstoned FROM dynamic_clients WHERE normalized_id=?1", [name.to_ascii_lowercase()],
            |r| Ok((r.get::<_,String>(0)?,r.get::<_,u64>(1)?,r.get::<_,Option<String>>(2)?,r.get::<_,bool>(3)?,r.get::<_,bool>(4)?))).optional().map_err(database_error)?;
        let (target_id, revision) = if let Some((id, revision, old_key, enabled, deleted)) = target
        {
            if deleted {
                return Err(EnrollmentStoreError::ClientNotFound);
            }
            if !enabled {
                return Err(EnrollmentStoreError::ClientDisabled);
            }
            if old_key.is_some() && purpose != 2 {
                return Err(EnrollmentStoreError::PurposeMismatch);
            }
            (Some(id), Some(revision))
        } else {
            (None, None)
        };
        tx.execute("INSERT INTO registration_requests (request_id, display_id, public_key, purpose, target_id, expected_revision, created_at, expires_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![request_id,name,public_key,purpose,target_id,revision,now,now.saturating_add(86400)]).map_err(database_error)?;
        audit(&tx, "registration_requested", request_id)?;
        tx.commit().map_err(database_error)?;
        Err(EnrollmentStoreError::ApprovalPending)
    }

    pub fn pending_approvals(&self) -> Result<Vec<RegistrationRequest>, EnrollmentStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| EnrollmentStoreError::Database("connection lock poisoned".into()))?;
        let mut statement = connection.prepare("SELECT request_id,display_id,public_key,purpose,created_at FROM registration_requests WHERE status=0 AND expires_at>?1 ORDER BY created_at,request_id LIMIT 256").map_err(database_error)?;
        let rows = statement
            .query_map([unix_now()?], |r| {
                let public_key: String = r.get(2)?;
                let fingerprint = public_key
                    .parse::<DevicePublicKey>()
                    .map(|k| k.fingerprint().to_string())
                    .unwrap_or_default();
                Ok(RegistrationRequest {
                    request_id: r.get(0)?,
                    client_id: r.get(1)?,
                    public_key,
                    fingerprint,
                    replacing: r.get::<_, i64>(3)? == 2,
                    created_at: r.get(4)?,
                })
            })
            .map_err(database_error)?;
        rows.collect::<Result<_, _>>().map_err(database_error)
    }

    pub fn review_approval(
        &self,
        request_id: &str,
        approve: bool,
    ) -> Result<Option<EnrollmentResult>, EnrollmentStoreError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| EnrollmentStoreError::Database("connection lock poisoned".into()))?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let row = tx.query_row("SELECT display_id, public_key, target_id, expected_revision, status, expires_at, result_revision FROM registration_requests WHERE request_id=?1", [request_id],
            |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,Option<String>>(2)?,r.get::<_,Option<u64>>(3)?,r.get::<_,i64>(4)?,r.get::<_,u64>(5)?,r.get::<_,Option<u64>>(6)?))).optional().map_err(database_error)?.ok_or(EnrollmentStoreError::ClientNotFound)?;
        let (name, key, target, expected, status, expires, result_revision) = row;
        self.ensure_not_static(&name, &key)?;
        if status != 0 {
            return match (status, approve) {
                (1, true) => {
                    let unchanged:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM dynamic_clients WHERE normalized_id=?1 AND public_key=?2 AND revision=?3 AND enabled=1 AND tombstoned=0)",params![name.to_ascii_lowercase(),key,result_revision],|r|r.get(0)).map_err(database_error)?;
                    if unchanged {
                        Ok(None)
                    } else {
                        Err(EnrollmentStoreError::RevisionConflict)
                    }
                }
                (2, false) => Ok(None),
                _ => Err(EnrollmentStoreError::RevisionConflict),
            };
        }
        if unix_now()? >= expires {
            return Err(EnrollmentStoreError::TokenExpired);
        }
        if !approve {
            tx.execute(
                "UPDATE registration_requests SET status=2 WHERE request_id=?1",
                [request_id],
            )
            .map_err(database_error)?;
            audit(&tx, "registration_rejected", request_id)?;
            tx.commit().map_err(database_error)?;
            return Ok(None);
        }
        let revision = if let Some(id) = target {
            let expected = expected.ok_or(EnrollmentStoreError::RevisionConflict)?;
            let next = expected
                .checked_add(1)
                .ok_or(EnrollmentStoreError::RevisionConflict)?;
            let changed=tx.execute("UPDATE dynamic_clients SET public_key=?1, revision=?2, updated_at=?3 WHERE internal_id=?4 AND revision=?5 AND enabled=1 AND tombstoned=0 AND normalized_id=?6",
                params![key,next,unix_now()?,id,expected,name.to_ascii_lowercase()]).map_err(|e| if e.sqlite_error_code()==Some(rusqlite::ErrorCode::ConstraintViolation) {EnrollmentStoreError::PublicKeyConflict} else {database_error(e)})?;
            if changed != 1 {
                return Err(EnrollmentStoreError::RevisionConflict);
            }
            tx.execute(
                "UPDATE enrollment_tokens SET revoked=1 WHERE target_id=?1 AND consumed_at IS NULL",
                [id],
            )
            .map_err(database_error)?;
            next
        } else {
            let count: usize = tx
                .query_row(
                    "SELECT COUNT(*) FROM dynamic_clients WHERE enabled=1 AND tombstoned=0",
                    [],
                    |r| r.get(0),
                )
                .map_err(database_error)?;
            if count >= self.limits.max_active_clients {
                return Err(EnrollmentStoreError::ClientCapacity);
            }
            tx.execute("INSERT INTO dynamic_clients (internal_id,display_id,normalized_id,public_key,enabled,revision,created_at,updated_at) VALUES (?1,?2,?3,?4,1,1,?5,?5)",
                params![random_id(),name,name.to_ascii_lowercase(),key,unix_now()?]).map_err(|e| if e.sqlite_error_code()==Some(rusqlite::ErrorCode::ConstraintViolation) {EnrollmentStoreError::RevisionConflict} else {database_error(e)})?;
            1
        };
        tx.execute(
            "UPDATE registration_requests SET status=1,result_revision=?1 WHERE request_id=?2",
            params![revision, request_id],
        )
        .map_err(database_error)?;
        audit(&tx, "registration_approved", request_id)?;
        tx.commit().map_err(database_error)?;
        Ok(Some(EnrollmentResult {
            display_id: name,
            revision,
        }))
    }
}
