//! Durable post-authorization progress. Only observed completed operations advance.
//! A kernel file lock prevents concurrent native workers and releases on crash.
use crate::{session::Session, Error, Result, Store};
use fs2::FileExt;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

pub struct RuntimeLease {
    file: File,
}
impl RuntimeLease {
    pub fn acquire(store: &Store) -> Result<Self> {
        let path = store.data_dir.join(".native-runtime.lock");
        if let Ok(meta) = fs::symlink_metadata(&path) {
            if !meta.is_file() || meta.file_type().is_symlink() {
                return Err(Error::Storage("invalid native worker lock".into()));
            }
            #[cfg(unix)]
            if meta.permissions().mode() & 0o077 != 0 {
                return Err(Error::Storage("native worker lock must be private".into()));
            }
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options.open(path)?;
        file.try_lock_exclusive()
            .map_err(|_| Error::Conflict("another native worker holds this session".into()))?;
        Ok(Self { file })
    }
}
impl Drop for RuntimeLease {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    pub name: String,
    pub state: StepState,
    pub updated_at_ms: i64,
    pub http_status: Option<u16>,
    pub server_status: Option<i64>,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StepState {
    Started,
    Completed,
    Failed,
}
#[derive(Debug, Serialize)]
pub struct RuntimeStatus {
    pub steps: Vec<Step>,
    pub bootstrap_complete: bool,
    pub native_sync_verified: bool,
}
impl Store {
    pub fn runtime_status(&self) -> Result<RuntimeStatus> {
        let conn = self.lock()?;
        let mut statement =
            conn.prepare("SELECT value FROM metadata WHERE key LIKE 'native_step:%' ORDER BY key")?;
        let mut steps = Vec::new();
        for row in statement.query_map([], |r| r.get::<_, String>(0))? {
            steps.push(
                serde_json::from_str(&row?)
                    .map_err(|_| Error::Storage("native journal corrupt".into()))?,
            );
        }
        Ok(RuntimeStatus {
            steps,
            bootstrap_complete: false,
            native_sync_verified: false,
        })
    }
    pub(crate) fn native_completed(&self, name: &str) -> Result<bool> {
        let raw: Option<String> = self
            .lock()?
            .query_row(
                "SELECT value FROM metadata WHERE key=?1",
                [format!("native_step:{name}")],
                |r| r.get(0),
            )
            .optional()?;
        raw.map(|raw| {
            serde_json::from_str::<Step>(&raw)
                .map(|step| step.state == StepState::Completed)
                .map_err(|_| Error::Storage("native journal corrupt".into()))
        })
        .unwrap_or(Ok(false))
    }
    pub(crate) fn native_flag(&self, key: &str) -> Result<Option<bool>> {
        let raw: Option<String> = self
            .lock()?
            .query_row(
                "SELECT value FROM metadata WHERE key=?1",
                [format!("native_flag:{key}")],
                |r| r.get(0),
            )
            .optional()?;
        raw.map(|raw| {
            raw.parse()
                .map_err(|_| Error::Storage("native flag corrupt".into()))
        })
        .transpose()
    }
    pub(crate) fn native_step(
        &self,
        name: &str,
        state: StepState,
        http_status: Option<u16>,
        server_status: Option<i64>,
    ) -> Result<()> {
        if !matches!(
            name,
            "contacts_sync"
                | "friends_sync"
                | "pilsner_listen"
                | "drawer_key_sync"
                | "drawer_pin_verify"
                | "pilsner_ping"
                | "drawer_recording_start"
                | "drawer_recording_complete"
                | "drawer_restore_completed"
                | "drawer_chat_backup_completed"
                | "drawer_media_backup_completed"
                | "drawer_backup_info"
                | "drawer_contact_snapshot"
                | "wallet_status"
                | "drawer_user_info"
                | "backup_list_precheck"
                | "backup_list_ui"
                | "getconf"
                | "checkin"
                | "loginlist"
                | "chat_lists_received"
        ) {
            return Err(Error::Invalid("unknown native step".into()));
        }
        let step = Step {
            name: name.into(),
            state,
            updated_at_ms: chrono::Utc::now().timestamp_millis(),
            http_status,
            server_status,
        };
        self.lock()?.execute("INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",params![format!("native_step:{name}"),serde_json::to_string(&step)?])?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct ActiveTokens {
    version: u32,
    user_id: i64,
    attempt_id: String,
    generation: u64,
    access_token: String,
    refresh_token: String,
    token_type: String,
}
impl Store {
    /// Install a refresh result iff it still replaces the expected token pair.
    /// Both tokens and the generation marker commit atomically; no handoff overwrite.
    pub(crate) fn rotate_tokens(
        &self,
        session: &Session,
        access: &str,
        refresh: &str,
        token_type: &str,
    ) -> Result<()> {
        validate_token(access)?;
        validate_token(refresh)?;
        if !token_type.eq_ignore_ascii_case("bearer") {
            return Err(Error::Storage("invalid refreshed token type".into()));
        }
        let current = self.session_load()?;
        if current.user_id != session.user_id
            || *current.access_token != *session.access_token
            || *current.refresh_token != *session.refresh_token
        {
            return Err(Error::Conflict(
                "session changed before token refresh commit".into(),
            ));
        }
        let mut conn = self.lock()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let attempt_id: String = tx.query_row(
            "SELECT attempt_id FROM qr_auth_attempt WHERE id=1 AND state='authorized'",
            [],
            |r| r.get(0),
        )?;
        let old: Option<String> = tx
            .query_row(
                "SELECT value FROM metadata WHERE key='native_tokens'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let generation = match old {
            Some(raw) => {
                let previous: ActiveTokens = serde_json::from_str(&raw)
                    .map_err(|_| Error::Storage("active token state corrupt".into()))?;
                if previous.access_token != *session.access_token
                    || previous.refresh_token != *session.refresh_token
                {
                    return Err(Error::Conflict("concurrent token refresh".into()));
                }
                previous
                    .generation
                    .checked_add(1)
                    .ok_or_else(|| Error::Storage("token generation exhausted".into()))?
            }
            None => 1,
        };
        let saved = ActiveTokens {
            version: 1,
            user_id: session.user_id,
            attempt_id,
            generation,
            access_token: access.into(),
            refresh_token: refresh.into(),
            token_type: token_type.into(),
        };
        tx.execute("INSERT INTO metadata(key,value) VALUES('native_tokens',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[serde_json::to_string(&saved)?])?;
        tx.execute("INSERT INTO metadata(key,value) VALUES('native_token_generation',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[generation.to_string()])?;
        tx.commit()?;
        Ok(())
    }
    pub(crate) fn load_active_tokens(&self, session: &mut Session, attempt_id: &str) -> Result<()> {
        let conn = self.lock()?;
        let marker: Option<String> = conn
            .query_row(
                "SELECT value FROM metadata WHERE key='native_token_generation'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let raw: Option<String> = conn
            .query_row(
                "SELECT value FROM metadata WHERE key='native_tokens'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        match (marker, raw) {
            (None, None) => Ok(()),
            (Some(marker), Some(raw)) => {
                let active: ActiveTokens = serde_json::from_str(&raw).map_err(|_| {
                    Error::Storage("active tokens corrupt; restore saved session".into())
                })?;
                if active.version != 1
                    || active.user_id != session.user_id
                    || active.attempt_id != attempt_id
                    || marker != active.generation.to_string()
                    || active.generation == 0
                    || !active.token_type.eq_ignore_ascii_case("bearer")
                {
                    return Err(Error::Storage("active token binding invalid".into()));
                }
                validate_token(&active.access_token)?;
                validate_token(&active.refresh_token)?;
                session.access_token = zeroize::Zeroizing::new(active.access_token);
                session.refresh_token = zeroize::Zeroizing::new(active.refresh_token);
                session.token_type = active.token_type;
                Ok(())
            }
            _ => Err(Error::Storage(
                "active tokens missing; refusing fallback to stale handoff".into(),
            )),
        }
    }
}
fn validate_token(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 16384 || value.chars().any(char::is_control) {
        return Err(Error::Storage("invalid token value".into()));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::io::Write;
    pub(crate) fn setup() -> (tempfile::TempDir, Store) {
        let dir = tempfile::Builder::new()
            .prefix("kakao-runtime-")
            .permissions(
                <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
            )
            .tempdir()
            .unwrap();
        let store = Store::initialize(dir.path()).unwrap();
        store
            .device_initialize(
                &serde_json::from_str(include_str!("../config/device-catalog.json")).unwrap(),
                chrono::NaiveDate::from_ymd_opt(2026, 11, 13).unwrap(),
            )
            .unwrap();
        store.qr_wire_initialize(1700000000000).unwrap();
        let bytes=serde_json::to_vec(&serde_json::json!({"schema_version":2,"method":"password","attempt_id":"fixture","authorized_at_epoch_ms":1700000000000_i64,"response":{"userId":42,"countryIso":"KR","accountId":51,"token_type":"bearer","access_token":"initial-access","refresh_token":"initial-refresh"}})).unwrap();
        let mut f = File::create(dir.path().join("qr-handoff.json")).unwrap();
        #[cfg(unix)]
        f.set_permissions(fs::Permissions::from_mode(0o600))
            .unwrap();
        f.write_all(&bytes).unwrap();
        store.lock().unwrap().execute("INSERT INTO qr_auth_attempt(id,attempt_id,state,started_at_ms,handoff_hash) VALUES(1,'fixture','authorized',1700000000000,?1)",[hex::encode(Sha256::digest(&bytes))]).unwrap();
        store
            .lock()
            .unwrap()
            .execute("INSERT INTO metadata VALUES('auth_method','password')", [])
            .unwrap();
        (dir, store)
    }
    #[test]
    fn worker_lease_excludes_other_process_handles_and_releases() {
        let (_dir, store) = setup();
        let first = RuntimeLease::acquire(&store).unwrap();
        assert!(RuntimeLease::acquire(&store).is_err());
        drop(first);
        assert!(RuntimeLease::acquire(&store).is_ok());
    }
    #[test]
    fn rotated_pair_is_atomic_bound_and_never_falls_back_when_damaged() {
        let (dir, store) = setup();
        let initial = store.session_load().unwrap();
        let handoff = fs::read(dir.path().join("qr-handoff.json")).unwrap();
        store
            .rotate_tokens(&initial, "new-access", "new-refresh", "bearer")
            .unwrap();
        let active = store.session_load().unwrap();
        assert_eq!(active.access_token.as_str(), "new-access");
        assert_eq!(active.refresh_token.as_str(), "new-refresh");
        assert!(store
            .rotate_tokens(&initial, "stale-overwrite", "stale-overwrite", "bearer")
            .is_err());
        assert_eq!(
            fs::read(dir.path().join("qr-handoff.json")).unwrap(),
            handoff
        );
        store
            .lock()
            .unwrap()
            .execute("DELETE FROM metadata WHERE key='native_tokens'", [])
            .unwrap();
        assert!(store.session_load().is_err());
    }
    #[test]
    fn journal_records_only_metadata_and_never_claims_completed_bootstrap() {
        let (_dir, store) = setup();
        store
            .native_step("getconf", StepState::Started, None, None)
            .unwrap();
        assert_eq!(
            store.runtime_status().unwrap().steps[0].state,
            StepState::Started
        );
        store
            .native_step("getconf", StepState::Completed, None, Some(0))
            .unwrap();
        let status = store.runtime_status().unwrap();
        assert!(!status.bootstrap_complete);
        assert!(!status.native_sync_verified);
        assert_eq!(status.steps.len(), 1);
        assert_eq!(status.steps[0].state, StepState::Completed);
        assert!(!serde_json::to_string(&status)
            .unwrap()
            .contains("initial-access"));
    }
}
