//! Existing Drawer history restoration. Selection is durable and cannot be
//! confused with the separate remote skip/restore-completed operation.
use crate::{runtime::RuntimeLease, Error, Result, Store};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub(crate) struct State {
    version: u32,
    pub(crate) user_id: i64,
    pub(crate) attempt_id: String,
    inventory_sequence: i64,
    #[serde(default)]
    key_sha256: Option<String>,
    pub(crate) status: RestoreStatus,
    #[serde(default)]
    pub(crate) progress: Progress,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct Progress {
    pub inventory_read: bool,
    pub rooms_done: bool,
    pub logs_done: bool,
    pub room_cursor: Option<i64>,
    pub log_cursor: Option<String>,
    pub recording_count: Option<i64>,
    pub recording_done: bool,
    pub rooms_prepared: bool,
    pub meta_done: bool,
    pub restore_completed: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RestoreStatus {
    pub choice: String,
    pub phase: String,
    pub backup_rooms: i64,
    pub backup_messages: i64,
    pub downloaded_messages: i64,
    pub indexed_messages: i64,
    #[serde(default)]
    pub key_available: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Inventory {
    backup_chat_count: i64,
    backup_chat_log_count: i64,
}
impl Store {
    /// Called only for an explicit restore choice; performs no skip or completion.
    pub fn select_drawer_restore(&self) -> Result<RestoreStatus> {
        let _lease = RuntimeLease::acquire(self)?;
        let session = self.session_load()?;
        if self.native_flag("activated")? != Some(true)
            || !self.native_completed("drawer_backup_info")?
        {
            return Err(Error::Conflict(
                "drawer backup inventory must complete first".into(),
            ));
        }
        let mut conn = self.lock()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let attempt: String = tx.query_row(
            "SELECT attempt_id FROM qr_auth_attempt WHERE id=1 AND state='authorized'",
            [],
            |r| r.get(0),
        )?;
        let prior: Option<String> = tx
            .query_row(
                "SELECT value FROM metadata WHERE key='drawer_restore'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(prior) = prior {
            let state = decode(&prior)?;
            if state.user_id != session.user_id() || state.attempt_id != attempt {
                return Err(Error::Conflict(
                    "restore belongs to another authorization".into(),
                ));
            }
            return Ok(state.status);
        }
        let completion:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM metadata WHERE key='native_step:drawer_restore_completed')",[],|r|r.get(0))?;
        if completion {
            return Err(Error::Conflict(
                "restore completion was already attempted; reconcile before choosing restoration"
                    .into(),
            ));
        }
        let inventory = {
            let mut stmt=tx.prepare("SELECT sequence,payload FROM native_events WHERE source='bootstrap_http' ORDER BY sequence DESC LIMIT 64")?;
            let mut rows = stmt.query([])?;
            let mut found = None;
            while let Some(row) = rows.next()? {
                let bytes: Vec<u8> = row.get(1)?;
                if let Ok(value) = serde_json::from_slice::<Inventory>(&bytes) {
                    if value.backup_chat_count < 0 || value.backup_chat_log_count < 0 {
                        return Err(Error::Storage("negative backup inventory".into()));
                    }
                    found = Some((row.get::<_, i64>(0)?, value));
                    break;
                }
            }
            found
                .ok_or_else(|| Error::Storage("verified drawer backup inventory missing".into()))?
        };
        let state = State {
            version: 1,
            user_id: session.user_id(),
            attempt_id: attempt,
            inventory_sequence: inventory.0,
            key_sha256: None,
            progress: Progress::default(),
            status: RestoreStatus {
                choice: "restore_existing_conversations".into(),
                phase: "route_pending".into(),
                backup_rooms: inventory.1.backup_chat_count,
                backup_messages: inventory.1.backup_chat_log_count,
                downloaded_messages: 0,
                indexed_messages: 0,
                key_available: false,
            },
        };
        tx.execute(
            "INSERT INTO metadata(key,value) VALUES('drawer_restore',?1)",
            [serde_json::to_string(&state)?],
        )?;
        tx.commit()?;
        Ok(state.status)
    }
    pub fn drawer_restore_status(&self) -> Result<Option<RestoreStatus>> {
        let raw: Option<String> = self
            .lock()?
            .query_row(
                "SELECT value FROM metadata WHERE key='drawer_restore'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        raw.map(|raw| decode(&raw).map(|state| state.status))
            .transpose()
    }
    pub(crate) fn drawer_restore_phase(&self, phase: &str) -> Result<()> {
        if !matches!(
            phase,
            "route_pending"
                | "key_auth_required"
                | "key_request_pending"
                | "key_request_failed"
                | "key_sync_failed"
                | "security_code_required"
                | "mypin_auth_required"
                | "key_not_found"
                | "mypin_rejected"
                | "mypin_locked"
                | "key_ready"
                | "key_handoff_pending"
                | "downloading_rooms"
                | "downloading_logs"
                | "recording_restore_pending"
        ) {
            return Err(Error::Invalid("unknown restoration phase".into()));
        }
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        let raw: String = tx.query_row(
            "SELECT value FROM metadata WHERE key='drawer_restore'",
            [],
            |r| r.get(0),
        )?;
        let mut state = decode(&raw)?;
        state.status.phase = phase.into();
        tx.execute(
            "UPDATE metadata SET value=?1 WHERE key='drawer_restore'",
            params![serde_json::to_string(&state)?],
        )?;
        tx.commit()?;
        Ok(())
    }
}
impl Store {
    pub(crate) fn drawer_save_key(&self, key: &crate::drawer::crypto::DrawerKey) -> Result<()> {
        use sha2::{Digest, Sha256};
        use std::io::Write;
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;
        let session = self.session_load()?;
        let path = self.data_dir.join("drawer-private-key.der");
        let encoded = key.private_der()?;
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        let raw: String = tx.query_row(
            "SELECT value FROM metadata WHERE key='drawer_restore'",
            [],
            |r| r.get(0),
        )?;
        let mut state = decode(&raw)?;
        let attempt: String = tx.query_row(
            "SELECT attempt_id FROM qr_auth_attempt WHERE id=1",
            [],
            |r| r.get(0),
        )?;
        if state.user_id != session.user_id()
            || state.attempt_id != attempt
            || state.key_sha256.is_some()
        {
            return Err(Error::Conflict("restore key binding conflict".into()));
        }
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&path).map_err(|_| {
            Error::Storage(
                "restore key exists or cannot be written; explicit recovery required".into(),
            )
        })?;
        file.write_all(encoded.as_bytes())?;
        file.sync_all()?;
        std::fs::File::open(&*self.data_dir)?.sync_all()?;
        state.key_sha256 = Some(hex::encode(Sha256::digest(encoded.as_bytes())));
        state.status.key_available = true;
        state.status.phase = "key_ready".into();
        tx.execute(
            "UPDATE metadata SET value=?1 WHERE key='drawer_restore'",
            [serde_json::to_string(&state)?],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub(crate) fn drawer_load_key(&self) -> Result<crate::drawer::crypto::DrawerKey> {
        use sha2::{Digest, Sha256};
        use std::io::Read;
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;
        let session = self.session_load()?;
        let conn = self.lock()?;
        let raw: String = conn.query_row(
            "SELECT value FROM metadata WHERE key='drawer_restore'",
            [],
            |r| r.get(0),
        )?;
        let state = decode(&raw)?;
        let attempt: String = conn.query_row(
            "SELECT attempt_id FROM qr_auth_attempt WHERE id=1",
            [],
            |r| r.get(0),
        )?;
        if state.user_id != session.user_id()
            || state.attempt_id != attempt
            || !state.status.key_available
        {
            return Err(Error::Storage("restore key unavailable".into()));
        }
        let path = self.data_dir.join("drawer-private-key.der");
        let meta = std::fs::symlink_metadata(&path)?;
        if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 16384 {
            return Err(Error::Storage("invalid restore key file".into()));
        }
        #[cfg(unix)]
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(Error::Storage("restore key must be private".into()));
        }
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        std::fs::File::open(path)?
            .take(16385)
            .read_to_end(&mut bytes)?;
        if state.key_sha256.as_deref() != Some(hex::encode(Sha256::digest(&*bytes)).as_str()) {
            return Err(Error::Storage("restore key hash mismatch".into()));
        }
        crate::drawer::crypto::DrawerKey::from_der(&bytes)
    }
}

pub(crate) fn decode(raw: &str) -> Result<State> {
    let state: State =
        serde_json::from_str(raw).map_err(|_| Error::Storage("restore state corrupt".into()))?;
    if state.version != 1 || state.status.choice != "restore_existing_conversations" {
        return Err(Error::Storage("unknown restore state".into()));
    }
    Ok(state)
}
/// Follow the official restore button's first network gate using the saved
/// account session. This does not register/reset keys or report completion.
pub async fn begin(store: &Store) -> Result<RestoreStatus> {
    let selected = store.select_drawer_restore()?;
    if !matches!(selected.phase.as_str(), "route_pending" | "key_sync_failed") {
        return Ok(selected);
    }
    let lease = std::sync::Arc::new(RuntimeLease::acquire(store)?);
    let mut session = store.session_load()?;
    let mut listener = crate::pilsner::Listener::new(store.clone(), lease);
    listener.ensure().await?;
    store.drawer_restore_phase("key_request_pending")?;
    store.native_step(
        "drawer_key_sync",
        crate::runtime::StepState::Started,
        None,
        None,
    )?;
    let result = crate::native_http::Client::new()?
        .execute(
            store,
            &mut session,
            crate::native_http::Operation::DrawerKeySync,
        )
        .await;
    let response = match result {
        Ok(response) => response,
        Err(error) => {
            store.drawer_restore_phase("key_sync_failed")?;
            store.native_step(
                "drawer_key_sync",
                crate::runtime::StepState::Failed,
                None,
                None,
            )?;
            listener.close().await?;
            return Err(error);
        }
    };
    store.capture_native("bootstrap_http", &response.body)?;
    let phase = key_sync_phase(response.http_status, &response.body)?;
    store.drawer_restore_phase(phase)?;
    store.native_step(
        "drawer_key_sync",
        if matches!(phase, "security_code_required" | "mypin_auth_required") {
            crate::runtime::StepState::Completed
        } else {
            crate::runtime::StepState::Failed
        },
        Some(response.http_status),
        response.server_status,
    )?;
    listener.close().await?;
    store
        .drawer_restore_status()?
        .ok_or_else(|| Error::Storage("restore state missing".into()))
}
fn key_sync_phase(http_status: u16, body: &[u8]) -> Result<&'static str> {
    #[derive(Deserialize)]
    struct SyncResponse {
        status: i64,
        #[serde(rename = "isSynced")]
        is_synced: Option<bool>,
    }
    let response: SyncResponse = serde_json::from_slice(body)
        .map_err(|_| Error::Invalid("invalid drawer key-sync response".into()))?;
    match (http_status, response.status) {
        (200..=299, 0) if response.is_synced == Some(true) => Ok("mypin_auth_required"),
        (200..=299, 0) => Ok("security_code_required"),
        (_, 404) => Ok("key_not_found"),
        _ => Ok("key_sync_failed"),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    pub(crate) fn restore_store() -> (tempfile::TempDir, crate::Store) {
        let (dir, store) = crate::runtime::tests::setup();
        store
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO metadata VALUES('native_flag:activated','true')",
                [],
            )
            .unwrap();
        store
            .native_step(
                "drawer_backup_info",
                crate::runtime::StepState::Completed,
                Some(200),
                None,
            )
            .unwrap();
        store
            .capture_native(
                "bootstrap_http",
                br#"{"backupChatCount":4,"backupChatLogCount":37}"#,
            )
            .unwrap();
        store.select_drawer_restore().unwrap();
        (dir, store)
    }
    #[test]
    fn private_key_handoff_is_bound_exclusive_and_detects_corruption() {
        use rsa::pkcs8::EncodePrivateKey;
        let (_dir, store) = restore_store();
        let rsa = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 1024).unwrap();
        let der = rsa.to_pkcs8_der().unwrap();
        let key = crate::drawer::crypto::DrawerKey::from_der(der.as_bytes()).unwrap();
        store.drawer_save_key(&key).unwrap();
        assert!(
            store
                .drawer_restore_status()
                .unwrap()
                .unwrap()
                .key_available
        );
        assert!(store.drawer_load_key().is_ok());
        assert!(store.drawer_save_key(&key).is_err());
        let path = store.data_dir.join("drawer-private-key.der");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(store.drawer_load_key().is_err());
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        store
            .lock()
            .unwrap()
            .execute("UPDATE qr_auth_attempt SET attempt_id='other'", [])
            .unwrap();
        assert!(store.drawer_load_key().is_err());
        // Restore the binding only in the synthetic fixture, then corrupt the file.
        let state: String = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT value FROM metadata WHERE key='drawer_restore'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let attempt = super::decode(&state).unwrap().attempt_id;
        store
            .lock()
            .unwrap()
            .execute("UPDATE qr_auth_attempt SET attempt_id=?1", [attempt])
            .unwrap();
        std::fs::write(path, b"corrupt").unwrap();
        assert!(store.drawer_load_key().is_err());
    }
    #[test]
    fn orphan_key_never_overwrites_or_claims_ready() {
        use rsa::pkcs8::EncodePrivateKey;
        let (_dir, store) = restore_store();
        let rsa = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 1024).unwrap();
        let der = rsa.to_pkcs8_der().unwrap();
        let key = crate::drawer::crypto::DrawerKey::from_der(der.as_bytes()).unwrap();
        let path = store.data_dir.join("drawer-private-key.der");
        std::fs::write(&path, b"orphan").unwrap();
        assert!(store.drawer_save_key(&key).is_err());
        assert_eq!(std::fs::read(path).unwrap(), b"orphan");
        assert!(
            !store
                .drawer_restore_status()
                .unwrap()
                .unwrap()
                .key_available
        );
        assert!(store.drawer_load_key().is_err());
    }
    #[test]
    fn restore_choice_is_idempotent_bound_and_not_completed() {
        let (_dir, store) = crate::runtime::tests::setup();
        store
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO metadata VALUES('native_flag:activated','true')",
                [],
            )
            .unwrap();
        store
            .native_step(
                "drawer_backup_info",
                crate::runtime::StepState::Completed,
                Some(200),
                None,
            )
            .unwrap();
        store
            .capture_native(
                "bootstrap_http",
                br#"{"backupChatCount":4,"backupChatLogCount":37}"#,
            )
            .unwrap();
        let first = store.select_drawer_restore().unwrap();
        assert_eq!(first.backup_messages, 37);
        assert_eq!(first.indexed_messages, 0);
        assert_eq!(first, store.select_drawer_restore().unwrap());
        store.drawer_restore_phase("key_auth_required").unwrap();
        assert_eq!(
            store.select_drawer_restore().unwrap().phase,
            "key_auth_required"
        );
        assert!(!store.native_completed("drawer_restore_completed").unwrap());
        store
            .lock()
            .unwrap()
            .execute("UPDATE qr_auth_attempt SET attempt_id='other'", [])
            .unwrap();
        assert!(store.select_drawer_restore().is_err());
    }
    #[test]
    fn key_sync_errors_never_select_security_code_fallback() {
        assert_eq!(
            super::key_sync_phase(200, br#"{"status":0,"isSynced":false}"#).unwrap(),
            "security_code_required"
        );
        assert_eq!(
            super::key_sync_phase(200, br#"{"status":0,"isSynced":true}"#).unwrap(),
            "mypin_auth_required"
        );
        assert_eq!(
            super::key_sync_phase(200, br#"{"status":404}"#).unwrap(),
            "key_not_found"
        );
        assert_eq!(
            super::key_sync_phase(403, br#"{"status":0}"#).unwrap(),
            "key_sync_failed"
        );
        assert!(super::key_sync_phase(200, br#"{"isSynced":false}"#).is_err());
    }
}
