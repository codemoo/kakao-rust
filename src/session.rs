//! Load the exact, hash-verified authorization handoff without displaying secrets.
//! Loading tokens does not complete Android account bootstrap or native login.
use crate::{qr::WireProfile, Error, Result, Store};
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    fs::{self, File},
    io::Read,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const LIMIT: u64 = 128 * 1024;

/// No Debug, Clone or Serialize: credentials cross only explicit transport boundaries.
pub struct Session {
    pub(crate) wire: WireProfile,
    pub(crate) user_id: i64,
    pub(crate) account_id: Option<i64>,
    pub(crate) country_iso: String,
    pub(crate) access_token: Zeroizing<String>,
    pub(crate) refresh_token: Zeroizing<String>,
    pub(crate) token_type: String,
    authorized_at_ms: i64,
    method: &'static str,
}
#[derive(Debug, Serialize)]
pub struct SessionStatus {
    pub authorization_verified_locally: bool,
    pub method: &'static str,
    pub authorized_at_epoch_ms: i64,
    pub device_model: String,
    pub token_handoff_complete: bool,
    pub bootstrap_complete: bool,
    pub native_sync_verified: bool,
}
impl Session {
    pub fn user_id(&self) -> i64 {
        self.user_id
    }
    pub fn account_id(&self) -> Option<i64> {
        self.account_id
    }
    pub fn country_iso(&self) -> &str {
        &self.country_iso
    }
    pub fn token_type(&self) -> &str {
        &self.token_type
    }
    pub fn status(&self) -> SessionStatus {
        SessionStatus {
            authorization_verified_locally: true,
            method: self.method,
            authorized_at_epoch_ms: self.authorized_at_ms,
            device_model: self.wire.model().to_owned(),
            token_handoff_complete: !self.access_token.is_empty() && !self.refresh_token.is_empty(),
            bootstrap_complete: false,
            native_sync_verified: false,
        }
    }
}
#[derive(Deserialize)]
struct Handoff {
    schema_version: u32,
    attempt_id: String,
    authorized_at_epoch_ms: i64,
    method: Option<String>,
    response: Option<PasswordResponse>,
    user_id: Option<String>,
    country_iso: Option<String>,
    account_id: Option<String>,
    access_token: Option<String>,
    refresh_token: Option<String>,
    token_type: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PasswordResponse {
    user_id: i64,
    country_iso: String,
    account_id: Option<i64>,
    #[serde(rename = "access_token")]
    access_token: String,
    #[serde(rename = "refresh_token")]
    refresh_token: String,
    #[serde(rename = "token_type")]
    token_type: String,
}
fn invalid() -> Error {
    Error::Storage(
        "authorization handoff invalid; restore saved session, do not reauthenticate".into(),
    )
}
fn valid_secret(value: &str) -> bool {
    !value.is_empty() && value.len() <= 16384 && !value.chars().any(char::is_control)
}
impl Store {
    pub fn session_load(&self) -> Result<Session> {
        let status = self.auth_status()?;
        if status.recovery_required || !status.handoff_present {
            return Err(invalid());
        }
        let (attempt_id,hash): (String,String) = self.lock()?.query_row(
            "SELECT attempt_id,handoff_hash FROM qr_auth_attempt WHERE id=1 AND state='authorized'",
            [],|r|Ok((r.get(0)?,r.get(1)?))).optional()?.ok_or_else(invalid)?;
        let path = self.data_dir.join("qr-handoff.json");
        let meta = fs::symlink_metadata(&path).map_err(|_| invalid())?;
        if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > LIMIT {
            return Err(invalid());
        }
        #[cfg(unix)]
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(invalid());
        }
        let file = File::open(&path).map_err(|_| invalid())?;
        let meta = file.metadata().map_err(|_| invalid())?;
        if !meta.is_file() || meta.len() > LIMIT {
            return Err(invalid());
        }
        #[cfg(unix)]
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(invalid());
        }
        let mut bytes = Zeroizing::new(Vec::new());
        file.take(LIMIT + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| invalid())?;
        if bytes.len() as u64 > LIMIT {
            return Err(invalid());
        }
        let actual = hex::encode(Sha256::digest(&bytes));
        if !bool::from(actual.as_bytes().ct_eq(hash.as_bytes())) {
            return Err(invalid());
        }
        let mut saved: Handoff = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        if saved.attempt_id != attempt_id || saved.authorized_at_epoch_ms <= 0 {
            return Err(invalid());
        }
        let method;
        let body = match saved.schema_version {
            2 if saved.method.as_deref() == Some("password") => {
                method = "password";
                saved.response.take().ok_or_else(invalid)?
            }
            1 if saved.method.is_none() => {
                method = "qr";
                PasswordResponse {
                    user_id: saved
                        .user_id
                        .take()
                        .ok_or_else(invalid)?
                        .parse()
                        .map_err(|_| invalid())?,
                    country_iso: saved.country_iso.take().ok_or_else(invalid)?,
                    account_id: saved
                        .account_id
                        .take()
                        .map(|v| v.parse())
                        .transpose()
                        .map_err(|_| invalid())?,
                    access_token: saved.access_token.take().ok_or_else(invalid)?,
                    refresh_token: saved.refresh_token.take().ok_or_else(invalid)?,
                    token_type: saved.token_type.take().ok_or_else(invalid)?,
                }
            }
            _ => return Err(invalid()),
        };
        let access_token = Zeroizing::new(body.access_token);
        let refresh_token = Zeroizing::new(body.refresh_token);
        if body.user_id <= 0
            || body.account_id.is_some_and(|v| v <= 0)
            || body.country_iso.len() != 2
            || !body.country_iso.bytes().all(|b| b.is_ascii_uppercase())
            || !valid_secret(&access_token)
            || !valid_secret(&refresh_token)
            || !body.token_type.eq_ignore_ascii_case("bearer")
        {
            return Err(invalid());
        }
        let mut session = Session {
            wire: self.qr_wire_show()?,
            user_id: body.user_id,
            account_id: body.account_id,
            country_iso: body.country_iso,
            access_token,
            refresh_token,
            token_type: body.token_type,
            authorized_at_ms: saved.authorized_at_epoch_ms,
            method,
        };
        self.load_active_tokens(&mut session, &attempt_id)?;
        Ok(session)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    fn setup() -> (tempfile::TempDir, Store) {
        let dir = tempfile::Builder::new()
            .prefix("kakao-session-")
            .permissions(
                <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
            )
            .tempdir()
            .unwrap();
        let store = Store::initialize(dir.path()).unwrap();
        let catalog = serde_json::from_str(include_str!("../config/device-catalog.json")).unwrap();
        store
            .device_initialize(
                &catalog,
                chrono::NaiveDate::from_ymd_opt(2026, 11, 13).unwrap(),
            )
            .unwrap();
        store.qr_wire_initialize(1700000000000).unwrap();
        (dir, store)
    }
    fn fixture(store: &Store, schema: u32) {
        let data = if schema == 2 {
            serde_json::json!({"schema_version":2,"method":"password","attempt_id":"fixture","authorized_at_epoch_ms":1700000000000_i64,"response":{"userId":42,"accountId":51,"countryIso":"KR","token_type":"bearer","access_token":"synthetic-sensitive-access","refresh_token":"synthetic-sensitive-refresh"}})
        } else {
            serde_json::json!({"schema_version":1,"attempt_id":"fixture","authorized_at_epoch_ms":1700000000000_i64,"user_id":"42","account_id":"51","country_iso":"KR","token_type":"bearer","access_token":"synthetic-sensitive-access","refresh_token":"synthetic-sensitive-refresh"})
        };
        let bytes = serde_json::to_vec(&data).unwrap();
        let path = store.data_dir.join("qr-handoff.json");
        let mut f = File::create(path).unwrap();
        #[cfg(unix)]
        f.set_permissions(fs::Permissions::from_mode(0o600))
            .unwrap();
        f.write_all(&bytes).unwrap();
        store.lock().unwrap().execute("INSERT INTO qr_auth_attempt(id,attempt_id,state,started_at_ms,handoff_hash) VALUES(1,'fixture','authorized',1700000000000,?1)",[hex::encode(Sha256::digest(&bytes))]).unwrap();
        store
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO metadata(key,value) VALUES('auth_method',?1)",
                [if schema == 2 { "password" } else { "qr" }],
            )
            .unwrap();
    }
    #[test]
    fn both_handoffs_load_same_identity_without_claiming_sync_or_disclosing_secrets() {
        for schema in [1, 2] {
            let (_dir, store) = setup();
            fixture(&store, schema);
            let identity = store.qr_wire_show().unwrap();
            let session = store.session_load().unwrap();
            assert_eq!(session.user_id(), 42);
            assert_eq!(session.account_id(), Some(51));
            assert_eq!(session.country_iso(), "KR");
            assert_eq!(session.token_type(), "bearer");
            assert_eq!(session.wire, identity);
            let status = serde_json::to_string(&session.status()).unwrap();
            assert!(!status.contains("sensitive"));
            assert!(!status.contains(identity.uuid()));
            assert!(!session.status().bootstrap_complete);
            assert!(!session.status().native_sync_verified);
            assert_eq!(store.qr_wire_show().unwrap(), identity);
        }
    }
    #[test]
    fn damaged_handoff_and_missing_wire_never_reauthenticate() {
        let (dir, store) = setup();
        fixture(&store, 2);
        let identity = store.qr_wire_show().unwrap();
        let path = dir.path().join("qr-handoff.json");
        let bytes = fs::read(&path).unwrap();
        fs::write(&path, b"synthetic-sensitive-corrupt").unwrap();
        let err = store.session_load().err().unwrap();
        assert!(!format!("{err}").contains("synthetic-sensitive"));
        assert_eq!(store.qr_wire_show().unwrap(), identity);
        fs::write(&path, bytes).unwrap();
        store
            .lock()
            .unwrap()
            .execute("DELETE FROM qr_wire_profile", [])
            .unwrap();
        assert!(store.session_load().is_err());
        assert!(store.qr_wire_initialize(1800000000000).is_err());
    }
}
