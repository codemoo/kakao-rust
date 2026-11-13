//! One supplied MyPIN candidate; no retry after counted rejection or ambiguous
//! delivery. Gateway-401 token refresh/replay remains applicable.
//! PIN is never persisted.
use crate::{
    drawer::crypto::Pin,
    drawer_restore::RestoreStatus,
    native_http::{Client, Operation},
    runtime::{RuntimeLease, StepState},
    Error, Result, Store,
};
use serde::Deserialize;
use zeroize::Zeroizing;
fn invalid() -> Error {
    Error::Invalid("invalid Drawer key authentication response".into())
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncryptedKey {
    status: i64,
    pin_encrypted_private_key: Option<String>,
    pin_hmac: Option<String>,
}
#[derive(Deserialize)]
struct Salt {
    status: i64,
    salt: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Verify {
    status: i64,
    password: Option<String>,
    iv: Option<String>,
    me_session: Option<String>,
    fail_count: Option<i64>,
    total_count: Option<i64>,
}
fn required(value: Option<String>) -> Result<Zeroizing<String>> {
    value
        .filter(|s| !s.is_empty())
        .map(Zeroizing::new)
        .ok_or_else(invalid)
}
/// `read_pin` must be hidden TTY or an explicitly selected private stdin pipe.
pub async fn unlock(
    store: &Store,
    read_pin: impl FnOnce() -> Result<Zeroizing<String>>,
) -> Result<RestoreStatus> {
    let _selected = store.select_drawer_restore()?;
    let lease = std::sync::Arc::new(RuntimeLease::acquire(store)?);
    let status = store.drawer_restore_status()?.ok_or_else(invalid)?;
    if status.key_available {
        let _key = store.drawer_load_key()?;
        return Ok(status);
    }
    if !matches!(
        status.phase.as_str(),
        "mypin_auth_required" | "mypin_rejected"
    ) {
        return Err(Error::Conflict(
            "MyPIN restoration route must be selected and verified first".into(),
        ));
    }
    if store.runtime_status()?.steps.iter().any(|s| {
        s.name == "drawer_pin_verify"
            && matches!(s.state, StepState::Started | StepState::Completed)
    }) || store.data_dir.join("drawer-private-key.der").exists()
    {
        return Err(Error::Conflict(
            "prior key verification outcome needs recovery; no automatic retry".into(),
        ));
    }
    let mut session = store.session_load()?;
    let client = Client::new()?;
    let mut listener = crate::pilsner::Listener::new(store.clone(), lease);
    listener.ensure().await?;
    let response = client
        .execute(store, &mut session, Operation::DrawerPinKey)
        .await?;
    let key: EncryptedKey = serde_json::from_slice(&response.body).map_err(|_| invalid())?;
    if !(200..300).contains(&response.http_status) || key.status != 0 {
        return Err(invalid());
    }
    let encrypted = required(key.pin_encrypted_private_key)?;
    let hmac = required(key.pin_hmac)?;
    let pin = Pin::new(read_pin()?)?;
    listener.ensure().await?;
    let response = client
        .execute(store, &mut session, Operation::DrawerPinSalt)
        .await?;
    let salt: Salt = serde_json::from_slice(&response.body).map_err(|_| invalid())?;
    if !(200..300).contains(&response.http_status) || salt.status != 0 {
        return Err(invalid());
    }
    let salt = required(salt.salt)?;
    let hashed = pin.hashed(&salt)?;
    store.native_step("drawer_pin_verify", StepState::Started, None, None)?;
    let response = client
        .execute(
            store,
            &mut session,
            Operation::DrawerPinVerify {
                hashed_pin: &hashed,
            },
        )
        .await?;
    let verified: Verify = serde_json::from_slice(&response.body).map_err(|_| invalid())?;
    if !(200..300).contains(&response.http_status) || verified.status != 0 {
        store.native_step(
            "drawer_pin_verify",
            StepState::Failed,
            Some(response.http_status),
            Some(verified.status),
        )?;
        let locked = verified.status == 402
            || verified
                .fail_count
                .zip(verified.total_count)
                .is_some_and(|(failed, total)| total > 0 && failed >= total);
        store.drawer_restore_phase(if locked {
            "mypin_locked"
        } else {
            "mypin_rejected"
        })?;
        listener.close().await?;
        return Err(Error::Invalid(format!(
            "My password verification rejected (status {}); no retry performed",
            verified.status
        )));
    }
    store.native_step(
        "drawer_pin_verify",
        StepState::Completed,
        Some(response.http_status),
        Some(0),
    )?;
    let _me_session = required(verified.me_session)?;
    let password = required(verified.password)?;
    let iv = required(verified.iv)?;
    let key = pin.recover(&salt, &password, &iv, &encrypted, &hmac)?;
    store.drawer_restore_phase("key_handoff_pending")?;
    store.drawer_save_key(&key)?;
    listener.close().await?;
    store.drawer_restore_status()?.ok_or_else(invalid)
}
