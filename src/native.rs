//! Ordered post-authentication initialization.
use crate::{
    native_http::{Client, Operation},
    runtime::{RuntimeLease, StepState},
    Error, Result, Store,
};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Notice {
    pub step: &'static str,
    pub http_status: Option<u16>,
    pub server_status: Option<i64>,
    pub flag: Option<bool>,
}

/// Preserve the live listen stream while exercising the proven post-auth reads.
/// Stops at a branch whose implementation is not yet verified, never skips to online.
pub async fn bootstrap_observe(
    store: &Store,
    seconds: u16,
    mut notice: impl FnMut(Notice),
) -> Result<()> {
    let lease = std::sync::Arc::new(RuntimeLease::acquire(store)?);
    let mut session = store.session_load()?;
    let client = Client::new()?;
    let mut listener = crate::pilsner::Listener::new(store.clone(), lease.clone());
    let ready = listener.ensure().await?;
    notice(Notice {
        step: "listen_started",
        http_status: None,
        server_status: None,
        flag: ready,
    });
    for (name, operation, key) in [
        (
            "wallet_status",
            Operation::WalletStatus {
                has_certificate: false,
            },
            "isRegistered",
        ),
        ("drawer_user_info", Operation::DrawerUserInfo, "activated"),
    ] {
        if store.native_completed(name)? && store.native_flag(key)?.is_some() {
            continue;
        }
        store.lock()?.execute(
            "DELETE FROM metadata WHERE key=?1",
            [format!("native_flag:{key}")],
        )?;
        store.native_step(name, StepState::Started, None, None)?;
        listener.ensure().await?;
        match client.execute(store, &mut session, operation).await {
            Ok(response) => {
                store.capture_native("bootstrap_http", &response.body)?;
                let value: serde_json::Value = serde_json::from_slice(&response.body)
                    .map_err(|_| Error::Invalid("bootstrap JSON invalid".into()))?;
                let flag = if name == "wallet_status" {
                    value
                        .get("detailedCertStatus")
                        .and_then(|v| v.as_str())
                        .map(|s| !s.is_empty() && s != "NONE")
                } else {
                    value.get(key).and_then(|v| v.as_bool())
                };
                let success = (200..300).contains(&response.http_status)
                    && response.server_status.is_none_or(|s| s == 0)
                    && flag.is_some();
                store.native_step(
                    name,
                    if success {
                        StepState::Completed
                    } else {
                        StepState::Failed
                    },
                    Some(response.http_status),
                    response.server_status,
                )?;
                // Only the branch discriminator is retained here; no user payload logs.
                if let Some(flag) = flag.filter(|_| success) {
                    store.lock()?.execute("INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",rusqlite::params![format!("native_flag:{key}"),flag.to_string()])?;
                }
                notice(Notice {
                    step: name,
                    http_status: Some(response.http_status),
                    server_status: response.server_status,
                    flag,
                });
            }
            Err(_) => {
                store.native_step(name, StepState::Failed, None, None)?;
                notice(Notice {
                    step: name,
                    http_status: None,
                    server_status: None,
                    flag: None,
                });
                // These recoverable failures allow initialization to continue.
            }
        }
    }
    if store.native_flag("activated")? == Some(true) {
        for (name, operation) in [
            (
                "drawer_chat_backup_completed",
                Operation::DrawerChatBackupCompleted,
            ),
            (
                "drawer_media_backup_completed",
                Operation::DrawerMediaBackupCompleted,
            ),
            ("drawer_backup_info", Operation::DrawerBackupInfo),
            ("drawer_contact_snapshot", Operation::DrawerContactSnapshot),
        ] {
            if store.native_completed(name)? {
                continue;
            }
            store.native_step(name, StepState::Started, None, None)?;
            listener.ensure().await?;
            match client.execute(store, &mut session, operation).await {
                Ok(response) => {
                    store.capture_native("bootstrap_http", &response.body)?;
                    let value: serde_json::Value = serde_json::from_slice(&response.body)
                        .map_err(|_| Error::Invalid("drawer bootstrap JSON invalid".into()))?;
                    let flag = value.get("completed").and_then(|v| v.as_bool());
                    let success = (200..300).contains(&response.http_status)
                        && response.server_status.is_none_or(|s| s == 0)
                        && (!matches!(
                            operation,
                            Operation::DrawerChatBackupCompleted
                                | Operation::DrawerMediaBackupCompleted
                        ) || flag.is_some());
                    store.native_step(
                        name,
                        if success {
                            StepState::Completed
                        } else {
                            StepState::Failed
                        },
                        Some(response.http_status),
                        response.server_status,
                    )?;
                    notice(Notice {
                        step: name,
                        http_status: Some(response.http_status),
                        server_status: response.server_status,
                        flag,
                    });
                    if !success {
                        break;
                    }
                }
                Err(_) => {
                    store.native_step(name, StepState::Failed, None, None)?;
                    notice(Notice {
                        step: name,
                        http_status: None,
                        server_status: None,
                        flag: None,
                    });
                    break;
                }
            }
        }
    }
    notice(Notice {
        step: if store.drawer_restore_status()?.is_some() {
            "restoration_selected"
        } else {
            "restoration_choice_pending"
        },
        http_status: None,
        server_status: None,
        flag: None,
    });
    listener.observe(seconds).await?;
    drop(lease);
    Ok(())
}

/// Explicit CLI choice corresponding to the drawer UI's skip confirmation.
/// This POST is not called by bootstrap_observe or by an implicit default.
pub async fn skip_drawer_restore(store: &Store) -> Result<()> {
    let lease = std::sync::Arc::new(RuntimeLease::acquire(store)?);
    if store.drawer_restore_status()?.is_some() {
        return Err(Error::Conflict(
            "existing conversation restoration selected; skip refused".into(),
        ));
    }
    if store.native_completed("drawer_restore_completed")? {
        return Ok(());
    }
    if store.native_flag("activated")? != Some(true)
        || !store.native_completed("drawer_contact_snapshot")?
    {
        return Err(Error::Conflict(
            "drawer restoration preflight must complete first".into(),
        ));
    }
    // A dispatched attempt without a receipt is ambiguous: do not replay a write
    // simply because the process restarted or the response was lost.
    if store
        .runtime_status()?
        .steps
        .iter()
        .any(|step| step.name == "drawer_restore_completed")
    {
        return Err(Error::Conflict(
            "restore completion already attempted; reconcile server state before retry".into(),
        ));
    }
    let mut session = store.session_load()?;
    let client = Client::new()?;
    let mut listener = crate::pilsner::Listener::new(store.clone(), lease);
    listener.ensure().await?;
    store.native_step("drawer_restore_completed", StepState::Started, None, None)?;
    let response = client
        .execute(store, &mut session, Operation::DrawerRestoreCompleted)
        .await?;
    let success =
        (200..300).contains(&response.http_status) && response.server_status.is_none_or(|s| s == 0);
    store.native_step(
        "drawer_restore_completed",
        if success {
            StepState::Completed
        } else {
            StepState::Failed
        },
        Some(response.http_status),
        response.server_status,
    )?;
    if !success {
        return Err(Error::Invalid("drawer restore completion rejected".into()));
    }
    listener.close().await?;
    Ok(())
}
