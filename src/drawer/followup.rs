//! Official post-download stages. Never infer overall completion from log EOF.
use crate::{
    drawer::history,
    drawer_restore::RestoreStatus,
    native_http::{Client, Operation},
    runtime::{RuntimeLease, StepState},
    session::Session,
    Error, Result, Store,
};
use serde::Deserialize;
#[derive(Deserialize)]
struct Usage {
    count: i64,
    size: i64,
}
fn usage(body: &[u8]) -> Result<Usage> {
    let value: Usage = serde_json::from_slice(body)
        .map_err(|_| Error::Invalid("invalid recording usage response".into()))?;
    if value.count < 0 || value.size < 0 {
        return Err(Error::Invalid("negative recording usage".into()));
    }
    Ok(value)
}
async fn once(
    store: &Store,
    client: &Client,
    session: &mut Session,
    name: &str,
    operation: Operation<'_>,
) -> Result<()> {
    if store.native_completed(name)? {
        return Ok(());
    }
    if store.runtime_status()?.steps.iter().any(|s| s.name == name) {
        return Err(Error::Conflict(
            "restoration mutation already attempted; reconcile before retry".into(),
        ));
    }
    store.native_step(name, StepState::Started, None, None)?;
    let response = client.execute(store, session, operation).await?;
    let success = (200..300).contains(&response.http_status);
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
    if !success {
        return Err(Error::Invalid("recording restore request rejected".into()));
    }
    Ok(())
}
pub async fn run(store: &Store) -> Result<RestoreStatus> {
    store.select_drawer_restore()?;
    let lease = std::sync::Arc::new(RuntimeLease::acquire(store)?);
    let _key = store.drawer_load_key()?;
    let mut session = store.session_load()?;
    let user = session.user_id();
    let mut state = store.drawer_progress(user)?;
    if !state.progress.logs_done {
        return Err(Error::Conflict(
            "history download must finish before restoration followup".into(),
        ));
    }
    if state.progress.restore_completed {
        return Ok(state.status);
    }
    let mut listener = crate::pilsner::Listener::new(store.clone(), lease);
    let client = Client::new()?;
    listener.ensure().await?;
    if !state.progress.recording_done {
        once(
            store,
            &client,
            &mut session,
            "drawer_recording_start",
            Operation::DrawerRecordingStart,
        )
        .await?;
        if state.progress.recording_count.is_none() {
            listener.ensure().await?;
            let response = client
                .execute(store, &mut session, Operation::DrawerRecordingUsage)
                .await?;
            if !(200..300).contains(&response.http_status)
                || response.server_status.is_some_and(|s| s != 0)
            {
                return Err(Error::Invalid("recording usage rejected".into()));
            }
            let count = usage(&response.body)?.count;
            store.capture_native("bootstrap_http", &response.body)?;
            let mut conn = store.lock()?;
            let tx = conn.transaction()?;
            state = history::load(&tx, user)?;
            state.progress.recording_count = Some(count);
            state.status.phase = if count == 0 {
                "recording_completion_pending"
            } else {
                "recording_metadata_required"
            }
            .into();
            history::save(&tx, &state)?;
            tx.commit()?;
        }
        if state.progress.recording_count == Some(0) {
            listener.ensure().await?;
            once(
                store,
                &client,
                &mut session,
                "drawer_recording_complete",
                Operation::DrawerRecordingComplete,
            )
            .await?;
            let mut conn = store.lock()?;
            let tx = conn.transaction()?;
            state = history::load(&tx, user)?;
            state.progress.recording_done = true;
            state.status.phase = "room_metadata_pending".into();
            history::save(&tx, &state)?;
            tx.commit()?;
        }
    }
    if !state.progress.recording_done {
        listener.close().await?;
        return Ok(state.status);
    }
    store.drawer_prepare_rooms(user)?;
    for _ in 0..10000 {
        let Some(request) = store.drawer_next_meta(user)? else {
            break;
        };
        listener.ensure().await?;
        let response = client
            .execute(
                store,
                &mut session,
                Operation::DrawerLogMeta {
                    chat_id: request.chat,
                    from: request.from,
                    to: request.to,
                },
            )
            .await?;
        if !(200..300).contains(&response.http_status)
            || response.server_status.is_some_and(|s| s != 0)
        {
            return Err(Error::Invalid(
                "restored message metadata request rejected".into(),
            ));
        }
        store.drawer_apply_meta(user, &request, &response.body)?;
    }
    store.drawer_mark_meta_done(user)?;
    listener.ensure().await?;
    once(
        store,
        &client,
        &mut session,
        "drawer_restore_completed",
        Operation::DrawerRestoreCompleted,
    )
    .await?;
    {
        let mut conn = store.lock()?;
        let tx = conn.transaction()?;
        state = history::load(&tx, user)?;
        if !state.progress.logs_done || !state.progress.recording_done || !state.progress.meta_done
        {
            return Err(Error::Conflict(
                "restoration completion prerequisites missing".into(),
            ));
        }
        state.progress.restore_completed = true;
        state.status.phase = "restored".into();
        history::save(&tx, &state)?;
        tx.commit()?;
    }
    listener.close().await?;
    Ok(state.status)
}
#[cfg(test)]
mod tests {
    #[test]
    fn usage_is_typed_and_does_not_treat_missing_count_as_empty() {
        assert_eq!(super::usage(br#"{"count":0,"size":0}"#).unwrap().count, 0);
        assert!(super::usage(br#"{"size":0}"#).is_err());
        assert!(super::usage(br#"{"count":"0","size":0}"#).is_err());
        assert!(super::usage(br#"{"count":-1,"size":0}"#).is_err());
        assert_eq!(
            super::usage(br#"{"count":2,"size":4000}"#).unwrap().count,
            2
        );
    }
}
