//! Long-lived GET /listen with BE32 lengths and protobuf events.
//! Capturing an event is not the same as applying its app-specific handler.
use crate::{Error, Result, Store};
use prost::Message;
use rusqlite::OptionalExtension;
use zeroize::Zeroizing;

const LIMIT: usize = 1024 * 1024;
#[derive(Clone, PartialEq, Message)]
pub struct Event {
    #[prost(string, tag = "1")]
    pub path: String,
    #[prost(string, tag = "2")]
    pub r#type: String,
    #[prost(bytes = "vec", tag = "3")]
    pub payload: Vec<u8>,
    // Padding is unused. Leave field4 unknown: live servers also send it as
    // a varint. Unknown protobuf fields must not reject the event.
}
#[derive(Default)]
pub struct Decoder {
    buffer: Zeroizing<Vec<u8>>,
}
impl Decoder {
    pub fn feed_each(
        &mut self,
        bytes: &[u8],
        mut complete: impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        // Append incrementally: arbitrary HTTP chunk boundaries never imply events.
        for byte in bytes {
            if self.buffer.len() >= LIMIT + 4 {
                return Err(Error::Invalid("pilsner frame too large".into()));
            }
            self.buffer.push(*byte);
            if self.buffer.len() >= 4 {
                let n = i32::from_be_bytes(self.buffer[..4].try_into().unwrap());
                if n < 0 || n as usize > LIMIT {
                    return Err(Error::Invalid("invalid pilsner frame length".into()));
                }
                if self.buffer.len() == n as usize + 4 {
                    let frame = self.buffer[4..].to_vec();
                    Event::decode(frame.as_slice())
                        .map_err(|_| Error::Invalid("invalid pilsner event".into()))?;
                    complete(&frame)?;
                    self.buffer.clear();
                }
            }
        }
        Ok(())
    }
    #[cfg(test)]
    fn feed(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
        let mut frames = Vec::new();
        self.feed_each(bytes, |frame| {
            frames.push(frame.to_vec());
            Ok(())
        })?;
        Ok(frames)
    }
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}
impl Store {
    pub(crate) fn booking_revision(&self, account: &str, revision: i32) -> Result<()> {
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        let requested: i32 = tx
            .query_row(
                "SELECT CAST(value AS INTEGER) FROM metadata WHERE key=?1",
                [format!("booking_requested_revision:{account}")],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(0);
        for (key, value) in [
            (
                format!("booking_observed_revision:{account}"),
                revision.to_string(),
            ),
            (
                format!("booking_required:{account}"),
                (revision < requested).to_string(),
            ),
        ] {
            tx.execute("INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",rusqlite::params![key,value])?;
        }
        tx.commit()?;
        Ok(())
    }

    fn capture_pilsner(&self, account: &str, raw: &[u8]) -> Result<i64> {
        let event =
            Event::decode(raw).map_err(|_| Error::Invalid("invalid pilsner event".into()))?;
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO native_events(source,received_at_ms,payload) VALUES('pilsner',?1,?2)",
            rusqlite::params![chrono::Utc::now().timestamp_millis(), raw],
        )?;
        let sequence = tx.last_insert_rowid();
        tx.execute(
            "INSERT INTO pilsner_accounts VALUES(?1,?2)",
            rusqlite::params![sequence, account],
        )?;
        Self::apply_pilsner(&tx, account, sequence, &event)?;
        tx.commit()?;
        Ok(sequence)
    }
    fn apply_pilsner(
        tx: &rusqlite::Transaction<'_>,
        account: &str,
        sequence: i64,
        event: &Event,
    ) -> Result<()> {
        let value = serde_json::from_slice::<serde_json::Value>(&event.payload).ok();
        let mut handled = false;
        let checkpoint = format!("pilsner_applied_sequence:{account}:{}", event.path);
        let previous: i64 = tx
            .query_row(
                "SELECT CAST(value AS INTEGER) FROM metadata WHERE key=?1",
                [&checkpoint],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(0);
        if let Some(value) = value.filter(|v| v.is_object()) {
            match event.path.as_str() {
                "chat/SettingsUpdated" => {
                    if let Some(revision) = value
                        .get("linkifyRevision")
                        .and_then(|v| v.as_i64())
                        .filter(|v| *v >= 0)
                    {
                        tx.execute("INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=CAST(max(CAST(value AS INTEGER),CAST(excluded.value AS INTEGER)) AS TEXT)",rusqlite::params![format!("text_config_requested:{account}"),revision.to_string()])?;
                        tx.execute("INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=CAST(max(CAST(value AS INTEGER),CAST(excluded.value AS INTEGER)) AS TEXT)",rusqlite::params![format!("refresh_request:{account}:text_config"),sequence.to_string()])?;
                    }
                    // Other settings fields remain pending for their own handlers.
                }
                "messaging/Settings" => {
                    if let Some(revision) = value
                        .get("locoConfRevision")
                        .and_then(|v| v.as_i64())
                        .and_then(|v| i32::try_from(v).ok())
                    {
                        if previous < sequence {
                            tx.execute("INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",rusqlite::params![format!("booking_requested_revision:{account}"),revision.to_string()])?;
                            let observed: i32 = tx
                                .query_row(
                                    "SELECT CAST(value AS INTEGER) FROM metadata WHERE key=?1",
                                    [format!("booking_observed_revision:{account}")],
                                    |r| r.get(0),
                                )
                                .optional()?
                                .unwrap_or(0);
                            tx.execute("INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",rusqlite::params![format!("booking_required:{account}"),(observed<revision).to_string()])?;
                        }
                        handled = true;
                    }
                }
                "talk/UpdateLessSettings" => {
                    tx.execute("INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=CAST(max(CAST(value AS INTEGER),CAST(excluded.value AS INTEGER)) AS TEXT)",rusqlite::params![format!("refresh_request:{account}:less_settings"),sequence.to_string()])?;
                    handled = true;
                }
                "talk/FriendFavoritesUpdated" => match value.get("friendUserId") {
                    None | Some(serde_json::Value::Null) => handled = true,
                    Some(v) => {
                        if let Some(id) = v.as_i64().filter(|id| *id > 0) {
                            tx.execute("INSERT INTO friend_refresh(account_id,user_id,requested_sequence) VALUES(?1,?2,?3) ON CONFLICT(account_id,user_id) DO UPDATE SET requested_sequence=max(requested_sequence,excluded.requested_sequence)",rusqlite::params![account,id,sequence])?;
                            handled = true;
                        }
                    }
                },
                _ => (),
            }
        }
        if handled {
            tx.execute("INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=CAST(max(CAST(value AS INTEGER),CAST(excluded.value AS INTEGER)) AS TEXT)",rusqlite::params![checkpoint,sequence.to_string()])?;
            tx.execute(
                "UPDATE native_events SET processed=1 WHERE sequence=?1",
                [sequence],
            )?;
        }
        Ok(())
    }
    pub(crate) fn replay_pilsner(&self, account: &str) -> Result<()> {
        let mut after = 0_i64;
        loop {
            let rows = {
                let conn = self.lock()?;
                let mut stmt = conn.prepare("SELECT n.sequence,n.payload FROM native_events n JOIN pilsner_accounts a USING(sequence) WHERE a.account_id=?1 AND n.source='pilsner' AND n.processed=0 AND n.sequence>?2 ORDER BY n.sequence LIMIT 32")?;
                let rows = stmt
                    .query_map(rusqlite::params![account, after], |r| {
                        Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?))
                    })?
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                rows
            };
            if rows.is_empty() {
                return Ok(());
            }
            for (seq, raw) in rows {
                after = seq;
                let Ok(event) = Event::decode(raw.as_slice()) else {
                    continue;
                };
                let mut conn = self.lock()?;
                let tx = conn.transaction()?;
                Self::apply_pilsner(&tx, account, seq, &event)?;
                tx.commit()?;
            }
        }
    }
    pub(crate) fn capture_native(&self, source: &str, payload: &[u8]) -> Result<i64> {
        if !matches!(
            source,
            "pilsner"
                | "loco"
                | "pilsner_invalid"
                | "bootstrap_http"
                | "more_settings"
                | "less_settings"
                | "text_settings"
        ) || payload.len() > 8 * 1024 * 1024
        {
            return Err(Error::Invalid("invalid native capture".into()));
        }
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO native_events(source,received_at_ms,payload) VALUES(?1,?2,?3)",
            rusqlite::params![source, chrono::Utc::now().timestamp_millis(), payload],
        )?;
        Ok(conn.last_insert_rowid())
    }
}
pub async fn capture_stream(store: Store, mut response: reqwest::Response) -> Result<u64> {
    let account = store.session_load()?.user_id().to_string();
    let mut decoder = Decoder::default();
    let mut count = 0;
    let client = crate::native_http::Client::new()?;
    let mut ping_at = None;
    loop {
        // Keep the same read future alive across a ping, including partial reads.
        let read = response.chunk();
        tokio::pin!(read);
        let chunk = loop {
            tokio::select! {
                chunk = &mut read => break chunk.map_err(|_| Error::Invalid("pilsner stream interrupted".into()))?,
                _ = async {
                    match ping_at {
                        Some(at) => tokio::time::sleep_until(at).await,
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    ping_at = None;
                    let mut session = store.session_load()?;
                    let ok = client.pilsner_ping(&store, &mut session).await.is_ok();
                    store.native_step("pilsner_ping", if ok { crate::runtime::StepState::Completed } else { crate::runtime::StepState::Failed }, None, None)?;
                    // App does not reschedule on ping completion or failure;
                    // the next parsed event arms another ten-minute alarm.
                }
            }
        };
        let Some(chunk) = chunk else { break };
        if let Err(error) = decoder.feed_each(&chunk, |frame| {
            store.capture_pilsner(&account, frame)?;
            count += 1;
            ping_at = Some(tokio::time::Instant::now() + std::time::Duration::from_secs(600));
            Ok(())
        }) {
            store.capture_native("pilsner_invalid", &decoder.buffer)?;
            return Err(error);
        }
    }
    if !decoder.is_empty() {
        store.capture_native("pilsner_invalid", &decoder.buffer)?;
        return Err(Error::Invalid("pilsner truncated event".into()));
    }
    Ok(count)
}

/// Implements the Pilsner request gate: IDLE may restart on the next ordinary
/// request, while normal EOF reconnects within the reader task itself.
pub struct Listener {
    store: Store,
    lease: std::sync::Arc<crate::runtime::RuntimeLease>,
    task: Option<tokio::task::JoinHandle<Result<()>>>,
    last_subscribed: std::sync::Arc<std::sync::atomic::AtomicI64>,
}
impl Listener {
    pub fn new(store: Store, lease: std::sync::Arc<crate::runtime::RuntimeLease>) -> Self {
        Self {
            store,
            lease,
            task: None,
            last_subscribed: std::sync::Arc::new(std::sync::atomic::AtomicI64::new(0)),
        }
    }
    pub async fn ensure(&mut self) -> Result<Option<bool>> {
        if self.task.as_ref().is_some_and(|task| !task.is_finished()) {
            return Ok(Some(true));
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
            self.store.native_step(
                "pilsner_listen",
                crate::runtime::StepState::Failed,
                None,
                None,
            )?;
        }
        let store = self.store.clone();
        let lease = self.lease.clone();
        let last = self.last_subscribed.clone();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        self.store.native_step(
            "pilsner_listen",
            crate::runtime::StepState::Started,
            None,
            None,
        )?;
        self.task = Some(tokio::spawn(async move {
            let _lease = lease;
            let client = crate::native_http::Client::new()?;
            let mut ready = Some(ready_tx);
            loop {
                let session = store.session_load()?;
                match client
                    .open_listen(&session, last.load(std::sync::atomic::Ordering::Relaxed))
                    .await
                {
                    Ok(response) => {
                        last.store(
                            chrono::Utc::now().timestamp(),
                            std::sync::atomic::Ordering::Relaxed,
                        );
                        if let Some(tx) = ready.take() {
                            let _ = tx.send(true);
                        }
                        capture_stream(store.clone(), response).await?;
                    }
                    Err(error) => {
                        if let Some(tx) = ready.take() {
                            let _ = tx.send(false);
                        }
                        return Err(error);
                    }
                }
            }
        }));
        Ok(
            tokio::time::timeout(std::time::Duration::from_millis(1000), ready_rx)
                .await
                .ok()
                .and_then(|value| value.ok()),
        )
    }
    pub async fn observe(&mut self, seconds: u16) -> Result<()> {
        if let Some(task) = self.task.as_mut() {
            tokio::select! {
                result=task=> {
                    self.task=None;
                    self.store.native_step("pilsner_listen",crate::runtime::StepState::Failed,None,None)?;
                    return result.map_err(|_|Error::Worker)?;
                }
                _=tokio::time::sleep(std::time::Duration::from_secs(seconds.into()))=>(),
                _=tokio::signal::ctrl_c()=>(),
            }
        }
        self.close().await
    }
    pub async fn close(&mut self) -> Result<()> {
        if let Some(mut task) = self.task.take() {
            task.abort();
            match (&mut task).await {
                Ok(result) => result?,
                Err(error) if error.is_cancelled() => (),
                Err(_) => return Err(Error::Worker),
            }
            self.store.native_step(
                "pilsner_listen",
                crate::runtime::StepState::Completed,
                None,
                None,
            )?;
        }
        Ok(())
    }
}
impl Drop for Listener {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
        // Task holds its own lease Arc until cancellation drops the socket.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replay_is_account_bound_and_preserves_independent_friend_refreshes() {
        let (_dir, store) = crate::runtime::tests::setup();
        let pending = |account: Option<&str>, path: &str, payload: &[u8]| {
            let event = Event {
                path: path.into(),
                r#type: String::new(),
                payload: payload.to_vec(),
            };
            let seq = store
                .capture_native("pilsner", &event.encode_to_vec())
                .unwrap();
            if let Some(account) = account {
                store
                    .lock()
                    .unwrap()
                    .execute(
                        "INSERT INTO pilsner_accounts VALUES(?1,?2)",
                        rusqlite::params![seq, account],
                    )
                    .unwrap();
            }
            seq
        };
        let first = pending(
            Some("42"),
            "talk/FriendFavoritesUpdated",
            br#"{"friendUserId":43}"#,
        );
        pending(Some("42"), "talk/UpdateLessSettings", b"{}");
        pending(
            Some("99"),
            "talk/FriendFavoritesUpdated",
            br#"{"friendUserId":45}"#,
        );
        pending(
            None,
            "talk/FriendFavoritesUpdated",
            br#"{"friendUserId":46}"#,
        );
        let unknown = pending(Some("42"), "unknown", b"{}");
        let malformed = pending(
            Some("42"),
            "talk/FriendFavoritesUpdated",
            br#"{"friendUserId":"47"}"#,
        );
        let newer = Event {
            path: "talk/FriendFavoritesUpdated".into(),
            r#type: String::new(),
            payload: br#"{"friendUserId":44}"#.to_vec(),
        };
        store.capture_pilsner("42", &newer.encode_to_vec()).unwrap();
        store.replay_pilsner("42").unwrap();
        store.replay_pilsner("42").unwrap();
        let conn = store.lock().unwrap();
        let ids = conn
            .prepare("SELECT user_id FROM friend_refresh WHERE account_id='42' ORDER BY user_id")
            .unwrap()
            .query_map([], |r| r.get::<_, i64>(0))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(ids, vec![43, 44]);
        for (seq, handled) in [(first, true), (unknown, false), (malformed, false)] {
            assert_eq!(
                conn.query_row(
                    "SELECT processed FROM native_events WHERE sequence=?1",
                    [seq],
                    |r| r.get::<_, bool>(0)
                )
                .unwrap(),
                handled
            );
        }
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM friend_refresh WHERE account_id='99'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
    }
    #[test]
    fn replay_of_old_settings_cannot_regress_a_newer_revision() {
        let (_dir, store) = crate::runtime::tests::setup();
        let event = |revision| Event {
            path: "messaging/Settings".into(),
            r#type: String::new(),
            payload: serde_json::to_vec(&serde_json::json!({"locoConfRevision":revision})).unwrap(),
        };
        let seq = store
            .capture_native("pilsner", &event(2).encode_to_vec())
            .unwrap();
        store
            .lock()
            .unwrap()
            .execute("INSERT INTO pilsner_accounts VALUES(?1,'42')", [seq])
            .unwrap();
        store
            .capture_pilsner("42", &event(7).encode_to_vec())
            .unwrap();
        store.replay_pilsner("42").unwrap();
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row(
                    "SELECT value FROM metadata WHERE key='booking_requested_revision:42'",
                    [],
                    |r| r.get::<_, String>(0)
                )
                .unwrap(),
            "7"
        );
    }
    #[test]
    fn exact_control_events_queue_atomically_and_unknown_or_malformed_remain_pending() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let store = Store::initialize(dir.path()).unwrap();
        for (path, payload, handled) in [
            (
                "messaging/Settings",
                br#"{"locoConfRevision":7}"#.as_slice(),
                true,
            ),
            ("talk/UpdateLessSettings", b"{}".as_slice(), true),
            ("unknown", b"{}".as_slice(), false),
            (
                "messaging/Settings",
                br#"{"locoConfRevision":"bad"}"#.as_slice(),
                false,
            ),
        ] {
            let event = Event {
                path: path.into(),
                r#type: "ignored".into(),
                payload: payload.to_vec(),
            };
            let seq = store.capture_pilsner("42", &event.encode_to_vec()).unwrap();
            assert_eq!(
                store
                    .lock()
                    .unwrap()
                    .query_row(
                        "SELECT processed FROM native_events WHERE sequence=?1",
                        [seq],
                        |r| r.get::<_, bool>(0)
                    )
                    .unwrap(),
                handled
            );
        }
        store
            .capture_native("less_settings", br#"{"status":0}"#)
            .unwrap();
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row(
                    "SELECT value FROM metadata WHERE key='booking_required:42'",
                    [],
                    |r| r.get::<_, String>(0)
                )
                .unwrap(),
            "true"
        );
        store.booking_revision("42", 7).unwrap();
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row(
                    "SELECT value FROM metadata WHERE key='booking_required:42'",
                    [],
                    |r| r.get::<_, String>(0)
                )
                .unwrap(),
            "false"
        );
        assert!(store.maintenance_requested("42", "less_settings").unwrap() > 0);
        assert_eq!(
            store.maintenance_requested("99", "less_settings").unwrap(),
            0
        );
        assert_eq!(store.maintenance_requested("42", "friends").unwrap(), 0);
    }
    #[test]
    fn valid_frame_before_bad_coalesced_frame_is_committed() {
        let valid = Event {
            path: "synthetic".into(),
            r#type: String::new(),
            payload: vec![],
        }
        .encode_to_vec();
        let mut bytes = (valid.len() as i32).to_be_bytes().to_vec();
        bytes.extend_from_slice(&valid);
        bytes.extend_from_slice(&1_i32.to_be_bytes());
        bytes.push(0xff);
        let mut saved = Vec::new();
        let mut decoder = Decoder::default();
        assert!(decoder
            .feed_each(&bytes, |frame| {
                saved.push(frame.to_vec());
                Ok(())
            })
            .is_err());
        assert_eq!(saved, vec![valid]);
        assert_eq!(decoder.buffer.as_slice(), &[0, 0, 0, 1, 0xff]);
    }
    #[test]
    fn protobuf_and_big_endian_frames_survive_all_chunk_boundaries() {
        let event = Event {
            path: "synthetic/path".into(),
            r#type: "update".into(),
            payload: br#"{"value":42}"#.to_vec(),
        };
        let mut payload = event.encode_to_vec();
        // The unused field 4 also accepts an unknown varint encoding.
        payload.extend_from_slice(&[0x20, 0xac, 0x02]);
        let mut bytes = (payload.len() as i32).to_be_bytes().to_vec();
        bytes.extend_from_slice(&payload);
        for split in 0..bytes.len() {
            let mut d = Decoder::default();
            assert!(d.feed(&bytes[..split]).unwrap().is_empty());
            let frames = d.feed(&bytes[split..]).unwrap();
            assert_eq!(frames.len(), 1);
            assert_eq!(Event::decode(frames[0].as_slice()).unwrap(), event);
            assert!(d.is_empty());
        }
        let mut d = Decoder::default();
        assert!(d.feed(&(-1i32).to_be_bytes()).is_err());
        let mut d = Decoder::default();
        assert!(d.feed(&(LIMIT as i32 + 1).to_be_bytes()).is_err());
    }
}
