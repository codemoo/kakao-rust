//! Bounded Drawer pages; raw records, deletion state, text index, and resume
//! cursor commit together. This stage deliberately does not report completion.
use crate::{
    drawer::crypto::{DrawerKey, RecordDecoder},
    drawer_restore::{self, State},
    ingest::Payload,
    native_http::{Client, Operation},
    runtime::RuntimeLease,
    Error, Result, Store,
};
use rusqlite::{params, OptionalExtension, Transaction};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
fn invalid() -> Error {
    Error::Invalid("invalid Drawer history page; cursor unchanged".into())
}
#[derive(Deserialize)]
struct Page {
    last: bool,
    size: i32,
    content: Vec<Value>,
}
impl Page {
    fn parse(bytes: &[u8], limit: usize) -> Result<Self> {
        let page: Self = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        if page.size < 0 || page.content.len() > limit || (!page.last && page.content.is_empty()) {
            return Err(invalid());
        }
        Ok(page)
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireLog {
    log_id: i64,
    chat_id: i64,
    #[serde(rename = "type")]
    kind: i32,
    send_at: i32,
    referer: i32,
    prev_id: i64,
    enc_message: Option<String>,
    enc_author_id: Option<String>,
    secured_key: Option<String>,
    iv: Option<String>,
    enc_version: Option<i32>,
    row_key: Option<String>,
    #[serde(default = "zero_revision")]
    revision: Option<i32>,
}
fn zero_revision() -> Option<i32> {
    Some(0)
}
struct Record {
    wire: WireLog,
    raw: Value,
    message: Zeroizing<String>,
    author: i64,
    deleted: bool,
    target: Option<i64>,
}
fn parse_record(raw: Value, decoder: &mut RecordDecoder<'_>) -> Result<Record> {
    let wire: WireLog = serde_json::from_value(raw.clone()).map_err(|_| invalid())?;
    // These fields are required even though they have no text-index projection.
    let _ = (wire.referer, wire.prev_id);
    if wire.enc_version.is_none() || wire.revision.unwrap_or(0) < 0 || wire.send_at < 0 {
        return Err(invalid());
    }
    let (message, author) = decoder.decrypt(
        wire.secured_key.as_deref().ok_or_else(invalid)?,
        wire.iv.as_deref().ok_or_else(invalid)?,
        wire.enc_message.as_deref(),
        wire.enc_author_id.as_deref().ok_or_else(invalid)?,
    )?;
    let flags_deleted = wire.kind == -11 || wire.kind > 0 && wire.kind & (0x4000 | 0x8000) != 0;
    let feed = if wire.kind == 0 {
        serde_json::from_str::<Value>(&message).ok()
    } else {
        None
    };
    let feed_type = feed
        .as_ref()
        .and_then(|v| v.get("feedType"))
        .and_then(Value::as_i64);
    let target = if feed_type == Some(14) {
        let id = feed
            .as_ref()
            .and_then(|v| v.get("logId"))
            .ok_or_else(invalid)?;
        Some(
            id.as_i64()
                .or_else(|| id.as_str().and_then(|s| s.parse().ok()))
                .ok_or_else(invalid)?,
        )
    } else {
        None
    };
    Ok(Record {
        wire,
        raw,
        message,
        author,
        deleted: flags_deleted || feed_type == Some(16),
        target,
    })
}
pub(super) fn load(tx: &Transaction<'_>, user: i64) -> Result<State> {
    let raw: String = tx.query_row(
        "SELECT value FROM metadata WHERE key='drawer_restore'",
        [],
        |r| r.get(0),
    )?;
    let state = drawer_restore::decode(&raw)?;
    let attempt: String = tx.query_row(
        "SELECT attempt_id FROM qr_auth_attempt WHERE id=1 AND state='authorized'",
        [],
        |r| r.get(0),
    )?;
    if state.user_id != user || state.attempt_id != attempt || !state.status.key_available {
        return Err(Error::Conflict(
            "Drawer restore authorization binding mismatch".into(),
        ));
    }
    Ok(state)
}
pub(super) fn save(tx: &Transaction<'_>, state: &State) -> Result<()> {
    tx.execute(
        "UPDATE metadata SET value=?1 WHERE key='drawer_restore'",
        [serde_json::to_string(state)?],
    )?;
    Ok(())
}
fn page_insert(
    tx: &Transaction<'_>,
    account: &str,
    stage: &str,
    cursor: &str,
    next: Option<&str>,
    last: bool,
    body: &[u8],
) -> Result<Option<i64>> {
    let prior: Option<Vec<u8>> = tx.query_row("SELECT payload FROM drawer_pages WHERE account_id=?1 AND stage=?2 AND request_cursor=?3", params![account,stage,cursor], |r| r.get(0)).optional()?;
    if let Some(prior) = prior {
        if prior == body {
            return Ok(None);
        }
        return Err(Error::Conflict("Drawer page replay differs".into()));
    }
    if !last {
        let next = next.filter(|s| !s.is_empty()).ok_or_else(invalid)?;
        let seen:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM drawer_pages WHERE account_id=?1 AND stage=?2 AND request_cursor=?3)",params![account,stage,next],|r|r.get(0))?;
        if next == cursor || seen {
            return Err(Error::Conflict(
                "Drawer pagination cursor cycle; cursor unchanged".into(),
            ));
        }
    }
    tx.execute("INSERT INTO drawer_pages(account_id,stage,request_cursor,next_cursor,is_last,payload,received_at_ms) VALUES(?1,?2,?3,?4,?5,?6,?7)", params![account,stage,cursor,next,last,body,chrono::Utc::now().timestamp_millis()])?;
    Ok(Some(tx.last_insert_rowid()))
}
fn payload_hash(payload: &Payload) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(payload)?)))
}
fn tombstone(
    tx: &Transaction<'_>,
    account: &str,
    chat: i64,
    log: i64,
    reason: &str,
    page: i64,
) -> Result<()> {
    tx.execute(
        "INSERT INTO drawer_tombstones VALUES(?1,?2,?3,?4,?5) ON CONFLICT DO NOTHING",
        params![account, chat, log, reason, page],
    )?;
    tx.execute(
        "UPDATE drawer_records SET deleted=1 WHERE account_id=?1 AND chat_id=?2 AND log_id=?3",
        params![account, chat, log],
    )?;
    type ExistingMessage = (i64, i64, Option<String>, bool, Option<String>);
    let old: Option<ExistingMessage> = tx.query_row("SELECT revision,sent_at_ms,sender_id,deleted,source_local_pk FROM messages WHERE account_id=?1 AND room_id=?2 AND message_id=?3", params![account,chat.to_string(),log.to_string()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
    if let Some((revision, time, sender, false, local)) = old {
        let hash = payload_hash(&Payload::Message {
            room_id: chat.to_string(),
            message_id: log.to_string(),
            revision,
            sent_at_ms: time,
            sender_id: sender,
            body: None,
            deleted: true,
            source_local_pk: local,
        })?;
        tx.execute("UPDATE messages SET deleted=1,body=NULL,payload_hash=?4 WHERE account_id=?1 AND room_id=?2 AND message_id=?3", params![account,chat.to_string(),log.to_string(),hash])?;
        tx.execute("INSERT INTO outbox(account_id,room_id,entity_id,kind,revision,source) VALUES(?1,?2,?3,'message_deleted',?4,'native_drawer')", params![account,chat.to_string(),log.to_string(),revision])?;
    }
    Ok(())
}
fn project(tx: &Transaction<'_>, account: &str, record: &Record, deleted: bool) -> Result<()> {
    // Text and replies have user-readable message bodies. Other record formats
    // remain fully available in private raw/restored storage for later handlers.
    let base = record.wire.kind & !(0x4000 | 0x8000);
    let w = &record.wire;
    let revision = i64::from(w.revision.unwrap_or(0));
    if !deleted
        && crate::mutations::suppress_projection(
            tx,
            account,
            &w.chat_id.to_string(),
            &w.log_id.to_string(),
            revision,
        )?
    {
        return Ok(());
    }
    tx.execute("DELETE FROM message_media WHERE account_id=?1 AND chat_id=?2 AND log_id=?3 AND revision<?4",params![account,w.chat_id,w.log_id,revision])?;
    if !deleted && matches!(base, 2 | 3 | 5 | 18 | 27) {
        if let Some(attachment) = record
            .raw
            .get("attachment")
            .and_then(serde_json::Value::as_str)
        {
            tx.execute("INSERT INTO message_media VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'native_drawer') ON CONFLICT(account_id,chat_id,log_id) DO UPDATE SET revision=excluded.revision,kind=excluded.kind,sent_at_ms=excluded.sent_at_ms,sender_id=excluded.sender_id,attachment=excluded.attachment,source=excluded.source WHERE excluded.revision>message_media.revision",params![account,w.chat_id,w.log_id,revision,base,i64::from(w.send_at)*1000,record.author,attachment])?;
        }
    }
    if deleted || !matches!(base, 2 | 3 | 5 | 18 | 27) {
        tx.execute("DELETE FROM message_media WHERE account_id=?1 AND chat_id=?2 AND log_id=?3 AND revision<=?4",params![account,w.chat_id,w.log_id,revision])?;
    }
    if !matches!(base, 1 | 26) {
        // A newer nontext winner invalidates a previously searchable projection.
        // This is not a terminal deletion: a later supported revision may return.
        let removed=tx.execute("DELETE FROM messages WHERE account_id=?1 AND room_id=?2 AND message_id=?3 AND revision<=?4 AND deleted=0",params![account,w.chat_id.to_string(),w.log_id.to_string(),revision])?;
        if removed > 0 {
            tx.execute("INSERT INTO outbox(account_id,room_id,entity_id,kind,revision,source) VALUES(?1,?2,?3,'message_projection_removed',?4,'native_drawer')",params![account,w.chat_id.to_string(),w.log_id.to_string(),revision])?;
        }
        return Ok(());
    }
    let time = i64::from(w.send_at) * 1000;
    let sender = (record.author > 0).then(|| record.author.to_string());
    let body = (!deleted).then(|| record.message.to_string());
    let payload = Payload::Message {
        room_id: w.chat_id.to_string(),
        message_id: w.log_id.to_string(),
        revision,
        sent_at_ms: time,
        sender_id: sender.clone(),
        body: body.clone(),
        deleted,
        source_local_pk: None,
    };
    let hash = payload_hash(&payload)?;
    let old: Option<(i64,String,i64,bool)> = tx.query_row("SELECT revision,payload_hash,sent_at_ms,deleted FROM messages WHERE account_id=?1 AND room_id=?2 AND message_id=?3", params![account,w.chat_id.to_string(),w.log_id.to_string()], |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
    if let Some((old_revision, old_hash, old_time, old_deleted)) = old {
        if old_deleted || old_revision > revision {
            return Ok(());
        }
        if old_time != time {
            return Err(Error::Conflict("Drawer message timestamp changed".into()));
        }
        if old_revision == revision && !deleted {
            if old_hash != hash {
                return Err(Error::Conflict("Drawer message revision conflict".into()));
            }
            return Ok(());
        }
    }
    tx.execute("INSERT INTO rooms(account_id,room_id,revision,source) VALUES(?1,?2,-1,'native_drawer') ON CONFLICT DO NOTHING",params![account,w.chat_id.to_string()])?;
    tx.execute("INSERT INTO messages(account_id,room_id,message_id,revision,sent_at_ms,sender_id,body,deleted,source,payload_hash) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'native_drawer',?9) ON CONFLICT(account_id,room_id,message_id) DO UPDATE SET revision=excluded.revision,sender_id=excluded.sender_id,body=excluded.body,deleted=excluded.deleted,source=excluded.source,payload_hash=excluded.payload_hash",params![account,w.chat_id.to_string(),w.log_id.to_string(),revision,time,sender,body,deleted,hash])?;
    tx.execute("INSERT INTO outbox(account_id,room_id,entity_id,kind,revision,source) VALUES(?1,?2,?3,?4,?5,'native_drawer')",params![account,w.chat_id.to_string(),w.log_id.to_string(),if deleted {"message_deleted"} else {"message_upserted"},revision])?;
    Ok(())
}
impl Store {
    pub(super) fn drawer_progress(&self, user: i64) -> Result<State> {
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        load(&tx, user)
    }
    fn drawer_inventory(&self, user: i64, body: &[u8]) -> Result<()> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Inventory {
            backup_chat_count: i64,
            backup_chat_log_count: i64,
        }
        let inventory: Inventory = serde_json::from_slice(body).map_err(|_| invalid())?;
        if inventory.backup_chat_count < 0 || inventory.backup_chat_log_count < 0 {
            return Err(invalid());
        }
        let required = u64::try_from(inventory.backup_chat_log_count)
            .map_err(|_| invalid())?
            .checked_mul(1024)
            .ok_or_else(invalid)?;
        if fs2::available_space(&*self.data_dir)? < required {
            return Err(Error::Storage(
                "insufficient free space for Drawer restoration".into(),
            ));
        }
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        let mut state = load(&tx, user)?;
        if state.progress.inventory_read {
            return Ok(());
        }
        page_insert(&tx, &user.to_string(), "inventory", "", None, true, body)?;
        state.status.backup_rooms = inventory.backup_chat_count;
        state.status.backup_messages = inventory.backup_chat_log_count;
        state.status.phase = "downloading_rooms".into();
        state.progress.inventory_read = true;
        save(&tx, &state)?;
        tx.commit()?;
        Ok(())
    }
    fn drawer_rooms_page(&self, user: i64, cursor: Option<i64>, body: &[u8]) -> Result<()> {
        let page = Page::parse(body, 100)?;
        let ids: Vec<i64> = page
            .content
            .iter()
            .map(|v| v.get("chatId").and_then(Value::as_i64).ok_or_else(invalid))
            .collect::<Result<_>>()?;
        let next = ids.last().copied();
        if !page.last && (next.is_none() || next == cursor) {
            return Err(invalid());
        }
        let account = user.to_string();
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        let mut state = load(&tx, user)?;
        let request = cursor.map(|v| v.to_string()).unwrap_or_default();
        let next_str = next.map(|v| v.to_string());
        let Some(id) = page_insert(
            &tx,
            &account,
            "rooms",
            &request,
            next_str.as_deref(),
            page.last,
            body,
        )?
        else {
            return Ok(());
        };
        if !state.progress.inventory_read
            || state.progress.rooms_done
            || state.progress.room_cursor != cursor
        {
            return Err(Error::Conflict("Drawer room cursor mismatch".into()));
        }
        for (chat, raw) in ids.into_iter().zip(page.content) {
            tx.execute("INSERT INTO drawer_rooms VALUES(?1,?2,?3,?4) ON CONFLICT(account_id,chat_id) DO UPDATE SET payload=excluded.payload,page_id=excluded.page_id",params![account,chat,serde_json::to_string(&raw)?,id])?;
            tx.execute("INSERT INTO rooms(account_id,room_id,revision,source) VALUES(?1,?2,-1,'native_drawer') ON CONFLICT DO NOTHING",params![account,chat.to_string()])?;
        }
        state.progress.rooms_done = page.last;
        state.progress.room_cursor = next;
        if page.last {
            state.status.phase = "downloading_logs".into();
        }
        save(&tx, &state)?;
        tx.commit()?;
        Ok(())
    }
    fn drawer_logs_page(
        &self,
        user: i64,
        cursor: Option<&str>,
        body: &[u8],
        decoder: &mut RecordDecoder<'_>,
    ) -> Result<()> {
        let page = Page::parse(body, 500)?;
        let records: Vec<Record> = page
            .content
            .into_iter()
            .map(|v| parse_record(v, decoder))
            .collect::<Result<_>>()?;
        let next = records.last().and_then(|r| r.wire.row_key.as_deref());
        if !page.last && (next.is_none_or(str::is_empty) || next == cursor) {
            return Err(invalid());
        }
        let mut conn = self.lock()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let mut state = load(&tx, user)?;
        let account = user.to_string();
        let Some(page_id) = page_insert(
            &tx,
            &account,
            "logs",
            cursor.unwrap_or(""),
            next,
            page.last,
            body,
        )?
        else {
            return Ok(());
        };
        if !state.progress.rooms_done
            || state.progress.logs_done
            || state.progress.log_cursor.as_deref() != cursor
        {
            return Err(Error::Conflict("Drawer log cursor mismatch".into()));
        }
        for r in &records {
            let w = &r.wire;
            if r.deleted {
                tombstone(&tx, &account, w.chat_id, w.log_id, "record", page_id)?;
            }
            if let Some(target) = r.target {
                tombstone(&tx, &account, w.chat_id, target, "delete_for_all", page_id)?;
            }
            let deleted:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM drawer_tombstones WHERE account_id=?1 AND chat_id=?2 AND log_id=?3) OR EXISTS(SELECT 1 FROM native_tombstones WHERE account_id=?1 AND chat_id=?2 AND log_id=?3)",params![account,w.chat_id,w.log_id],|r|r.get(0))?;
            let changed=tx.execute("INSERT INTO drawer_records VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11) ON CONFLICT(account_id,chat_id,log_id) DO UPDATE SET revision=excluded.revision,raw_type=excluded.raw_type,author_id=excluded.author_id,message=excluded.message,deleted=max(drawer_records.deleted,excluded.deleted),payload=excluded.payload,page_id=excluded.page_id WHERE excluded.revision>=drawer_records.revision",params![account,w.chat_id,w.log_id,w.revision.unwrap_or(0),w.kind,r.author,i64::from(w.send_at)*1000,r.message.as_str(),deleted,serde_json::to_string(&r.raw)?,page_id])?;
            if changed > 0 {
                project(&tx, &account, r, deleted)?;
            }
        }
        state.progress.log_cursor = next.map(str::to_owned);
        state.progress.logs_done = page.last;
        state.status.downloaded_messages += records.len() as i64;
        state.status.indexed_messages=tx.query_row("SELECT count(*) FROM messages WHERE account_id=?1 AND source='native_drawer' AND deleted=0",[&account],|r|r.get(0))?;
        if page.last {
            state.status.phase = "recording_restore_pending".into();
        }
        save(&tx, &state)?;
        tx.commit()?;
        Ok(())
    }
}
/// Page budget permits observation/resume without changing server page sizes.
/// A transport/decryption/storage error stops immediately with committed cursor intact.
pub async fn download(store: &Store, max_pages: u32) -> Result<drawer_restore::RestoreStatus> {
    if max_pages == 0 {
        return Err(Error::Invalid("page budget must be positive".into()));
    }
    store.select_drawer_restore()?;
    let lease = std::sync::Arc::new(RuntimeLease::acquire(store)?);
    let key: DrawerKey = store.drawer_load_key()?;
    let mut session = store.session_load()?;
    let user = session.user_id();
    let mut state = store.drawer_progress(user)?;
    if state.progress.logs_done {
        return Ok(state.status);
    }
    let mut listener = crate::pilsner::Listener::new(store.clone(), lease);
    let client = Client::new()?;
    let mut decoder = RecordDecoder::new(&key);
    for _ in 0..max_pages {
        listener.ensure().await?;
        let operation = if !state.progress.inventory_read {
            Operation::DrawerBackupInfo
        } else if !state.progress.rooms_done {
            Operation::DrawerChats {
                last_chat_id: state.progress.room_cursor,
            }
        } else {
            Operation::DrawerLogs {
                last_row_key: state.progress.log_cursor.as_deref(),
            }
        };
        let response = client.execute(store, &mut session, operation).await?;
        if !(200..300).contains(&response.http_status)
            || response.server_status.is_some_and(|s| s != 0)
        {
            return Err(Error::Invalid(
                "Drawer download rejected; cursor unchanged".into(),
            ));
        }
        if !state.progress.inventory_read {
            store.drawer_inventory(user, &response.body)?;
        } else if !state.progress.rooms_done {
            store.drawer_rooms_page(user, state.progress.room_cursor, &response.body)?;
        } else {
            store.drawer_logs_page(
                user,
                state.progress.log_cursor.as_deref(),
                &response.body,
                &mut decoder,
            )?;
        }
        state = store.drawer_progress(user)?;
        if state.progress.logs_done {
            break;
        }
    }
    listener.close().await?;
    Ok(state.status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use ctr::cipher::{KeyIvInit, StreamCipher};
    use rsa::{pkcs8::EncodePrivateKey, Oaep, RsaPrivateKey};
    use serde_json::json;
    const CHAT: i64 = 9007199254740993;
    struct Fixture {
        _dir: tempfile::TempDir,
        store: Store,
        key: DrawerKey,
        secured: String,
    }
    impl Fixture {
        fn new() -> Self {
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
                    br#"{"backupChatCount":1,"backupChatLogCount":7}"#,
                )
                .unwrap();
            store.select_drawer_restore().unwrap();
            let rsa = RsaPrivateKey::new(&mut rand::rngs::OsRng, 1024).unwrap();
            let key = DrawerKey::from_der(rsa.to_pkcs8_der().unwrap().as_bytes()).unwrap();
            store.drawer_save_key(&key).unwrap();
            store
                .drawer_inventory(42, br#"{"backupChatCount":1,"backupChatLogCount":7}"#)
                .unwrap();
            let bytes=serde_json::to_vec(&json!({"last":true,"size":1,"content":[{"chatId":CHAT,"type":"DirectChat","unknown":"preserve"}]})).unwrap();
            store.drawer_rooms_page(42, None, &bytes).unwrap();
            let mut wrapped = vec![7u8; 32];
            wrapped.extend_from_slice(&md5::Md5::digest([7u8; 32]));
            let secured = STANDARD.encode(
                rsa.to_public_key()
                    .encrypt(&mut rand::rngs::OsRng, Oaep::new::<sha1::Sha1>(), &wrapped)
                    .unwrap(),
            );
            Self {
                _dir: dir,
                store,
                key,
                secured,
            }
        }
        fn record(&self, id: i64, kind: i32, message: &str) -> Value {
            fn enc(text: &str) -> String {
                let mut data = text.as_bytes().to_vec();
                ctr::Ctr128BE::<aes::Aes256>::new_from_slices(&[7u8; 32], &[3u8; 16])
                    .unwrap()
                    .apply_keystream(&mut data);
                STANDARD.encode(data)
            }
            json!({"logId":id,"chatId":CHAT,"type":kind,"sendAt":1700000000,"referer":0,"prevId":id-1,"encMessage":enc(message),"encAuthorId":enc("9007199254740995"),"securedKey":self.secured,"iv":STANDARD.encode([3u8;16]),"encVersion":1,"rowKey":format!("opaque:{id}"),"attachment":"retained","extraFutureField":true})
        }
        fn page(&self, records: Vec<Value>, last: bool) -> Vec<u8> {
            serde_json::to_vec(&json!({"last":last,"size":records.len(),"content":records}))
                .unwrap()
        }
    }
    #[test]
    fn native_delete_and_newer_raw_revision_block_later_restore_projection() {
        let f = Fixture::new();
        f.store
            .lock()
            .unwrap()
            .execute("INSERT INTO native_tombstones VALUES('42',?1,1,10)", [CHAT])
            .unwrap();
        f.store.lock().unwrap().execute("INSERT INTO loco_logs(account_id,chat_id,log_id,prev_id,revision,kind,raw,capture_sequence,projected) VALUES('42',?1,2,0,3,2,x'00',11,0)",[CHAT]).unwrap();
        let body = f.page(
            vec![
                f.record(1, 1, "deleted text"),
                f.record(2, 1, "outdated text"),
            ],
            true,
        );
        f.store
            .drawer_logs_page(42, None, &body, &mut RecordDecoder::new(&f.key))
            .unwrap();
        let conn = f.store.lock().unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM messages WHERE deleted=0", [], |r| r
                .get::<_, i64>(
                0
            ))
            .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM message_text WHERE message_text MATCH 'text'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
    }
    #[test]
    fn atomic_pages_keep_tombstones_across_resume_and_remove_search_text() {
        let f = Fixture::new();
        let mut decoder = RecordDecoder::new(&f.key);
        let first = f.page(
            vec![
                f.record(1, 1, "first searchable"),
                f.record(3, 0, r#"{"feedType":14,"logId":2}"#),
            ],
            false,
        );
        f.store
            .drawer_logs_page(42, None, &first, &mut decoder)
            .unwrap();
        assert_eq!(
            f.store
                .drawer_progress(42)
                .unwrap()
                .progress
                .log_cursor
                .as_deref(),
            Some("opaque:3")
        );
        let second = f.page(
            vec![
                f.record(2, 1, "must never resurrect"),
                f.record(4, 2, "photo metadata"),
            ],
            false,
        );
        f.store
            .drawer_logs_page(42, Some("opaque:3"), &second, &mut decoder)
            .unwrap();
        assert_eq!(
            f.store
                .drawer_restore_status()
                .unwrap()
                .unwrap()
                .indexed_messages,
            1
        );
        let third = f.page(
            vec![
                f.record(5, 0, r#"{"feedType":14,"logId":1}"#),
                f.record(6, 26, "reply searchable"),
            ],
            true,
        );
        f.store
            .drawer_logs_page(42, Some("opaque:4"), &third, &mut decoder)
            .unwrap();
        f.store
            .drawer_logs_page(42, Some("opaque:4"), &third, &mut decoder)
            .unwrap();
        let state = f.store.drawer_progress(42).unwrap();
        assert_eq!(state.status.downloaded_messages, 6);
        assert_eq!(state.status.indexed_messages, 1);
        assert!(state.progress.logs_done);
        assert_eq!(state.status.phase, "recording_restore_pending");
        let conn = f.store.lock().unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM message_text WHERE message_text MATCH 'searchable'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row("SELECT count(*) FROM messages WHERE deleted=1", [], |r| r
                .get::<_, i64>(
                0
            ))
            .unwrap(),
            2
        );
        assert_eq!(
            conn.query_row("SELECT count(*) FROM drawer_records", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            6
        );
        assert_eq!(
            conn.query_row(
                "SELECT author_id FROM drawer_records WHERE log_id=6",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            9007199254740995
        );
        drop(conn);
        assert!(!f
            .store
            .native_completed("drawer_restore_completed")
            .unwrap_or(false));
    }
    #[test]
    fn cursor_cycles_rollback_in_both_room_and_log_stages() {
        let f = Fixture::new();
        let mut decoder = RecordDecoder::new(&f.key);
        let first = f.page(vec![f.record(1, 1, "one")], false);
        let second = f.page(vec![f.record(2, 1, "two")], false);
        let mut third = f.record(3, 1, "three");
        third["rowKey"] = json!("opaque:1");
        f.store
            .drawer_logs_page(42, None, &first, &mut decoder)
            .unwrap();
        f.store
            .drawer_logs_page(42, Some("opaque:1"), &second, &mut decoder)
            .unwrap();
        assert!(f
            .store
            .drawer_logs_page(
                42,
                Some("opaque:2"),
                &f.page(vec![third], false),
                &mut decoder
            )
            .is_err());
        assert_eq!(
            f.store
                .drawer_progress(42)
                .unwrap()
                .progress
                .log_cursor
                .as_deref(),
            Some("opaque:2")
        );
        assert_eq!(
            f.store
                .drawer_restore_status()
                .unwrap()
                .unwrap()
                .downloaded_messages,
            2
        );

        let f = Fixture::new();
        {
            let mut conn = f.store.lock().unwrap();
            let tx = conn.transaction().unwrap();
            let mut state = load(&tx, 42).unwrap();
            state.progress.rooms_done = false;
            state.progress.room_cursor = None;
            tx.execute("DELETE FROM drawer_rooms", []).unwrap();
            tx.execute("DELETE FROM drawer_pages WHERE stage='rooms'", [])
                .unwrap();
            save(&tx, &state).unwrap();
            tx.commit().unwrap();
        }
        let page = |chat| {
            serde_json::to_vec(&json!({"last":false,"size":1,"content":[{"chatId":chat}]})).unwrap()
        };
        f.store.drawer_rooms_page(42, None, &page(10)).unwrap();
        f.store.drawer_rooms_page(42, Some(10), &page(20)).unwrap();
        assert!(f.store.drawer_rooms_page(42, Some(20), &page(10)).is_err());
        assert_eq!(
            f.store.drawer_progress(42).unwrap().progress.room_cursor,
            Some(20)
        );
    }
    #[test]
    fn projection_follows_winning_revision_across_type_changes() {
        let f = Fixture::new();
        let mut decoder = RecordDecoder::new(&f.key);
        let mut nontext = f.record(1, 2, "newer photo");
        nontext["revision"] = json!(2);
        f.store
            .drawer_logs_page(42, None, &f.page(vec![nontext], false), &mut decoder)
            .unwrap();
        let mut stale = f.record(1, 1, "stale searchable");
        stale["revision"] = json!(1);
        stale["rowKey"] = json!("next:2");
        f.store
            .drawer_logs_page(
                42,
                Some("opaque:1"),
                &f.page(vec![stale], false),
                &mut decoder,
            )
            .unwrap();
        assert_eq!(
            f.store
                .drawer_restore_status()
                .unwrap()
                .unwrap()
                .indexed_messages,
            0
        );
        let mut live = f.record(2, 1, "live searchable");
        live["revision"] = json!(1);
        live["rowKey"] = json!("next:3");
        f.store
            .drawer_logs_page(42, Some("next:2"), &f.page(vec![live], false), &mut decoder)
            .unwrap();
        assert_eq!(
            f.store
                .drawer_restore_status()
                .unwrap()
                .unwrap()
                .indexed_messages,
            1
        );
        let mut changed = f.record(2, 2, "now photo");
        changed["revision"] = json!(2);
        changed["rowKey"] = json!("next:4");
        f.store
            .drawer_logs_page(
                42,
                Some("next:3"),
                &f.page(vec![changed], false),
                &mut decoder,
            )
            .unwrap();
        assert_eq!(
            f.store
                .drawer_restore_status()
                .unwrap()
                .unwrap()
                .indexed_messages,
            0
        );
        let mut supported = f.record(2, 1, "latest searchable");
        supported["revision"] = json!(3);
        f.store
            .drawer_logs_page(
                42,
                Some("next:4"),
                &f.page(vec![supported], true),
                &mut decoder,
            )
            .unwrap();
        assert_eq!(
            f.store
                .drawer_restore_status()
                .unwrap()
                .unwrap()
                .indexed_messages,
            1
        );
        assert_eq!(
            f.store
                .lock()
                .unwrap()
                .query_row(
                    "SELECT count(*) FROM outbox WHERE kind='message_projection_removed'",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            1
        );
    }
    #[test]
    fn invalid_second_record_and_transaction_conflict_never_advance_page() {
        let f = Fixture::new();
        let mut decoder = RecordDecoder::new(&f.key);
        let mut bad = f.record(2, 1, "secret");
        bad["encAuthorId"] = json!("bad_base64");
        let body = f.page(vec![f.record(1, 1, "valid"), bad], false);
        assert!(f
            .store
            .drawer_logs_page(42, None, &body, &mut decoder)
            .is_err());
        assert_eq!(
            f.store
                .drawer_progress(42)
                .unwrap()
                .status
                .downloaded_messages,
            0
        );
        assert!(f
            .store
            .drawer_progress(42)
            .unwrap()
            .progress
            .log_cursor
            .is_none());
        let first = f.page(vec![f.record(1, 1, "valid")], false);
        f.store
            .drawer_logs_page(42, None, &first, &mut decoder)
            .unwrap();
        let conflict = f.page(
            vec![
                f.record(2, 1, "will roll back"),
                f.record(1, 1, "same revision changed"),
            ],
            true,
        );
        assert!(f
            .store
            .drawer_logs_page(42, Some("opaque:1"), &conflict, &mut decoder)
            .is_err());
        let state = f.store.drawer_progress(42).unwrap();
        assert_eq!(state.status.downloaded_messages, 1);
        assert!(!state.progress.logs_done);
        assert_eq!(
            f.store
                .lock()
                .unwrap()
                .query_row("SELECT count(*) FROM drawer_records", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        let empty = br#"{"last":false,"size":0,"content":[]}"#;
        assert!(f
            .store
            .drawer_logs_page(42, Some("opaque:1"), empty, &mut decoder)
            .is_err());
        assert!(Page::parse(br#"{"last":true,"size":0,"chatLogs":[]}"#, 500).is_err());
    }
}
