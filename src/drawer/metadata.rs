//! Post-restore room state and message metadata. Android deleted_at semantics
//! are intentionally separate from search visibility and delete/blind type flags.
use crate::{drawer::history, Error, Result, Store};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
fn invalid() -> Error {
    Error::Invalid("invalid restored message metadata; cursor unchanged".into())
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Room {
    #[serde(default)]
    r#type: Option<String>,
    #[serde(default)]
    last_seen_log_id: i64,
    #[serde(default)]
    new_message_count: i32,
    #[serde(default)]
    invalid_new_message_count: bool,
}
#[derive(Deserialize)]
struct Page {
    content: Vec<Meta>,
    size: i32,
    #[serde(default)]
    last: bool,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Meta {
    #[serde(default)]
    log_id: i64,
    #[serde(default)]
    chat_id: i64,
    #[serde(default)]
    link_id: i64,
    #[serde(default)]
    r#type: i32,
    content: String,
    #[serde(default)]
    revision: i64,
    extra: Option<String>,
}
impl Meta {
    fn valid(&self) -> bool {
        self.chat_id > 0 && self.log_id > 0 && self.revision > 0 && !self.content.trim().is_empty()
    }
    fn kind(&self) -> i32 {
        if matches!(self.r#type, 0..=2) {
            self.r#type
        } else {
            -1
        }
    }
}
pub(super) struct Request {
    pub chat: i64,
    pub from: i64,
    pub to: i64,
}
impl Store {
    pub(super) fn drawer_prepare_rooms(&self, user: i64) -> Result<()> {
        let mut conn = self.lock()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let mut state = history::load(&tx, user)?;
        if !state.progress.logs_done || !state.progress.recording_done {
            return Err(Error::Conflict(
                "restoration postprocessing prerequisites missing".into(),
            ));
        }
        if state.progress.rooms_prepared {
            return Ok(());
        }
        let account = user.to_string();
        let rooms = {
            let mut stmt = tx.prepare(
                "SELECT chat_id,payload FROM drawer_rooms WHERE account_id=?1 ORDER BY chat_id",
            )?;
            let rows = stmt
                .query_map([&account], |r| {
                    Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            rows
        };
        for (chat, payload) in rooms {
            let room: Room = serde_json::from_str(&payload).map_err(|_| invalid())?;
            if let Some(kind) = room.r#type.as_deref() {
                crate::room_sync::save_context(&tx, &account, chat, kind, 0, -1)?;
            }
            let first:i64=tx.query_row("SELECT coalesce(min(log_id),0) FROM drawer_android_logs WHERE account_id=?1 AND chat_id=?2 AND log_id>0 AND android_deleted=0",params![account,chat],|r|r.get(0))?;
            let last:i64=tx.query_row("SELECT coalesce(max(log_id),0) FROM drawer_android_logs WHERE account_id=?1 AND chat_id=?2 AND android_deleted=0 AND android_type!=0 AND (scope IS NULL OR (scope & 1)!=0)",params![account,chat],|r|r.get(0))?;
            let unread = if room.invalid_new_message_count {
                tx.query_row("SELECT min(count(*),300) FROM drawer_android_logs WHERE account_id=?1 AND chat_id=?2 AND log_id>?3 AND android_deleted=0 AND android_type>0 AND author_id!=?4 AND (scope IS NULL OR (scope & 1)!=0)",params![account,chat,room.last_seen_log_id,user],|r|r.get::<_,i64>(0))?
            } else {
                i64::from(room.new_message_count.clamp(0, 300))
            };
            let preview:Option<i64>=tx.query_row("SELECT log_id FROM drawer_records WHERE account_id=?1 AND chat_id=?2 AND log_id=?3 AND deleted=0",params![account,chat,last],|r|r.get(0)).optional()?;
            // Derive bounds from locally restored rows, not the backup lastLogId.
            // Metadata synchronization never advances the read position.
            let done = !matches!(room.r#type.as_deref(), Some("DirectChat" | "MultiChat"))
                || first == 0
                || last == 0
                || first > last;
            tx.execute("INSERT INTO drawer_room_state(account_id,chat_id,first_log_id,last_log_id,last_seen_log_id,last_read_log_id,unread_count,preview_log_id,meta_to,meta_done) VALUES(?1,?2,?3,?4,?5,?5,?6,?7,?4,?8)",params![account,chat,first,last,room.last_seen_log_id,unread,preview,done])?;
        }
        state.progress.rooms_prepared = true;
        state.status.phase = "message_metadata_sync".into();
        history::save(&tx, &state)?;
        tx.commit()?;
        Ok(())
    }
    pub(super) fn drawer_next_meta(&self, user: i64) -> Result<Option<Request>> {
        Ok(self.lock()?.query_row("SELECT chat_id,first_log_id,meta_to FROM drawer_room_state WHERE account_id=?1 AND meta_done=0 ORDER BY chat_id LIMIT 1",[user.to_string()],|r|Ok(Request{chat:r.get(0)?,from:r.get(1)?,to:r.get(2)?})).optional()?)
    }
    pub(super) fn drawer_apply_meta(
        &self,
        user: i64,
        request: &Request,
        body: &[u8],
    ) -> Result<()> {
        let page: Page = serde_json::from_slice(body).map_err(|_| invalid())?;
        if page.size < 0 || page.content.len() > 100000 {
            return Err(invalid());
        }
        let metas: Vec<_> = page.content.into_iter().filter(Meta::valid).collect();
        if metas
            .iter()
            .any(|m| m.chat_id != request.chat || m.log_id < request.from || m.log_id > request.to)
        {
            return Err(invalid());
        }
        let account = user.to_string();
        let mut conn = self.lock()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let state = history::load(&tx, user)?;
        if !state.progress.rooms_prepared || !state.progress.recording_done {
            return Err(invalid());
        }
        let current:(i64,i64,bool,i64)=tx.query_row("SELECT first_log_id,meta_to,meta_done,synced_meta_log_id FROM drawer_room_state WHERE account_id=?1 AND chat_id=?2",params![account,request.chat],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
        if current.0 != request.from || current.1 != request.to || current.2 {
            return Err(Error::Conflict("message metadata cursor mismatch".into()));
        }
        let done = page.last || (metas.is_empty() && current.3 == 0);
        let next = if done {
            request.to
        } else {
            metas.last().map(|m| m.log_id).ok_or_else(invalid)?
        };
        if !done && next >= request.to {
            return Err(Error::Conflict(
                "message metadata pagination did not advance".into(),
            ));
        }
        tx.execute(
            "INSERT INTO drawer_meta_pages VALUES(?1,?2,?3,?4,?5)",
            params![account, request.chat, request.to, body, page.last],
        )?;
        let max_log = metas.iter().map(|m| m.log_id).max().unwrap_or(0);
        let max_rev = metas.iter().map(|m| m.revision).max().unwrap_or(0);
        for (ordinal, meta) in metas.iter().enumerate() {
            tx.execute(
                "INSERT INTO drawer_meta_stage VALUES(?1,?2,?3,?4,?5,?6)",
                params![
                    account,
                    request.chat,
                    request.to,
                    ordinal as i64,
                    meta.log_id,
                    serde_json::to_string(meta)?
                ],
            )?;
        }
        if done {
            // Apply the accumulated room result once: a log's
            // group may span page boundaries. Delete Legacy before the whole
            // group, then let its last incoming normalized type win.
            tx.execute("DELETE FROM drawer_log_meta WHERE account_id=?1 AND chat_id=?2 AND type=0 AND log_id IN (SELECT log_id FROM drawer_meta_stage WHERE account_id=?1 AND chat_id=?2)",params![account,request.chat])?;
            let mut stmt=tx.prepare("SELECT payload FROM drawer_meta_stage WHERE account_id=?1 AND chat_id=?2 ORDER BY request_to DESC,ordinal ASC")?;
            let mut rows = stmt.query(params![account, request.chat])?;
            while let Some(row) = rows.next()? {
                let raw: String = row.get(0)?;
                let meta: Meta = serde_json::from_str(&raw).map_err(|_| invalid())?;
                let kind = meta.kind();
                let extra_rev = if kind == 2 { 0 } else { meta.revision };
                let extra_state = if kind == 2 { "INCOMPLETE" } else { "NONE" };
                tx.execute("INSERT INTO drawer_log_meta VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11) ON CONFLICT(account_id,chat_id,log_id,type) DO UPDATE SET raw_type=excluded.raw_type,revision=excluded.revision,content=excluded.content,extra=coalesce(excluded.extra,drawer_log_meta.extra),extra_revision=CASE WHEN excluded.extra_revision>0 THEN excluded.extra_revision ELSE drawer_log_meta.extra_revision END,extra_state=CASE WHEN excluded.extra_state!='NONE' THEN excluded.extra_state ELSE drawer_log_meta.extra_state END,payload=excluded.payload",params![account,meta.chat_id,meta.log_id,kind,meta.r#type,meta.revision,meta.content,meta.extra,extra_rev,extra_state,raw])?;
            }
        }
        tx.execute("UPDATE drawer_room_state SET meta_to=?3,meta_done=?4,synced_meta_log_id=max(synced_meta_log_id,?5),meta_revision=max(meta_revision,?6) WHERE account_id=?1 AND chat_id=?2",params![account,request.chat,next,done,max_log,max_rev])?;
        tx.commit()?;
        Ok(())
    }
    pub(super) fn drawer_mark_meta_done(&self, user: i64) -> Result<()> {
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        let mut state = history::load(&tx, user)?;
        if !state.progress.rooms_prepared
            || !state.progress.logs_done
            || !state.progress.recording_done
        {
            return Err(invalid());
        }
        let pending: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM drawer_room_state WHERE account_id=?1 AND meta_done=0)",
            [user.to_string()],
            |r| r.get(0),
        )?;
        if pending {
            return Err(Error::Conflict("message metadata remains pending".into()));
        }
        state.progress.meta_done = true;
        state.status.phase = "restore_ready_to_complete".into();
        history::save(&tx, &state)?;
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn fixture() -> (tempfile::TempDir, Store) {
        let (dir, store) = crate::drawer_restore::tests::restore_store();
        {
            let mut conn = store.lock().unwrap();
            let tx = conn.transaction().unwrap();
            let raw: String = tx
                .query_row(
                    "SELECT value FROM metadata WHERE key='drawer_restore'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            let mut state = crate::drawer_restore::decode(&raw).unwrap();
            state.status.key_available = true;
            state.progress.logs_done = true;
            state.progress.recording_done = true;
            history::save(&tx, &state).unwrap();
            tx.execute("INSERT INTO drawer_pages(account_id,stage,request_cursor,is_last,payload,received_at_ms) VALUES('42','rooms','',1,?1,0)",[b"{}".as_slice()]).unwrap();
            let page = tx.last_insert_rowid();
            tx.execute("INSERT INTO drawer_rooms VALUES('42',10,?1,?2)",params![json!({"chatId":10,"type":"DirectChat","lastSeenLogId":5,"lastLogId":999,"newMessageCount":30,"invalidNewMessageCount":true}).to_string(),page]).unwrap();
            for (log, kind, author, message, scope, deleted) in [
                (1, 0, 99, r#"{"feedType":16}"#, None, true),
                (2, 0, 99, r#"{"feedType":1}"#, None, false),
                (3, 1, 99, "other scope", Some(2), false),
                (6, 1, 42, "self", None, false),
                (7, 1, 99, "incoming", None, false),
                (8, 0x4001, 99, "hidden but not deleted_at", None, true),
                (9, 0, 99, r#"{"feedType":16}"#, None, true),
                (10, 1, 99, "other scope", Some(2), false),
            ] {
                tx.execute("INSERT INTO drawer_records VALUES('42',10,?1,0,?2,?3,1700000000000,?4,?5,?6,?7)",params![log,kind,author,message,deleted,json!({"scope":scope,"supplement":""}).to_string(),page]).unwrap();
            }
            tx.commit().unwrap();
        }
        (dir, store)
    }
    #[test]
    fn headless_room_state_uses_android_filters_and_preserves_seen_position() {
        let (_dir, store) = fixture();
        store.drawer_prepare_rooms(42).unwrap();
        let row:(i64,i64,i64,i64,i64,Option<i64>)=store.lock().unwrap().query_row("SELECT first_log_id,last_log_id,last_seen_log_id,last_read_log_id,unread_count,preview_log_id FROM drawer_room_state",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).unwrap();
        assert_eq!(row, (2, 8, 5, 5, 2, None));
        assert!(store.drawer_mark_meta_done(42).is_err());
    }
    #[test]
    fn page_staging_preserves_groups_across_boundaries_and_rejects_cross_room() {
        let (_dir, store) = fixture();
        store.drawer_prepare_rooms(42).unwrap();
        let meta = |log, kind, rev| json!({"chatId":10,"logId":log,"type":kind,"revision":rev,"content":"synthetic","extra":null});
        let first = json!({"size":2,"last":false,"content":[meta(8,1,1),meta(7,0,2)]});
        let request = store.drawer_next_meta(42).unwrap().unwrap();
        store
            .drawer_apply_meta(42, &request, &serde_json::to_vec(&first).unwrap())
            .unwrap();
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row("SELECT count(*) FROM drawer_log_meta", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        let request = store.drawer_next_meta(42).unwrap().unwrap();
        assert_eq!(request.to, 7);
        let wrong = json!({"size":1,"last":true,"content":[{"chatId":11,"logId":6,"revision":1,"content":"wrong room"}]});
        assert!(store
            .drawer_apply_meta(42, &request, &serde_json::to_vec(&wrong).unwrap())
            .is_err());
        assert_eq!(store.drawer_next_meta(42).unwrap().unwrap().to, 7);
        store.lock().unwrap().execute("INSERT INTO drawer_log_meta VALUES('42',10,6,2,2,3,'previous', 'cached-extra',9,'VALID','{}')",[]).unwrap();
        let second = json!({"size":2,"last":true,"content":[meta(7,1,3),meta(6,2,4)]});
        store
            .drawer_apply_meta(42, &request, &serde_json::to_vec(&second).unwrap())
            .unwrap();
        assert!(store.drawer_next_meta(42).unwrap().is_none());
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row(
                    "SELECT count(*) FROM drawer_log_meta WHERE log_id=7",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            2
        );
        let extra: (i64, String) = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT extra_revision,extra_state FROM drawer_log_meta WHERE type=2",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(extra, (9, "INCOMPLETE".into()));
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row("SELECT extra FROM drawer_log_meta WHERE type=2", [], |r| {
                    r.get::<_, String>(0)
                })
                .unwrap(),
            "cached-extra"
        );
        store.drawer_mark_meta_done(42).unwrap();
        assert_eq!(
            store.drawer_restore_status().unwrap().unwrap().phase,
            "restore_ready_to_complete"
        );
        assert!(!store.native_completed("drawer_restore_completed").unwrap());
    }
}
