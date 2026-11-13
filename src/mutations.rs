//! Received feed mutations, distinct from any outgoing edit/delete command.
use crate::{ingest::Payload, live_store::store_log, Error, Result};
use bson::Document;
use rusqlite::{params, OptionalExtension, Transaction};
use sha2::{Digest, Sha256};
fn invalid() -> Error {
    Error::Invalid("invalid received mutation; raw packet retained".into())
}
pub(crate) fn apply(
    tx: &Transaction<'_>,
    account: &str,
    seq: i64,
    body: &Document,
) -> Result<bool> {
    let Some(feed) = body.get_document("chatLog").ok() else {
        return Ok(false);
    };
    crate::loco::response::validate_chat_log(feed).map_err(|_| invalid())?;
    let chat = body
        .get_i64("c")
        .unwrap_or(feed.get_i64("chatId").map_err(|_| invalid())?);
    if chat <= 0 || feed.get_i64("chatId").ok() != Some(chat) {
        return Err(invalid());
    }
    let result = apply_feed(
        tx,
        account,
        chat,
        seq,
        feed,
        body.get_document("modifiedChatLog").ok(),
    )?;
    store_log(tx, account, chat, seq, 0, feed)?;
    Ok(result)
}
/// All intake paths (push, catch-up, lists) apply the same feed effects.
/// The checkpoint represents the effect or its durable refresh job, not content completeness.
pub(crate) fn apply_feed(
    tx: &Transaction<'_>,
    account: &str,
    chat: i64,
    seq: i64,
    feed: &Document,
    modified: Option<&Document>,
) -> Result<bool> {
    let Ok(raw) = feed.get_str("message") else {
        return Ok(false);
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(raw) else {
        return Ok(false);
    };
    let Some(kind @ (14 | 25)) = json.get("feedType").and_then(|v| v.as_i64()) else {
        return Ok(false);
    };
    let target = json
        .get("logId")
        .and_then(|v| {
            v.as_i64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .filter(|v| *v > 0)
        .ok_or_else(invalid)?;
    let feed_id = feed.get_i64("logId").map_err(|_| invalid())?;
    let key = format!("mutation_seen:{account}:{chat}:{feed_id}");
    let seen: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM metadata WHERE key=?1)",
        [&key],
        |r| r.get(0),
    )?;
    if seen {
        return Ok(true);
    }
    if kind == 14 {
        delete(tx, account, chat, target, seq)?;
    } else {
        let mut applied = false;
        if let Some(modified) = modified {
            if modified.get_i64("chatId").ok() != Some(chat)
                || modified.get_i64("logId").ok() != Some(target)
            {
                return Err(invalid());
            }
            if crate::loco::response::validate_chat_log(modified).is_ok()
                && modified.get_i32("sendAt").is_ok()
                && modified.get_i64("authorId").is_ok()
            {
                let revision = i64::from(modified.get_i32("revision").unwrap_or(0));
                let old:i64=tx.query_row("SELECT coalesce(max(revision),-1) FROM (SELECT revision FROM loco_logs WHERE account_id=?1 AND chat_id=?2 AND log_id=?3 UNION ALL SELECT revision FROM messages WHERE account_id=?1 AND room_id=CAST(?2 AS TEXT) AND message_id=CAST(?3 AS TEXT))",params![account,chat,target],|r|r.get(0))?;
                applied = if revision > old {
                    store_log(tx, account, chat, seq, 1, modified)?
                } else {
                    true
                };
            }
        }
        if !applied {
            tx.execute("INSERT INTO message_refresh(account_id,chat_id,log_id,requested_sequence) VALUES(?1,?2,?3,?4) ON CONFLICT(account_id,chat_id,log_id) DO UPDATE SET requested_sequence=max(requested_sequence,excluded.requested_sequence)",params![account,chat,target,seq])?;
        }
    }
    tx.execute(
        "INSERT INTO metadata(key,value) VALUES(?1,?2)",
        params![key, seq.to_string()],
    )?;
    Ok(true)
}
/// A winning raw revision survives removal of its searchable projection.
pub(crate) fn suppress_projection(
    tx: &Transaction<'_>,
    account: &str,
    room: &str,
    message: &str,
    revision: i64,
) -> Result<bool> {
    let (Ok(chat), Ok(log)) = (room.parse::<i64>(), message.parse::<i64>()) else {
        return Ok(false);
    };
    if chat.to_string() != room || log.to_string() != message {
        return Ok(false);
    }
    Ok(tx.query_row("SELECT EXISTS(SELECT 1 FROM native_tombstones WHERE account_id=?1 AND chat_id=?2 AND log_id=?3) OR EXISTS(SELECT 1 FROM drawer_tombstones WHERE account_id=?1 AND chat_id=?2 AND log_id=?3) OR EXISTS(SELECT 1 FROM loco_logs WHERE account_id=?1 AND chat_id=?2 AND log_id=?3 AND revision>?4) OR EXISTS(SELECT 1 FROM drawer_records WHERE account_id=?1 AND chat_id=?2 AND log_id=?3 AND revision>?4)",params![account,chat,log,revision],|r|r.get(0))?)
}

fn delete(tx: &Transaction<'_>, account: &str, chat: i64, id: i64, seq: i64) -> Result<()> {
    let inserted = tx.execute(
        "INSERT INTO native_tombstones VALUES(?1,?2,?3,?4) ON CONFLICT DO NOTHING",
        params![account, chat, id, seq],
    )?;
    tx.execute(
        "DELETE FROM message_media WHERE account_id=?1 AND chat_id=?2 AND log_id=?3",
        params![account, chat, id],
    )?;
    type Old = (i64, i64, Option<String>, bool, Option<String>);
    let old:Option<Old>=tx.query_row("SELECT revision,sent_at_ms,sender_id,deleted,source_local_pk FROM messages WHERE account_id=?1 AND room_id=?2 AND message_id=?3",params![account,chat.to_string(),id.to_string()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
    let revision = old.as_ref().map_or(0, |o| o.0);
    if let Some((revision, sent, sender, false, local)) = old {
        let payload = Payload::Message {
            room_id: chat.to_string(),
            message_id: id.to_string(),
            revision,
            sent_at_ms: sent,
            sender_id: sender,
            body: None,
            deleted: true,
            source_local_pk: local,
        };
        let hash = hex::encode(Sha256::digest(serde_json::to_vec(&payload)?));
        tx.execute("UPDATE messages SET deleted=1,body=NULL,payload_hash=?4 WHERE account_id=?1 AND room_id=?2 AND message_id=?3",params![account,chat.to_string(),id.to_string(),hash])?;
    }
    if inserted > 0 {
        tx.execute("INSERT INTO outbox(account_id,room_id,entity_id,kind,revision,source) VALUES(?1,?2,?3,'message_deleted',?4,'native_loco')",params![account,chat.to_string(),id.to_string(),revision])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{loco::codec::Packet, Store};
    use bson::doc;
    fn setup() -> (tempfile::TempDir, Store) {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let store = Store::initialize(d.path()).unwrap();
        (d, store)
    }
    fn log(id: i64, revision: i32, text: &str) -> Document {
        doc! {"chatId":7_i64,"logId":id,"prevId":0_i64,"type":1,"revision":revision,"sendAt":1700000000,"authorId":43_i64,"message":text}
    }
    fn receive(store: &Store, command: &str, body: Document) -> Result<()> {
        let p = Packet::request(1, command, body).unwrap();
        let seq = store.live_capture("42", "g", &p)?;
        store.live_apply("42", seq, &p)
    }
    fn feed(id: i64, kind: i32, target: i64) -> Document {
        let mut d = log(
            id,
            0,
            &serde_json::json!({"feedType":kind,"logId":target}).to_string(),
        );
        d.insert("type", 0);
        d
    }
    #[test]
    fn crash_before_refresh_hint_application_is_recovered_without_ack() {
        let (_dir, store) = setup();
        for (id, command, body) in [
            (1, "SYNCCREATE", doc! {"chatId":7_i64}),
            (2, "SPUSH", doc! {"t":4,"o":9_i64}),
        ] {
            let p = Packet::request(id, command, body).unwrap();
            store.live_capture("42", "g", &p).unwrap();
        }
        store.live_replay("42").unwrap();
        assert_eq!(store.room_refresh_next("42").unwrap().unwrap().0, 7);
        assert!(store.maintenance_requested("42", "friends").unwrap() > 0);
        let first = store.maintenance_requested("42", "friends").unwrap();
        store.live_replay("42").unwrap();
        assert_eq!(store.maintenance_requested("42", "friends").unwrap(), first);
    }
    #[test]
    fn offline_feeds_and_interleaved_edits_survive_replay_without_lost_work() {
        let (_d, store) = setup();
        receive(
            &store,
            "MSG",
            doc! {"chatId":7_i64,"chatLog":log(100,0,"original")},
        )
        .unwrap();
        receive(
            &store,
            "SYNCMSG",
            doc! {"isOK":true,"chatLogs":[feed(200,25,100)]},
        )
        .unwrap();
        store
            .record_request(
                "42",
                "g",
                8,
                "GETMSGS",
                &doc! {"chatIds":[7_i64],"logIds":[100_i64]},
            )
            .unwrap();
        receive(&store, "SYNCMODMSG", doc! {"chatLog":feed(201,25,100)}).unwrap();
        let p =
            Packet::request(8, "GETMSGS", doc! {"chatLogs":[log(100,1,"intermediate")]}).unwrap();
        let seq = store.live_capture("42", "g", &p).unwrap();
        store.live_apply("42", seq, &p).unwrap();
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row("SELECT count(*) FROM message_refresh", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        store
            .record_request(
                "42",
                "g",
                9,
                "GETMSGS",
                &doc! {"chatIds":[7_i64],"logIds":[100_i64]},
            )
            .unwrap();
        let p = Packet::request(9, "GETMSGS", doc! {"chatLogs":[log(100,2,"latest")]}).unwrap();
        let seq = store.live_capture("42", "g", &p).unwrap();
        store.live_apply("42", seq, &p).unwrap();
        store.live_replay("42").unwrap();
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row("SELECT count(*) FROM message_refresh", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        receive(
            &store,
            "SYNCMSG",
            doc! {"isOK":true,"chatLogs":[feed(202,14,100)]},
        )
        .unwrap();
        assert!(store
            .lock()
            .unwrap()
            .query_row(
                "SELECT deleted FROM messages WHERE message_id='100'",
                [],
                |r| r.get::<_, bool>(0)
            )
            .unwrap());
    }
    #[test]
    fn edit_target_revisions_then_delete_are_atomic_and_terminal_on_replay() {
        let (d, store) = setup();
        receive(
            &store,
            "MSG",
            doc! {"chatId":7_i64,"chatLog":log(100,0,"old searchable")},
        )
        .unwrap();
        receive(&store,"SYNCMODMSG",doc!{"c":7_i64,"chatLog":feed(200,25,100),"modifiedChatLog":log(100,1,"new searchable")}).unwrap();
        receive(&store,"SYNCMODMSG",doc!{"c":7_i64,"chatLog":feed(201,25,100),"modifiedChatLog":log(100,0,"old searchable")}).unwrap();
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row(
                    "SELECT body FROM messages WHERE message_id='100'",
                    [],
                    |r| r.get::<_, String>(0)
                )
                .unwrap(),
            "new searchable"
        );
        receive(&store, "SYNCDLMSG", doc! {"chatLog":feed(202,14,100)}).unwrap();
        receive(
            &store,
            "MSG",
            doc! {"chatId":7_i64,"chatLog":log(100,2,"must not return")},
        )
        .unwrap();
        drop(store);
        let store = Store::open(d.path()).unwrap();
        store.live_replay("42").unwrap();
        let conn = store.lock().unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT deleted,body FROM messages WHERE message_id='100'",
                [],
                |r| Ok((r.get::<_, bool>(0)?, r.get::<_, Option<String>>(1)?))
            )
            .unwrap(),
            (true, None)
        );
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM message_text WHERE message_text MATCH 'searchable'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM outbox WHERE kind='message_deleted'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
    }
    #[test]
    fn missing_edit_payload_queues_exact_target_and_cross_room_is_rejected() {
        let (_d, store) = setup();
        receive(&store, "SYNCMODMSG", doc! {"chatLog":feed(200,25,100)}).unwrap();
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row("SELECT log_id FROM message_refresh", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            100
        );
        let mut bad = log(100, 1, "foreign");
        bad.insert("chatId", 8_i64);
        assert!(receive(
            &store,
            "SYNCMODMSG",
            doc! {"chatLog":feed(201,25,100),"modifiedChatLog":bad}
        )
        .is_err());
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row("SELECT count(*) FROM messages", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
        receive(&store, "SYNCDLMSG", doc! {"chatLog":feed(202,14,100)}).unwrap();
        receive(
            &store,
            "MSG",
            doc! {"chatId":7_i64,"chatLog":log(100,0,"late original")},
        )
        .unwrap();
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row("SELECT count(*) FROM messages", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
}
