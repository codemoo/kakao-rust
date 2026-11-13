//! Receive-side room/member enrichment. GETMEM entries are observed identities,
//! never an authoritative removal list or proof that omitted members left.
use crate::{Error, Result, Store};
use bson::{Bson, Document};
use rusqlite::{params, OptionalExtension, Transaction};
fn invalid() -> Error {
    Error::Invalid("invalid room metadata; previous state retained".into())
}
pub(crate) fn response_ok(packet: &crate::loco::codec::Packet) -> bool {
    packet.header.status == 0 && matches!(packet.body.get("status"), None | Some(Bson::Int32(0)))
}
pub(crate) fn save_context(
    tx: &Transaction<'_>,
    account: &str,
    chat: i64,
    kind: &str,
    link: i64,
    seq: i64,
) -> Result<()> {
    if kind.is_empty() || kind.len() > 128 || link < 0 {
        return Err(invalid());
    }
    let prior:Option<(String,i64,i64)>=tx.query_row("SELECT room_type,link_id,capture_sequence FROM room_identity_context WHERE account_id=?1 AND chat_id=?2",params![account,chat],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
    if prior.as_ref().is_some_and(|p| p.2 >= seq) {
        return Ok(());
    }
    if prior
        .as_ref()
        .is_some_and(|p| p.0 != kind || (p.1 != link && link != 0))
    {
        invalidate_roster(tx, account, chat, seq)?;
    }
    tx.execute("INSERT INTO room_identity_context VALUES(?1,?2,?3,?4,?5) ON CONFLICT(account_id,chat_id) DO UPDATE SET room_type=excluded.room_type,link_id=CASE WHEN excluded.link_id=0 AND excluded.room_type=room_identity_context.room_type THEN room_identity_context.link_id ELSE excluded.link_id END,capture_sequence=excluded.capture_sequence",params![account,chat,kind,link,seq])?;
    Ok(())
}
pub(crate) fn migrate_context(tx: &Transaction<'_>) -> Result<()> {
    // Backup room types protect historical open-chat names before network refresh.
    tx.execute("INSERT OR IGNORE INTO room_identity_context SELECT account_id,chat_id,json_extract(payload,'$.type'),0,-1 FROM drawer_rooms WHERE json_valid(payload) AND json_type(payload,'$.type')='text'",[])?;
    let lists = tx
        .prepare("SELECT account_id,chat_id,raw FROM loco_rooms WHERE raw IS NOT NULL")?
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, Vec<u8>>(2)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for (account, chat, raw) in lists {
        let body: Document = bson::from_slice(&raw).map_err(|_| invalid())?;
        save_context(
            tx,
            &account,
            chat,
            body.get_str("t").map_err(|_| invalid())?,
            body.get_i64("li").unwrap_or(0).max(0),
            0,
        )?;
    }
    let rows = tx
        .prepare("SELECT account_id,chat_id,raw,capture_sequence FROM room_details")?
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for (account, chat, raw, seq) in rows {
        let body: Document = bson::from_slice(&raw).map_err(|_| invalid())?;
        save_context(
            tx,
            &account,
            chat,
            body.get_str("type").map_err(|_| invalid())?,
            body.get_i64("li").unwrap_or(0).max(0),
            seq,
        )?;
    }
    // Legacy identity rows have no proven link/type at capture time. Keep them
    // privately but wait for a fresh bound response before attaching provenance.
    Ok(())
}
pub(crate) fn queue(tx: &Transaction<'_>, account: &str, chat: i64, seq: i64) -> Result<()> {
    tx.execute("INSERT INTO room_refresh(account_id,chat_id,requested_sequence) VALUES(?1,?2,?3) ON CONFLICT(account_id,chat_id) DO UPDATE SET requested_sequence=max(requested_sequence,excluded.requested_sequence)",params![account,chat,seq])?;
    Ok(())
}
pub(crate) fn invalidate_roster(
    tx: &Transaction<'_>,
    account: &str,
    chat: i64,
    seq: i64,
) -> Result<()> {
    tx.execute("INSERT INTO room_roster_state(account_id,chat_id,capture_sequence,updated_at_ms) VALUES(?1,?2,?3,?4) ON CONFLICT(account_id,chat_id) DO UPDATE SET complete=0,capture_sequence=excluded.capture_sequence WHERE excluded.capture_sequence>room_roster_state.capture_sequence",params![account,chat,seq,chrono::Utc::now().timestamp_millis()])?;
    Ok(())
}

/// Native MEMLIST returns the current other-member list when nonempty. Its
/// empty response means reuse existing IDs, not an empty authoritative roster.
pub(crate) fn member_ids(body: &Document) -> Result<Vec<i64>> {
    body.get_str("type").map_err(|_| invalid())?;
    let ids = match body.get("memberIds") {
        None | Some(Bson::Null) => vec![],
        Some(Bson::Array(values)) if values.len() <= 100_000 => values
            .iter()
            .map(|v| v.as_i64().ok_or_else(invalid))
            .collect::<Result<Vec<_>>>()?,
        _ => return Err(invalid()),
    };
    let mut seen = std::collections::HashSet::new();
    if ids.iter().any(|id| *id <= 0 || !seen.insert(*id)) {
        return Err(invalid());
    }
    Ok(ids)
}
pub(crate) fn apply_roster(
    tx: &Transaction<'_>,
    account: &str,
    seq: i64,
    body: &Document,
) -> Result<bool> {
    let Some(req) = request(tx, account, seq)? else {
        return Ok(false);
    };
    let chat = req.get_i64("chatId").map_err(|_| invalid())?;
    if chat <= 0
        || req.get_i64("token").ok() != Some(0)
        || req.get_bool("excludeMe").ok() != Some(true)
    {
        return Err(invalid());
    }
    let ids = member_ids(body)?;
    let kind = body.get_str("type").map_err(|_| invalid())?;
    if !matches!(kind, "DirectChat" | "MultiChat" | "OD" | "OM") {
        return Ok(false);
    }
    let token = match body.get("token") {
        None => 0,
        Some(Bson::Int64(v)) if *v >= 0 => *v,
        _ => return Err(invalid()),
    };
    let own: i64 = account.parse().map_err(|_| invalid())?;
    if own <= 0 || ids.contains(&own) {
        return Err(invalid());
    }
    let active: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM loco_rooms WHERE account_id=?1 AND chat_id=?2 AND active=1)",
        params![account, chat],
        |r| r.get(0),
    )?;
    let issued: i64=tx.query_row("SELECT r.issued_sequence FROM loco_requests r JOIN loco_inbox i ON r.account_id=i.account_id AND r.generation=i.generation AND r.packet_id=i.packet_id AND r.command=i.command WHERE i.account_id=?1 AND i.sequence=?2",params![account,seq],|r|r.get(0))?;
    let context:Option<(String,i64,i64)>=tx.query_row("SELECT room_type,link_id,capture_sequence FROM room_identity_context WHERE account_id=?1 AND chat_id=?2",params![account,chat],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
    if !context.is_some_and(|(t, li, captured)| {
        t == kind && captured <= issued && (!matches!(kind, "OD" | "OM") || li > 0)
    }) {
        return Ok(false);
    }
    let old: Option<i64> = tx
        .query_row(
            "SELECT capture_sequence FROM room_roster_state WHERE account_id=?1 AND chat_id=?2",
            params![account, chat],
            |r| r.get(0),
        )
        .optional()?;
    if !active || old.is_some_and(|v| v > issued) {
        return Ok(false);
    }
    // An empty token-zero response cannot establish new coverage.
    if ids.is_empty() {
        return Ok(true);
    }
    tx.execute(
        "DELETE FROM room_active_members WHERE account_id=?1 AND chat_id=?2",
        params![account, chat],
    )?;
    for id in ids.into_iter().chain(std::iter::once(own)) {
        tx.execute(
            "INSERT INTO room_active_members VALUES(?1,?2,?3)",
            params![account, chat, id],
        )?;
    }
    tx.execute("INSERT INTO room_roster_state VALUES(?1,?2,?3,1,?4,?5) ON CONFLICT(account_id,chat_id) DO UPDATE SET member_token=excluded.member_token,complete=1,capture_sequence=excluded.capture_sequence,updated_at_ms=excluded.updated_at_ms",params![account,chat,token,seq,chrono::Utc::now().timestamp_millis()])?;
    Ok(true)
}
pub(crate) fn request(tx: &Transaction<'_>, account: &str, seq: i64) -> Result<Option<Document>> {
    let bytes:Option<Vec<u8>>=tx.query_row("SELECT r.body FROM loco_requests r JOIN loco_inbox i ON r.account_id=i.account_id AND r.generation=i.generation AND r.packet_id=i.packet_id AND r.command=i.command WHERE i.account_id=?1 AND i.sequence=?2",params![account,seq],|r|r.get(0)).optional()?;
    bytes
        .map(|b| bson::from_slice(&b).map_err(|_| invalid()))
        .transpose()
}
pub(crate) fn apply(
    tx: &Transaction<'_>,
    account: &str,
    seq: i64,
    command: &str,
    body: &Document,
) -> Result<bool> {
    let Some(req) = request(tx, account, seq)? else {
        return Ok(false);
    };
    let chat = req.get_i64("chatId").map_err(|_| invalid())?;
    let now = chrono::Utc::now().timestamp_millis();
    let issued:i64=tx.query_row("SELECT r.issued_sequence FROM loco_requests r JOIN loco_inbox i ON r.account_id=i.account_id AND r.generation=i.generation AND r.packet_id=i.packet_id AND r.command=i.command WHERE i.account_id=?1 AND i.sequence=?2",params![account,seq],|r|r.get(0))?;
    let newer_context:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM room_identity_context WHERE account_id=?1 AND chat_id=?2 AND capture_sequence>?3)",params![account,chat,issued],|r|r.get(0))?;
    if newer_context {
        if command == "CHATINFO"
            && body
                .get_document("chatInfo")
                .ok()
                .and_then(|d| d.get_i64("chatId").ok())
                != Some(chat)
        {
            return Err(invalid());
        }
        if command == "MEMBER" && body.get_i64("chatId").ok() != Some(chat) {
            return Err(invalid());
        }
        return Ok(false);
    }
    if command == "CHATINFO" {
        let info = body.get_document("chatInfo").map_err(|_| invalid())?;
        if info.get_i64("chatId").ok() != Some(chat) {
            return Err(invalid());
        }
        let kind = info.get_str("type").map_err(|_| invalid())?;
        save_context(
            tx,
            account,
            chat,
            kind,
            info.get_i64("li").unwrap_or(0).max(0),
            seq,
        )?;
        info.get_i32("activeMembersCount").map_err(|_| invalid())?;
        info.get_i32("newMessageCount").map_err(|_| invalid())?;
        info.get_bool("pushAlert").map_err(|_| invalid())?;
        tx.execute("INSERT INTO room_details(account_id,chat_id,raw,updated_at_ms,capture_sequence) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(account_id,chat_id) DO UPDATE SET raw=excluded.raw,updated_at_ms=excluded.updated_at_ms,capture_sequence=excluded.capture_sequence WHERE excluded.capture_sequence>room_details.capture_sequence",params![account,chat,bson::to_vec(info).map_err(|_|invalid())?,now,seq])?;
        if let Some(Bson::Array(metas)) = info.get("chatMetas") {
            for meta in metas {
                let meta = meta.as_document().ok_or_else(invalid)?;
                apply_meta(tx, account, chat, meta, now)?;
            }
        }
        // Display members are partial but their names can resolve unknown senders.
        if let Some(Bson::Array(members)) = info.get("displayMembers") {
            for value in members {
                let member = value.as_document().ok_or_else(invalid)?;
                save_member(tx, account, chat, member, false, now, seq)?;
            }
        }
    } else {
        if command == "MEMBER" && body.get_i64("chatId").ok() != Some(chat) {
            return Err(invalid());
        }
        let token = if command == "GETMEM" {
            Some(body.get_i64("token").map_err(|_| invalid())?)
        } else {
            None
        };
        match body.get("members") {
            None | Some(Bson::Null) => (),
            Some(Bson::Array(members)) if members.len() <= 100_000 => {
                for member in members {
                    if command == "MEMBER" {
                        let id = member
                            .as_document()
                            .and_then(|d| d.get_i64("userId").ok())
                            .ok_or_else(invalid)?;
                        if !req
                            .get_array("memberIds")
                            .map_err(|_| invalid())?
                            .iter()
                            .any(|v| v.as_i64() == Some(id))
                        {
                            return Err(invalid());
                        }
                    }
                    save_member(
                        tx,
                        account,
                        chat,
                        member.as_document().ok_or_else(invalid)?,
                        true,
                        now,
                        seq,
                    )?;
                }
            }
            _ => return Err(invalid()),
        }
        tx.execute(
            "UPDATE room_details SET member_token=?3 WHERE account_id=?1 AND chat_id=?2 AND ?3 IS NOT NULL",
            params![account, chat, token],
        )?;
    }
    Ok(true)
}
pub(crate) fn apply_meta(
    tx: &Transaction<'_>,
    account: &str,
    chat: i64,
    meta: &Document,
    now: i64,
) -> Result<()> {
    let kind = meta.get_i32("type").map_err(|_| invalid())?;
    let revision = meta.get_i64("revision").map_err(|_| invalid())?;
    let content = meta.get_str("content").map_err(|_| invalid())?;
    meta.get_i64("authorId").map_err(|_| invalid())?;
    meta.get_i32("updatedAt").map_err(|_| invalid())?;
    if kind == 3 && revision >= 0 {
        // Shared title is literal text. Empty means no explicit shared title.
        let key = format!("room_title_revision:{account}:{chat}");
        let old: Option<i64> = tx
            .query_row(
                "SELECT CAST(value AS INTEGER) FROM metadata WHERE key=?1",
                [&key],
                |r| r.get(0),
            )
            .optional()?;
        if old.is_none_or(|rev| rev < revision) {
            tx.execute("INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",params![key,revision.to_string()])?;
            tx.execute("INSERT INTO rooms(account_id,room_id,revision,display_name,name_source,observed_at_ms,source) VALUES(?1,?2,?3,?4,'kakao_shared_title',?5,'native_loco') ON CONFLICT(account_id,room_id) DO UPDATE SET revision=excluded.revision,display_name=excluded.display_name,name_source=excluded.name_source,observed_at_ms=excluded.observed_at_ms,source=excluded.source",params![account,chat.to_string(),revision,(!content.is_empty()).then_some(content),now])?;
        }
    }
    Ok(())
}
fn save_member(
    tx: &Transaction<'_>,
    account: &str,
    chat: i64,
    member: &Document,
    full: bool,
    now: i64,
    seq: i64,
) -> Result<()> {
    let id = member.get_i64("userId").map_err(|_| invalid())?;
    let name = member.get_str("nickName").map_err(|_| invalid())?;
    let kind = if full {
        member.get_i32("type").map_err(|_| invalid())?
    } else {
        -1
    };
    if id <= 0 || name.len() > 65536 {
        return Err(invalid());
    }
    tx.execute("INSERT INTO room_members VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(account_id,chat_id,user_id) DO UPDATE SET nickname=excluded.nickname,member_type=CASE WHEN excluded.member_type=-1 THEN member_type ELSE excluded.member_type END,raw=excluded.raw,updated_at_ms=excluded.updated_at_ms,capture_sequence=excluded.capture_sequence WHERE excluded.capture_sequence>room_members.capture_sequence",params![account,chat,id,name,kind,bson::to_vec(member).map_err(|_|invalid())?,now,seq])?;
    tx.execute("INSERT INTO room_member_origins SELECT ?1,?2,?3,link_id,room_type FROM room_identity_context WHERE account_id=?1 AND chat_id=?2 AND EXISTS(SELECT 1 FROM room_members WHERE account_id=?1 AND chat_id=?2 AND user_id=?3 AND capture_sequence=?4) ON CONFLICT(account_id,chat_id,user_id) DO UPDATE SET link_id=excluded.link_id,room_type=excluded.room_type",params![account,chat,id,seq])?;
    Ok(())
}
impl Store {
    pub(crate) fn room_refresh_next(&self, account: &str) -> Result<Option<(i64, i64)>> {
        Ok(self.lock()?.query_row("SELECT q.chat_id,q.requested_sequence FROM room_refresh q JOIN loco_rooms r ON r.account_id=q.account_id AND r.chat_id=q.chat_id WHERE q.account_id=?1 AND r.active=1 AND q.retry_at_ms<=?2 AND (q.requested_sequence>q.completed_sequence OR NOT EXISTS(SELECT 1 FROM room_details d WHERE d.account_id=q.account_id AND d.chat_id=q.chat_id AND d.updated_at_ms>?3)) ORDER BY q.retry_at_ms,q.chat_id LIMIT 1",params![account,chrono::Utc::now().timestamp_millis(),chrono::Utc::now().timestamp_millis()-86_400_000],|r|Ok((r.get(0)?,r.get(1)?))).optional()?)
    }
    pub(crate) fn room_refresh_finish(
        &self,
        account: &str,
        chat: i64,
        requested: i64,
        ok: bool,
    ) -> Result<()> {
        self.lock()?.execute("UPDATE room_refresh SET completed_sequence=CASE WHEN ?4 THEN max(completed_sequence,?3) ELSE completed_sequence END,retry_at_ms=?5 WHERE account_id=?1 AND chat_id=?2",params![account,chat,requested,ok,chrono::Utc::now().timestamp_millis()+if ok{0}else{300_000}])?;
        Ok(())
    }
    pub(crate) fn record_request(
        &self,
        account: &str,
        generation: &str,
        id: i32,
        command: &str,
        body: &Document,
    ) -> Result<()> {
        if matches!(
            command,
            "WRITE" | "CHATINFO" | "GETMEM" | "GETMSGS" | "MEMLIST" | "MEMBER" | "BLMEMBER"
        ) {
            self.lock()?.execute("INSERT INTO loco_requests(account_id,generation,packet_id,command,body,issued_sequence,refresh_sequence) VALUES(?1,?2,?3,?4,?5,(SELECT coalesce(max(sequence),0) FROM native_events),(SELECT coalesce(max(requested_sequence),0) FROM message_refresh WHERE account_id=?1)) ON CONFLICT(account_id,generation,packet_id) DO UPDATE SET command=excluded.command,body=excluded.body,issued_sequence=excluded.issued_sequence,refresh_sequence=excluded.refresh_sequence",params![account,generation,id,command,bson::to_vec(body).map_err(|_|invalid())?])?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loco::codec::Packet;
    use bson::doc;
    #[test]
    fn migration_never_attaches_legacy_alias_to_latest_link() {
        let (dir, store) = crate::runtime::tests::setup();
        let raw = bson::to_vec(&doc! {"chatId":7_i64,"type":"OM","li":200_i64}).unwrap();
        store.lock().unwrap().execute("INSERT INTO room_details(account_id,chat_id,raw,updated_at_ms,capture_sequence) VALUES('42',7,?1,1000,20)",[raw]).unwrap();
        store
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO room_members VALUES('42',7,43,'Old alias',1000,X'00',1000,10)",
                [],
            )
            .unwrap();
        let raw = bson::to_vec(&doc! {"c":8_i64,"t":"OD","li":300_i64}).unwrap();
        store
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO loco_rooms(account_id,chat_id,raw) VALUES('42',8,?1)",
                [raw],
            )
            .unwrap();
        store.lock().unwrap().execute_batch("DROP TABLE outgoing_attempts; DROP TABLE outgoing_messages; DROP TABLE blocked_profile_retry; DROP TABLE blocked_profiles; DROP TABLE block_sync_state; DROP TABLE blocked_users; DROP TABLE room_member_origins; DROP TABLE room_identity_context; DROP TABLE domain_tokens; PRAGMA user_version=12;").unwrap();
        drop(store);
        let store = Store::open(dir.path()).unwrap();
        let conn = store.lock().unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM room_member_origins", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row(
                "SELECT room_type FROM room_identity_context WHERE chat_id=8",
                [],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
            "OD"
        );
        assert_eq!(
            conn.query_row("SELECT count(*) FROM room_members", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
    #[test]
    fn roster_requires_matching_context_that_existed_before_request() {
        for (response_type, late) in [("MultiChat", false), ("OM", true)] {
            let (_dir, store) = crate::runtime::tests::setup();
            store
                .lock()
                .unwrap()
                .execute(
                    "INSERT INTO loco_rooms(account_id,chat_id) VALUES('42',7)",
                    [],
                )
                .unwrap();
            if !late {
                store
                    .lock()
                    .unwrap()
                    .execute(
                        "INSERT INTO room_identity_context VALUES('42',7,'OM',100,0)",
                        [],
                    )
                    .unwrap();
            }
            store
                .record_request(
                    "42",
                    "g",
                    1000,
                    "MEMLIST",
                    &crate::loco::request::memlist(7),
                )
                .unwrap();
            if late {
                let p = Packet::request(0, "PING", doc! {}).unwrap();
                let seq = store.live_capture("42", "g", &p).unwrap();
                let mut conn = store.lock().unwrap();
                let tx = conn.transaction().unwrap();
                save_context(&tx, "42", 7, "OM", 100, seq).unwrap();
                tx.commit().unwrap();
            }
            let p = Packet::request(
                1000,
                "MEMLIST",
                doc! {"type":response_type,"memberIds":[43_i64]},
            )
            .unwrap();
            let seq = store.live_capture("42", "g", &p).unwrap();
            store.live_apply("42", seq, &p).unwrap();
            assert!(active_ids(&store).is_empty());
        }
    }
    #[test]
    fn open_roster_needs_link_context_and_inflight_member_cannot_cross_reassignment() {
        let (_dir, store) = crate::runtime::tests::setup();
        store
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO loco_rooms(account_id,chat_id) VALUES('42',7)",
                [],
            )
            .unwrap();
        for (i, link) in [(1000, 0), (1001, 100)] {
            store.lock().unwrap().execute("INSERT INTO room_identity_context VALUES('42',7,'OM',?1,0) ON CONFLICT DO UPDATE SET link_id=excluded.link_id",[link]).unwrap();
            store
                .record_request("42", "g", i, "MEMLIST", &crate::loco::request::memlist(7))
                .unwrap();
            let p = Packet::request(i, "MEMLIST", doc! {"type":"OM","memberIds":[43_i64]}).unwrap();
            let seq = store.live_capture("42", "g", &p).unwrap();
            store.live_apply("42", seq, &p).unwrap();
            assert_eq!(active_ids(&store).is_empty(), link == 0);
        }
        store
            .record_request(
                "42",
                "g",
                1002,
                "MEMBER",
                &crate::loco::request::member(7, &[43]),
            )
            .unwrap();
        let changed = Packet::request(0, "PING", doc! {}).unwrap();
        let changed_seq = store.live_capture("42", "g", &changed).unwrap();
        {
            let mut conn = store.lock().unwrap();
            let tx = conn.transaction().unwrap();
            save_context(&tx, "42", 7, "OM", 200, changed_seq).unwrap();
            tx.commit().unwrap();
        }
        let p=Packet::request(1002,"MEMBER",doc!{"chatId":7_i64,"members":[{"userId":43_i64,"nickName":"Old link name","type":1000}]}).unwrap();
        let seq = store.live_capture("42", "g", &p).unwrap();
        store.live_apply("42", seq, &p).unwrap();
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row("SELECT count(*) FROM room_members", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert!(!store
            .lock()
            .unwrap()
            .query_row("SELECT complete FROM room_roster_state", [], |r| r
                .get::<_, bool>(0))
            .unwrap());
    }
    fn roster_reply(store: &Store, packet_id: i32, ids: Vec<i64>) -> Result<()> {
        store.lock()?.execute(
            "INSERT OR IGNORE INTO room_identity_context VALUES('42',7,'MultiChat',0,0)",
            [],
        )?;
        store.record_request(
            "42",
            "g",
            packet_id,
            "MEMLIST",
            &crate::loco::request::memlist(7),
        )?;
        let packet = Packet::request(
            packet_id,
            "MEMLIST",
            doc! {"type":"MultiChat","memberIds":ids,"token":55_i64},
        )
        .unwrap();
        let seq = store.live_capture("42", "g", &packet)?;
        store.live_apply("42", seq, &packet)
    }
    fn active_ids(store: &Store) -> Vec<i64> {
        store
            .lock()
            .unwrap()
            .prepare(
                "SELECT user_id FROM room_active_members WHERE account_id='42' ORDER BY user_id",
            )
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap()
    }
    #[test]
    fn deleted_or_kicked_room_invalidates_roster_and_rejects_inflight_reply_on_replay() {
        for field in ["delChatIds", "kc"] {
            let (_dir, store) = crate::runtime::tests::setup();
            store
                .lock()
                .unwrap()
                .execute(
                    "INSERT INTO loco_rooms(account_id,chat_id) VALUES('42',7)",
                    [],
                )
                .unwrap();
            roster_reply(&store, 1000, vec![43]).unwrap();
            store
                .lock()
                .unwrap()
                .execute(
                    "INSERT INTO room_members VALUES('42',7,43,'Historical',3,X'00',1000,1)",
                    [],
                )
                .unwrap();
            store
                .record_request(
                    "42",
                    "g",
                    1001,
                    "MEMLIST",
                    &crate::loco::request::memlist(7),
                )
                .unwrap();
            let mut body = doc! {"userId":42_i64,"eof":true};
            body.insert(field, vec![7_i64]);
            let deletion = Packet::request(1002, "LOGINLIST", body).unwrap();
            let seq = store.live_capture("42", "g", &deletion).unwrap();
            store.live_apply("42", seq, &deletion).unwrap();
            let reply = Packet::request(
                1001,
                "MEMLIST",
                doc! {"type":"MultiChat","memberIds":[44_i64],"token":55_i64},
            )
            .unwrap();
            let seq = store.live_capture("42", "g", &reply).unwrap();
            store.live_apply("42", seq, &reply).unwrap();
            store.live_replay("42").unwrap();
            let conn = store.lock().unwrap();
            assert!(!conn
                .query_row("SELECT complete FROM room_roster_state", [], |r| r
                    .get::<_, bool>(0))
                .unwrap());
            assert!(!conn
                .query_row("SELECT active FROM loco_rooms", [], |r| r.get::<_, bool>(0))
                .unwrap());
            assert_eq!(
                conn.query_row(
                    "SELECT count(*) FROM room_members WHERE user_id=43",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
                1
            );
            drop(conn);
            assert_eq!(active_ids(&store), vec![42, 43]);
        }
    }
    #[test]
    fn memlist_replaces_active_ids_preserves_history_and_ignores_empty() {
        let (_dir, store) = crate::runtime::tests::setup();
        store
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO loco_rooms(account_id,chat_id) VALUES('42',7)",
                [],
            )
            .unwrap();
        roster_reply(&store, 1000, vec![]).unwrap();
        assert!(active_ids(&store).is_empty());
        roster_reply(&store, 1001, vec![43, 9007199254740993]).unwrap();
        assert_eq!(active_ids(&store), vec![42, 43, 9007199254740993]);
        store
            .record_request(
                "42",
                "g",
                1002,
                "MEMBER",
                &crate::loco::request::member(7, &[43]),
            )
            .unwrap();
        let packet=Packet::request(1002,"MEMBER",doc!{"chatId":7_i64,"members":[{"userId":43_i64,"nickName":"Historical name","type":3}]}).unwrap();
        let seq = store.live_capture("42", "g", &packet).unwrap();
        store.live_apply("42", seq, &packet).unwrap();
        roster_reply(&store, 1003, vec![44]).unwrap();
        roster_reply(&store, 1004, vec![]).unwrap();
        assert_eq!(active_ids(&store), vec![42, 44]);
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row(
                    "SELECT count(*) FROM room_members WHERE user_id=43",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            1
        );
        assert!(roster_reply(&store, 1005, vec![45, 45]).is_err());
        assert_eq!(active_ids(&store), vec![42, 44]);
    }
    #[test]
    fn roster_response_cannot_overwrite_interleaved_membership_change_or_cross_room_profile() {
        let (_dir, store) = crate::runtime::tests::setup();
        store
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO loco_rooms(account_id,chat_id) VALUES('42',7)",
                [],
            )
            .unwrap();
        roster_reply(&store, 1000, vec![43]).unwrap();
        store
            .record_request(
                "42",
                "g",
                1001,
                "MEMLIST",
                &crate::loco::request::memlist(7),
            )
            .unwrap();
        let change = Packet::request(0, "DELMEM", doc! {"c":7_i64}).unwrap();
        let seq = store.live_capture("42", "g", &change).unwrap();
        store.live_apply("42", seq, &change).unwrap();
        let packet = Packet::request(
            1001,
            "MEMLIST",
            doc! {"type":"MultiChat","memberIds":[44_i64],"token":55_i64},
        )
        .unwrap();
        let seq = store.live_capture("42", "g", &packet).unwrap();
        store.live_apply("42", seq, &packet).unwrap();
        assert_eq!(active_ids(&store), vec![42, 43]);
        assert!(!store
            .lock()
            .unwrap()
            .query_row("SELECT complete FROM room_roster_state", [], |r| r
                .get::<_, bool>(0))
            .unwrap());
        store
            .record_request(
                "42",
                "g",
                1002,
                "MEMBER",
                &crate::loco::request::member(7, &[43]),
            )
            .unwrap();
        for (chat, user) in [(8_i64, 43_i64), (7, 44)] {
            let p = Packet::request(
                1002,
                "MEMBER",
                doc! {"chatId":chat,"members":[{"userId":user,"nickName":"Wrong","type":3}]},
            )
            .unwrap();
            let seq = store.live_capture("42", "g", &p).unwrap();
            assert!(store.live_apply("42", seq, &p).is_err());
        }
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row("SELECT count(*) FROM room_members", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    #[test]
    fn shared_title_push_applies_monotonically_and_invalid_payload_rolls_back() {
        let (_dir, store) = crate::runtime::tests::setup();
        for (revision, title) in [(2_i64, "Latest"), (1, "Older")] {
            let p=Packet::request(0,"CHGMETA",doc!{"chatId":7_i64,"meta":{"type":3,"revision":revision,"authorId":43_i64,"updatedAt":1700000000,"content":title}}).unwrap();
            let seq = store.live_capture("42", "g", &p).unwrap();
            store.live_apply("42", seq, &p).unwrap();
        }
        let p = Packet::request(0, "CHGMETA", doc! {"chatId":7_i64}).unwrap();
        let seq = store.live_capture("42", "g", &p).unwrap();
        assert!(store.live_apply("42", seq, &p).is_err());
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row(
                    "SELECT display_name FROM rooms WHERE room_id='7'",
                    [],
                    |r| r.get::<_, String>(0)
                )
                .unwrap(),
            "Latest"
        );
    }
    #[test]
    fn request_binding_members_are_not_clear_on_empty_and_titles_are_literal() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let store = Store::initialize(d.path()).unwrap();
        store
            .record_request("42", "g", 1000, "CHATINFO", &doc! {"chatId":7_i64})
            .unwrap();
        let p=Packet::request(1000,"CHATINFO",doc!{"chatInfo":{"chatId":7_i64,"type":"MultiChat","activeMembersCount":2,"newMessageCount":0,"pushAlert":true,"chatMetas":[{"type":3,"revision":5_i64,"authorId":43_i64,"updatedAt":1700000000,"content":"Shared title"}]}}).unwrap();
        let seq = store.live_capture("42", "g", &p).unwrap();
        store.live_apply("42", seq, &p).unwrap();
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row("SELECT display_name FROM rooms", [], |r| r
                    .get::<_, String>(0))
                .unwrap(),
            "Shared title"
        );
        for (id, members) in [
            (
                1001,
                vec![doc! {"userId":43_i64,"nickName":"Member","type":3}],
            ),
            (1002, vec![]),
        ] {
            store
                .record_request("42", "g", id, "GETMEM", &doc! {"chatId":7_i64})
                .unwrap();
            let p = Packet::request(id, "GETMEM", doc! {"token":55_i64,"members":members}).unwrap();
            let seq = store.live_capture("42", "g", &p).unwrap();
            store.live_apply("42", seq, &p).unwrap();
        }
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row("SELECT count(*) FROM room_members", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        let p = Packet::request(1000, "CHATINFO", doc! {"chatInfo":{"chatId":8_i64}}).unwrap();
        let seq = store.live_capture("42", "g", &p).unwrap();
        assert!(store.live_apply("42", seq, &p).is_err());
    }
}
