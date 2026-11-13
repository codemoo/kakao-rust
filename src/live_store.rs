//! Durable receive inbox, searchable projection and per-room recovery bounds.
//! Global app/config tokens stay unadvanced while unrelated handlers are pending.
use crate::{
    ingest::{apply_event, ImportEvent, ImportReport, Payload, Source},
    loco::{codec::Packet, response::ChatList},
    Error, Result, Store,
};
use bson::Document;
use rusqlite::{params, OptionalExtension, Transaction};
use serde::Serialize;

fn invalid() -> Error {
    Error::Invalid("invalid live message; durable packet retained".into())
}
#[derive(Default, Debug, Serialize)]
pub struct LiveStatus {
    pub phase: String,
    pub connected: bool,
    pub updated_at_ms: Option<i64>,
    pub last_packet_at_ms: Option<i64>,
    pub connections: i64,
    pub messages_received: i64,
    pub pending_packets: i64,
    pub pending_rooms: i64,
    pub error_category: Option<String>,
    pub server_status: Option<i64>,
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Range {
    pub chat: i64,
    pub cur: i64,
    pub max: i64,
    pub count: i32,
    pub target: i64,
}
impl Store {
    pub fn live_status(&self, account: &str) -> Result<LiveStatus> {
        let conn = self.lock()?;
        let mut s=conn.query_row("SELECT phase,updated_at_ms,last_packet_at_ms,connections,messages_received,error_category,server_status FROM live_status WHERE account_id=?1",[account],|r|Ok(LiveStatus{phase:r.get(0)?,updated_at_ms:Some(r.get(1)?),last_packet_at_ms:r.get(2)?,connections:r.get(3)?,messages_received:r.get(4)?,error_category:r.get(5)?,server_status:r.get(6)?,..Default::default()})).optional()?.unwrap_or(LiveStatus{phase:"stopped".into(),..Default::default()});
        s.connected = matches!(s.phase.as_str(), "connected" | "catching_up")
            && s.updated_at_ms
                .is_some_and(|t| chrono::Utc::now().timestamp_millis().saturating_sub(t) < 45_000);
        if !s.connected && matches!(s.phase.as_str(), "connected" | "catching_up") {
            s.phase = "stale".into();
        }
        s.pending_packets = conn.query_row(
            "SELECT count(*) FROM loco_inbox WHERE account_id=?1 AND applied=0",
            [account],
            |r| r.get(0),
        )?;
        s.pending_rooms = conn.query_row(
            "SELECT count(*) FROM loco_rooms WHERE account_id=?1 AND active=1 AND target>cursor",
            [account],
            |r| r.get(0),
        )?;
        Ok(s)
    }
    pub(crate) fn live_phase(
        &self,
        account: &str,
        generation: &str,
        phase: &str,
        error: Option<&str>,
        status: Option<i16>,
    ) -> Result<()> {
        self.lock()?.execute("INSERT INTO live_status(account_id,phase,generation,updated_at_ms,error_category,server_status,connections) VALUES(?1,?2,?3,?4,?5,?6,CASE WHEN ?2='connecting' THEN 1 ELSE 0 END) ON CONFLICT(account_id) DO UPDATE SET phase=excluded.phase,generation=excluded.generation,updated_at_ms=excluded.updated_at_ms,error_category=excluded.error_category,server_status=excluded.server_status,connections=live_status.connections+CASE WHEN ?2='connecting' THEN 1 ELSE 0 END",params![account,phase,generation,chrono::Utc::now().timestamp_millis(),error,status])?;
        Ok(())
    }
    pub(crate) fn live_seed(&self, account: &str) -> Result<()> {
        if self
            .drawer_restore_status()?
            .is_some_and(|s| s.phase != "restored")
        {
            return Err(Error::Conflict(
                "complete selected history restoration before live collection".into(),
            ));
        }
        // The completed restore is the starting point for NEW message catch-up,
        // not a claim that history before this boundary is complete.
        self.lock()?.execute("INSERT INTO loco_rooms(account_id,chat_id,read_log_id,cursor,target) SELECT account_id,chat_id,last_read_log_id,last_log_id,last_log_id FROM drawer_room_state WHERE account_id=?1 ON CONFLICT DO NOTHING",[account])?;
        Ok(())
    }
    pub(crate) fn live_inputs(&self, account: &str) -> Result<(Vec<i64>, Vec<i64>)> {
        let conn = self.lock()?;
        let mut stmt=conn.prepare("SELECT chat_id,read_log_id FROM loco_rooms WHERE account_id=?1 AND active=1 ORDER BY chat_id")?;
        let rows = stmt
            .query_map([account], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if rows.len() > 100_000 {
            return Err(invalid());
        }
        Ok(rows.into_iter().unzip())
    }
    pub(crate) fn live_capture(
        &self,
        account: &str,
        generation: &str,
        packet: &Packet,
    ) -> Result<i64> {
        let raw = packet.encode().map_err(|_| invalid())?;
        let now = chrono::Utc::now().timestamp_millis();
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO native_events(source,received_at_ms,payload) VALUES('loco',?1,?2)",
            params![now, raw.as_slice()],
        )?;
        let seq = tx.last_insert_rowid();
        tx.execute("INSERT INTO loco_inbox(sequence,account_id,generation,command,packet_id) VALUES(?1,?2,?3,?4,?5)",params![seq,account,generation,packet.header.command,packet.header.packet_id])?;
        tx.execute("UPDATE live_status SET last_packet_at_ms=?2,updated_at_ms=?2,messages_received=messages_received+CASE WHEN ?3='MSG' THEN 1 ELSE 0 END WHERE account_id=?1",params![account,now,packet.header.command])?;
        tx.commit()?;
        Ok(seq)
    }
    /// Replay committed packets after a crash, without sending acknowledgements
    /// from an obsolete socket generation. SYNC cursor bounds remain conservative.
    pub(crate) fn live_replay(&self, account: &str) -> Result<()> {
        let mut after = 0_i64;
        loop {
            let rows = {
                let conn = self.lock()?;
                let mut stmt = conn.prepare("SELECT i.sequence,n.payload FROM loco_inbox i JOIN native_events n USING(sequence) WHERE i.account_id=?1 AND i.applied=0 AND i.sequence>?2 AND i.command IN ('WRITE','MSG','SYNCMSG','LOGINLIST','LCHATLIST','PING','SYNCDLMSG','SYNCMODMSG','GETMSGS','GETMEM','CHATINFO','MEMLIST','MEMBER','CHGMETA','CHGMCMETA','CHGMOMETAS','CHGCHATST','LEFT','SYNCCREATE','NEWMEM','DELMEM','SPUSH','GETTOKEN','BLSYNC','BLMEMBER','DECUNREAD','SYNCACTION') ORDER BY i.sequence LIMIT 32")?;
                let rows = stmt
                    .query_map(params![account, after], |r| {
                        Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?))
                    })?
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                rows
            };
            if rows.is_empty() {
                return Ok(());
            }
            for (seq, raw) in rows {
                let mut decoder = crate::loco::codec::Decoder::default();
                decoder.feed(&raw).map_err(|_| invalid())?;
                let packet = decoder
                    .next_packet()
                    .map_err(|_| invalid())?
                    .ok_or_else(invalid)?;
                if !decoder.is_empty() {
                    return Err(invalid());
                }
                after = seq;
                // Retain rejected RPCs without scheduling them for application.
                // In particular a captured -950 must not block restart after refresh.
                let applicable = match packet.header.command.as_str() {
                    "LOGINLIST" => matches!(packet.header.status, 0 | -305 | -310),
                    "LCHATLIST" => matches!(packet.header.status, 0 | -310),
                    "SYNCMSG" | "PING" => packet.header.status == 0,
                    _ => true,
                };
                if applicable {
                    if matches!(
                        packet.header.command.as_str(),
                        "BLSYNC" | "BLMEMBER" | "GETTOKEN" | "SPUSH"
                    ) {
                        self.live_apply_optional(account, seq, &packet)?;
                    } else {
                        self.live_apply(account, seq, &packet)?;
                    }
                }
            }
        }
    }
    pub(crate) fn live_apply_optional(
        &self,
        account: &str,
        seq: i64,
        packet: &Packet,
    ) -> Result<()> {
        match self.live_apply(account, seq, packet) {
            Err(Error::Invalid(_)) => Ok(()), // Keep malformed optional effect pending; retain receive availability.
            result => result,
        }
    }
    pub(crate) fn live_apply(&self, account: &str, seq: i64, packet: &Packet) -> Result<()> {
        let mut conn = self.lock()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let raw:Vec<u8>=tx.query_row("SELECT n.payload FROM native_events n JOIN loco_inbox i USING(sequence) WHERE i.sequence=?1 AND i.account_id=?2",params![seq,account],|r|r.get(0))?;
        if raw != packet.encode().map_err(|_| invalid())?.as_slice() {
            return Err(invalid());
        }
        let mut projected = true;
        match packet.header.command.as_str() {
            "WRITE" => {
                if let Some((chat, mut log)) =
                    crate::outgoing::apply_reply(&tx, account, seq, packet)?
                {
                    // An incomplete acknowledgement must never overwrite a richer echo.
                    let id = log.get_i64("logId").map_err(|_| invalid())?;
                    let known:Option<bool>=tx.query_row("SELECT projected FROM loco_logs WHERE account_id=?1 AND chat_id=?2 AND log_id=?3",params![account,chat,id],|r|r.get(0)).optional()?;
                    if known.is_some_and(|complete| complete) {
                        projected = true;
                    } else {
                        if log.get_i32("sendAt").ok() == Some(0) {
                            log.remove("sendAt");
                        }
                        projected = store_log(&tx, account, chat, seq, 0, &log)?;
                    }
                }
            }
            "MSG" => {
                if packet.header.status != 0 {
                    return Err(invalid());
                }
                let chat = packet.body.get_i64("chatId").map_err(|_| invalid())?;
                projected = store_log(
                    &tx,
                    account,
                    chat,
                    seq,
                    0,
                    packet.body.get_document("chatLog").map_err(|_| invalid())?,
                )?;
                let log = packet.body.get_document("chatLog").map_err(|_| invalid())?;
                let id = log.get_i64("logId").map_err(|_| invalid())?;
                let prev = log.get_i64("prevId").map_err(|_| invalid())?;
                // A predecessor already covered by the local recovery boundary
                // needs no extra SYNCMSG. A gap remains queued for catch-up.
                tx.execute("UPDATE loco_rooms SET cursor=max(cursor,?3) WHERE account_id=?1 AND chat_id=?2 AND cursor>=?4",params![account,chat,id,prev])?;
            }
            "LOGINLIST" | "LCHATLIST" => {
                let list = ChatList::parse(
                    packet,
                    if packet.header.command == "LOGINLIST" {
                        Some(account.parse().map_err(|_| invalid())?)
                    } else {
                        None
                    },
                )
                .map_err(|_| invalid())?;
                for (index, chat) in list.chats.iter().enumerate() {
                    let id = chat.get_i64("c").map_err(|_| invalid())?;
                    let target = chat.get_i64("ll").unwrap_or(0).max(
                        chat.get_document("l")
                            .ok()
                            .and_then(|l| l.get_i64("logId").ok())
                            .unwrap_or(0),
                    );
                    if id <= 0 || target < 0 {
                        return Err(invalid());
                    }
                    tx.execute("INSERT INTO loco_rooms(account_id,chat_id,target,raw) VALUES(?1,?2,?3,?4) ON CONFLICT(account_id,chat_id) DO UPDATE SET target=max(target,excluded.target),raw=excluded.raw,active=1",params![account,id,target,bson::to_vec(chat).map_err(|_|invalid())?])?;
                    crate::room_sync::save_context(
                        &tx,
                        account,
                        id,
                        chat.get_str("t").map_err(|_| invalid())?,
                        chat.get_i64("li").unwrap_or(0).max(0),
                        seq,
                    )?;
                    crate::room_sync::invalidate_roster(&tx, account, id, seq)?;
                    crate::room_sync::queue(&tx, account, id, seq)?;
                    tx.execute("INSERT INTO rooms(account_id,room_id,revision,source) VALUES(?1,?2,-1,'native_loco') ON CONFLICT DO NOTHING",params![account,id.to_string()])?;
                    if let Ok(log) = chat.get_document("l") {
                        store_log(&tx, account, id, seq, index, log)?;
                    }
                }
                for id in list.deleted.into_iter().chain(list.kicked) {
                    tx.execute(
                        "UPDATE loco_rooms SET active=0 WHERE account_id=?1 AND chat_id=?2",
                        params![account, id],
                    )?;
                    crate::room_sync::invalidate_roster(&tx, account, id, seq)?;
                }
                // Other app/config/secret-chat effects remain raw and pending.
                projected = false;
            }
            "SYNCMSG" => {
                if packet.header.status != 0 {
                    return Err(invalid());
                }
                packet.body.get_bool("isOK").map_err(|_| invalid())?;
                let empty = Vec::new();
                let logs = match packet.body.get("chatLogs") {
                    None | Some(bson::Bson::Null) => &empty,
                    Some(bson::Bson::Array(logs)) => logs,
                    _ => return Err(invalid()),
                };
                if logs.len() > 100_000 {
                    return Err(invalid());
                }
                for (index, log) in logs.iter().enumerate() {
                    let log = log.as_document().ok_or_else(invalid)?;
                    let chat = log.get_i64("chatId").map_err(|_| invalid())?;
                    projected &= store_log(&tx, account, chat, seq, index, log)?;
                }
            }
            "SYNCDLMSG" | "SYNCMODMSG" => {
                if packet.header.status != 0 {
                    return Err(invalid());
                }
                projected = crate::mutations::apply(&tx, account, seq, &packet.body)?;
            }
            "MEMLIST" => {
                projected = crate::room_sync::response_ok(packet)
                    && crate::room_sync::apply_roster(&tx, account, seq, &packet.body)?;
            }
            "CHATINFO" | "GETMEM" | "MEMBER" => {
                if crate::room_sync::response_ok(packet) {
                    projected = crate::room_sync::apply(
                        &tx,
                        account,
                        seq,
                        &packet.header.command,
                        &packet.body,
                    )?;
                } else {
                    projected = false;
                }
            }
            "GETMSGS" => {
                if packet.header.status != 0 {
                    return Ok(());
                }
                if let Some(request) = crate::room_sync::request(&tx, account, seq)? {
                    let chats = request.get_array("chatIds").map_err(|_| invalid())?;
                    let ids = request.get_array("logIds").map_err(|_| invalid())?;
                    if chats.len() != ids.len() {
                        return Err(invalid());
                    }
                    let empty = Vec::new();
                    let logs = match packet.body.get("chatLogs") {
                        None | Some(bson::Bson::Null) => &empty,
                        Some(bson::Bson::Array(logs)) => logs,
                        _ => return Err(invalid()),
                    };
                    let cutoff:i64=tx.query_row("SELECT r.refresh_sequence FROM loco_requests r JOIN loco_inbox i ON r.account_id=i.account_id AND r.generation=i.generation AND r.packet_id=i.packet_id WHERE i.sequence=?1",[seq],|r|r.get(0))?;
                    {
                        for (index, log) in logs.iter().enumerate() {
                            let log = log.as_document().ok_or_else(invalid)?;
                            let chat = log.get_i64("chatId").map_err(|_| invalid())?;
                            let id = log.get_i64("logId").map_err(|_| invalid())?;
                            if !chats
                                .iter()
                                .zip(ids)
                                .any(|(c, i)| c.as_i64() == Some(chat) && i.as_i64() == Some(id))
                            {
                                return Err(invalid());
                            }
                            let applied = store_log(&tx, account, chat, seq, index, log)?;
                            if applied {
                                tx.execute("DELETE FROM message_refresh WHERE account_id=?1 AND chat_id=?2 AND log_id=?3 AND requested_sequence<=?4",params![account,chat,id,cutoff])?;
                            }
                            projected &= applied;
                        }
                    }
                } else {
                    projected = false;
                }
            }
            "DECUNREAD" => {
                if packet.header.status != 0 {
                    return Err(invalid());
                }
                let chat = packet.body.get_i64("chatId").map_err(|_| invalid())?;
                let user = packet.body.get_i64("userId").map_err(|_| invalid())?;
                let mark = packet.body.get_i64("watermark").map_err(|_| invalid())?;
                if chat <= 0 || user <= 0 || mark < 0 {
                    return Err(invalid());
                }
                let known: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM loco_rooms r WHERE r.account_id=?1 AND r.chat_id=?2 AND r.active=1 AND (CAST(?3 AS TEXT)=?1 OR EXISTS(SELECT 1 FROM room_active_members m JOIN room_roster_state s USING(account_id,chat_id) WHERE m.account_id=r.account_id AND m.chat_id=r.chat_id AND m.user_id=?3 AND s.complete=1)))",
                    params![account, chat,user],
                    |r| r.get(0),
                )?;
                if known {
                    // Observed read state never creates a roster entry or advances collection.
                    tx.execute("INSERT INTO room_read_watermarks VALUES(?1,?2,?3,?4,?5) ON CONFLICT(account_id,chat_id,user_id) DO UPDATE SET watermark=excluded.watermark,capture_sequence=excluded.capture_sequence WHERE excluded.watermark>room_read_watermarks.watermark",params![account,chat,user,mark,seq])?;
                    if user.to_string() == account {
                        tx.execute("UPDATE loco_rooms SET read_log_id=max(read_log_id,?3) WHERE account_id=?1 AND chat_id=?2",params![account,chat,mark])?;
                    }
                }
            }
            "SYNCACTION" => {
                if packet.header.status != 0 {
                    return Err(invalid());
                }
                packet.body.get_i64("chatId").map_err(|_| invalid())?;
                packet.body.get_i64("userId").map_err(|_| invalid())?;
                packet.body.get_i32("type").map_err(|_| invalid())?;
                packet.body.get_i64("logId").map_err(|_| invalid())?;
                // Typing is ephemeral and has no message/read/roster cursor effect.
            }
            "LEFT" => {
                if packet.header.status != 0 {
                    return Err(invalid());
                }
                let chat = packet.body.get_i64("chatId").map_err(|_| invalid())?;
                tx.execute(
                    "UPDATE loco_rooms SET active=0 WHERE account_id=?1 AND chat_id=?2",
                    params![account, chat],
                )?;
                crate::room_sync::invalidate_roster(&tx, account, chat, seq)?;
                // Preserve historical names/logs; global token remains unapplied.
                projected = false;
            }
            "CHGMETA" => {
                if packet.header.status != 0 {
                    return Err(invalid());
                }
                let chat = packet.body.get_i64("chatId").map_err(|_| invalid())?;
                if chat <= 0 {
                    return Err(invalid());
                }
                let meta = packet.body.get_document("meta").map_err(|_| invalid())?;
                crate::room_sync::apply_meta(
                    &tx,
                    account,
                    chat,
                    meta,
                    chrono::Utc::now().timestamp_millis(),
                )?;
                crate::room_sync::queue(&tx, account, chat, seq)?;
                projected = false; // li/global token and other metadata consumers remain pending.
            }
            "CHGMCMETA" | "CHGMOMETAS" | "CHGCHATST" | "SYNCCREATE" | "NEWMEM" | "DELMEM" => {
                let chat = if matches!(packet.header.command.as_str(), "NEWMEM" | "DELMEM") {
                    let feed = packet
                        .body
                        .get_document("chatLog")
                        .ok()
                        .and_then(|v| v.get_i64("chatId").ok());
                    let direct = packet.body.get_i64("c").ok();
                    if matches!((direct,feed),(Some(a),Some(b)) if a!=b) {
                        return Err(invalid());
                    }
                    direct.or(feed)
                } else {
                    packet.body.get_i64("chatId").ok()
                }
                .filter(|v| *v > 0)
                .ok_or_else(invalid)?;
                if matches!(packet.header.command.as_str(), "SYNCCREATE" | "NEWMEM") {
                    tx.execute("INSERT INTO loco_rooms(account_id,chat_id,target) VALUES(?1,?2,0) ON CONFLICT DO NOTHING",params![account,chat])?;
                    tx.execute("INSERT INTO rooms(account_id,room_id,revision,source) VALUES(?1,?2,-1,'native_loco') ON CONFLICT DO NOTHING",params![account,chat.to_string()])?;
                }
                if matches!(
                    packet.header.command.as_str(),
                    "NEWMEM" | "DELMEM" | "SYNCCREATE"
                ) {
                    crate::room_sync::invalidate_roster(&tx, account, chat, seq)?;
                }
                crate::room_sync::queue(&tx, account, chat, seq)?;
                projected = false; // Refresh hint is durable; other native effects stay pending.
            }
            "BLMEMBER" => {
                projected = packet.header.status == 0
                    && crate::block_sync::apply_profiles(&tx, account, seq, &packet.body)?;
            }
            "BLSYNC" => {
                if packet.header.status == 0 {
                    crate::block_sync::apply(&tx, account, seq, &packet.body)?;
                }
                projected = false; // Native identity effects and protocol confirmation remain pending.
            }
            "SPUSH" | "GETTOKEN" => {
                if packet.header.status == 0 {
                    crate::domain_sync::apply(
                        &tx,
                        account,
                        seq,
                        &packet.header.command,
                        &packet.body,
                    )?;
                }
                projected = false; // Observed tokens are distinct from completed feature handlers.
            }
            "PING" => (),
            _ => projected = false,
        }
        if projected {
            tx.execute("UPDATE loco_inbox SET applied=1 WHERE sequence=?1", [seq])?;
            tx.execute(
                "UPDATE native_events SET processed=1 WHERE sequence=?1",
                [seq],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
    pub(crate) fn live_range(
        &self,
        account: &str,
        deferred: &std::collections::HashSet<i64>,
    ) -> Result<Option<Range>> {
        let conn = self.lock()?;
        let candidate = {
            let mut stmt = conn.prepare("SELECT chat_id,cursor,target FROM loco_rooms WHERE account_id=?1 AND active=1 AND target>cursor ORDER BY chat_id")?;
            let mut rows = stmt.query([account])?;
            let mut candidate = None;
            while let Some(row) = rows.next()? {
                let chat: i64 = row.get(0)?;
                if !deferred.contains(&chat) {
                    candidate = Some((chat, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?));
                    break;
                }
            }
            candidate
        };
        let Some((chat, cur, target)) = candidate else {
            return Ok(None);
        };
        drop(conn);
        self.live_range_at(account, chat, cur, target).map(Some)
    }
    pub(crate) fn live_range_at(
        &self,
        account: &str,
        chat: i64,
        cur: i64,
        target: i64,
    ) -> Result<Range> {
        let conn = self.lock()?;
        let (count,max):(i32,i64)=conn.query_row("SELECT count(*),coalesce(max(log_id),0) FROM (SELECT log_id FROM (SELECT log_id FROM loco_logs WHERE account_id=?1 AND chat_id=?2 AND log_id>?3 AND log_id<=?4 UNION SELECT log_id FROM drawer_records WHERE account_id=?1 AND chat_id=?2 AND log_id>?3 AND log_id<=?4) ORDER BY log_id LIMIT 300)",params![account,chat,cur,target],|r|Ok((r.get(0)?,r.get(1)?)))?;
        Ok(Range {
            chat,
            cur,
            max: if count == 300 { max } else { target },
            count,
            target,
        })
    }
    pub(crate) fn live_advance(&self, account: &str, range: Range, next: i64) -> Result<()> {
        if next < range.cur || next > range.max || (next == range.cur && range.cur != range.max) {
            return Err(invalid());
        }
        self.lock()?.execute(
            "UPDATE loco_rooms SET cursor=max(cursor,?3) WHERE account_id=?1 AND chat_id=?2",
            params![account, range.chat, next],
        )?;
        Ok(())
    }
}
pub(crate) fn store_log(
    tx: &Transaction<'_>,
    account: &str,
    chat: i64,
    seq: i64,
    index: usize,
    log: &Document,
) -> Result<bool> {
    crate::loco::response::validate_chat_log(log).map_err(|_| invalid())?;
    let id = log.get_i64("logId").map_err(|_| invalid())?;
    let prev = log.get_i64("prevId").map_err(|_| invalid())?;
    let revision = log.get_i32("revision").unwrap_or(0) as i64;
    let kind = log.get_i32("type").map_err(|_| invalid())?;
    if chat <= 0
        || id <= 0
        || prev < 0
        || prev >= id
        || revision < 0
        || log.get_i64("chatId").ok() != Some(chat)
    {
        return Err(invalid());
    }
    crate::outgoing::reconcile_echo(tx, account, chat, log)?;
    tx.execute("INSERT INTO loco_rooms(account_id,chat_id,target) VALUES(?1,?2,?3) ON CONFLICT(account_id,chat_id) DO UPDATE SET target=max(target,excluded.target)",params![account,chat,id])?;
    let known:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM room_members WHERE account_id=?1 AND chat_id=?2 AND user_id=?3)",params![account,chat,log.get_i64("authorId").unwrap_or(-1)],|r|r.get(0))?;
    if !known && log.get_i64("authorId").unwrap_or(-1) > 0 {
        crate::room_sync::queue(tx, account, chat, seq)?;
    }
    let prior: Option<(i64, i64)> = tx
        .query_row(
            "SELECT revision,capture_sequence FROM loco_logs WHERE account_id=?1 AND chat_id=?2 AND log_id=?3",
            params![account, chat, id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let raw = bson::to_vec(log).map_err(|_| invalid())?;
    if prior
        .as_ref()
        .is_some_and(|(v, captured)| *v > revision || (*v == revision && *captured > seq))
    {
        return Ok(true);
    }
    // Unknown fields may change without a message revision. Retain every original
    // packet; only canonical text conflicts prevent the searchable projection.
    tx.execute("INSERT INTO loco_logs(account_id,chat_id,log_id,prev_id,revision,kind,raw,capture_sequence,projected) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,0) ON CONFLICT(account_id,chat_id,log_id) DO UPDATE SET prev_id=excluded.prev_id,revision=excluded.revision,kind=excluded.kind,raw=excluded.raw,capture_sequence=excluded.capture_sequence,projected=0",params![account,chat,id,prev,revision,kind,raw,seq])?;
    let tombstone:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM native_tombstones WHERE account_id=?1 AND chat_id=?2 AND log_id=?3) OR EXISTS(SELECT 1 FROM drawer_tombstones WHERE account_id=?1 AND chat_id=?2 AND log_id=?3) OR EXISTS(SELECT 1 FROM messages WHERE account_id=?1 AND room_id=?4 AND message_id=?5 AND deleted=1)",params![account,chat,id,chat.to_string(),id.to_string()],|r|r.get(0))?;
    if tombstone {
        tx.execute(
            "UPDATE loco_logs SET projected=1 WHERE account_id=?1 AND chat_id=?2 AND log_id=?3",
            params![account, chat, id],
        )?;
        return Ok(true);
    }
    if matches!(kind, 0 | 0x10000000)
        && crate::mutations::apply_feed(tx, account, chat, seq, log, None)?
    {
        tx.execute(
            "UPDATE loco_logs SET projected=1 WHERE account_id=?1 AND chat_id=?2 AND log_id=?3",
            params![account, chat, id],
        )?;
        return Ok(true);
    }
    if crate::mutations::suppress_projection(
        tx,
        account,
        &chat.to_string(),
        &id.to_string(),
        revision,
    )? {
        return Ok(true);
    }
    tx.execute("DELETE FROM message_media WHERE account_id=?1 AND chat_id=?2 AND log_id=?3 AND revision<?4",params![account,chat,id,revision])?;
    crate::media::capture(tx, account, chat, id, revision, kind, log)?;
    if !matches!(kind, 1 | 26) {
        remove_superseded_projection(tx, account, chat, id, revision)?;
        let captured:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM message_media WHERE account_id=?1 AND chat_id=?2 AND log_id=?3 AND revision=?4)",params![account,chat,id,revision],|r|r.get(0))?;
        if captured {
            tx.execute(
                "UPDATE loco_logs SET projected=1 WHERE account_id=?1 AND chat_id=?2 AND log_id=?3",
                params![account, chat, id],
            )?;
        }
        return Ok(captured);
    }
    let (Ok(message), Ok(send_at), Ok(author)) = (
        log.get_str("message"),
        log.get_i32("sendAt"),
        log.get_i64("authorId"),
    ) else {
        remove_superseded_projection(tx, account, chat, id, revision)?;
        return Ok(false);
    };
    if send_at < 0 {
        return Err(invalid());
    }
    let payload = Payload::Message {
        room_id: chat.to_string(),
        message_id: id.to_string(),
        revision,
        sent_at_ms: i64::from(send_at) * 1000,
        sender_id: (author > 0).then(|| author.to_string()),
        body: Some(message.to_owned()),
        deleted: false,
        source_local_pk: None,
    };
    let event = ImportEvent {
        schema_version: 1,
        account_id: account.into(),
        event_id: format!("{seq}:{index}"),
        source: Source::NativeLoco,
        stream_id: format!("live:{chat}:{id}"),
        position: seq,
        cursor: seq.to_string(),
        payload,
    };
    event.validate()?;
    tx.execute_batch("SAVEPOINT live_projection")?;
    let result = apply_event(tx, &event, &mut ImportReport::default());
    if matches!(result, Err(Error::Conflict(_))) {
        tx.execute_batch("ROLLBACK TO live_projection; RELEASE live_projection")?;
        return Ok(false);
    }
    result?;
    tx.execute_batch("RELEASE live_projection")?;
    tx.execute(
        "UPDATE loco_logs SET projected=1 WHERE account_id=?1 AND chat_id=?2 AND log_id=?3",
        params![account, chat, id],
    )?;
    Ok(true)
}

fn remove_superseded_projection(
    tx: &Transaction<'_>,
    account: &str,
    chat: i64,
    id: i64,
    revision: i64,
) -> Result<()> {
    // Equal revision with absent fields cannot erase a richer restored message.
    let removed = tx.execute("DELETE FROM messages WHERE account_id=?1 AND room_id=?2 AND message_id=?3 AND revision<?4 AND deleted=0", params![account,chat.to_string(),id.to_string(),revision])?;
    if removed > 0 {
        tx.execute("INSERT INTO outbox(account_id,room_id,entity_id,kind,revision,source) VALUES(?1,?2,?3,'message_projection_removed',?4,'native_loco')",params![account,chat.to_string(),id.to_string(),revision])?;
    }
    Ok(())
}
