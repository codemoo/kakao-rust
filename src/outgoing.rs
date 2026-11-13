//! Durable, explicitly authorized text sends. No message or credential logging.
use crate::{
    auth::{Principal, Scope},
    Error, Result, Store,
};
use bson::Document;
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub(crate) const SCHEMA: &str = r#"
CREATE TABLE outgoing_messages(
 id TEXT PRIMARY KEY, account_id TEXT NOT NULL, chat_id INTEGER NOT NULL,
 credential_id TEXT NOT NULL REFERENCES api_credentials(id), idempotency_key TEXT NOT NULL,
 body TEXT NOT NULL, payload_hash TEXT NOT NULL, extra TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('queued','dispatching','sent','rejected','unknown','cancelled')),
 created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL, deadline_ms INTEGER NOT NULL,
 baseline_log_id INTEGER NOT NULL DEFAULT 0,
 generation TEXT NOT NULL, client_id INTEGER, packet_id INTEGER, server_log_id INTEGER,
 server_status INTEGER, failure TEXT,
 UNIQUE(account_id,idempotency_key), UNIQUE(account_id,generation,packet_id)
) STRICT;
CREATE TABLE outgoing_attempts(
 account_id TEXT NOT NULL, generation TEXT NOT NULL, packet_id INTEGER NOT NULL,
 outgoing_id TEXT NOT NULL REFERENCES outgoing_messages(id),
 PRIMARY KEY(account_id,generation,packet_id)
) STRICT;
CREATE INDEX outgoing_pending ON outgoing_messages(account_id,state,created_at_ms);
"#;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TextInput {
    pub text: String,
}
#[derive(Serialize)]
pub(crate) struct SendStatus {
    pub request_id: String,
    pub room_id: String,
    pub state: String,
    pub message_id: Option<String>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub server_status: Option<i32>,
    pub failure: Option<String>,
}
type PendingRow = (
    String,
    i64,
    String,
    String,
    String,
    i64,
    String,
    Option<i64>,
);
// Deliberately no Debug: the job holds private message content.
pub(crate) struct Job {
    pub id: String,
    pub chat: i64,
    pub text: String,
    pub extra: String,
    pub client_id: Option<i64>,
}
fn status(tx: &rusqlite::Connection, account: &str, chat: i64, id: &str) -> Result<SendStatus> {
    tx.query_row(
        "SELECT id,chat_id,state,server_log_id,created_at_ms,updated_at_ms,server_status,failure
             FROM outgoing_messages
             WHERE account_id=?1
             AND chat_id=?2
             AND id=?3",
        params![account, chat, id],
        |r| {
            Ok(SendStatus {
                request_id: r.get(0)?,
                room_id: r.get::<_, i64>(1)?.to_string(),
                state: r.get(2)?,
                message_id: r.get::<_, Option<i64>>(3)?.map(|v| v.to_string()),
                created_at_ms: r.get(4)?,
                updated_at_ms: r.get(5)?,
                server_status: r.get(6)?,
                failure: r.get(7)?,
            })
        },
    )
    .optional()?
    .ok_or(Error::NotFound)
}
fn room_id(room: &str) -> Result<i64> {
    let id = room
        .parse::<i64>()
        .map_err(|_| Error::Invalid("invalid room identifier".into()))?;
    if id <= 0 || id.to_string() != room {
        return Err(Error::Invalid("invalid room identifier".into()));
    }
    Ok(id)
}
fn normal_room(tx: &Transaction<'_>, account: &str, chat: i64) -> Result<bool> {
    Ok(tx.query_row(
        "SELECT EXISTS(SELECT 1
             FROM loco_rooms l
             JOIN room_identity_context c USING(account_id,chat_id)
             WHERE l.account_id=?1
             AND l.chat_id=?2
             AND l.active=1
             AND c.room_type IN ('DirectChat','MultiChat'))",
        params![account, chat],
        |r| r.get(0),
    )?)
}
fn credential_valid(
    tx: &Transaction<'_>,
    account: &str,
    chat: i64,
    credential: &str,
    now: i64,
) -> Result<bool> {
    let row:Option<(String,Option<String>)>=tx.query_row("SELECT scopes,rooms FROM api_credentials WHERE id=?1 AND account_id=?2 AND revoked_at IS NULL AND expires_at>?3",params![credential,account,now/1000],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
    let Some((scopes, rooms)) = row else {
        return Ok(false);
    };
    let scopes: BTreeSet<Scope> = serde_json::from_str(&scopes)?;
    let rooms: Option<BTreeSet<String>> = rooms.map(|s| serde_json::from_str(&s)).transpose()?;
    Ok(scopes.contains(&Scope::MessagesWrite)
        && rooms.is_none_or(|r| r.contains(&chat.to_string())))
}
impl Store {
    pub(crate) fn enqueue_text(
        &self,
        p: &Principal,
        room: &str,
        key: &str,
        input: TextInput,
        now: i64,
    ) -> Result<SendStatus> {
        p.require(Scope::MessagesWrite)?;
        p.require_room(room)?;
        let chat = room_id(room)?;
        if key.is_empty()
            || key.len() > 128
            || !key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
        {
            return Err(Error::Invalid(
                "a stable Idempotency-Key is required".into(),
            ));
        }
        if input.text.trim().is_empty()
            || input.text.encode_utf16().count() > 3999
            || input
                .text
                .chars()
                .any(|c| c.is_control() && c != '\n' && c != '\t')
        {
            return Err(Error::Invalid(
                "text must be nonblank and at most 3999 UTF-16 units".into(),
            ));
        }
        let hash = hex::encode(Sha256::digest(serde_json::to_vec(&(room, &input.text))?));
        let mut conn = self.lock()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old:Option<(String,i64,String,String)>=tx.query_row("SELECT id,chat_id,payload_hash,credential_id FROM outgoing_messages WHERE account_id=?1 AND idempotency_key=?2",params![p.account_id,key],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
        if let Some((id, old_chat, old_hash, credential)) = old {
            if old_chat != chat || old_hash != hash || credential != p.credential_id {
                return Err(Error::Conflict(
                    "idempotency key already used for another request".into(),
                ));
            }
            return status(&tx, &p.account_id, chat, &id);
        }
        if !normal_room(&tx, &p.account_id, chat)? {
            return Err(Error::Conflict(
                "text sending requires a known active ordinary chat".into(),
            ));
        }
        let generation:Option<String>=tx.query_row("SELECT generation FROM live_status WHERE account_id=?1 AND phase='connected' AND updated_at_ms>?2 AND generation IS NOT NULL",params![p.account_id,now-45_000],|r|r.get(0)).optional()?;
        let generation = generation.ok_or(Error::ServiceUnavailable("collector_not_connected"))?;
        let pending:i64=tx.query_row("SELECT count(*) FROM outgoing_messages WHERE account_id=?1 AND state IN ('queued','dispatching')",[&p.account_id],|r|r.get(0))?;
        if pending >= 32 {
            return Err(Error::Busy);
        }
        // Preprocessing is performed before a durable send is accepted.
        let extra = crate::send_text::prepare_extra(&tx, &p.account_id, &input.text)?;
        let id = uuid::Uuid::new_v4().simple().to_string();
        tx.execute("INSERT INTO outgoing_messages(id,account_id,chat_id,credential_id,idempotency_key,body,payload_hash,extra,state,created_at_ms,updated_at_ms,deadline_ms,generation)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'queued',?9,?9,?10,?11)",params![id,p.account_id,chat,p.credential_id,key,input.text,hash,extra,now,now+60_000,generation])?;
        let result = status(&tx, &p.account_id, chat, &id)?;
        tx.commit()?;
        Ok(result)
    }
    pub(crate) fn outgoing_status(
        &self,
        p: &Principal,
        room: &str,
        id: &str,
    ) -> Result<SendStatus> {
        p.require(Scope::MessagesWrite)?;
        p.require_room(room)?;
        status(&*self.lock()?, &p.account_id, room_id(room)?, id)
    }
    pub(crate) fn recover_outgoing(&self, account: &str) -> Result<()> {
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE outgoing_messages
             SET state='unknown',failure='connection_lost',updated_at_ms=?2
             WHERE account_id=?1
             AND state='dispatching'",
            params![account, chrono::Utc::now().timestamp_millis()],
        )?;
        tx.execute(
            "UPDATE outgoing_messages
             SET state=CASE WHEN client_id IS NULL THEN 'cancelled'
             ELSE 'unknown'
             END,failure='collector_restarted',updated_at_ms=?2
             WHERE account_id=?1
             AND state='queued'",
            params![account, chrono::Utc::now().timestamp_millis()],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub(crate) fn next_outgoing(
        &self,
        account: &str,
        generation: &str,
        now: i64,
    ) -> Result<Option<Job>> {
        let mut conn = self.lock()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        loop {
            let row: Option<PendingRow> = tx
                .query_row(
                    "SELECT id,chat_id,body,extra,credential_id,deadline_ms,generation,client_id
             FROM outgoing_messages
             WHERE account_id=?1
             AND state='queued'
             ORDER BY created_at_ms,id
             LIMIT 1",
                    [account],
                    |r| {
                        Ok((
                            r.get(0)?,
                            r.get(1)?,
                            r.get(2)?,
                            r.get(3)?,
                            r.get(4)?,
                            r.get(5)?,
                            r.get(6)?,
                            r.get(7)?,
                        ))
                    },
                )
                .optional()?;
            let Some((id, chat, text, extra, credential, deadline, queued_generation, client_id)) =
                row
            else {
                tx.commit()?;
                return Ok(None);
            };
            let failure = if deadline <= now {
                Some("queue_expired")
            } else if queued_generation != generation && client_id.is_none() {
                Some("connection_changed")
            } else if !credential_valid(&tx, account, chat, &credential, now)? {
                Some("authorization_changed")
            } else if !normal_room(&tx, account, chat)? {
                Some("room_unavailable")
            } else {
                None
            };
            if let Some(failure) = failure {
                tx.execute(
                    "UPDATE outgoing_messages
             SET state=CASE WHEN client_id IS NULL THEN 'cancelled'
             ELSE 'unknown'
             END,failure=?2,updated_at_ms=?3
             WHERE id=?1",
                    params![id, failure, now],
                )?;
                continue;
            }
            tx.commit()?;
            return Ok(Some(Job {
                id,
                chat,
                text,
                extra,
                client_id,
            }));
        }
    }
    pub(crate) fn prepare_outgoing(
        &self,
        account: &str,
        generation: &str,
        job: &Job,
        client_id: i64,
        packet_id: i32,
        now: i64,
    ) -> Result<bool> {
        let mut conn = self.lock()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let credential: Option<String> = tx
            .query_row(
                "SELECT credential_id
             FROM outgoing_messages
             WHERE id=?1
             AND account_id=?2
             AND chat_id=?3
             AND (generation=?4 OR client_id IS NOT NULL)
             AND state='queued'
             AND deadline_ms>?5",
                params![job.id, account, job.chat, generation, now],
                |r| r.get(0),
            )
            .optional()?;
        let Some(credential) = credential else {
            return Ok(false);
        };
        if !credential_valid(&tx, account, job.chat, &credential, now)?
            || !normal_room(&tx, account, job.chat)?
        {
            return Ok(false);
        };
        if job.client_id.is_none() {
            match crate::send_text::prepare_extra(&tx, account, &job.text) {
                Ok(extra) if extra == job.extra => (),
                Err(Error::ServiceUnavailable(_)) => return Ok(false),
                Ok(_) | Err(Error::Invalid(_)) => {
                    tx.execute("UPDATE outgoing_messages SET state='cancelled',failure='text_settings_changed',updated_at_ms=?2 WHERE id=?1",params![job.id,now])?;
                    tx.commit()?;
                    return Ok(false);
                }
                Err(error) => return Err(error),
            }
        }
        if client_id <= 0 {
            return Ok(false);
        }
        // Avoid reusing an identifier already assigned by this installation.
        let used:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM outgoing_messages WHERE account_id=?1 AND client_id=?2 AND id!=?3)",params![account,client_id,job.id],|r|r.get(0))?;
        if used {
            return Ok(false);
        }
        tx.execute("INSERT INTO outgoing_attempts(account_id,generation,packet_id,outgoing_id) VALUES(?1,?2,?3,?4)",params![account,generation,packet_id,job.id])?;
        let retry_seconds: Option<i64> = tx
            .query_row(
                "SELECT CAST(value AS INTEGER) FROM metadata WHERE key=?1",
                [format!("write_retry_seconds:{account}")],
                |r| r.get(0),
            )
            .optional()?;
        tx.execute("UPDATE outgoing_messages
             SET state='dispatching',failure=NULL,generation=?7,client_id=?2,packet_id=?3,updated_at_ms=?4,baseline_log_id=CASE WHEN client_id IS NULL THEN (SELECT target
             FROM loco_rooms
             WHERE account_id=?5
             AND chat_id=?6)
             ELSE baseline_log_id
             END,deadline_ms=CASE WHEN client_id IS NULL THEN ?8
             ELSE deadline_ms
             END
             WHERE id=?1",params![job.id,client_id,packet_id,now,account,job.chat,generation,now.saturating_add(retry_seconds.unwrap_or(0).saturating_mul(1000))])?;
        tx.commit()?;
        Ok(true)
    }
    pub(crate) fn outgoing_transport_failure(
        &self,
        account: &str,
        id: &str,
        retryable: bool,
    ) -> Result<()> {
        let now = chrono::Utc::now().timestamp_millis();
        let conn = self.lock()?;
        let raw:Option<Vec<u8>>=conn.query_row("SELECT payload FROM native_events WHERE source='more_settings' ORDER BY sequence DESC LIMIT 1",[],|r|r.get(0)).optional()?;
        let enabled = raw
            .and_then(|r| serde_json::from_slice::<serde_json::Value>(&r).ok())
            .and_then(|v| v.get("available").and_then(|v| v.as_i64()))
            .is_some_and(|flags| flags & 0x100000 != 0);
        conn.execute(
            "UPDATE outgoing_messages
             SET state=CASE WHEN ?4
             AND deadline_ms>?3 THEN 'queued'
             ELSE 'unknown'
             END,failure=CASE WHEN ?4
             AND deadline_ms>?3 THEN 'retry_pending'
             ELSE 'response_not_confirmed'
             END,updated_at_ms=?3
             WHERE account_id=?1
             AND id=?2
             AND state='dispatching'",
            params![account, id, now, retryable && enabled],
        )?;
        Ok(())
    }
}

pub(crate) fn apply_reply(
    tx: &Transaction<'_>,
    account: &str,
    seq: i64,
    packet: &crate::loco::codec::Packet,
) -> Result<Option<(i64, Document)>> {
    let row: Option<(String, i64, i64, String, String, String)> = tx
        .query_row(
            "SELECT o.id,o.chat_id,o.client_id,o.body,o.extra,o.state
             FROM outgoing_messages o
             JOIN outgoing_attempts a ON a.outgoing_id=o.id
             JOIN loco_inbox i ON i.account_id=a.account_id
             AND i.generation=a.generation
             AND i.packet_id=a.packet_id
             WHERE i.sequence=?1
             AND o.account_id=?2
             AND i.command='WRITE'",
            params![seq, account],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            },
        )
        .optional()?;
    let Some((id, chat, client_id, text, extra, state)) = row else {
        return Ok(None);
    };
    if !matches!(
        state.as_str(),
        "queued" | "dispatching" | "unknown" | "sent"
    ) {
        return Ok(None);
    };
    let self_user = account
        .parse::<i64>()
        .map_err(|_| Error::Storage("invalid outgoing account".into()))?;
    let now = chrono::Utc::now().timestamp_millis();
    match crate::loco::outgoing::parse_reply(packet, chat, client_id, self_user, &text, &extra) {
        crate::loco::outgoing::WriteReply::Rejected(code) => {
            if state != "sent" {
                tx.execute("UPDATE outgoing_messages SET state='rejected',server_status=?2,failure='server_rejected',updated_at_ms=?3 WHERE id=?1",params![id,code,now])?;
            }
            Ok(None)
        }
        crate::loco::outgoing::WriteReply::Invalid => {
            if state != "sent" {
                tx.execute("UPDATE outgoing_messages SET state='unknown',failure='invalid_response',updated_at_ms=?2 WHERE id=?1",params![id,now])?;
            }
            Ok(None)
        }
        crate::loco::outgoing::WriteReply::Accepted { log_id, log } => {
            let existing: Option<i64> = tx.query_row(
                "SELECT server_log_id FROM outgoing_messages WHERE id=?1",
                [&id],
                |r| r.get(0),
            )?;
            if existing.is_some_and(|prior| prior != log_id) {
                return Ok(None);
            }
            tx.execute("UPDATE outgoing_messages SET state='sent',server_log_id=?2,server_status=0,failure=NULL,updated_at_ms=?3 WHERE id=?1",params![id,log_id,now])?;
            Ok(Some((chat, log)))
        }
    }
}

pub(crate) fn reconcile_echo(
    tx: &Transaction<'_>,
    account: &str,
    chat: i64,
    log: &Document,
) -> Result<()> {
    let Some(user) = account.parse::<i64>().ok() else {
        return Ok(());
    };
    if log.get_i64("authorId").ok() != Some(user) {
        return Ok(());
    }
    let (Ok(client), Ok(id)) = (log.get_i64("msgId"), log.get_i64("logId")) else {
        return Ok(());
    };
    if client <= 0 || id <= 0 {
        return Ok(());
    }
    // A self echo is authoritative only for this exact room and saved local message.
    tx.execute(
        "UPDATE outgoing_messages
             SET state='sent',server_log_id=?4,server_status=0,failure=NULL,updated_at_ms=?5
             WHERE account_id=?1
             AND chat_id=?2
             AND client_id=?3
             AND state IN ('queued','dispatching','unknown')
             AND body=?6
             AND baseline_log_id<?4",
        params![
            account,
            chat,
            client,
            id,
            chrono::Utc::now().timestamp_millis(),
            log.get_str("message").unwrap_or("")
        ],
    )?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests;
