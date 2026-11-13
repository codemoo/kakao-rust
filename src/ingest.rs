//! Caller-supplied normalized JSONL only. No Android DB or native protocol decoding.
use crate::{error::valid_id, Error, Result, Store};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::BufRead;

const MAX_LINE: usize = 512 * 1024;
const MAX_BATCH: usize = 128 * 1024 * 1024;
const MAX_EVENTS: usize = 100_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportEvent {
    pub schema_version: u32,
    pub account_id: String,
    pub event_id: String,
    pub source: Source,
    pub stream_id: String,
    /// Strictly increasing for new events in this source stream; replays keep original positions.
    pub position: i64,
    pub cursor: String,
    pub payload: Payload,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    OfflineImport,
    #[serde(skip_deserializing)]
    NativeLoco,
}
impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OfflineImport => "offline_import",
            Self::NativeLoco => "native_loco",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Payload {
    Message {
        room_id: String,
        message_id: String,
        revision: i64,
        sent_at_ms: i64,
        sender_id: Option<String>,
        body: Option<String>,
        deleted: bool,
        source_local_pk: Option<String>,
    },
    Room {
        room_id: String,
        revision: i64,
        display_name: Option<String>,
        name_source: Option<String>,
        observed_at_ms: Option<i64>,
    },
    Friend {
        user_id: String,
        revision: i64,
        display_name: Option<String>,
        name_source: Option<String>,
        observed_at_ms: Option<i64>,
    },
}
#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct ImportReport {
    pub events: usize,
    pub changed: usize,
    pub replayed: usize,
    pub stale_or_unchanged: usize,
}
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct SyncCursor {
    pub position: i64,
    pub cursor: String,
}

impl ImportEvent {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.schema_version != 1 || self.position < 0 {
            return Err(Error::Invalid(
                "unsupported event version or negative stream position".into(),
            ));
        }
        for (value, label) in [
            (&self.account_id, "account ID"),
            (&self.event_id, "event ID"),
            (&self.stream_id, "stream ID"),
            (&self.cursor, "cursor"),
        ] {
            valid_id(value, label)?;
        }
        match &self.payload {
            Payload::Message {
                room_id,
                message_id,
                revision,
                sent_at_ms,
                sender_id,
                body,
                deleted,
                source_local_pk,
            } => {
                valid_id(room_id, "room ID")?;
                valid_id(message_id, "message ID")?;
                if let Some(sender) = sender_id {
                    valid_id(sender, "sender ID")?;
                }
                if let Some(pk) = source_local_pk {
                    valid_id(pk, "source local PK")?;
                }
                if *revision < 0
                    || *sent_at_ms < 0
                    || (*deleted && body.is_some())
                    || (!*deleted && body.is_none())
                    || body.as_ref().is_some_and(|b| b.len() > 128 * 1024)
                {
                    return Err(Error::Invalid("message requires nonnegative revision/time, text for live messages, and no body for tombstones".into()));
                }
            }
            Payload::Room {
                room_id,
                revision,
                display_name,
                name_source,
                observed_at_ms,
            } => {
                valid_id(room_id, "room ID")?;
                validate_name(*revision, display_name, name_source, *observed_at_ms)?;
            }
            Payload::Friend {
                user_id,
                revision,
                display_name,
                name_source,
                observed_at_ms,
            } => {
                valid_id(user_id, "user ID")?;
                validate_name(*revision, display_name, name_source, *observed_at_ms)?;
            }
        }
        Ok(())
    }
}
fn validate_name(
    revision: i64,
    name: &Option<String>,
    source: &Option<String>,
    observed: Option<i64>,
) -> Result<()> {
    if revision < 0
        || name.is_some() != source.is_some()
        || name.as_ref().is_some_and(|n| n.len() > 4096)
        || (name.is_some() && observed.is_none())
        || observed.is_some_and(|t| t < 0)
    {
        return Err(Error::Invalid(
            "names require provenance and observation time; revision/time must be nonnegative"
                .into(),
        ));
    }
    if let Some(source) = source {
        valid_id(source, "name source")?;
    }
    Ok(())
}
fn hash(value: &impl Serialize) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}

impl Store {
    /// All events, semantic changes, outbox records, and cursor writes commit together.
    pub fn import_jsonl(&self, mut reader: impl BufRead) -> Result<ImportReport> {
        let mut connection = self.lock()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut report = ImportReport::default();
        let mut total = 0;
        loop {
            let mut line = Vec::new();
            let count = std::io::Read::take(&mut reader, (MAX_LINE + 1) as u64)
                .read_until(b'\n', &mut line)?;
            if count == 0 {
                break;
            }
            total += count;
            if count > MAX_LINE || total > MAX_BATCH || report.events >= MAX_EVENTS {
                return Err(Error::Invalid(
                    "import batch exceeds size/event limit".into(),
                ));
            }
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let event: ImportEvent = serde_json::from_slice(&line).map_err(|_| {
                Error::Invalid(format!(
                    "invalid normalized event at nonblank record {}",
                    report.events + 1
                ))
            })?;
            event.validate()?;
            report.events += 1;
            if apply_event(&tx, &event, &mut report)? {
                report.changed += 1;
            }
        }
        tx.commit()?;
        Ok(report)
    }

    pub fn sync_cursor(&self, account_id: &str, stream_id: &str) -> Result<Option<SyncCursor>> {
        Ok(self.lock()?.query_row("SELECT position,cursor FROM sync_cursors WHERE account_id=?1 AND source='offline_import' AND stream_id=?2", params![account_id,stream_id], |r| Ok(SyncCursor {position:r.get(0)?,cursor:r.get(1)?})).optional()?)
    }
}

pub(crate) fn apply_event(
    tx: &Transaction<'_>,
    event: &ImportEvent,
    report: &mut ImportReport,
) -> Result<bool> {
    let event_hash = hash(event)?;
    let existing: Option<String> = tx.query_row("SELECT event_hash FROM ingest_events WHERE account_id=?1 AND source=?2 AND stream_id=?3 AND event_id=?4", params![event.account_id,event.source.as_str(),event.stream_id,event.event_id], |r| r.get(0)).optional()?;
    if let Some(existing) = existing {
        if existing != event_hash {
            return Err(Error::Conflict(
                "event ID replayed with different data".into(),
            ));
        }
        report.replayed += 1;
        return Ok(false);
    }
    let position: Option<i64> = tx
        .query_row(
            "SELECT position FROM sync_cursors WHERE account_id=?1 AND source=?2 AND stream_id=?3",
            params![event.account_id, event.source.as_str(), event.stream_id],
            |r| r.get(0),
        )
        .optional()?;
    if position.is_some_and(|p| event.position <= p) {
        return Err(Error::Conflict(
            "new event positions must increase; replay original event IDs to retry".into(),
        ));
    }
    let changed = apply_payload(tx, event)?;
    if !changed {
        report.stale_or_unchanged += 1;
    }
    tx.execute("INSERT INTO ingest_events(account_id,source,stream_id,event_id,position,event_hash) VALUES(?1,?2,?3,?4,?5,?6)", params![event.account_id,event.source.as_str(),event.stream_id,event.event_id,event.position,event_hash])?;
    tx.execute("INSERT INTO sync_cursors(account_id,source,stream_id,position,cursor) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(account_id,source,stream_id) DO UPDATE SET position=excluded.position,cursor=excluded.cursor", params![event.account_id,event.source.as_str(),event.stream_id,event.position,event.cursor])?;
    Ok(changed)
}

fn apply_payload(tx: &Transaction<'_>, event: &ImportEvent) -> Result<bool> {
    let payload_hash = hash(&event.payload)?;
    let account = &event.account_id;
    let source = event.source.as_str();
    let (room, entity, kind, revision) = match &event.payload {
        Payload::Message {
            room_id,
            message_id,
            revision,
            sent_at_ms,
            sender_id,
            body,
            deleted,
            source_local_pk,
        } => {
            if !*deleted
                && crate::mutations::suppress_projection(
                    tx, account, room_id, message_id, *revision,
                )?
            {
                return Ok(false);
            }
            let old: Option<(i64,String,i64,bool)> = tx.query_row("SELECT revision,payload_hash,sent_at_ms,deleted FROM messages WHERE account_id=?1 AND room_id=?2 AND message_id=?3", params![account,room_id,message_id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
            if let Some((old_revision, old_hash, old_time, old_deleted)) = old {
                if *revision < old_revision {
                    return Ok(false);
                }
                if *revision == old_revision {
                    if old_hash != payload_hash {
                        return Err(Error::Conflict(
                            "same message revision has different payload".into(),
                        ));
                    }
                    return Ok(false);
                }
                if old_time != *sent_at_ms {
                    return Err(Error::Conflict("message sent_at_ms is immutable".into()));
                }
                if old_deleted && !deleted {
                    return Err(Error::Conflict(
                        "deleted messages cannot be resurrected".into(),
                    ));
                }
            }
            tx.execute("INSERT INTO rooms(account_id,room_id,revision,source) VALUES(?1,?2,-1,?3) ON CONFLICT DO NOTHING", params![account,room_id,source])?;
            tx.execute("INSERT INTO messages(account_id,room_id,message_id,revision,sent_at_ms,sender_id,body,deleted,source,source_local_pk,payload_hash) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11) ON CONFLICT(account_id,room_id,message_id) DO UPDATE SET revision=excluded.revision,sender_id=excluded.sender_id,body=excluded.body,deleted=excluded.deleted,source=excluded.source,source_local_pk=excluded.source_local_pk,payload_hash=excluded.payload_hash", params![account,room_id,message_id,revision,sent_at_ms,sender_id,body,deleted,source,source_local_pk,payload_hash])?;
            (
                Some(room_id),
                message_id,
                if *deleted {
                    "message_deleted"
                } else {
                    "message_upserted"
                },
                *revision,
            )
        }
        Payload::Room {
            room_id,
            revision,
            display_name,
            name_source,
            observed_at_ms,
        } => {
            let old: Option<(i64, Option<String>)> = tx
                .query_row(
                    "SELECT revision,payload_hash FROM rooms WHERE account_id=?1 AND room_id=?2",
                    params![account, room_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if !should_replace(old, *revision, &payload_hash)? {
                return Ok(false);
            }
            tx.execute("INSERT INTO rooms(account_id,room_id,revision,display_name,name_source,observed_at_ms,source,payload_hash) VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(account_id,room_id) DO UPDATE SET revision=excluded.revision,display_name=excluded.display_name,name_source=excluded.name_source,observed_at_ms=excluded.observed_at_ms,source=excluded.source,payload_hash=excluded.payload_hash", params![account,room_id,revision,display_name,name_source,observed_at_ms,source,payload_hash])?;
            (Some(room_id), room_id, "room_upserted", *revision)
        }
        Payload::Friend {
            user_id,
            revision,
            display_name,
            name_source,
            observed_at_ms,
        } => {
            let old: Option<(i64, Option<String>)> = tx
                .query_row(
                    "SELECT revision,payload_hash FROM friends WHERE account_id=?1 AND user_id=?2",
                    params![account, user_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if !should_replace(old, *revision, &payload_hash)? {
                return Ok(false);
            }
            tx.execute("INSERT INTO friends(account_id,user_id,revision,display_name,name_source,observed_at_ms,source,payload_hash) VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(account_id,user_id) DO UPDATE SET revision=excluded.revision,display_name=excluded.display_name,name_source=excluded.name_source,observed_at_ms=excluded.observed_at_ms,source=excluded.source,payload_hash=excluded.payload_hash", params![account,user_id,revision,display_name,name_source,observed_at_ms,source,payload_hash])?;
            (None, user_id, "friend_upserted", *revision)
        }
    };
    // Outbox intentionally contains identifiers/revisions only, never historical message bodies.
    tx.execute("INSERT INTO outbox(account_id,room_id,entity_id,kind,revision,source) VALUES(?1,?2,?3,?4,?5,?6)", params![account,room,entity,kind,revision,source])?;
    Ok(true)
}
fn should_replace(old: Option<(i64, Option<String>)>, revision: i64, hash: &str) -> Result<bool> {
    if let Some((old_revision, old_hash)) = old {
        if revision < old_revision {
            return Ok(false);
        }
        if revision == old_revision {
            if old_hash.as_deref() != Some(hash) {
                return Err(Error::Conflict(
                    "same entity revision has different payload".into(),
                ));
            }
            return Ok(false);
        }
    }
    Ok(true)
}
