//! Request and response helpers for ordinary background text messages.
use super::codec::Packet;
use bson::{doc, Bson, Document};

/// Stateful client IDs. Keep one instance per device and serialize access.
pub struct MessageIds {
    device_hash: i8,
    last_id: i64,
    last_generated_id: i64,
    last_time_ms: i64,
}

impl MessageIds {
    pub fn new(device: &str, now_ms: i64) -> Self {
        let hash = device.encode_utf16().fold(0_i32, |hash, unit| {
            hash.wrapping_mul(31).wrapping_add(i32::from(unit))
        });
        let mut state = Self {
            device_hash: (hash % 100) as i8,
            last_id: 0,
            last_generated_id: 0,
            last_time_ms: 0,
        };
        state.last_id = state.candidate(now_ms);
        state.last_generated_id = state.last_id;
        state
    }

    fn candidate(&self, time_ms: i64) -> i64 {
        ((time_ms % 2_147_483_547) / 100) * 100 + i64::from(self.device_hash)
    }

    pub fn next(&mut self, now_ms: i64) -> i64 {
        self.last_time_ms = if now_ms > self.last_time_ms {
            now_ms
        } else {
            self.last_time_ms.wrapping_add(1)
        };
        let candidate = self.candidate(self.last_time_ms);
        let next = if candidate > self.last_id || candidate < self.last_generated_id {
            candidate
        } else {
            let incremented = self.last_id + 100;
            if incremented > i64::from(i32::MAX) {
                self.candidate(incremented)
            } else {
                incremented
            }
        };
        self.last_id = next;
        self.last_generated_id = candidate;
        next
    }
}

/// Callers validate supported text and produce any attachment preprocessing.
pub fn text_request(chat: i64, client_id: i64, text: &str, extra: &str) -> Document {
    let mut body = doc! {
        "chatId": chat,
        "msg": text,
        "type": 1_i32,
        "noSeen": true,
        "extra": extra,
        "scope": 1_i32,
        "silence": false,
    };
    if client_id > 0 {
        body.insert("msgId", client_id);
    }
    body
}

/// No Debug: accepted logs contain private message text.
pub enum WriteReply {
    Rejected(i32),
    Accepted { log_id: i64, log: Document },
    Invalid,
}

fn optional_i64(document: &Document, key: &str) -> Result<Option<i64>, ()> {
    match document.get(key) {
        None | Some(Bson::Null) => Ok(None),
        Some(Bson::Int64(value)) => Ok(Some(*value)),
        _ => Err(()),
    }
}

fn optional_i32(document: &Document, key: &str) -> Result<Option<i32>, ()> {
    match document.get(key) {
        None | Some(Bson::Null) => Ok(None),
        Some(Bson::Int32(value)) => Ok(Some(*value)),
        _ => Err(()),
    }
}

fn optional_string<'a>(document: &'a Document, key: &str) -> Result<Option<&'a str>, ()> {
    match document.get(key) {
        None | Some(Bson::Null) => Ok(None),
        Some(Bson::String(value)) => Ok(Some(value.as_str())),
        _ => Err(()),
    }
}

fn matches_i64(document: &Document, key: &str, expected: i64) -> bool {
    match document.get(key) {
        None => true,
        Some(Bson::Int64(value)) => *value == expected,
        _ => false,
    }
}

fn matches_i32(document: &Document, key: &str, expected: i32) -> bool {
    match document.get(key) {
        None => true,
        Some(Bson::Int32(value)) => *value == expected,
        _ => false,
    }
}

fn valid_client_id(value: Option<i64>, expected: i64) -> bool {
    value.is_none_or(|id| id == 0 || (id > 0 && id == expected))
}

pub fn parse_reply(
    packet: &Packet,
    chat: i64,
    client_id: i64,
    self_user: i64,
    text: &str,
    extra: &str,
) -> WriteReply {
    if packet.header.command != "WRITE" {
        return WriteReply::Invalid;
    }
    if packet.header.status != 0 {
        return WriteReply::Rejected(i32::from(packet.header.status));
    }
    let status = match packet.body.get_i32("status") {
        Ok(status) => status,
        Err(_) => return WriteReply::Invalid,
    };
    if status != 0 {
        return WriteReply::Rejected(status);
    }
    let parsed = (|| -> Result<(i64, Document), ()> {
        let body = &packet.body;
        let log_id = body.get_i64("logId").map_err(|_| ())?;
        if chat <= 0
            || log_id <= 0
            || self_user <= 0
            || body.get_i64("chatId").map_err(|_| ())? != chat
        {
            return Err(());
        }
        let outer_msg_id = optional_i64(body, "msgId")?;
        if !valid_client_id(outer_msg_id, client_id) {
            return Err(());
        }
        let outer_send_at = optional_i32(body, "sendAt")?;
        let outer_prev_id = optional_i64(body, "prevId")?;
        optional_string(body, "authorNickname")?;
        let nested = match body.get("chatLog") {
            None | Some(Bson::Null) => None,
            Some(Bson::Document(log)) => Some(log),
            _ => return Err(()),
        };
        let (message, attachment, send_at, msg_id, nested_prev_id) = if let Some(log) = nested {
            if log.get_i64("chatId").map_err(|_| ())? != chat
                || log.get_i64("logId").map_err(|_| ())? != log_id
                || log.get_i32("type").map_err(|_| ())? != 1
                || !matches_i64(log, "authorId", self_user)
                || !matches_i64(log, "userId", self_user)
                || !matches_i32(log, "scope", 1)
                || optional_i64(log, "threadId")?.is_some_and(|id| id != 0)
            {
                return Err(());
            }
            let msg_id = optional_i64(log, "msgId")?;
            if !valid_client_id(msg_id, client_id) {
                return Err(());
            }
            (
                optional_string(log, "message")?
                    .map(|s| Bson::String(s.into()))
                    .unwrap_or(Bson::Null),
                optional_string(log, "attachment")?
                    .map(|s| Bson::String(s.into()))
                    .unwrap_or(Bson::Null),
                optional_i32(log, "sendAt")?.unwrap_or(0),
                msg_id.unwrap_or(0),
                Some(log.get_i64("prevId").map_err(|_| ())?),
            )
        } else {
            (
                Bson::String(text.into()),
                Bson::String(extra.into()),
                outer_send_at.unwrap_or(0),
                outer_msg_id.unwrap_or(0),
                None,
            )
        };
        let prev_id = outer_prev_id.or(nested_prev_id).unwrap_or(0);
        if send_at < 0 || prev_id < 0 || prev_id >= log_id {
            return Err(());
        }
        let mut log = nested.cloned().unwrap_or_default();
        if optional_i32(&log, "revision")?.is_some_and(|revision| revision < 0) {
            return Err(());
        }
        log.insert("chatId", chat);
        log.insert("logId", log_id);
        log.insert("authorId", self_user);
        log.insert("type", 1_i32);
        log.insert("scope", 1_i32);
        log.insert("message", message);
        log.insert("attachment", attachment);
        log.insert("sendAt", send_at);
        log.insert("msgId", msg_id);
        log.insert("prevId", prev_id);
        Ok((log_id, log))
    })();
    match parsed {
        Ok((log_id, log)) => WriteReply::Accepted { log_id, log },
        Err(()) => WriteReply::Invalid,
    }
}

#[cfg(test)]
mod tests;
