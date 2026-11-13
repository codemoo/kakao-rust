//! Typed views of Android BSON responses. Keep original packets privately for replay.
use super::codec::{Packet, ProtocolError, Result};
use bson::{Bson, Document};

pub struct Configuration {
    pub write_timeout_seconds: Option<u64>,
    pub ticket_hosts: Vec<String>,
    pub ports: Vec<u16>,
    pub foreground_ping_seconds: Option<u64>,
    pub background_ping_seconds: Option<u64>,
}
impl Configuration {
    pub fn parse(body: &Document) -> Result<Self> {
        let ticket = body
            .get_document("ticket")
            .map_err(|_| ProtocolError::Bson)?;
        let wifi = body.get_document("wifi").map_err(|_| ProtocolError::Bson)?;
        let ticket_hosts = strings(ticket, "lsl")?;
        let ports = wifi
            .get_array("ports")
            .map_err(|_| ProtocolError::Bson)?
            .iter()
            .map(|v| {
                v.as_i32()
                    .and_then(|v| u16::try_from(v).ok())
                    .filter(|v| *v != 0)
                    .ok_or(ProtocolError::Bson)
            })
            .collect::<Result<Vec<_>>>()?;
        if ticket_hosts.is_empty() || ports.is_empty() {
            return Err(ProtocolError::Bson);
        }
        Ok(Self {
            write_timeout_seconds: positive_seconds(wifi, "recvHeaderTimeout"),
            ticket_hosts,
            ports,
            foreground_ping_seconds: positive_seconds(wifi, "fgPingItv"),
            background_ping_seconds: positive_seconds(wifi, "bgPingItv"),
        })
    }
}
fn positive_seconds(body: &Document, key: &str) -> Option<u64> {
    body.get_i32(key).ok().filter(|v| *v > 0).map(|v| v as u64)
}
pub struct Carriage {
    pub host: String,
    pub port: u16,
}
impl Carriage {
    pub fn parse(body: &Document) -> Result<Self> {
        let host = body
            .get_str("host")
            .map_err(|_| ProtocolError::Bson)?
            .to_owned();
        let port = body
            .get_i32("port")
            .ok()
            .and_then(|p| u16::try_from(p).ok())
            .filter(|p| *p != 0)
            .ok_or(ProtocolError::Bson)?;
        if host.is_empty() || host.len() > 253 || host.chars().any(char::is_whitespace) {
            return Err(ProtocolError::Bson);
        }
        Ok(Self { host, port })
    }
}
fn strings(body: &Document, key: &str) -> Result<Vec<String>> {
    body.get_array(key)
        .map_err(|_| ProtocolError::Bson)?
        .iter()
        .map(|v| v.as_str().map(str::to_owned).ok_or(ProtocolError::Bson))
        .collect()
}
/// Validates required fields before advancing any durable checkpoint.
pub fn validate_chat_log(body: &Document) -> Result<()> {
    for key in ["logId", "chatId", "prevId"] {
        body.get_i64(key).map_err(|_| ProtocolError::Bson)?;
    }
    body.get_i32("type").map_err(|_| ProtocolError::Bson)?;
    Ok(())
}
pub struct ChatList {
    pub chats: Vec<Document>,
    pub deleted: Vec<i64>,
    pub kicked: Vec<i64>,
    pub eof: bool,
    pub last_chat_id: i64,
    pub last_token_id: i64,
}
impl ChatList {
    pub fn parse(packet: &Packet, expected_user: Option<i64>) -> Result<Self> {
        let accepted = match packet.header.command.as_str() {
            "LOGINLIST" => matches!(packet.header.status, 0 | -305 | -310),
            "LCHATLIST" => matches!(packet.header.status, 0 | -310),
            _ => false,
        };
        if !accepted {
            return Err(ProtocolError::Frame);
        }
        let body = &packet.body;
        if let Some(user) = expected_user {
            if body.get_i64("userId").ok() != Some(user) {
                return Err(ProtocolError::Bson);
            }
        }
        let mut chats = Vec::new();
        if let Ok(values) = body.get_array("chatDatas") {
            for value in values {
                let chat = value.as_document().ok_or(ProtocolError::Bson)?;
                for key in ["c", "s"] {
                    chat.get_i64(key).map_err(|_| ProtocolError::Bson)?;
                }
                for key in ["a", "n"] {
                    chat.get_i32(key).map_err(|_| ProtocolError::Bson)?;
                }
                chat.get_str("t").map_err(|_| ProtocolError::Bson)?;
                chat.get_bool("p").map_err(|_| ProtocolError::Bson)?;
                if let Ok(log) = chat.get_document("l") {
                    validate_chat_log(log)?;
                }
                chats.push(chat.clone());
            }
        }
        Ok(Self {
            chats,
            deleted: ids(body, "delChatIds")?,
            kicked: ids(body, "kc")?,
            eof: body.get_bool("eof").unwrap_or(true),
            last_chat_id: body.get_i64("lastChatId").unwrap_or(0),
            last_token_id: body.get_i64("lastTokenId").unwrap_or(0),
        })
    }
}
fn ids(body: &Document, key: &str) -> Result<Vec<i64>> {
    match body.get(key) {
        None => Ok(vec![]),
        Some(Bson::Array(a)) => a
            .iter()
            .map(|v| v.as_i64().ok_or(ProtocolError::Bson))
            .collect(),
        _ => Err(ProtocolError::Bson),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use bson::doc;
    #[test]
    fn rejects_id_narrowing_and_account_mismatch() {
        let mut packet = Packet::request(1000,"LOGINLIST",doc!{"userId":42_i64,"eof":false,"lastChatId":9007199254740993_i64,"chatDatas":[{"c":9007199254740993_i64,"s":0_i64,"a":2,"n":1,"t":"DirectChat","p":true}]}).unwrap();
        let parsed = ChatList::parse(&packet, Some(42)).unwrap();
        assert_eq!(parsed.last_chat_id, 9007199254740993);
        assert!(!parsed.eof);
        assert!(ChatList::parse(&packet, Some(43)).is_err());
        packet.body.insert("userId", 42_i32);
        assert!(ChatList::parse(&packet, Some(42)).is_err());
        assert!(
            validate_chat_log(&doc! {"logId":1_i32,"chatId":2_i64,"prevId":0_i64,"type":1})
                .is_err()
        );
    }
}
