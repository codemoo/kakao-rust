//! LOCO packet framing with little-endian integer fields.
//! Packet plaintext is a stream: a packet may span multiple secure records.
use bson::Document;
use std::io::Cursor;
use zeroize::Zeroizing;

pub const HEADER_LEN: usize = 22;
pub const MAX_BODY: usize = 8 * 1024 * 1024; // Client-side allocation limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProtocolError {
    #[error("invalid LOCO frame")]
    Frame,
    #[error("LOCO frame exceeds local size limit")]
    Size,
    #[error("invalid LOCO BSON body")]
    Bson,
    #[error("LOCO secure record authentication failed")]
    Authentication,
    #[error("LOCO key exchange failure")]
    KeyExchange,
}
pub type Result<T> = std::result::Result<T, ProtocolError>;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub packet_id: i32,
    pub status: i16,
    pub command: String,
    pub body_len: usize,
}
impl Header {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != HEADER_LEN {
            return Err(ProtocolError::Frame);
        }
        let length = i32::from_le_bytes(bytes[18..22].try_into().unwrap());
        if length < 0 || length as usize > MAX_BODY {
            return Err(ProtocolError::Size);
        }
        let command = std::str::from_utf8(&bytes[6..17])
            .map_err(|_| ProtocolError::Frame)?
            .trim_matches(|c: char| c as u32 <= 32);
        validate_command(command)?;
        Ok(Self {
            packet_id: i32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            status: i16::from_le_bytes(bytes[4..6].try_into().unwrap()),
            command: command.into(),
            body_len: length as usize,
        })
    }
    pub fn encode(&self) -> Result<[u8; HEADER_LEN]> {
        validate_command(&self.command)?;
        if self.body_len > MAX_BODY {
            return Err(ProtocolError::Size);
        }
        let mut bytes = [0; HEADER_LEN];
        bytes[..4].copy_from_slice(&self.packet_id.to_le_bytes());
        bytes[4..6].copy_from_slice(&self.status.to_le_bytes());
        bytes[6..6 + self.command.len()].copy_from_slice(self.command.as_bytes());
        bytes[18..].copy_from_slice(&(self.body_len as i32).to_le_bytes());
        Ok(bytes)
    }
}
fn validate_command(command: &str) -> Result<()> {
    if command.is_empty()
        || command.len() > 11
        || !command
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
    {
        return Err(ProtocolError::Frame);
    }
    Ok(())
}
/// No Debug: BSON can contain credentials and private messages.
pub struct Packet {
    pub header: Header,
    pub body: Document,
}
impl Packet {
    pub fn request(packet_id: i32, command: &str, body: Document) -> Result<Self> {
        let body_len = bson::to_vec(&body).map_err(|_| ProtocolError::Bson)?.len();
        let header = Header {
            packet_id,
            status: 0,
            command: command.into(),
            body_len,
        };
        header.encode()?;
        Ok(Self { header, body })
    }
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let body = Zeroizing::new(bson::to_vec(&self.body).map_err(|_| ProtocolError::Bson)?);
        let mut header = self.header.clone();
        header.body_len = body.len();
        let mut bytes = Zeroizing::new(Vec::with_capacity(HEADER_LEN + body.len()));
        bytes.extend_from_slice(&header.encode()?);
        bytes.extend_from_slice(&body);
        Ok(bytes)
    }
}
#[derive(Default)]
pub struct Decoder {
    buffer: Zeroizing<Vec<u8>>,
}
impl Decoder {
    pub fn feed(&mut self, bytes: &[u8]) -> Result<()> {
        // One packet plus one maximum secure record of read-ahead.
        if bytes.len() > MAX_BODY + HEADER_LEN + 131068 - self.buffer.len() {
            return Err(ProtocolError::Size);
        }
        self.buffer.extend_from_slice(bytes);
        Ok(())
    }
    pub fn next_packet(&mut self) -> Result<Option<Packet>> {
        if self.buffer.len() < HEADER_LEN {
            return Ok(None);
        }
        let header = Header::parse(&self.buffer[..HEADER_LEN])?;
        let total = HEADER_LEN + header.body_len;
        if self.buffer.len() < total {
            return Ok(None);
        }
        let body = if header.body_len == 0 {
            Document::new()
        } else {
            if header.body_len < 5 {
                return Err(ProtocolError::Bson);
            }
            let mut reader = Cursor::new(&self.buffer[HEADER_LEN..total]);
            let doc = Document::from_reader(&mut reader).map_err(|_| ProtocolError::Bson)?;
            if reader.position() != header.body_len as u64 {
                return Err(ProtocolError::Bson);
            }
            doc
        };
        self.buffer.drain(..total);
        Ok(Some(Packet { header, body }))
    }
    pub(crate) fn take_raw(&mut self, limit: usize) -> Vec<u8> {
        let length = limit.min(self.buffer.len());
        self.buffer.drain(..length).collect()
    }
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn known_header_and_arbitrary_stream_splits() {
        let packet = Packet::request(0x01020304, "PING", Document::new()).unwrap();
        let bytes = packet.encode().unwrap();
        assert_eq!(
            hex::encode(&bytes),
            "04030201000050494e470000000000000000050000000500000000"
        );
        let header = Header {
            packet_id: -1,
            status: -100,
            command: "LOGINLIST".into(),
            body_len: 5,
        };
        assert_eq!(&header.encode().unwrap()[4..6], &[0x9c, 0xff]);
        for split in 0..bytes.len() {
            let mut decoder = Decoder::default();
            decoder.feed(&bytes[..split]).unwrap();
            assert!(decoder.next_packet().unwrap().is_none());
            decoder.feed(&bytes[split..]).unwrap();
            decoder.feed(&bytes).unwrap();
            assert_eq!(
                decoder.next_packet().unwrap().unwrap().header.packet_id,
                0x01020304
            );
            assert!(decoder.next_packet().unwrap().is_some());
            assert!(decoder.is_empty());
        }
    }
    #[test]
    fn malformed_lengths_bson_and_commands_rejected() {
        let bytes = Packet::request(1, "PING", Document::new())
            .unwrap()
            .encode()
            .unwrap();
        for length in [-1, i32::MAX, 1, 4, 6] {
            let mut bad = bytes.to_vec();
            bad[18..22].copy_from_slice(&length.to_le_bytes());
            bad.push(0);
            let mut decoder = Decoder::default();
            decoder.feed(&bad).unwrap();
            assert!(decoder.next_packet().is_err());
        }
        assert!(Packet::request(1, "TOO_LONG_COMMAND", Document::new()).is_err());
    }
}
