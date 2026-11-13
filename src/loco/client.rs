//! Discovery and chat-list bootstrap; caller owns the exclusive runtime lease.
//! Requests use the persisted device identity and OAuth access token.
use super::{
    codec::Packet,
    request,
    response::{Carriage, Configuration},
    transport::Connection,
};
use crate::{runtime::StepState, session::Session, Error, Result, Store};
use bson::Document;

pub struct PacketIds(i32);
impl Default for PacketIds {
    fn default() -> Self {
        Self(1000)
    }
}
impl PacketIds {
    pub fn allocate(&mut self) -> i32 {
        let value = self.0;
        self.0 = if value == 99_999_999 { 1000 } else { value + 1 };
        value
    }
}
fn protocol_error(_: impl std::fmt::Display) -> Error {
    Error::Invalid("LOCO exchange or response validation failed".into())
}
async fn exchange(
    store: &Store,
    connection: &mut Connection,
    ids: &mut PacketIds,
    command: &str,
    body: Document,
) -> Result<Packet> {
    let response = connection
        .exchange(&Packet::request(ids.allocate(), command, body).map_err(protocol_error)?)
        .await
        .map_err(protocol_error)?;
    store.capture_native("loco", &response.encode().map_err(protocol_error)?)?;
    Ok(response)
}
pub struct Connected {
    pub connection: Connection,
    pub ids: PacketIds,
    pub configuration: Configuration,
}
/// Discover a carriage. Login runs on the dedicated live reader so interleaved
/// pushes are captured and applied in receive order, including during bootstrap.
pub async fn discover(store: &Store, session: &Session, use_sub: bool) -> Result<Connected> {
    let mut ids = PacketIds::default();
    store.native_step("getconf", StepState::Started, None, None)?;
    let mut booking = Connection::booking().await.map_err(protocol_error)?;
    let config = exchange(
        store,
        &mut booking,
        &mut ids,
        "GETCONF",
        request::getconf(session.user_id, ""),
    )
    .await?;
    if config.header.status != 0 {
        store.native_step(
            "getconf",
            StepState::Failed,
            None,
            Some(config.header.status.into()),
        )?;
        return Err(protocol_error("status"));
    }
    let configuration = Configuration::parse(&config.body).map_err(protocol_error)?;
    // Discovery already fetches GETCONF on every reconnect; a Pilsner hint never
    // tears down a healthy socket or advances unrelated LOGINLIST config cursors.
    if let Ok(revision) = config.body.get_i32("revision") {
        store.booking_revision(&session.user_id().to_string(), revision)?;
    }
    if let Some(seconds) = config
        .body
        .get_document("trailer")
        .ok()
        .and_then(|t| t.get_i32("contentExpireTime").ok())
        .filter(|s| *s >= 0)
    {
        store.lock()?.execute("INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",rusqlite::params![format!("media_expiry_seconds:{}",session.user_id()),seconds.to_string()])?;
    }
    if let Some(seconds) = config
        .body
        .get_document("etc")
        .ok()
        .and_then(|v| v.get_i32("writeRetryTimeout").ok())
        .filter(|v| *v >= 0)
    {
        store.lock()?.execute("INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",rusqlite::params![format!("write_retry_seconds:{}",session.user_id()),seconds.to_string()])?;
    }
    store.native_step("getconf", StepState::Completed, None, Some(0))?;
    drop(booking);
    store.native_step("checkin", StepState::Started, None, None)?;
    let mut selected = None;
    // Server-returned IPv4 list/port ordering. Retry policy lives in supervisor;
    // a successful connect is not sufficient: CHECKIN must return an endpoint.
    'hosts: for host in &configuration.ticket_hosts {
        for port in &configuration.ports {
            let Ok(mut ticket) = Connection::discovered(host, *port).await else {
                continue;
            };
            let response = exchange(
                store,
                &mut ticket,
                &mut ids,
                "CHECKIN",
                request::checkin(session.user_id, 0, "26.3.2", "ko", "", use_sub),
            )
            .await?;
            if response.header.status != 0 {
                store.native_step(
                    "checkin",
                    StepState::Failed,
                    None,
                    Some(response.header.status.into()),
                )?;
                return Err(protocol_error("status"));
            }
            selected = Some(Carriage::parse(&response.body).map_err(protocol_error)?);
            break 'hosts;
        }
    }
    let carriage = selected.ok_or_else(|| protocol_error("ticket unavailable"))?;
    store.native_step("checkin", StepState::Completed, None, Some(0))?;
    let connection = Connection::discovered(&carriage.host, carriage.port)
        .await
        .map_err(protocol_error)?;
    Ok(Connected {
        connection,
        ids,
        configuration,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn packet_ids_match_app_range_and_wrap() {
        let mut ids = PacketIds::default();
        assert_eq!(ids.allocate(), 1000);
        assert_eq!(ids.allocate(), 1001);
        ids.0 = 99_999_999;
        assert_eq!(ids.allocate(), 99_999_999);
        assert_eq!(ids.allocate(), 1000);
    }
}
