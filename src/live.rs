//! Continuous LOCO worker with explicitly authorized text sends. One socket owner, durable inbox before
//! ACK, independent recovery/read cursors, bounded reconnect and explicit gaps.
use crate::{
    live_store::Range,
    loco::{
        client::{discover, PacketIds},
        codec::Packet,
        request,
        response::ChatList,
        transport::LiveConnection,
    },
    native_http::Client,
    runtime::{RuntimeLease, StepState},
    Error, Result, Store,
};
use bson::Document;
use std::{future::Future, sync::Arc, time::Duration};
use tokio::{
    sync::watch,
    time::{timeout, Instant},
};

#[derive(Debug, thiserror::Error)]
enum Failure {
    #[error("collector stopped")]
    Shutdown,
    #[error("collector control stop: {0}")]
    Stop(&'static str),
    #[error("LOCO rejected login: {0}")]
    Login(i16),
    #[error("LOCO transport failed")]
    Transport(#[from] crate::loco::transport::TransportError),
    #[error("LOCO request deadline exceeded")]
    Timeout,
    #[error("collector protocol validation failed")]
    Protocol,
    #[error("collector storage/application failed")]
    Local(#[from] Error),
    #[error("server requested new connection")]
    Reconnect,
    #[error("discovery failed")]
    Discovery,
}
impl From<rusqlite::Error> for Failure {
    fn from(error: rusqlite::Error) -> Self {
        Self::Local(Error::Database(error))
    }
}
type Outcome<T> = std::result::Result<T, Failure>;
struct Worker {
    store: Store,
    account: String,
    generation: String,
    socket: LiveConnection,
    ids: PacketIds,
    stop: watch::Receiver<bool>,
    write_timeout: Duration,
    heartbeat: Duration,
    ping_at: Instant,
    message_ids: Arc<std::sync::Mutex<crate::loco::outgoing::MessageIds>>,
    recovery_scans: std::collections::HashMap<i64, (i64, i64)>,
}
impl Worker {
    async fn next(&mut self) -> Outcome<(Packet, i64)> {
        let packet = tokio::select! {
            biased;
            _=self.stop.changed()=>return Err(Failure::Shutdown),
            packet=self.socket.receive()=>packet?,
        };
        self.ping_at = Instant::now() + self.heartbeat;
        let seq = self
            .store
            .live_capture(&self.account, &self.generation, &packet)?;
        Ok((packet, seq))
    }
    async fn push(&mut self, packet: Packet, seq: i64) -> Outcome<()> {
        match packet.header.command.as_str() {
            "MSG" => {
                if packet.header.status != 0 {
                    return Err(Failure::Protocol);
                }
                self.store.live_apply(&self.account, seq, &packet)?;
                // Durable raw inbox is guaranteed even for unsupported projection.
                // ACK never crosses this Worker/socket generation.
                let ack =
                    Packet::request(packet.header.packet_id, "MSG", request::message_ack(false))
                        .map_err(|_| Failure::Protocol)?;
                self.socket.send(&ack).await?;
            }
            "WRITE" | "SYNCDLMSG" | "SYNCMODMSG" => {
                self.store.live_apply(&self.account, seq, &packet)?
            }
            "CHGMETA" | "CHGMCMETA" | "CHGMOMETAS" | "CHGCHATST" | "LEFT" | "SYNCCREATE"
            | "NEWMEM" | "DELMEM" | "DECUNREAD" | "SYNCACTION" => {
                self.store.live_apply(&self.account, seq, &packet)?
            }
            "SPUSH" | "BLSYNC" => self
                .store
                .live_apply_optional(&self.account, seq, &packet)?,
            "CHANGESVR" => return Err(Failure::Reconnect),
            "KICKOUT" => {
                packet
                    .body
                    .get_i32("reason")
                    .map_err(|_| Failure::Protocol)?;
                return Err(Failure::Stop("kicked_out"));
            }
            "RESTART" => {
                let code = packet.body.get_i32("code").map_err(|_| Failure::Protocol)?;
                // All supported saved profiles authenticate as the local sub-device.
                // The native reset_alert special case tests local mode, not server useSub.
                if code == 1 && packet.body.get_str("ref").ok() == Some("reset_alert") {
                    return Ok(());
                }
                // Global LOCO token is already zero until all related handlers commit.
                // Reinitialize the connection without resetting room coverage or OAuth.
                return Err(Failure::Reconnect);
            }
            // Unsupported events are durable pending records; no invented ACK.
            _ => (),
        }
        Ok(())
    }
    async fn rpc(&mut self, command: &str, body: Document) -> Outcome<(Packet, i64)> {
        let id = self.ids.allocate();
        self.rpc_with_id(id, command, body).await
    }
    async fn rpc_with_id(
        &mut self,
        id: i32,
        command: &str,
        body: Document,
    ) -> Outcome<(Packet, i64)> {
        self.store
            .record_request(&self.account, &self.generation, id, command, &body)?;
        let deadline = Instant::now()
            + if command == "WRITE" {
                self.write_timeout
            } else {
                Duration::from_secs(20)
            };
        let request = Packet::request(id, command, body).map_err(|_| Failure::Protocol)?;
        tokio::select! {
            biased;
            _=self.stop.changed()=>return Err(Failure::Shutdown),
            result=tokio::time::timeout_at(deadline,self.socket.send(&request))=>result.map_err(|_|Failure::Timeout)??,
        }
        loop {
            let (packet, seq) = tokio::time::timeout_at(deadline, self.next())
                .await
                .map_err(|_| Failure::Timeout)??;
            if packet.header.packet_id == id {
                if packet.header.command != command {
                    return Err(Failure::Protocol);
                }
                return Ok((packet, seq));
            }
            self.push(packet, seq).await?;
        }
    }
    async fn send_next(&mut self) -> Outcome<()> {
        let now = chrono::Utc::now().timestamp_millis();
        let Some(job) = self
            .store
            .next_outgoing(&self.account, &self.generation, now)?
        else {
            return Ok(());
        };
        let client_id = match job.client_id {
            Some(id) => id,
            None => self
                .message_ids
                .lock()
                .map_err(|_| Failure::Protocol)?
                .next(now),
        };
        let packet_id = self.ids.allocate();
        if !self.store.prepare_outgoing(
            &self.account,
            &self.generation,
            &job,
            client_id,
            packet_id,
            now,
        )? {
            return Ok(());
        }
        let body = crate::loco::outgoing::text_request(job.chat, client_id, &job.text, &job.extra);
        match self.rpc_with_id(packet_id, "WRITE", body).await {
            Ok((reply, sequence)) => self.store.live_apply(&self.account, sequence, &reply)?,
            Err(error) => {
                let retryable = matches!(
                    error,
                    Failure::Transport(
                        crate::loco::transport::TransportError::Io
                            | crate::loco::transport::TransportError::Closed
                    ) | Failure::Reconnect
                );
                self.store
                    .outgoing_transport_failure(&self.account, &job.id, retryable)?;
                return Err(error);
            }
        }
        Ok(())
    }
    async fn login(&mut self, session: &crate::session::Session) -> Outcome<()> {
        let (chat_ids, max_ids) = self.store.live_inputs(&self.account)?;
        self.store
            .native_step("loginlist", StepState::Started, None, None)?;
        let body = request::LoginList {
            app_version: "26.3.2",
            protocol_version: "1",
            language: "ko",
            device_uuid: session.wire.uuid(),
            network_type: 0,
            mccmnc: "",
            revision: 0,
            chat_ids: &chat_ids,
            max_ids: &max_ids,
            last_token_id: 0,
            last_blind_token_id: 0,
            block_revision: 0,
            plus_block_revision: 0,
            is_background: true,
            oauth_token: &session.access_token,
        }
        .body();
        let (packet, seq) = self.rpc("LOGINLIST", body).await?;
        if !matches!(packet.header.status, 0 | -305 | -310) {
            return Err(Failure::Login(packet.header.status));
        }
        let mut receipt_status = packet.header.status;
        let mut page =
            ChatList::parse(&packet, Some(session.user_id)).map_err(|_| Failure::Protocol)?;
        self.store.live_apply(&self.account, seq, &packet)?;
        let mut seen = std::collections::HashSet::new();
        while !page.eof {
            if seen.len() >= 10_000 || !seen.insert(page.last_chat_id) {
                return Err(Failure::Protocol);
            }
            let (packet, seq) = self
                .rpc(
                    "LCHATLIST",
                    request::lchatlist(&chat_ids, &max_ids, 0, page.last_chat_id),
                )
                .await?;
            if packet.header.status != 0 {
                receipt_status = packet.header.status;
            }
            page = ChatList::parse(&packet, None).map_err(|_| Failure::Protocol)?;
            self.store.live_apply(&self.account, seq, &packet)?;
        }
        self.store.native_step(
            "chat_lists_received",
            StepState::Completed,
            None,
            Some(receipt_status.into()),
        )?;
        // Global app/config tokens remain zero until all their handlers exist.
        // GETTOKEN values are retained raw, never asserted as applied subsystems.
        let (tokens, seq) = self.rpc("GETTOKEN", request::gettoken()).await?;
        if tokens.header.status != 0 {
            return Err(Failure::Protocol);
        }
        self.store
            .live_apply_optional(&self.account, seq, &tokens)?;
        Ok(())
    }
    async fn catch_up(&mut self, initial: Range) -> Outcome<bool> {
        let mut cur = self
            .recovery_scans
            .remove(&initial.chat)
            .filter(|(_, target)| *target == initial.target)
            .map_or(initial.cur, |(cur, _)| cur.max(initial.cur));
        for _ in 0..4 {
            let range =
                self.store
                    .live_range_at(&self.account, initial.chat, cur, initial.target)?;
            let (packet, seq) = self
                .rpc(
                    "SYNCMSG",
                    request::syncmsg(range.chat, range.cur, range.max, range.count),
                )
                .await?;
            let (ok, next) = validate_sync(&packet, range)?;
            self.store.live_apply(&self.account, seq, &packet)?;
            if !ok && next == cur {
                return Ok(false);
            }
            if ok {
                self.store.live_advance(&self.account, range, next)?;
            }
            if ok && next >= initial.target {
                return Ok(true);
            }
            if next <= cur || next > initial.target {
                return Err(Failure::Protocol);
            }
            cur = next;
        }
        self.recovery_scans
            .insert(initial.chat, (cur, initial.target));
        Ok(true)
    }
    async fn receive_loop(&mut self) -> Outcome<()> {
        let mut metadata_at = Instant::now();
        let mut deferred = std::collections::HashMap::<i64, Instant>::new();
        let mut pulse = tokio::time::interval(Duration::from_secs(15));
        pulse.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            if *self.stop.borrow() {
                return Err(Failure::Shutdown);
            }
            // Drain already delivered packets before issuing catch-up requests.
            if let Ok(packet) = timeout(Duration::from_millis(1), self.next()).await {
                let (packet, seq) = packet?;
                self.push(packet, seq).await?;
            }
            self.send_next().await?;
            if let Some((key, mut job)) = self.store.relay_next(&self.account)? {
                let plan = job.authorize(&self.store);
                if let Ok(plan) = plan {
                    if let Some(token) = plan.attachment.token {
                        let (reply, _) = self
                            .rpc(
                                "GETTRAILER",
                                bson::doc! {"k":token,"t":plan.attachment.relay_kind},
                            )
                            .await?;
                        job.endpoint = if reply.header.status == 0 {
                            reply
                                .body
                                .get_str("vh")
                                .ok()
                                .filter(|h| !h.is_empty() && h.len() <= 253)
                                .zip(
                                    reply
                                        .body
                                        .get_i32("p")
                                        .ok()
                                        .and_then(|p| u16::try_from(p).ok())
                                        .filter(|p| *p > 0),
                                )
                                .map(|(h, p)| (h.to_owned(), p))
                        } else {
                            None
                        };
                    }
                }
                job.failed = job.endpoint.is_none();
                self.store.relay_finish(&key, &job)?;
            }
            if Instant::now() >= metadata_at {
                metadata_at = Instant::now() + Duration::from_secs(1);
                if let Some((chat, requested)) = self.store.room_refresh_next(&self.account)? {
                    let (info, seq) = self.rpc("CHATINFO", request::chatinfo(chat)).await?;
                    let mut ok = crate::room_sync::response_ok(&info);
                    if ok {
                        self.store.live_apply(&self.account, seq, &info)?;
                        let (members, seq) = self.rpc("GETMEM", request::getmem(chat)).await?;
                        ok = crate::room_sync::response_ok(&members);
                        if ok {
                            self.store.live_apply(&self.account, seq, &members)?;
                        }
                        let supported = info
                            .body
                            .get_document("chatInfo")
                            .ok()
                            .and_then(|d| d.get_str("type").ok())
                            .is_some_and(|t| matches!(t, "DirectChat" | "MultiChat"));
                        if ok && supported {
                            let (list, seq) = self.rpc("MEMLIST", request::memlist(chat)).await?;
                            ok = crate::room_sync::response_ok(&list);
                            if ok {
                                self.store.live_apply(&self.account, seq, &list)?;
                                let accepted: bool = self.store.lock()?.query_row(
                                    "SELECT applied FROM loco_inbox WHERE sequence=?1",
                                    [seq],
                                    |r| r.get(0),
                                )?;
                                let ids = if accepted {
                                    crate::room_sync::member_ids(&list.body)?
                                } else {
                                    ok = false;
                                    Vec::new()
                                };
                                for chunk in ids.chunks(500) {
                                    let (members, seq) =
                                        self.rpc("MEMBER", request::member(chat, chunk)).await?;
                                    ok = crate::room_sync::response_ok(&members);
                                    if !ok {
                                        break;
                                    }
                                    self.store.live_apply(&self.account, seq, &members)?;
                                }
                            }
                        }
                    }
                    self.store
                        .room_refresh_finish(&self.account, chat, requested, ok)?;
                }
                if let Some(body) = self.store.blocked_profile_request(&self.account)? {
                    let (reply, seq) = self.rpc("BLMEMBER", body).await?;
                    self.store.live_apply_optional(&self.account, seq, &reply)?;
                }
                let pending = {
                    let conn = self.store.lock()?;
                    use rusqlite::OptionalExtension;
                    conn.query_row("SELECT chat_id,log_id FROM message_refresh WHERE account_id=?1 AND retry_at_ms<=?2 ORDER BY requested_sequence LIMIT 1",rusqlite::params![self.account,chrono::Utc::now().timestamp_millis()],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,i64>(1)?))).optional()?
                };
                if let Some((chat, log)) = pending {
                    self.store.lock()?.execute("UPDATE message_refresh SET retry_at_ms=?4 WHERE account_id=?1 AND chat_id=?2 AND log_id=?3",rusqlite::params![self.account,chat,log,chrono::Utc::now().timestamp_millis()+300_000])?;
                    let (packet, seq) = self
                        .rpc("GETMSGS", request::getmsgs(&[chat], &[log]))
                        .await?;
                    self.store.live_apply(&self.account, seq, &packet)?;
                }
            }
            deferred.retain(|_, retry_at| *retry_at > Instant::now());
            if let Some(range) = self
                .store
                .live_range(&self.account, &deferred.keys().copied().collect())?
            {
                self.store.live_phase(
                    &self.account,
                    &self.generation,
                    "catching_up",
                    None,
                    None,
                )?;
                if !self.catch_up(range).await? {
                    // History availability is independent of the live socket.
                    // Preserve the gap; retry without starving other rooms/pushes.
                    deferred.insert(range.chat, Instant::now() + Duration::from_secs(300));
                }
                continue;
            }
            self.store
                .live_phase(&self.account, &self.generation, "connected", None, None)?;
            tokio::select! {
                _=self.stop.changed()=>return Err(Failure::Shutdown),
                packet=self.socket.receive()=>{
                    let packet=packet?; self.ping_at=Instant::now()+self.heartbeat;
                    let seq=self.store.live_capture(&self.account,&self.generation,&packet)?;
                    self.push(packet,seq).await?;
                }
                _=tokio::time::sleep_until(self.ping_at)=>{
                    let (packet,seq)=self.rpc("PING",request::ping()).await?;
                    if packet.header.status!=0{return Err(Failure::Protocol);}
                    self.store.live_apply(&self.account,seq,&packet)?;
                }
                _=pulse.tick()=>(),
                _=tokio::time::sleep_until(metadata_at)=>(),
            }
        }
    }
}
fn validate_sync(packet: &Packet, range: Range) -> Outcome<(bool, i64)> {
    if packet.header.status != 0 {
        return Err(Failure::Protocol);
    }
    let ok = packet
        .body
        .get_bool("isOK")
        .map_err(|_| Failure::Protocol)?;
    let empty = Vec::new();
    let logs = match packet.body.get("chatLogs") {
        None | Some(bson::Bson::Null) => &empty,
        Some(bson::Bson::Array(logs)) => logs,
        _ => return Err(Failure::Protocol),
    };
    let mut next = range.cur;
    for log in logs {
        let log = log.as_document().ok_or(Failure::Protocol)?;
        let id = log.get_i64("logId").map_err(|_| Failure::Protocol)?;
        if log.get_i64("chatId").ok() != Some(range.chat) || id <= next || id > range.max {
            return Err(Failure::Protocol);
        }
        next = id;
    }
    if logs.is_empty() && ok {
        next = range.max;
    }
    Ok((ok, next))
}
/// Run until shutdown; does not bind an API port or create another authorization.
pub async fn run(store: &Store, shutdown: impl Future<Output = ()>) -> Result<()> {
    let lease = Arc::new(RuntimeLease::acquire(store)?);
    let session = store.session_load()?;
    let account = session.user_id.to_string();
    store.live_seed(&account)?;
    store.replay_pilsner(&account)?;
    store.live_replay(&account)?;
    store.recover_outgoing(&account)?;
    let mut listener = crate::pilsner::Listener::new(store.clone(), lease.clone());
    let (stop_tx, stop) = watch::channel(false);
    let result = {
        listener.ensure().await?;
        let work = supervise(store, &account, lease.clone(), stop.clone());
        let maintenance = crate::maintenance::run(store, &mut listener, stop.clone());
        tokio::pin!(work);
        tokio::pin!(maintenance);
        tokio::pin!(shutdown);
        tokio::select! {
            result=&mut work=>{let _=stop_tx.send(true);result},
            result=&mut maintenance=>{let _=stop_tx.send(true);let closed=work.await;result.and(closed)},
            _=&mut shutdown=>{let _=stop_tx.send(true);work.await},
        }
    };
    listener.close().await?;
    drop(lease);
    result
}
async fn supervise(
    store: &Store,
    account: &str,
    lease: Arc<RuntimeLease>,
    mut stop: watch::Receiver<bool>,
) -> Result<()> {
    let client = Client::new()?;
    let session = store.session_load()?;
    let message_ids = Arc::new(std::sync::Mutex::new(
        crate::loco::outgoing::MessageIds::new(
            session.wire.uuid(),
            chrono::Utc::now().timestamp_millis(),
        ),
    ));
    let mut failures = 0_u32;
    let mut refreshed = false;
    loop {
        if *stop.borrow() {
            store.live_phase(account, "", "stopped", None, None)?;
            return Ok(());
        }
        let generation = uuid::Uuid::new_v4().to_string();
        store.live_phase(account, &generation, "connecting", None, None)?;
        let session = store.session_load()?;
        let started = Instant::now();
        let result = async {
            let connected = tokio::select! {
                _ = stop.changed() => return Err(Failure::Shutdown),
                result = discover(store, &session, store.native_flag("useSub")?.unwrap_or(false)) =>
                    result.map_err(|_| Failure::Discovery)?,
            };
            let heartbeat = Duration::from_secs(
                connected
                    .configuration
                    .background_ping_seconds
                    .unwrap_or(600),
            );
            let mut worker = Worker {
                store: store.clone(),
                account: account.into(),
                generation: generation.clone(),
                socket: connected
                    .connection
                    .into_live_guarded(Some(lease.clone()))?,
                ids: connected.ids,
                stop: stop.clone(),
                heartbeat,
                write_timeout: Duration::from_secs(
                    connected.configuration.write_timeout_seconds.unwrap_or(20),
                ),
                ping_at: Instant::now() + heartbeat,
                recovery_scans: Default::default(),
                message_ids: message_ids.clone(),
            };
            let result = async {
                worker.login(&session).await?;
                refreshed = false;
                store.live_phase(account, &generation, "connected", None, None)?;
                worker.receive_loop().await
            }
            .await;
            worker.socket.close().await;
            result
        }
        .await;
        let (category, status) = match result {
            Err(Failure::Shutdown) => {
                store.live_phase(account, &generation, "stopped", None, None)?;
                return Ok(());
            }
            Err(Failure::Login(-950)) if !refreshed => {
                refreshed = true;
                let mut session = store.session_load()?;
                if client.refresh(store, &mut session).await.is_err() {
                    store.live_phase(
                        account,
                        &generation,
                        "stopped",
                        Some("refresh_failed"),
                        Some(-950),
                    )?;
                    return Err(Error::Unauthorized);
                }
                ("access_token_refreshed", Some(-950))
            }
            Err(Failure::Login(status)) => {
                store.live_phase(
                    account,
                    &generation,
                    "stopped",
                    Some("login_rejected"),
                    Some(status),
                )?;
                return Err(Error::Unauthorized);
            }
            Err(Failure::Stop(reason)) => {
                store.live_phase(account, &generation, "stopped", Some(reason), None)?;
                return Err(Error::Conflict(format!("collector stopped: {reason}")));
            }
            Err(Failure::Local(error)) => {
                store.live_phase(
                    account,
                    &generation,
                    "stopped",
                    Some("local_storage_or_validation"),
                    None,
                )?;
                return Err(error);
            }
            Err(Failure::Protocol) => ("protocol", None),
            Err(Failure::Transport(error)) => (
                match error {
                    crate::loco::transport::TransportError::Io => "transport_io",
                    crate::loco::transport::TransportError::Closed => "transport_closed",
                    crate::loco::transport::TransportError::Timeout => "transport_timeout",
                    crate::loco::transport::TransportError::Tls => "transport_tls",
                    crate::loco::transport::TransportError::Correlation => "transport_correlation",
                    crate::loco::transport::TransportError::Backlog => "transport_backlog",
                    crate::loco::transport::TransportError::Poisoned => "transport_poisoned",
                    crate::loco::transport::TransportError::Protocol(_) => "transport_protocol",
                },
                None,
            ),
            Err(Failure::Timeout) => ("timeout", None),
            Err(Failure::Discovery) => ("discovery", None),
            Err(Failure::Reconnect) => ("server_change", None),
            Ok(()) => ("closed", None),
        };
        if started.elapsed() > Duration::from_secs(60) {
            failures = 0;
        }
        failures = failures.saturating_add(1);
        // Apply the supervisor retry policy across connection attempts.
        // Bound outage retries at 5 minutes; never reauthenticate/register a device.
        let delay = Duration::from_secs((1_u64 << failures.min(8)).min(300));
        store.live_phase(account, &generation, "reconnecting", Some(category), status)?;
        tokio::select! {_ = stop.changed()=>(),_ = tokio::time::sleep(delay)=>()}
    }
}

#[cfg(test)]
mod tests;
