//! Optional QR authorization adapter. No bootstrap, refresh, native sync or phone APIs.
//! Production destination is fixed; only cfg(test) permits a loopback mock backend.
//! Tokens are intentionally stored UNENCRYPTED in a private 0600 handoff file.
use crate::{
    qr::{self, AuthHandoff, LoginOutcome, QrError, Session, Stage, WireProfile},
    Store,
};
use qrcode::{render::svg, EcLevel, QrCode};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::{
    fs::{self, File, OpenOptions},
    future::Future,
    io::{Read, Write},
    path::{Path, PathBuf},
    pin::Pin,
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::time::Instant;
use uuid::Uuid;

const PRODUCTION_BASE: &str = "https://katalk.kakao.com/android/account/";
const RESPONSE_LIMIT: usize = 64 * 1024;
const HANDOFF_LIMIT: u64 = 128 * 1024;
const HANDOFF_FILE: &str = "qr-handoff.json";
const PENDING_FILE: &str = "qr-handoff.pending";
const LOCK_DIR: &str = ".qr-auth-lock";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthErrorCode {
    TerminalInput,
    InvalidCredentialsInput,
    InvalidTimeout,
    DeviceRequired,
    AlreadyAuthorized,
    RecoveryRequired,
    Busy,
    Storage,
    Transport,
    RequestTimeout,
    OverallTimeout,
    Cancelled,
    Expired,
    HttpStatus,
    Redirect,
    ResponseTooLarge,
    ResponseDecode,
    InvalidResponse,
    QrArtifact,
    Protocol,
}
/// Fixed metadata only; never wraps a request, response body, URL, ID or token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, thiserror::Error)]
#[error("experimental authorization: {code:?} (protocol {protocol:?}); inspect auth status before another attempt")]
pub struct AuthError {
    pub code: AuthErrorCode,
    pub protocol: Option<QrError>,
}
impl AuthError {
    pub(crate) fn new(code: AuthErrorCode) -> Self {
        Self {
            code,
            protocol: None,
        }
    }
    pub(crate) fn storage<T>(_: T) -> Self {
        Self::new(AuthErrorCode::Storage)
    }
}
impl From<QrError> for AuthError {
    fn from(protocol: QrError) -> Self {
        Self {
            code: AuthErrorCode::Protocol,
            protocol: Some(protocol),
        }
    }
}
pub type AuthResult<T> = std::result::Result<T, AuthError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthState {
    NotStarted,
    Stopped,
    RecoveryRequired,
    QrAuthorizedBootstrapPending,
    PasswordAuthorizedBootstrapPending,
}
#[derive(Debug, Serialize)]
pub struct AuthStatus {
    pub state: AuthState,
    pub method: Option<String>,
    pub started_at_epoch_ms: Option<i64>,
    pub stop_code: Option<String>,
    pub recovery_required: bool,
    pub handoff_present: bool,
    pub process_lock_present: bool,
    pub native_auth_ready: bool,
    pub bootstrap_complete: bool,
    pub native_sync_verified: bool,
    pub secrets_encrypted_at_rest: bool,
}
impl Store {
    /// Local metadata only. Never returns token, QR URL, UUID, account ID or passcode.
    pub fn auth_status(&self) -> AuthResult<AuthStatus> {
        let connection = self.lock().map_err(AuthError::storage)?;
        let attempt: Option<(String, i64, Option<String>, Option<String>)> = connection
            .query_row(
                "SELECT state,started_at_ms,stop_code,handoff_hash FROM qr_auth_attempt WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()
            .map_err(AuthError::storage)?;
        let lock = self.data_dir.join(LOCK_DIR).symlink_metadata().is_ok();
        let method: Option<String> = connection
            .query_row(
                "SELECT value FROM metadata WHERE key='auth_method'",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(AuthError::storage)?;
        let method = match method.as_deref() {
            Some("password") => Some("password".to_owned()),
            Some("qr") | None if attempt.is_some() => Some("qr".to_owned()),
            _ => None,
        };
        let handoff = self.data_dir.join(HANDOFF_FILE).symlink_metadata().is_ok();
        let pending = self.data_dir.join(PENDING_FILE).symlink_metadata().is_ok();
        let (mut state, started, stop_code) = match &attempt {
            None => (AuthState::NotStarted, None, None),
            Some((state, started, code, _)) => (
                match state.as_str() {
                    "stopped" => AuthState::Stopped,
                    "authorized" if method.as_deref() == Some("password") => {
                        AuthState::PasswordAuthorizedBootstrapPending
                    }
                    "authorized" => AuthState::QrAuthorizedBootstrapPending,
                    _ => AuthState::RecoveryRequired,
                },
                Some(*started),
                code.as_ref().map(|code| {
                    if matches!(
                        code.as_str(),
                        "terminal_server_status"
                            | "cancellation_confirmed"
                            | "generation_only_stopped"
                            | "password_server_rejected"
                            | "password_challenge_stopped"
                            | "password_input_stopped"
                    ) {
                        code.clone()
                    } else {
                        "unrecognized_stop_code".into()
                    }
                }),
            ),
        };
        match &attempt {
            Some((saved_state, _, _, Some(hash))) if saved_state == "authorized" && !pending => {
                if !verify_handoff(&self.data_dir.join(HANDOFF_FILE), hash) {
                    state = AuthState::RecoveryRequired;
                }
            }
            Some((saved_state, _, _, _)) if saved_state == "authorized" => {
                state = AuthState::RecoveryRequired
            }
            _ if handoff || pending => state = AuthState::RecoveryRequired,
            _ => (),
        }
        if lock {
            state = AuthState::RecoveryRequired;
        }
        Ok(AuthStatus {
            state,
            method,
            started_at_epoch_ms: started,
            stop_code,
            recovery_required: state == AuthState::RecoveryRequired,
            handoff_present: handoff,
            process_lock_present: lock,
            native_auth_ready: false,
            bootstrap_complete: false,
            native_sync_verified: false,
            secrets_encrypted_at_rest: false,
        })
    }
}
fn private_file(metadata: &fs::Metadata) -> bool {
    metadata.is_file() && !metadata.file_type().is_symlink() && {
        #[cfg(unix)]
        {
            metadata.permissions().mode() & 0o077 == 0
        }
        #[cfg(not(unix))]
        {
            true
        }
    }
}
fn verify_handoff(path: &Path, expected_hash: &str) -> bool {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    if !private_file(&metadata) || metadata.len() > HANDOFF_LIMIT {
        return false;
    }
    let Ok(file) = File::open(path) else {
        return false;
    };
    let mut bytes = Vec::new();
    if file
        .take(HANDOFF_LIMIT + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() as u64 > HANDOFF_LIMIT
    {
        return false;
    }
    let hash = hex::encode(Sha256::digest(&bytes));
    bool::from(hash.as_bytes().ct_eq(expected_hash.as_bytes()))
}

struct Transport {
    client: reqwest::Client,
    base: reqwest::Url,
}
impl Transport {
    fn production() -> AuthResult<Self> {
        Self::build(PRODUCTION_BASE, Duration::from_secs(10), true)
    }
    fn build(base: &str, timeout: Duration, https_only: bool) -> AuthResult<Self> {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .referer(false)
            .https_only(https_only)
            .connect_timeout(timeout)
            .timeout(timeout)
            .user_agent("okhttp/4.12.0")
            .gzip(true)
            .build()
            .map_err(|_| AuthError::new(AuthErrorCode::Transport))?;
        let base =
            reqwest::Url::parse(base).map_err(|_| AuthError::new(AuthErrorCode::Transport))?;
        Ok(Self { client, base })
    }
    #[cfg(test)]
    fn mock(address: std::net::SocketAddr, timeout: Duration) -> Self {
        assert!(address.ip().is_loopback());
        Self::build(
            &format!("http://{address}/android/account/"),
            timeout,
            false,
        )
        .unwrap()
    }
    async fn post(&self, path: &str, body: &impl Serialize) -> AuthResult<Vec<u8>> {
        if !matches!(path, qr::GENERATE_PATH | qr::LOGIN_PATH | qr::CANCEL_PATH) {
            return Err(AuthError::new(AuthErrorCode::Transport));
        }
        let body =
            serde_json::to_vec(body).map_err(|_| AuthError::new(AuthErrorCode::InvalidResponse))?;
        let url = self
            .base
            .join(path)
            .map_err(|_| AuthError::new(AuthErrorCode::Transport))?;
        let mut response = self
            .client
            .post(url)
            .header(qr::A_HEADER_NAME, qr::A_HEADER)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT_ENCODING, "gzip")
            .header(reqwest::header::CONNECTION, "Keep-Alive")
            .body(body)
            .send()
            .await
            .map_err(network_error)?;
        let status = response.status();
        if status.is_redirection() {
            return Err(AuthError::new(AuthErrorCode::Redirect));
        }
        if !status.is_success() && !status.is_client_error() {
            return Err(AuthError::new(AuthErrorCode::HttpStatus));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(network_error)? {
            if chunk.len() > RESPONSE_LIMIT - bytes.len() {
                return Err(AuthError::new(AuthErrorCode::ResponseTooLarge));
            }
            bytes.extend_from_slice(&chunk);
        }
        // Negative business status may arrive in a 4xx envelope. HTTP errors can
        // never turn a status=0 body into a successful authorization handoff.
        if status.is_client_error() {
            let envelope: StatusEnvelope = serde_json::from_slice(&bytes)
                .map_err(|_| AuthError::new(AuthErrorCode::HttpStatus))?;
            if envelope.status.is_none_or(|status| status >= 0) {
                return Err(AuthError::new(AuthErrorCode::HttpStatus));
            }
        }
        Ok(bytes)
    }
}
fn network_error(error: reqwest::Error) -> AuthError {
    AuthError::new(if error.is_timeout() {
        AuthErrorCode::RequestTimeout
    } else if error.is_decode() {
        AuthErrorCode::ResponseDecode
    } else {
        AuthErrorCode::Transport
    })
}
#[derive(Deserialize)]
struct StatusEnvelope {
    status: Option<i32>,
}

pub(crate) struct Attempt {
    store: Store,
    id: String,
    retain_lock: bool,
    login_dispatched: bool,
    svg_path: PathBuf,
}
impl Attempt {
    fn begin(store: &Store) -> AuthResult<(Self, WireProfile)> {
        Self::begin_method(store, "qr")
    }
    pub(crate) fn begin_password(store: &Store) -> AuthResult<(Self, WireProfile)> {
        Self::begin_method(store, "password")
    }
    fn begin_method(store: &Store, method: &str) -> AuthResult<(Self, WireProfile)> {
        store
            .device_show()
            .map_err(|_| AuthError::new(AuthErrorCode::DeviceRequired))?;
        let lock = store.data_dir.join(LOCK_DIR);
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        builder.mode(0o700);
        builder.create(&lock).map_err(|error| {
            AuthError::new(if error.kind() == std::io::ErrorKind::AlreadyExists {
                AuthErrorCode::Busy
            } else {
                AuthErrorCode::Storage
            })
        })?;
        let id = Uuid::new_v4().simple().to_string();
        let mut attempt = Self {
            store: store.clone(),
            id: id.clone(),
            retain_lock: false,
            login_dispatched: false,
            svg_path: store.data_dir.join(format!("qr-login-{id}.svg")),
        };
        File::open(&*store.data_dir)
            .and_then(|file| file.sync_all())
            .map_err(AuthError::storage)?;
        // Our own live lock is expected here; inspect persistent attempts directly.
        let connection = store.lock().map_err(AuthError::storage)?;
        let prior: Option<String> = connection
            .query_row("SELECT state FROM qr_auth_attempt WHERE id=1", [], |r| {
                r.get(0)
            })
            .optional()
            .map_err(AuthError::storage)?;
        if prior.as_deref() == Some("authorized") {
            return Err(AuthError::new(AuthErrorCode::AlreadyAuthorized));
        }
        if prior.as_deref().is_some_and(|state| state != "stopped")
            || store.data_dir.join(HANDOFF_FILE).symlink_metadata().is_ok()
            || store.data_dir.join(PENDING_FILE).symlink_metadata().is_ok()
        {
            return Err(AuthError::new(AuthErrorCode::RecoveryRequired));
        }
        drop(connection);
        let wire = store
            .qr_wire_initialize(chrono::Utc::now().timestamp_millis())
            .map_err(AuthError::storage)?;
        let mut connection = store.lock().map_err(AuthError::storage)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(AuthError::storage)?;
        tx.execute("INSERT INTO qr_auth_attempt(id,attempt_id,state,started_at_ms) VALUES(1,?1,'pending',?2) ON CONFLICT(id) DO UPDATE SET attempt_id=excluded.attempt_id,state='pending',started_at_ms=excluded.started_at_ms,stop_code=NULL,handoff_hash=NULL",params![attempt.id,chrono::Utc::now().timestamp_millis()]).map_err(AuthError::storage)?;
        tx.execute("INSERT INTO metadata(key,value) VALUES('auth_method',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value", [method]).map_err(AuthError::storage)?;
        tx.commit().map_err(AuthError::storage)?;
        attempt.retain_lock = true;
        Ok((attempt, wire))
    }
    fn write_svg(&self, url: &str) -> AuthResult<()> {
        let code = QrCode::with_error_correction_level(url.as_bytes(), EcLevel::M)
            .map_err(|_| AuthError::new(AuthErrorCode::QrArtifact))?;
        let image = code
            .render::<svg::Color>()
            .min_dimensions(512, 512)
            .quiet_zone(true)
            .build();
        exclusive_write(&self.svg_path, image.as_bytes()).map_err(AuthError::storage)?;
        sync_dir(&self.store.data_dir).map_err(AuthError::storage)
    }
    pub(crate) fn stop_confirmed(&mut self, reason: &str) -> AuthResult<()> {
        let changed=self.store.lock().map_err(AuthError::storage)?.execute("UPDATE qr_auth_attempt SET state='stopped',stop_code=?2 WHERE id=1 AND attempt_id=?1 AND state='pending'",params![self.id,reason]).map_err(AuthError::storage)?;
        if changed != 1 {
            return Err(AuthError::new(AuthErrorCode::Storage));
        }
        self.retain_lock = false;
        Ok(())
    }
    fn persist_handoff(&mut self, handoff: AuthHandoff) -> AuthResult<()> {
        // Deliberate one-way serialization at the private persistence boundary.
        // The token-bearing type itself has no Debug or Serialize implementation.
        #[derive(Serialize)]
        struct Saved<'a> {
            schema_version: u32,
            attempt_id: &'a str,
            authorized_at_epoch_ms: i64,
            user_id: &'a str,
            country_iso: &'a str,
            account_id: Option<&'a str>,
            display_account_id: Option<&'a str>,
            access_token: &'a str,
            refresh_token: &'a str,
            token_type: &'a str,
            native_sync_verified: bool,
        }
        let saved = Saved {
            schema_version: 1,
            attempt_id: &self.id,
            authorized_at_epoch_ms: chrono::Utc::now().timestamp_millis(),
            user_id: &handoff.user.user_id,
            country_iso: &handoff.user.country_iso,
            account_id: handoff.user.account_id.as_deref(),
            display_account_id: handoff.user.display_account_id.as_deref(),
            access_token: handoff.expose_access_token(),
            refresh_token: handoff.expose_refresh_token(),
            token_type: handoff.token_type(),
            native_sync_verified: false,
        };
        let bytes = serde_json::to_vec(&saved).map_err(AuthError::storage)?;
        self.persist_bytes(&bytes)
    }
    pub(crate) fn persist_password(&mut self, response: &serde_json::Value) -> AuthResult<()> {
        // Preserve bootstrap fields only; never save echoed credentials or diagnostics.
        let mut saved_response = serde_json::Map::new();
        for key in [
            "server_time",
            "userId",
            "profileId",
            "countryIso",
            "accountId",
            "sessionKey",
            "access_token",
            "refresh_token",
            "token_type",
            "autoLoginAccountId",
            "displayAccountId",
        ] {
            if let Some(value) = response.get(key) {
                saved_response.insert(key.to_owned(), value.clone());
            }
        }
        let bytes = serde_json::to_vec(&serde_json::json!({
            "schema_version":2, "method":"password", "attempt_id":self.id,
            "authorized_at_epoch_ms":chrono::Utc::now().timestamp_millis(),
            "response":saved_response, "native_sync_verified":false
        }))
        .map_err(AuthError::storage)?;
        self.persist_bytes(&bytes)
    }
    fn persist_bytes(&mut self, bytes: &[u8]) -> AuthResult<()> {
        if bytes.len() as u64 > HANDOFF_LIMIT {
            return Err(AuthError::new(AuthErrorCode::Storage));
        }
        let pending = self.store.data_dir.join(PENDING_FILE);
        exclusive_write(&pending, bytes).map_err(AuthError::storage)?;
        // hard_link publishes atomically and fails if the final name already exists.
        fs::hard_link(&pending, self.store.data_dir.join(HANDOFF_FILE))
            .map_err(AuthError::storage)?;
        sync_dir(&self.store.data_dir).map_err(AuthError::storage)?;
        fs::remove_file(&pending).map_err(AuthError::storage)?;
        sync_dir(&self.store.data_dir).map_err(AuthError::storage)?;
        let hash = hex::encode(Sha256::digest(bytes));
        let changed=self.store.lock().map_err(AuthError::storage)?.execute("UPDATE qr_auth_attempt SET state='authorized',handoff_hash=?2,stop_code=NULL WHERE id=1 AND attempt_id=?1 AND state='pending'",params![self.id,hash]).map_err(AuthError::storage)?;
        if changed != 1 {
            return Err(AuthError::new(AuthErrorCode::Storage));
        }
        self.retain_lock = false;
        Ok(())
    }
}
impl Drop for Attempt {
    fn drop(&mut self) {
        if !self.retain_lock {
            let _ = fs::remove_file(&self.svg_path);
            let _ = fs::remove_dir(self.store.data_dir.join(LOCK_DIR));
            let _ = sync_dir(&self.store.data_dir);
        }
    }
}
fn exclusive_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}
fn sync_dir(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

/// Explicit display notices. Neither QR URLs nor challenge IDs are emitted here.
/// Only the passcode notice deliberately exposes a phone-approval passcode.
pub enum Notice<'a> {
    QrReady {
        path: &'a Path,
        expires_in_seconds: u64,
    },
    Passcode {
        value: &'a str,
        remaining_seconds: u64,
    },
}
/// This is the only public production entry point. Calling it explicitly generates
/// a QR challenge on the fixed Kakao host; it never contacts phone authorize/confirm.
pub async fn authorize_qr<C, F>(
    store: &Store,
    timeout_seconds: u16,
    cancellation: C,
    observer: F,
) -> AuthResult<AuthStatus>
where
    C: Future<Output = ()>,
    F: FnMut(Notice<'_>),
{
    if !(1..=600).contains(&timeout_seconds) {
        return Err(AuthError::new(AuthErrorCode::InvalidTimeout));
    }
    let transport = Transport::production()?;
    authorize_with_transport(
        store,
        Duration::from_secs(u64::from(timeout_seconds)),
        cancellation,
        observer,
        transport,
    )
    .await
}
async fn authorize_with_transport<C, F>(
    store: &Store,
    timeout: Duration,
    cancellation: C,
    mut observer: F,
    transport: Transport,
) -> AuthResult<AuthStatus>
where
    C: Future<Output = ()>,
    F: FnMut(Notice<'_>),
{
    let (mut attempt, wire) = Attempt::begin(store)?;
    let mut session = Session::new(wire)?;
    let start = Instant::now();
    let overall = start + timeout;
    tokio::pin!(cancellation);
    let result = drive(
        &mut attempt,
        &mut session,
        &transport,
        start,
        overall,
        &mut cancellation,
        &mut observer,
    )
    .await;
    match result {
        Ok(handoff) => {
            attempt.persist_handoff(handoff)?;
            drop(attempt);
            store.auth_status()
        }
        Err(error) => {
            let known_terminal = error.protocol.is_some_and(|error| {
                matches!(
                    error.code,
                    qr::ErrorCode::Denied
                        | qr::ErrorCode::AllowlistRequired
                        | qr::ErrorCode::LoginConflict
                )
            });
            if known_terminal {
                attempt.stop_confirmed("terminal_server_status")?;
            } else if matches!(
                session.stage(),
                Stage::WaitingApproval | Stage::PasscodeRequired | Stage::LoginInFlight
            ) {
                let ambiguous = session.stage() == Stage::LoginInFlight;
                if let Ok(request) = session.prepare_cancel(elapsed(start)) {
                    if let Ok(bytes) = transport.post(qr::CANCEL_PATH, &request).await {
                        if serde_json::from_slice::<StatusEnvelope>(&bytes)
                            .ok()
                            .is_some_and(|body| body.status == Some(0))
                            && !ambiguous
                        {
                            attempt.stop_confirmed("cancellation_confirmed")?;
                        }
                    }
                }
            }
            if !attempt.login_dispatched && attempt.retain_lock {
                // Generation alone cannot produce a login token. A completed error
                // path can stop safely; crashes still leave the durable pending marker.
                attempt.stop_confirmed("generation_only_stopped")?;
            }
            // Once login could have authorized, ambiguous network outcomes, parser
            // errors and token-persistence failures retain pending state and the lock.
            Err(error)
        }
    }
}
fn elapsed(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}
async fn exchange<C: Future<Output = ()>>(
    transport: &Transport,
    path: &str,
    request: &impl Serialize,
    cancellation: &mut Pin<&mut C>,
    deadline: Instant,
) -> AuthResult<Vec<u8>> {
    tokio::select! {biased;
        _=cancellation.as_mut()=>Err(AuthError::new(AuthErrorCode::Cancelled)),
        _=tokio::time::sleep_until(deadline)=>Err(AuthError::new(AuthErrorCode::OverallTimeout)),
        response=transport.post(path,request)=>response,
    }
}
async fn drive<C, F>(
    attempt: &mut Attempt,
    session: &mut Session,
    transport: &Transport,
    start: Instant,
    overall: Instant,
    cancellation: &mut Pin<&mut C>,
    observer: &mut F,
) -> AuthResult<AuthHandoff>
where
    C: Future<Output = ()>,
    F: FnMut(Notice<'_>),
{
    let generate = session.prepare_generate(None, elapsed(start))?;
    let response = exchange(
        transport,
        qr::GENERATE_PATH,
        &generate,
        cancellation,
        overall,
    )
    .await?;
    let challenge = session.receive_generate(&response, elapsed(start))?;
    attempt.write_svg(challenge.expose_qr_url())?;
    observer(Notice::QrReady {
        path: &attempt.svg_path,
        expires_in_seconds: challenge.expires_at_ms.saturating_sub(elapsed(start)) / 1000,
    });
    loop {
        let expiry = start
            + Duration::from_millis(
                session
                    .expires_at_ms()
                    .ok_or_else(|| AuthError::new(AuthErrorCode::InvalidResponse))?,
            );
        let end = overall.min(expiry);
        let wake = start
            + Duration::from_millis(
                session
                    .next_poll_at_ms()
                    .ok_or_else(|| AuthError::new(AuthErrorCode::InvalidResponse))?,
            );
        tokio::select! {biased;
            _=cancellation.as_mut()=>return Err(AuthError::new(AuthErrorCode::Cancelled)),
            _=tokio::time::sleep_until(end)=>return Err(AuthError::new(if expiry<=overall{AuthErrorCode::Expired}else{AuthErrorCode::OverallTimeout})),
            _=tokio::time::sleep_until(wake)=>(),
        }
        let now = elapsed(start);
        if session.expires_at_ms().is_some_and(|expiry| now >= expiry) {
            return Err(AuthError::new(AuthErrorCode::Expired));
        }
        let login = session.prepare_login(now)?;
        // Set before polling the HTTP future: cancellation at the boundary is
        // conservatively considered a possibly dispatched login.
        attempt.login_dispatched = true;
        let response = exchange(transport, qr::LOGIN_PATH, &login, cancellation, end).await?;
        let now = elapsed(start);
        if session.expires_at_ms().is_some_and(|expiry| now >= expiry) {
            // Keep the challenge ID for one best-effort cancel. A response received
            // after expiry may already have authorized remotely, so recovery stays pending.
            return Err(AuthError::new(AuthErrorCode::Expired));
        }
        match session.receive_login(&response, now)? {
            LoginOutcome::Waiting { .. } => (),
            LoginOutcome::Passcode(passcode) => observer(Notice::Passcode {
                value: passcode.expose_passcode(),
                remaining_seconds: passcode.expires_at_ms.saturating_sub(elapsed(start)) / 1000,
            }),
            LoginOutcome::Authorized(handoff) => return Ok(handoff),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        extract::{Request, State},
        http::HeaderMap,
        response::Response,
        Router,
    };
    use serde_json::{json, Value};
    use std::{
        collections::VecDeque,
        net::SocketAddr,
        sync::{Arc, Mutex},
    };
    struct Recorded {
        path: String,
        method: String,
        headers: HeaderMap,
        body: Vec<u8>,
    }
    enum Reply {
        Json(u16, Value),
        Raw(u16, Vec<u8>, Option<&'static str>),
        Redirect,
        Sleep(Duration, Box<Reply>),
    }
    struct Backend {
        replies: Mutex<VecDeque<Reply>>,
        requests: Mutex<Vec<Recorded>>,
    }
    struct Mock {
        address: SocketAddr,
        backend: Arc<Backend>,
        task: tokio::task::JoinHandle<()>,
    }
    impl Drop for Mock {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    impl Mock {
        async fn start(replies: Vec<Reply>) -> Self {
            async fn handler(State(backend): State<Arc<Backend>>, request: Request) -> Response {
                let (parts, body) = request.into_parts();
                let bytes = to_bytes(body, 32 * 1024).await.unwrap();
                backend.requests.lock().unwrap().push(Recorded {
                    path: parts.uri.path().into(),
                    method: parts.method.to_string(),
                    headers: parts.headers,
                    body: bytes.to_vec(),
                });
                let mut reply = backend
                    .replies
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("unexpected additional request");
                loop {
                    match reply {
                        Reply::Json(status, ref json) => {
                            return Response::builder()
                                .status(status)
                                .header("content-type", "application/json")
                                .body(Body::from(serde_json::to_vec(json).unwrap()))
                                .unwrap()
                        }
                        Reply::Raw(status, bytes, encoding) => {
                            let mut response = Response::builder().status(status);
                            if let Some(encoding) = encoding {
                                response = response.header("content-encoding", encoding);
                            }
                            return response.body(Body::from(bytes)).unwrap();
                        }
                        Reply::Redirect => {
                            return Response::builder()
                                .status(302)
                                .header("location", "/must-never-be-followed?secret=synthetic")
                                .body(Body::from("synthetic-secret-response"))
                                .unwrap()
                        }
                        Reply::Sleep(delay, next) => {
                            tokio::time::sleep(delay).await;
                            reply = *next;
                        }
                    }
                }
            }
            let backend = Arc::new(Backend {
                replies: Mutex::new(replies.into()),
                requests: Mutex::new(Vec::new()),
            });
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let app = Router::new().fallback(handler).with_state(backend.clone());
            let task = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            Self {
                address,
                backend,
                task,
            }
        }
        fn transport(&self) -> Transport {
            Transport::mock(self.address, Duration::from_secs(2))
        }
        fn requests(&self) -> usize {
            self.backend.requests.lock().unwrap().len()
        }
    }
    fn setup() -> (tempfile::TempDir, Store) {
        let temp = tempfile::Builder::new()
            .prefix("kakao-auth-test-")
            .permissions(
                <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
            )
            .tempdir()
            .unwrap();
        let store = Store::initialize(temp.path()).unwrap();
        let catalog = serde_json::from_str(include_str!("../config/device-catalog.json")).unwrap();
        store
            .device_initialize(
                &catalog,
                chrono::NaiveDate::from_ymd_opt(2026, 11, 13).unwrap(),
            )
            .unwrap();
        (temp, store)
    }
    fn generated() -> Reply {
        Reply::Json(
            200,
            json!({"status":0,"url":"synthetic://qr?id=synthetic-id","remainingSeconds":30}),
        )
    }
    fn success() -> Reply {
        Reply::Json(
            200,
            json!({"status":0,"user":{"userId":9007199254740993_i64,"countryIso":"KR"},"accessToken":"synthetic-access-secret","refreshToken":"synthetic-refresh-secret","tokenType":"Bearer"}),
        )
    }
    fn code<T>(result: AuthResult<T>) -> AuthError {
        match result {
            Err(error) => error,
            Ok(_) => panic!("expected redacted error"),
        }
    }
    async fn run(store: &Store, mock: &Mock) -> AuthResult<AuthStatus> {
        authorize_with_transport(
            store,
            Duration::from_secs(5),
            std::future::pending(),
            |_| {},
            mock.transport(),
        )
        .await
    }

    #[tokio::test]
    async fn headers_bodies_wait_passcode_and_exclusive_durable_handoff() {
        let (temp, store) = setup();
        let mock=Mock::start(vec![generated(),Reply::Json(400,json!({"status":-150,"nextRequestIntervalInSeconds":1})),Reply::Json(400,json!({"status":-100,"nextRequestIntervalInSeconds":1,"remainingSeconds":30,"passcode":"synthetic-1234"})),success()]).await;
        let mut qr_seen = false;
        let mut passcode_seen = false;
        let status = authorize_with_transport(
            &store,
            Duration::from_secs(5),
            std::future::pending(),
            |notice| match notice {
                Notice::QrReady {
                    path,
                    expires_in_seconds,
                } => {
                    assert!(path.starts_with(std::fs::canonicalize(temp.path()).unwrap()));
                    assert!(expires_in_seconds <= 30);
                    let image = fs::read_to_string(path).unwrap();
                    assert!(image.contains("<svg"));
                    assert!(!image.contains("synthetic://"));
                    #[cfg(unix)]
                    assert_eq!(
                        fs::metadata(path).unwrap().permissions().mode() & 0o777,
                        0o600
                    );
                    qr_seen = true;
                }
                Notice::Passcode { value, .. } => {
                    assert_eq!(value, "synthetic-1234");
                    passcode_seen = true;
                }
            },
            mock.transport(),
        )
        .await
        .unwrap();
        assert!(qr_seen && passcode_seen);
        assert_eq!(status.state, AuthState::QrAuthorizedBootstrapPending);
        assert!(
            !status.native_auth_ready
                && !status.bootstrap_complete
                && !status.native_sync_verified
                && !status.secrets_encrypted_at_rest
        );
        assert!(!status.recovery_required && !status.process_lock_present);
        let metadata = serde_json::to_string(&status).unwrap();
        for secret in [
            "synthetic-access-secret",
            "synthetic-refresh-secret",
            "synthetic-id",
            "synthetic-1234",
            "9007199254740993",
        ] {
            assert!(!metadata.contains(secret));
        }
        let handoff = fs::read_to_string(temp.path().join(HANDOFF_FILE)).unwrap();
        assert!(handoff.contains("synthetic-access-secret"));
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(temp.path().join(HANDOFF_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(!temp.path().join(PENDING_FILE).exists());
        assert!(fs::read_dir(temp.path()).unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".svg")));
        {
            let requests = mock.backend.requests.lock().unwrap();
            assert_eq!(requests.len(), 4);
            let wire = store.qr_wire_show().unwrap();
            for (index, request) in requests.iter().enumerate() {
                assert_eq!(request.method, "POST");
                assert_eq!(request.headers["a"], "android/26.3.2/ko");
                assert_eq!(request.headers["user-agent"], "okhttp/4.12.0");
                assert_eq!(request.headers["content-type"], "application/json");
                assert_eq!(request.headers["accept-encoding"], "gzip");
                assert_eq!(request.headers["connection"], "Keep-Alive");
                assert_eq!(request.headers["host"], mock.address.to_string());
                assert_eq!(
                    request.headers["content-length"]
                        .to_str()
                        .unwrap()
                        .parse::<usize>()
                        .unwrap(),
                    request.body.len()
                );
                assert!(!request.headers.contains_key("authorization"));
                assert!(!request.headers.contains_key("x-vc"));
                let body: Value = serde_json::from_slice(&request.body).unwrap();
                if index == 0 {
                    assert_eq!(request.path, "/android/account/qrCodeLogin/generate");
                    assert_eq!(
                        body,
                        json!({"device":{"name":wire.model(),"uuid":wire.uuid(),"model":wire.model(),"osVersion":"13"}})
                    );
                } else {
                    assert_eq!(request.path, "/android/account/qrCodeLogin/login");
                    assert_eq!(
                        body,
                        json!({"device":{"uuid":wire.uuid()},"id":"synthetic-id"})
                    );
                }
            }
        }
        assert_eq!(
            code(run(&store, &mock).await).code,
            AuthErrorCode::AlreadyAuthorized
        );
        assert_eq!(mock.requests(), 4);
        fs::write(temp.path().join(HANDOFF_FILE), "damaged synthetic handoff").unwrap();
        let status = store.auth_status().unwrap();
        assert_eq!(status.state, AuthState::RecoveryRequired);
        assert!(!serde_json::to_string(&status).unwrap().contains("damaged"));
    }

    #[tokio::test]
    async fn transport_refuses_redirect_oversize_gzip_expansion_and_server_errors() {
        use base64::Engine;
        // gzip of 65,537 'x' bytes: decoded size must trigger the same 64 KiB cap.
        let compressed=base64::engine::general_purpose::STANDARD.decode("H4sIAAAAAAAC/+3BAQEAAACCoNvOryFAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwA2B2CqcAQABAA==").unwrap();
        for (reply, expected) in [
            (Reply::Redirect, AuthErrorCode::Redirect),
            (
                Reply::Raw(200, vec![b'x'; RESPONSE_LIMIT + 1], None),
                AuthErrorCode::ResponseTooLarge,
            ),
            (
                Reply::Raw(200, compressed, Some("gzip")),
                AuthErrorCode::ResponseTooLarge,
            ),
            (
                Reply::Raw(200, b"not-gzip-synthetic-secret".to_vec(), Some("gzip")),
                AuthErrorCode::ResponseDecode,
            ),
            (
                Reply::Json(500, json!({"status":0,"accessToken":"synthetic-secret"})),
                AuthErrorCode::HttpStatus,
            ),
            (
                Reply::Json(400, json!({"status":0,"accessToken":"synthetic-secret"})),
                AuthErrorCode::HttpStatus,
            ),
        ] {
            let (_temp, store) = setup();
            let mock = Mock::start(vec![reply]).await;
            let error = code(run(&store, &mock).await);
            assert_eq!(error.code, expected);
            assert_eq!(mock.requests(), 1);
            assert!(!format!("{error:?} {error}").contains("synthetic-secret"));
            assert_eq!(store.auth_status().unwrap().state, AuthState::Stopped);
            assert!(!store.auth_status().unwrap().process_lock_present);
            assert_eq!(mock.requests(), 1);
        }
    }

    #[tokio::test]
    async fn generation_timeout_has_no_hidden_retry_and_allows_explicit_same_identity_retry() {
        let (_temp, store) = setup();
        let mock = Mock::start(vec![Reply::Sleep(
            Duration::from_secs(1),
            Box::new(generated()),
        )])
        .await;
        let transport = Transport::mock(mock.address, Duration::from_millis(30));
        let error = code(
            authorize_with_transport(
                &store,
                Duration::from_secs(3),
                std::future::pending(),
                |_| {},
                transport,
            )
            .await,
        );
        assert_eq!(error.code, AuthErrorCode::RequestTimeout);
        assert_eq!(mock.requests(), 1);
        let status = store.auth_status().unwrap();
        assert_eq!(status.state, AuthState::Stopped);
        assert!(!status.recovery_required && !status.process_lock_present);
        let wire = store.qr_wire_show().unwrap();
        let retry = Mock::start(vec![generated(), Reply::Json(400, json!({"status":-151}))]).await;
        assert_eq!(
            code(run(&store, &retry).await).protocol.unwrap().code,
            qr::ErrorCode::Denied
        );
        assert_eq!(store.qr_wire_show().unwrap(), wire);
    }

    #[tokio::test]
    async fn terminal_denial_is_stopped_without_an_extra_cancel_or_retry() {
        let (_temp, store) = setup();
        let mock = Mock::start(vec![
            generated(),
            Reply::Json(400, json!({"status":-151,"message":"synthetic-secret"})),
        ])
        .await;
        let error = code(run(&store, &mock).await);
        assert_eq!(error.protocol.unwrap().code, qr::ErrorCode::Denied);
        assert_eq!(mock.requests(), 2);
        assert_eq!(store.auth_status().unwrap().state, AuthState::Stopped);
        assert!(!store.auth_status().unwrap().process_lock_present);
    }

    #[tokio::test]
    async fn cancellation_while_waiting_confirms_cancel_but_inflight_stays_ambiguous() {
        let (_temp, store) = setup();
        let mock = Mock::start(vec![
            generated(),
            Reply::Json(
                200,
                json!({"status":-150,"nextRequestIntervalInSeconds":10}),
            ),
            Reply::Json(200, json!({"status":0})),
        ])
        .await;
        let error = code(
            authorize_with_transport(
                &store,
                Duration::from_secs(5),
                tokio::time::sleep(Duration::from_millis(120)),
                |_| {},
                mock.transport(),
            )
            .await,
        );
        assert_eq!(error.code, AuthErrorCode::Cancelled);
        assert_eq!(store.auth_status().unwrap().state, AuthState::Stopped);
        {
            let requests = mock.backend.requests.lock().unwrap();
            assert_eq!(requests.len(), 3);
            assert_eq!(requests[2].path, "/android/account/qrCodeLogin/cancel");
            let body: Value = serde_json::from_slice(&requests[2].body).unwrap();
            assert_eq!(body["id"], "synthetic-id");
            assert_eq!(body["device"]["uuid"], store.qr_wire_show().unwrap().uuid());
        }
        let (_temp, store) = setup();
        let mock = Mock::start(vec![
            generated(),
            Reply::Sleep(Duration::from_millis(300), Box::new(success())),
            Reply::Json(200, json!({"status":0})),
        ])
        .await;
        let error = code(
            authorize_with_transport(
                &store,
                Duration::from_secs(5),
                tokio::time::sleep(Duration::from_millis(120)),
                |_| {},
                mock.transport(),
            )
            .await,
        );
        assert_eq!(error.code, AuthErrorCode::Cancelled);
        assert_eq!(mock.requests(), 3);
        assert_eq!(
            store.auth_status().unwrap().state,
            AuthState::RecoveryRequired
        );
    }

    #[tokio::test]
    async fn overall_deadline_and_expiry_cancel_known_challenge_once() {
        let (_temp, store) = setup();
        let mock = Mock::start(vec![
            generated(),
            Reply::Json(
                200,
                json!({"status":-150,"nextRequestIntervalInSeconds":10}),
            ),
            Reply::Json(200, json!({"status":0})),
        ])
        .await;
        let error = code(
            authorize_with_transport(
                &store,
                Duration::from_millis(120),
                std::future::pending(),
                |_| {},
                mock.transport(),
            )
            .await,
        );
        assert_eq!(error.code, AuthErrorCode::OverallTimeout);
        assert_eq!(mock.requests(), 3);
        assert_eq!(store.auth_status().unwrap().state, AuthState::Stopped);
        let (_temp, store) = setup();
        let mock = Mock::start(vec![
            Reply::Json(
                200,
                json!({"status":0,"url":"synthetic://qr?id=x","remainingSeconds":1}),
            ),
            Reply::Json(
                200,
                json!({"status":-150,"nextRequestIntervalInSeconds":10}),
            ),
            Reply::Json(200, json!({"status":0})),
        ])
        .await;
        let error = code(run(&store, &mock).await);
        assert_eq!(error.code, AuthErrorCode::Expired);
        assert_eq!(mock.requests(), 3);
        assert_eq!(store.auth_status().unwrap().state, AuthState::Stopped);
    }

    #[tokio::test]
    async fn prior_pending_or_orphaned_files_never_generate_another_qr() {
        let (temp, store) = setup();
        let (attempt, _) = Attempt::begin(&store).unwrap();
        drop(attempt);
        let mock = Mock::start(vec![]).await;
        assert_eq!(code(run(&store, &mock).await).code, AuthErrorCode::Busy);
        fs::remove_dir(temp.path().join(LOCK_DIR)).unwrap();
        assert_eq!(
            code(run(&store, &mock).await).code,
            AuthErrorCode::RecoveryRequired
        );
        assert_eq!(mock.requests(), 0);
        let (temp, store) = setup();
        exclusive_write(
            &temp.path().join(HANDOFF_FILE),
            b"orphaned synthetic secret",
        )
        .unwrap();
        assert_eq!(
            code(run(&store, &mock).await).code,
            AuthErrorCode::RecoveryRequired
        );
        assert!(!temp.path().join(LOCK_DIR).exists());
        assert_eq!(mock.requests(), 0);
    }

    #[tokio::test]
    async fn corrupt_or_unknown_response_remains_redacted_and_fail_closed() {
        for reply in [
            Reply::Raw(200, b"synthetic-secret-invalid-json".to_vec(), None),
            Reply::Json(200, json!({"status":-999,"message":"synthetic-secret"})),
            Reply::Json(200, json!({"url":"synthetic-secret","remainingSeconds":30})),
        ] {
            let (_temp, store) = setup();
            let mock = Mock::start(vec![reply]).await;
            let error = code(run(&store, &mock).await);
            assert_eq!(error.code, AuthErrorCode::Protocol);
            assert!(!format!("{error:?} {error}").contains("synthetic-secret"));
            assert_eq!(mock.requests(), 1);
            assert_eq!(store.auth_status().unwrap().state, AuthState::Stopped);
        }
    }
    #[tokio::test]
    async fn login_transport_failure_is_ambiguous_even_after_cancel_success() {
        let (_temp, store) = setup();
        let mock = Mock::start(vec![
            generated(),
            Reply::Sleep(Duration::from_millis(200), Box::new(success())),
            Reply::Json(200, json!({"status":0})),
        ])
        .await;
        let transport = Transport::mock(mock.address, Duration::from_millis(50));
        let error = code(
            authorize_with_transport(
                &store,
                Duration::from_secs(3),
                std::future::pending(),
                |_| {},
                transport,
            )
            .await,
        );
        assert_eq!(error.code, AuthErrorCode::RequestTimeout);
        assert_eq!(mock.requests(), 3);
        let status = store.auth_status().unwrap();
        assert!(status.recovery_required && status.process_lock_present);
        assert_eq!(code(run(&store, &mock).await).code, AuthErrorCode::Busy);
        assert_eq!(mock.requests(), 3);
    }

    #[tokio::test]
    async fn successful_remote_handoff_never_overwrites_existing_file_or_reports_success_early() {
        let (temp, store) = setup();
        let mock = Mock::start(vec![generated(), success()]).await;
        let path = temp.path().join(HANDOFF_FILE);
        let error = code(
            authorize_with_transport(
                &store,
                Duration::from_secs(3),
                std::future::pending(),
                |notice| {
                    if matches!(notice, Notice::QrReady { .. }) {
                        exclusive_write(&path, b"do-not-overwrite-synthetic").unwrap();
                    }
                },
                mock.transport(),
            )
            .await,
        );
        assert_eq!(error.code, AuthErrorCode::Storage);
        assert_eq!(fs::read(&path).unwrap(), b"do-not-overwrite-synthetic");
        assert!(temp.path().join(PENDING_FILE).exists());
        let status = store.auth_status().unwrap();
        assert_eq!(status.state, AuthState::RecoveryRequired);
        assert!(status.process_lock_present);
        assert_eq!(mock.requests(), 2);
    }

    #[tokio::test]
    async fn production_security_builder_refuses_plain_http_before_sending() {
        let mock = Mock::start(vec![]).await;
        let transport = Transport::build(
            &format!("http://{}/android/account/", mock.address),
            Duration::from_millis(50),
            true,
        )
        .unwrap();
        let error = code(
            transport
                .post(
                    qr::GENERATE_PATH,
                    &serde_json::json!({"synthetic":"secret"}),
                )
                .await,
        );
        assert_eq!(error.code, AuthErrorCode::Transport);
        assert_eq!(mock.requests(), 0);
        assert!(!format!("{error:?} {error}").contains("secret"));
    }
}
