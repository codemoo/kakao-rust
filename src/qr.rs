//! Offline QR request and authorization state primitives.
//! No HTTP client, automatic regeneration, token persistence, or synchronization.
//!
//! Require an explicit response status,
//! accept only status 0 as success, stop on unknown/invalid responses, zero or excessive
//! intervals, time regression, incomplete tokens, and expiry. There is no fallback
//! three-second retry or automatic QR regeneration. Durations are bounded to 24 hours,
//! poll intervals to one hour, and JSON bodies to 64 KiB. An early poll is rejected
//! without emitting a request; it may be retried when its deadline arrives.
use crate::{device::decode_profile, Error, Result, Store};
use rusqlite::{OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const A_HEADER_NAME: &str = "A";
pub const A_HEADER: &str = "android/26.3.2/ko";
pub const REQUEST_METHOD: &str = "POST";
pub const GENERATE_PATH: &str = "qrCodeLogin/generate";
pub const LOGIN_PATH: &str = "qrCodeLogin/login";
pub const CANCEL_PATH: &str = "qrCodeLogin/cancel";
const MAX_EPOCH_MS: i64 = 253_402_300_799_999;
const MAX_RESPONSE: usize = 64 * 1024;
const MAX_LIFETIME_SECONDS: u64 = 86_400;
const MAX_INTERVAL_SECONDS: u64 = 3600;
const MAX_ELAPSED_MS: u64 = i64::MAX as u64 - 86_400_000;

/// Persistent protocol identity, independent of the local app_instance_id.
/// OS 13 is the original S9/S9+ firmware choice, not an observed running Android host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireProfile {
    schema_version: u32,
    local_app_instance_id: Uuid,
    uuid: String,
    model: String,
    name: String,
    os_version: String,
    created_at_epoch_ms: i64,
}
impl WireProfile {
    pub fn uuid(&self) -> &str {
        &self.uuid
    }
    pub fn model(&self) -> &str {
        &self.model
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn os_version(&self) -> &str {
        &self.os_version
    }
    pub fn native_auth_ready(&self) -> bool {
        false
    }
    fn validate(&self) -> QrResult<()> {
        if self.schema_version != 1
            || self.local_app_instance_id.is_nil()
            || self.uuid.len() != 64
            || !self
                .uuid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !matches!(self.model.as_str(), "SM-X710" | "SM-X810")
            || self.name != self.model
            || self.os_version != "13"
            || !(0..=MAX_EPOCH_MS).contains(&self.created_at_epoch_ms)
        {
            return Err(QrError::new(ErrorCode::InvalidIdentity, None));
        }
        Ok(())
    }
    pub fn generate_request(&self, previous_id: Option<&str>) -> QrResult<GenerateRequest> {
        self.validate()?;
        let previous_id = optional_id(previous_id)?;
        Ok(GenerateRequest {
            device: GenerateDevice {
                name: self.name.clone(),
                uuid: self.uuid.clone(),
                model: self.model.clone(),
                os_version: self.os_version.clone(),
            },
            previous_id,
        })
    }
    pub fn login_request(&self, id: Option<&str>) -> QrResult<LoginRequest> {
        self.validate()?;
        Ok(LoginRequest {
            device: UuidDevice {
                uuid: self.uuid.clone(),
            },
            id: optional_id(id)?,
        })
    }
    pub fn cancel_request(&self, id: Option<&str>) -> QrResult<CancelRequest> {
        self.validate()?;
        Ok(CancelRequest {
            device: UuidDevice {
                uuid: self.uuid.clone(),
            },
            id: optional_id(id)?,
        })
    }
}

/// Pure deterministic derivation, separate from random generation/storage.
/// The seed is a UUID v4 followed by '-' and decimal Unix epoch milliseconds.
pub fn derive_wire_uuid(random_uuid: Uuid, epoch_ms: i64) -> QrResult<String> {
    if random_uuid.get_version_num() != 4 || !(0..=MAX_EPOCH_MS).contains(&epoch_ms) {
        return Err(QrError::new(ErrorCode::InvalidInput, None));
    }
    Ok(hex::encode(Sha256::digest(
        format!("dkljleskljfeisflssljeif {random_uuid}-{epoch_ms}").as_bytes(),
    )))
}

impl Store {
    pub fn qr_wire_show(&self) -> Result<WireProfile> {
        let connection = self.lock()?;
        load_wire(&connection)?.ok_or(Error::NotFound)
    }
    /// Explicit opt-in only. Existing wire identity wins over changed wall-clock input.
    /// Missing/corrupt saved identity or marker is an error, never a random regeneration.
    pub fn qr_wire_initialize(&self, epoch_ms: i64) -> Result<WireProfile> {
        let mut connection = self.lock()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(profile) = load_wire(&tx)? {
            return Ok(profile);
        }
        let device_marker: String = tx.query_row(
            "SELECT value FROM metadata WHERE key='device_initialized'",
            [],
            |r| r.get(0),
        )?;
        let device_raw: Option<String> = tx
            .query_row("SELECT json FROM device_profile WHERE id=1", [], |r| {
                r.get(0)
            })
            .optional()?;
        if device_marker != "1" {
            return Err(Error::Storage(
                "select a persistent device profile before initializing QR wire identity".into(),
            ));
        }
        let device =
            decode_profile(&device_raw.ok_or_else(|| {
                Error::Storage("device profile missing; restore identity".into())
            })?)?;
        if !matches!(device.model.model_code.as_str(), "SM-X710" | "SM-X810") {
            return Err(Error::Invalid(
                "QR OS profile is verified only for original S9/S9+ firmware".into(),
            ));
        }
        let profile = WireProfile {
            schema_version: 1,
            local_app_instance_id: device.app_instance_id,
            uuid: derive_wire_uuid(Uuid::new_v4(), epoch_ms)
                .map_err(|_| Error::Invalid("invalid QR identity creation time".into()))?,
            model: device.model.model_code.clone(),
            name: device.model.model_code,
            os_version: "13".into(),
            created_at_epoch_ms: epoch_ms,
        };
        tx.execute(
            "INSERT INTO qr_wire_profile(id,json) VALUES(1,?1)",
            [serde_json::to_string(&profile)?],
        )?;
        tx.execute(
            "UPDATE metadata SET value='1' WHERE key='qr_wire_initialized'",
            [],
        )?;
        tx.commit()?;
        Ok(profile)
    }
}
fn load_wire(connection: &rusqlite::Connection) -> Result<Option<WireProfile>> {
    let marker: String = connection.query_row(
        "SELECT value FROM metadata WHERE key='qr_wire_initialized'",
        [],
        |r| r.get(0),
    )?;
    let raw: Option<String> = connection
        .query_row("SELECT json FROM qr_wire_profile WHERE id=1", [], |r| {
            r.get(0)
        })
        .optional()?;
    match (marker.as_str(), raw) {
        ("0", None) => Ok(None),
        ("1", Some(raw)) => {
            let profile: WireProfile = serde_json::from_str(&raw).map_err(|_| {
                Error::Storage("QR wire identity corrupt; restore saved identity".into())
            })?;
            profile.validate().map_err(|_| {
                Error::Storage("QR wire identity inconsistent; restore saved identity".into())
            })?;
            let device_marker: String = connection.query_row(
                "SELECT value FROM metadata WHERE key='device_initialized'",
                [],
                |r| r.get(0),
            )?;
            let device_raw: String =
                connection.query_row("SELECT json FROM device_profile WHERE id=1", [], |r| {
                    r.get(0)
                })?;
            let device = decode_profile(&device_raw)?;
            if device_marker != "1"
                || profile.local_app_instance_id != device.app_instance_id
                || profile.model != device.model.model_code
            {
                return Err(Error::Storage(
                    "QR wire identity does not match the saved device".into(),
                ));
            }
            Ok(Some(profile))
        }
        _ => Err(Error::Storage(
            "QR wire identity or marker missing; explicit recovery required".into(),
        )),
    }
}

// Request types deliberately have no Debug: QR identifiers must not enter routine logs.
#[derive(Serialize)]
pub struct GenerateRequest {
    device: GenerateDevice,
    #[serde(rename = "previousId", skip_serializing_if = "Option::is_none")]
    previous_id: Option<String>,
}
#[derive(Serialize)]
struct GenerateDevice {
    name: String,
    uuid: String,
    model: String,
    #[serde(rename = "osVersion")]
    os_version: String,
}
#[derive(Serialize)]
pub struct LoginRequest {
    device: UuidDevice,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
}
#[derive(Serialize)]
pub struct CancelRequest {
    device: UuidDevice,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
}
#[derive(Serialize)]
struct UuidDevice {
    uuid: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidInput,
    InvalidIdentity,
    InvalidResponse,
    MissingStatus,
    UnknownStatus,
    Bounds,
    InvalidTransition,
    ClockRegression,
    TooEarly,
    Expired,
    Denied,
    AllowlistRequired,
    LoginConflict,
    Cancelled,
}
/// Only fixed codes and numeric status are retained. No body, URL, passcode or token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, thiserror::Error)]
#[error("QR protocol stopped: {code:?} (status {status:?})")]
pub struct QrError {
    pub code: ErrorCode,
    pub status: Option<i32>,
}
impl QrError {
    fn new(code: ErrorCode, status: Option<i32>) -> Self {
        Self { code, status }
    }
}
pub type QrResult<T> = std::result::Result<T, QrError>;
fn text(value: &str, max: usize) -> QrResult<()> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        Err(QrError::new(ErrorCode::InvalidInput, None))
    } else {
        Ok(())
    }
}
fn optional_id(value: Option<&str>) -> QrResult<Option<String>> {
    value
        .map(|value| {
            text(value, 4096)?;
            Ok(value.to_string())
        })
        .transpose()
}
/// Literal split, intentionally NOT URL query parsing, percent decoding or host checking.
/// For repeated 'id=' delimiters, retain the second segment including '&...' tails.
/// Empty/missing identifiers are rejected by the bounded request/state layer.
pub fn extract_qr_id_literal(url: &str) -> QrResult<Option<String>> {
    text(url, 8192)?;
    Ok(url.split("id=").nth(1).map(str::to_string))
}
fn parse<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> QrResult<T> {
    if bytes.len() > MAX_RESPONSE {
        return Err(QrError::new(ErrorCode::Bounds, None));
    }
    serde_json::from_slice(bytes).map_err(|_| QrError::new(ErrorCode::InvalidResponse, None))
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GenerateResponse {
    status: Option<i32>,
    url: Option<String>,
    remaining_seconds: Option<u64>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginResponse {
    status: Option<i32>,
    next_request_interval_in_seconds: Option<u64>,
    passcode: Option<String>,
    remaining_seconds: Option<u64>,
    user: Option<WireUser>,
    access_token: Option<String>,
    refresh_token: Option<String>,
    token_type: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireUser {
    user_id: i64,
    country_iso: String,
    account_id: Option<i64>,
    display_account_id: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedUser {
    pub user_id: String,
    pub country_iso: String,
    pub account_id: Option<String>,
    pub display_account_id: Option<String>,
}
/// Intentionally no Debug/Serialize/Clone; exposing tokens is an explicit caller action.
/// This is an authorization handoff, not a connected or synchronized Kakao client.
pub struct AuthHandoff {
    pub user: AuthorizedUser,
    access_token: String,
    refresh_token: String,
    token_type: String,
}
impl AuthHandoff {
    pub fn expose_access_token(&self) -> &str {
        &self.access_token
    }
    pub fn expose_refresh_token(&self) -> &str {
        &self.refresh_token
    }
    pub fn token_type(&self) -> &str {
        &self.token_type
    }
    pub fn native_sync_verified(&self) -> bool {
        false
    }
}
/// No Debug/Serialize: passcodes and QR URLs must be displayed only deliberately.
pub struct Challenge {
    url: String,
    pub expires_at_ms: u64,
}
impl Challenge {
    pub fn expose_qr_url(&self) -> &str {
        &self.url
    }
}
pub struct Passcode {
    value: String,
    pub expires_at_ms: u64,
    pub next_poll_at_ms: u64,
}
impl Passcode {
    pub fn expose_passcode(&self) -> &str {
        &self.value
    }
}
pub enum LoginOutcome {
    Waiting { next_poll_at_ms: u64 },
    Passcode(Passcode),
    Authorized(AuthHandoff),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Fresh,
    GenerateInFlight,
    WaitingApproval,
    PasscodeRequired,
    LoginInFlight,
    AuthorizationHandoff,
    Stopped,
}
/// Pure in-memory coordinator. Caller supplies a nondecreasing elapsed-ms clock.
/// It never sleeps, starts a timer, sends a request or retries a failed operation.
pub struct Session {
    profile: WireProfile,
    stage: Stage,
    last_ms: u64,
    expires_at_ms: Option<u64>,
    next_poll_at_ms: Option<u64>,
    id: Option<String>,
    terminal: Option<QrError>,
}
impl Session {
    pub fn new(profile: WireProfile) -> QrResult<Self> {
        profile.validate()?;
        Ok(Self {
            profile,
            stage: Stage::Fresh,
            last_ms: 0,
            expires_at_ms: None,
            next_poll_at_ms: None,
            id: None,
            terminal: None,
        })
    }
    pub fn stage(&self) -> Stage {
        self.stage
    }
    pub fn terminal_error(&self) -> Option<QrError> {
        self.terminal
    }
    pub fn expires_at_ms(&self) -> Option<u64> {
        self.expires_at_ms
    }
    pub fn next_poll_at_ms(&self) -> Option<u64> {
        self.next_poll_at_ms
    }
    fn stop<T>(&mut self, error: QrError) -> QrResult<T> {
        self.stage = Stage::Stopped;
        self.terminal = Some(error);
        self.id = None;
        self.next_poll_at_ms = None;
        Err(error)
    }
    fn clock(&mut self, now: u64) -> QrResult<()> {
        if now > MAX_ELAPSED_MS {
            return self.stop(QrError::new(ErrorCode::Bounds, None));
        }
        if now < self.last_ms {
            return self.stop(QrError::new(ErrorCode::ClockRegression, None));
        }
        self.last_ms = now;
        Ok(())
    }
    fn active(&mut self, now: u64) -> QrResult<()> {
        self.clock(now)?;
        if self.expires_at_ms.is_some_and(|expiry| now >= expiry) {
            return self.stop(QrError::new(ErrorCode::Expired, None));
        }
        Ok(())
    }
    fn require_stage(&mut self, allowed: &[Stage]) -> QrResult<()> {
        if self.stage == Stage::Stopped {
            return Err(self
                .terminal
                .unwrap_or_else(|| QrError::new(ErrorCode::InvalidTransition, None)));
        }
        if !allowed.contains(&self.stage) {
            return self.stop(QrError::new(ErrorCode::InvalidTransition, None));
        }
        Ok(())
    }
    pub fn prepare_generate(
        &mut self,
        previous_id: Option<&str>,
        now: u64,
    ) -> QrResult<GenerateRequest> {
        self.require_stage(&[Stage::Fresh])?;
        self.clock(now)?;
        match self.profile.generate_request(previous_id) {
            Ok(request) => {
                self.stage = Stage::GenerateInFlight;
                Ok(request)
            }
            Err(error) => self.stop(error),
        }
    }
    pub fn receive_generate(&mut self, bytes: &[u8], now: u64) -> QrResult<Challenge> {
        self.require_stage(&[Stage::GenerateInFlight])?;
        self.clock(now)?;
        let result = (|| {
            let response: GenerateResponse = parse(bytes)?;
            let status = explicit_status(response.status)?;
            if status != 0 {
                return Err(status_error(status));
            }
            let url = response
                .url
                .ok_or_else(|| QrError::new(ErrorCode::InvalidResponse, Some(status)))?;
            let id = extract_qr_id_literal(&url)?
                .ok_or_else(|| QrError::new(ErrorCode::InvalidResponse, Some(status)))?;
            text(&id, 4096)?;
            let expires = deadline(now, response.remaining_seconds, MAX_LIFETIME_SECONDS)?;
            Ok((url, id, expires))
        })();
        match result {
            Ok((url, id, expires)) => {
                self.id = Some(id);
                self.expires_at_ms = Some(expires);
                self.next_poll_at_ms = Some(now);
                self.stage = Stage::WaitingApproval;
                Ok(Challenge {
                    url,
                    expires_at_ms: expires,
                })
            }
            Err(error) => self.stop(error),
        }
    }
    pub fn prepare_login(&mut self, now: u64) -> QrResult<LoginRequest> {
        self.require_stage(&[Stage::WaitingApproval, Stage::PasscodeRequired])?;
        self.active(now)?;
        if self.next_poll_at_ms.is_some_and(|deadline| now < deadline) {
            return Err(QrError::new(ErrorCode::TooEarly, None));
        }
        let request = self.profile.login_request(self.id.as_deref())?;
        self.stage = Stage::LoginInFlight;
        self.next_poll_at_ms = None;
        Ok(request)
    }
    pub fn receive_login(&mut self, bytes: &[u8], now: u64) -> QrResult<LoginOutcome> {
        self.require_stage(&[Stage::LoginInFlight])?;
        self.active(now)?;
        let result = (|| {
            let response: LoginResponse = parse(bytes)?;
            let status = explicit_status(response.status)?;
            match status {
                -150 => Ok(LoginOutcome::Waiting {
                    next_poll_at_ms: deadline(
                        now,
                        response.next_request_interval_in_seconds,
                        MAX_INTERVAL_SECONDS,
                    )?,
                }),
                -100 => {
                    let value = response
                        .passcode
                        .ok_or_else(|| QrError::new(ErrorCode::InvalidResponse, Some(status)))?;
                    text(&value, 128)?;
                    Ok(LoginOutcome::Passcode(Passcode {
                        value,
                        expires_at_ms: deadline(
                            now,
                            response.remaining_seconds,
                            MAX_LIFETIME_SECONDS,
                        )?,
                        next_poll_at_ms: deadline(
                            now,
                            response.next_request_interval_in_seconds,
                            MAX_INTERVAL_SECONDS,
                        )?,
                    }))
                }
                0 => Ok(LoginOutcome::Authorized(handoff(response)?)),
                _ => Err(status_error(status)),
            }
        })();
        match result {
            Ok(outcome) => {
                match &outcome {
                    LoginOutcome::Waiting { next_poll_at_ms } => {
                        self.stage = Stage::WaitingApproval;
                        self.next_poll_at_ms = Some(*next_poll_at_ms);
                    }
                    LoginOutcome::Passcode(passcode) => {
                        self.stage = Stage::PasscodeRequired;
                        self.next_poll_at_ms = Some(passcode.next_poll_at_ms);
                        self.expires_at_ms = Some(passcode.expires_at_ms);
                    }
                    LoginOutcome::Authorized(_) => {
                        self.stage = Stage::AuthorizationHandoff;
                        self.id = None;
                        self.next_poll_at_ms = None;
                    }
                }
                Ok(outcome)
            }
            Err(error) => self.stop(error),
        }
    }
    /// Produces a cancel request and stops locally. Does not claim server cancellation.
    pub fn prepare_cancel(&mut self, now: u64) -> QrResult<CancelRequest> {
        self.require_stage(&[
            Stage::WaitingApproval,
            Stage::PasscodeRequired,
            Stage::LoginInFlight,
        ])?;
        self.clock(now)?;
        let request = self.profile.cancel_request(self.id.as_deref())?;
        let _: QrResult<()> = self.stop(QrError::new(ErrorCode::Cancelled, None));
        Ok(request)
    }
}
fn explicit_status(status: Option<i32>) -> QrResult<i32> {
    status.ok_or_else(|| QrError::new(ErrorCode::MissingStatus, None))
}
fn status_error(status: i32) -> QrError {
    QrError::new(
        match status {
            -151 => ErrorCode::Denied,
            -132 => ErrorCode::AllowlistRequired,
            -101 => ErrorCode::LoginConflict,
            _ => ErrorCode::UnknownStatus,
        },
        Some(status),
    )
}
fn deadline(now: u64, seconds: Option<u64>, maximum: u64) -> QrResult<u64> {
    let seconds = seconds.ok_or_else(|| QrError::new(ErrorCode::InvalidResponse, None))?;
    if seconds == 0 || seconds > maximum {
        return Err(QrError::new(ErrorCode::Bounds, None));
    }
    now.checked_add(
        seconds
            .checked_mul(1000)
            .ok_or_else(|| QrError::new(ErrorCode::Bounds, None))?,
    )
    .ok_or_else(|| QrError::new(ErrorCode::Bounds, None))
}
fn handoff(response: LoginResponse) -> QrResult<AuthHandoff> {
    let user = response
        .user
        .ok_or_else(|| QrError::new(ErrorCode::InvalidResponse, Some(0)))?;
    if user.user_id <= 0
        || user.account_id.is_some_and(|id| id <= 0)
        || user.country_iso.len() != 2
        || !user.country_iso.bytes().all(|b| b.is_ascii_alphabetic())
    {
        return Err(QrError::new(ErrorCode::InvalidResponse, Some(0)));
    }
    if let Some(display) = &user.display_account_id {
        text(display, 256)?;
    }
    let access_token = response
        .access_token
        .ok_or_else(|| QrError::new(ErrorCode::InvalidResponse, Some(0)))?;
    let refresh_token = response
        .refresh_token
        .ok_or_else(|| QrError::new(ErrorCode::InvalidResponse, Some(0)))?;
    let token_type = response
        .token_type
        .ok_or_else(|| QrError::new(ErrorCode::InvalidResponse, Some(0)))?;
    text(&access_token, 16 * 1024)?;
    text(&refresh_token, 16 * 1024)?;
    text(&token_type, 64)?;
    Ok(AuthHandoff {
        user: AuthorizedUser {
            user_id: user.user_id.to_string(),
            country_iso: user.country_iso,
            account_id: user.account_id.map(|id| id.to_string()),
            display_account_id: user.display_account_id,
        },
        access_token,
        refresh_token,
        token_type,
    })
}
