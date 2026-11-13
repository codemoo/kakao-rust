//! Account/password authentication for a persistent secondary device.
//! Submit credentials as form fields over HTTPS. Never include them in Debug output.
use crate::{
    qr::WireProfile,
    qr_auth::{AuthError, AuthErrorCode, AuthResult},
};
use serde::Deserialize;
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

pub const LOGIN_PATH: &str = "login.json";

pub struct Credentials {
    account: Zeroizing<String>,
    password: Zeroizing<String>,
}
impl Credentials {
    pub(crate) fn xvc(&self, user_agent: &str) -> String {
        xvc(&self.account, user_agent)
    }
    pub fn new(account: String, password: String) -> AuthResult<Self> {
        let mut account = Zeroizing::new(account);
        let mut password = Zeroizing::new(password);
        // Normalize ASCII spaces consistently in both credential fields.
        account.retain(|c| c != ' ');
        password.retain(|c| c != ' ');
        if account.trim().is_empty()
            || account.len() > 320
            || account.chars().any(char::is_control)
            || password.is_empty()
            || password.len() > 4096
            || password.chars().any(char::is_control)
        {
            return Err(AuthError::new(AuthErrorCode::InvalidCredentialsInput));
        }
        Ok(Self { account, password })
    }
    pub fn prompt() -> AuthResult<Self> {
        let account = rpassword::prompt_password("Kakao account (hidden): ")
            .map_err(|_| AuthError::new(AuthErrorCode::TerminalInput))?;
        let account = Zeroizing::new(account);
        let password = rpassword::prompt_password("Password (hidden): ")
            .map_err(|_| AuthError::new(AuthErrorCode::TerminalInput))?;
        Self::new(account.to_string(), password)
    }
}

pub(crate) fn user_agent(wire: &WireProfile) -> String {
    format!("KT/26.3.2 An/{} ko", wire.os_version())
}
pub(crate) fn xvc(account: &str, user_agent: &str) -> String {
    let input = Zeroizing::new(format!("BARD|{user_agent}|DANTE|{account}|SIAN"));
    hex::encode(&Sha512::digest(input.as_bytes())[..8])
}

/// Omit absent optional fields rather than serializing them as null.
/// forced=false/permanent=true are constructor defaults; no forced device eviction.
pub(crate) fn login_form(
    credentials: &Credentials,
    wire: &WireProfile,
    passcode: Option<&str>,
    verification_uri: Option<&str>,
) -> Zeroizing<String> {
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    form.append_pair("email", &credentials.account)
        .append_pair("password", &credentials.password)
        .append_pair("device_uuid", wire.uuid())
        .append_pair("device_name", wire.name())
        .append_pair("forced", "false")
        .append_pair("permanent", "true");
    if let Some(code) = passcode {
        form.append_pair("passcode", code);
    }
    if let Some(uri) = verification_uri {
        form.append_pair("another_email_verification_uri", uri);
    }
    Zeroizing::new(form.finish())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Authorized,
    DeviceApprovalRequired,
    EmailVerificationRequired,
    AccountTermsRequired,
    Rejected(i32),
}
#[derive(Deserialize)]
struct Envelope {
    status: i32,
}
/// A successful account login returns identity and tokens in top-level fields.
/// Require complete tokens before marking the durable attempt authorized.
pub fn classify_response(bytes: &[u8]) -> AuthResult<Outcome> {
    if bytes.len() > 64 * 1024 {
        return Err(AuthError::new(AuthErrorCode::ResponseTooLarge));
    }
    let envelope: Envelope =
        serde_json::from_slice(bytes).map_err(|_| AuthError::new(AuthErrorCode::ResponseDecode))?;
    Ok(match envelope.status {
        0 => {
            let body: serde_json::Value = serde_json::from_slice(bytes)
                .map_err(|_| AuthError::new(AuthErrorCode::ResponseDecode))?;
            if body
                .get("userId")
                .and_then(|v| v.as_i64())
                .is_none_or(|v| v <= 0)
                || ["countryIso", "access_token", "refresh_token", "token_type"]
                    .iter()
                    .any(|key| {
                        body.get(key).and_then(|v| v.as_str()).is_none_or(|v| {
                            v.trim().is_empty()
                                || v.len() > 16384
                                || v.chars().any(char::is_control)
                        })
                    })
            {
                return Err(AuthError::new(AuthErrorCode::InvalidResponse));
            }
            Outcome::Authorized
        }
        -100 => Outcome::DeviceApprovalRequired,
        31 => Outcome::EmailVerificationRequired,
        -126 => Outcome::AccountTermsRequired,
        other => Outcome::Rejected(other),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn xvc_matches_independent_sha512_fixture() {
        assert_eq!(
            xvc("synthetic@example.test", "KT/26.3.2 An/13 ko"),
            "10b25b934c84f88a"
        );
        assert_eq!(
            xvc("+82 10 0000 0000", "KT/26.3.2 An/13 ko"),
            "cdfc045e4fe44cc8"
        );
    }
    #[test]
    fn response_is_strict_and_redacts_errors() {
        assert_eq!(
            classify_response(br#"{"status":-100}"#).unwrap(),
            Outcome::DeviceApprovalRequired
        );
        assert_eq!(
            classify_response(br#"{"status":31}"#).unwrap(),
            Outcome::EmailVerificationRequired
        );
        assert_eq!(
            classify_response(br#"{"status":-126}"#).unwrap(),
            Outcome::AccountTermsRequired
        );
        assert_eq!(
            classify_response(br#"{"status":12}"#).unwrap(),
            Outcome::Rejected(12)
        );
        for bytes in [
            br#"{}"#.as_slice(),
            br#"{"status":0}"#,
            br#"{"status":"0","password":"synthetic-secret"}"#,
        ] {
            let error = classify_response(bytes).unwrap_err();
            assert!(!format!("{error:?} {error}").contains("synthetic-secret"));
        }
        assert_eq!(classify_response(br#"{"status":0,"userId":42,"countryIso":"KR","access_token":"synthetic-access","refresh_token":"synthetic-refresh","token_type":"Bearer"}"#).unwrap(), Outcome::Authorized);
    }
}

pub(crate) fn passcode_json(
    credentials: &Credentials,
    wire: &WireProfile,
    generate: bool,
) -> AuthResult<Zeroizing<String>> {
    #[derive(serde::Serialize)]
    struct Device<'a> {
        uuid: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        model: Option<&'a str>,
        #[serde(rename = "osVersion", skip_serializing_if = "Option::is_none")]
        os_version: Option<&'a str>,
    }
    #[derive(serde::Serialize)]
    struct Request<'a> {
        email: &'a str,
        password: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        permanent: Option<bool>,
        device: Device<'a>,
    }
    let request = Request {
        email: &credentials.account,
        password: &credentials.password,
        permanent: generate.then_some(true),
        device: Device {
            uuid: wire.uuid(),
            name: generate.then_some(wire.model()),
            model: generate.then_some(wire.model()),
            os_version: generate.then_some(wire.os_version()),
        },
    };
    serde_json::to_string(&request)
        .map(Zeroizing::new)
        .map_err(|_| AuthError::new(AuthErrorCode::InvalidCredentialsInput))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PasscodeResponse {
    pub status: i32,
    pub passcode: Option<String>,
    pub remaining_seconds: Option<u64>,
    pub next_request_interval_in_seconds: Option<u64>,
}
impl PasscodeResponse {
    pub fn parse(bytes: &[u8]) -> AuthResult<Self> {
        if bytes.len() > 65536 {
            return Err(AuthError::new(AuthErrorCode::ResponseTooLarge));
        }
        serde_json::from_slice(bytes).map_err(|_| AuthError::new(AuthErrorCode::ResponseDecode))
    }
    pub fn challenge(&self) -> AuthResult<(&str, u64)> {
        match (self.passcode.as_deref(), self.remaining_seconds) {
            (Some(code), Some(seconds))
                if self.status == 0
                    && code.len() == 4
                    && code.bytes().all(|c| c.is_ascii_digit())
                    && (1..=86400).contains(&seconds) =>
            {
                Ok((code, seconds))
            }
            _ => Err(AuthError::new(AuthErrorCode::InvalidResponse)),
        }
    }
    pub fn interval(&self) -> AuthResult<u64> {
        let interval = self.next_request_interval_in_seconds.unwrap_or(3);
        if !(1..=3600).contains(&interval) {
            return Err(AuthError::new(AuthErrorCode::InvalidResponse));
        }
        Ok(interval)
    }
}
