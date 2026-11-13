//! Fixed-host HTTPS transport for secondary-device password authorization.
//! No redirects, automatic retries, cookies, proxy, or sensitive response logging.
use crate::{
    password::{self, Credentials},
    qr::WireProfile,
    qr_auth::{AuthError, AuthErrorCode, AuthResult},
};
use std::{cell::Cell, future::Future, time::Duration};
use tokio::time::Instant;
use zeroize::Zeroizing;

pub(crate) struct Transport {
    client: reqwest::Client,
    base: reqwest::Url,
}
impl Transport {
    pub(crate) fn production() -> AuthResult<Self> {
        Self::build(
            "https://katalk.kakao.com/android/account/",
            true,
            Duration::from_secs(10),
        )
    }
    fn build(base: &str, https: bool, timeout: Duration) -> AuthResult<Self> {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .referer(false)
            .https_only(https)
            .connect_timeout(timeout)
            .timeout(timeout)
            .gzip(true)
            .build()
            .map_err(|_| AuthError::new(AuthErrorCode::Transport))?;
        let base =
            reqwest::Url::parse(base).map_err(|_| AuthError::new(AuthErrorCode::Transport))?;
        Ok(Self { client, base })
    }
    pub(crate) async fn post(
        &self,
        path: &str,
        credentials: &Credentials,
        wire: &WireProfile,
        form: Zeroizing<String>,
    ) -> AuthResult<Zeroizing<Vec<u8>>> {
        if !matches!(
            path,
            "login.json"
                | "verify_email.json"
                | "request_verify_email.json"
                | GENERATE
                | REGISTER
                | CANCEL
        ) {
            return Err(AuthError::new(AuthErrorCode::Transport));
        }
        let ua = password::user_agent(wire);
        let json = matches!(path, GENERATE | REGISTER | CANCEL);
        let request = self
            .client
            .post(
                self.base
                    .join(path)
                    .map_err(|_| AuthError::new(AuthErrorCode::Transport))?,
            )
            .header("A", crate::qr::A_HEADER)
            .header("X-VC", credentials.xvc(&ua))
            .header("User-Agent", ua)
            .header("Accept-Encoding", "gzip")
            .header("Connection", "Keep-Alive")
            .header(
                "Content-Type",
                if json {
                    "application/json"
                } else {
                    "application/x-www-form-urlencoded"
                },
            );
        let request = if json {
            request
        } else {
            request.header("Accept-Language", "ko")
        };
        let mut response = request
            .body(form.as_bytes().to_vec())
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
        let mut bytes = Zeroizing::new(Vec::new());
        while let Some(chunk) = response.chunk().await.map_err(network_error)? {
            if chunk.len() > 64 * 1024 - bytes.len() {
                return Err(AuthError::new(AuthErrorCode::ResponseTooLarge));
            }
            bytes.extend_from_slice(&chunk);
        }
        if !status.is_success() {
            #[derive(serde::Deserialize)]
            struct Envelope {
                status: i32,
            }
            let e: Envelope = serde_json::from_slice(&bytes)
                .map_err(|_| AuthError::new(AuthErrorCode::HttpStatus))?;
            if e.status == 0 {
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

#[derive(serde::Serialize)]
pub struct LoginResult {
    pub outcome: &'static str,
    pub server_status: Option<i32>,
    pub auth: crate::qr_auth::AuthStatus,
}

const GENERATE: &str = "passcodeLogin/generate";
const REGISTER: &str = "passcodeLogin/registerDevice";
const CANCEL: &str = "passcodeLogin/cancel";

/// Deliberate terminal display only; no account/password/remote diagnostics.
pub enum Notice {
    Passcode {
        value: String,
        remaining_seconds: u64,
    },
}

/// Credentials remain in memory. Ambiguous requests retain the shared auth lock.
pub async fn authorize_password(
    store: &crate::Store,
    credentials: Credentials,
    timeout_seconds: u16,
    notice: impl FnMut(Notice),
) -> AuthResult<LoginResult> {
    if !(1..=600).contains(&timeout_seconds) {
        return Err(AuthError::new(AuthErrorCode::InvalidTimeout));
    }
    let transport = Transport::production()?;
    run(
        store,
        &credentials,
        &transport,
        Duration::from_secs(timeout_seconds.into()),
        async {
            let _ = tokio::signal::ctrl_c().await;
        },
        notice,
    )
    .await
}
#[cfg(test)]
async fn authorize_with(
    store: &crate::Store,
    credentials: &Credentials,
    transport: &Transport,
) -> AuthResult<LoginResult> {
    run(
        store,
        credentials,
        transport,
        Duration::from_secs(30),
        std::future::pending(),
        |_| {},
    )
    .await
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    InFlight,
    ChallengeWaiting,
    Registered,
}

async fn run(
    store: &crate::Store,
    credentials: &Credentials,
    transport: &Transport,
    timeout: Duration,
    cancel: impl Future<Output = ()>,
    mut notice: impl FnMut(Notice),
) -> AuthResult<LoginResult> {
    let (mut attempt, wire) = crate::qr_auth::Attempt::begin_password(store)?;
    let phase = Cell::new(Phase::InFlight);
    let deadline = Instant::now() + timeout;
    let result = {
        let flow = async {
            let mut bytes = transport
                .post(
                    password::LOGIN_PATH,
                    credentials,
                    &wire,
                    password::login_form(credentials, &wire, None, None),
                )
                .await?;
            if password::classify_response(&bytes)? == password::Outcome::DeviceApprovalRequired {
                phase.set(Phase::InFlight);
                let generated = transport
                    .post(
                        GENERATE,
                        credentials,
                        &wire,
                        password::passcode_json(credentials, &wire, true)?,
                    )
                    .await?;
                let challenge = password::PasscodeResponse::parse(&generated)?;
                if challenge.status != 0 {
                    return Ok(("passcode_generation_rejected", Some(challenge.status)));
                }
                let (code, remaining) = challenge.challenge()?;
                let mut expires = Instant::now() + Duration::from_secs(remaining);
                notice(Notice::Passcode {
                    value: code.to_owned(),
                    remaining_seconds: remaining,
                });
                // Dispatch register immediately after generate; subsequent
                // calls wait the server interval (three seconds only when absent).
                loop {
                    phase.set(Phase::InFlight);
                    let poll = transport
                        .post(
                            REGISTER,
                            credentials,
                            &wire,
                            password::passcode_json(credentials, &wire, false)?,
                        )
                        .await?;
                    let response = password::PasscodeResponse::parse(&poll)?;
                    if response.status == 0 {
                        phase.set(Phase::Registered);
                        break;
                    }
                    phase.set(Phase::ChallengeWaiting);
                    if !matches!(response.status, -100 | -102 | -112) {
                        // Unknown/terminal status never schedules another poll.
                        return Ok(("device_approval_rejected", Some(response.status)));
                    }
                    if let Some(remaining) = response.remaining_seconds {
                        if remaining > 86400 {
                            return Err(AuthError::new(AuthErrorCode::InvalidResponse));
                        }
                        expires = expires.min(Instant::now() + Duration::from_secs(remaining));
                    }
                    let wake = Instant::now() + Duration::from_secs(response.interval()?);
                    if wake >= expires {
                        tokio::time::sleep_until(expires).await;
                        return Err(AuthError::new(AuthErrorCode::Expired));
                    }
                    tokio::time::sleep_until(wake).await;
                }
                phase.set(Phase::InFlight);
                // Device approval retries the original login fields; no passcode/model
                // injection or forced=true. Never reuse a main-device authorize API.
                bytes = transport
                    .post(
                        password::LOGIN_PATH,
                        credentials,
                        &wire,
                        password::login_form(credentials, &wire, None, None),
                    )
                    .await?;
            }
            match password::classify_response(&bytes)? {
                password::Outcome::Authorized => {
                    let value = serde_json::from_slice(&bytes)
                        .map_err(|_| AuthError::new(AuthErrorCode::ResponseDecode))?;
                    attempt.persist_password(&value)?;
                    Ok(("authorized_bootstrap_pending", Some(0)))
                }
                password::Outcome::Rejected(code) => Ok(("server_rejected", Some(code))),
                password::Outcome::AccountTermsRequired => {
                    Ok(("account_terms_required", Some(-126)))
                }
                password::Outcome::EmailVerificationRequired => {
                    Ok(("email_verification_required", Some(31)))
                }
                password::Outcome::DeviceApprovalRequired => {
                    Ok(("device_approval_required", Some(-100)))
                }
            }
        };
        tokio::pin!(flow);
        tokio::select! {
            result=&mut flow => result,
            _=cancel => Err(AuthError::new(AuthErrorCode::Cancelled)),
            _=tokio::time::sleep_until(deadline) => Err(AuthError::new(AuthErrorCode::OverallTimeout)),
        }
    };
    match result {
        Ok((outcome, server_status)) => {
            if outcome != "authorized_bootstrap_pending" {
                if phase.get() == Phase::ChallengeWaiting {
                    cancel_challenge(transport, credentials, &wire).await?;
                }
                attempt.stop_confirmed("password_server_rejected")?;
            }
            drop(attempt);
            Ok(LoginResult {
                outcome,
                server_status,
                auth: store.auth_status()?,
            })
        }
        Err(error) => {
            if phase.get() == Phase::ChallengeWaiting
                && cancel_challenge(transport, credentials, &wire)
                    .await
                    .is_ok()
            {
                attempt.stop_confirmed("cancellation_confirmed")?;
            }
            Err(error)
        }
    }
}
async fn cancel_challenge(
    transport: &Transport,
    credentials: &Credentials,
    wire: &WireProfile,
) -> AuthResult<()> {
    let response = transport
        .post(
            CANCEL,
            credentials,
            wire,
            password::passcode_json(credentials, wire, false)?,
        )
        .await?;
    if password::PasscodeResponse::parse(&response)?.status != 0 {
        return Err(AuthError::new(AuthErrorCode::InvalidResponse));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        http::{HeaderMap, StatusCode},
        routing::post,
        Router,
    };
    use std::sync::{Arc, Mutex};
    fn setup() -> (tempfile::TempDir, crate::Store) {
        let dir = tempfile::Builder::new()
            .prefix("kakao-password-test-")
            .permissions(
                <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
            )
            .tempdir()
            .unwrap();
        let store = crate::Store::initialize(dir.path()).unwrap();
        store
            .device_initialize(
                &serde_json::from_str(include_str!("../config/device-catalog.json")).unwrap(),
                chrono::NaiveDate::from_ymd_opt(2026, 11, 13).unwrap(),
            )
            .unwrap();
        (dir, store)
    }
    async fn mock(router: Router) -> (Transport, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (
            Transport::build(
                &format!("http://{address}/android/account/"),
                false,
                Duration::from_secs(2),
            )
            .unwrap(),
            task,
        )
    }
    #[tokio::test]
    async fn login_uses_form_headers_and_persists_without_credentials() {
        let (dir, store) = setup();
        let recorded = Arc::new(Mutex::new(None));
        let capture = recorded.clone();
        let (transport, task) = mock(Router::new().route("/android/account/login.json",post(move |headers: HeaderMap, body: String| {
            let capture = capture.clone();
            async move {
                *capture.lock().unwrap() = Some((headers,body));
                r#"{"status":0,"userId":42,"countryIso":"KR","access_token":"synthetic-access","refresh_token":"synthetic-refresh","token_type":"Bearer","sessionKey":"synthetic-session"}"#
            }
        }))).await;
        let result = authorize_with(
            &store,
            &Credentials::new("synthetic@example.test".into(), "a+&=한글 space".into()).unwrap(),
            &transport,
        )
        .await
        .unwrap();
        assert_eq!(result.outcome, "authorized_bootstrap_pending");
        assert_eq!(
            result.auth.state,
            crate::qr_auth::AuthState::PasswordAuthorizedBootstrapPending
        );
        assert_eq!(result.auth.method.as_deref(), Some("password"));
        let (headers, body) = recorded.lock().unwrap().take().unwrap();
        assert_eq!(headers["user-agent"], "KT/26.3.2 An/13 ko");
        assert_eq!(headers["x-vc"], "10b25b934c84f88a");
        assert_eq!(headers["a"], "android/26.3.2/ko");
        assert_eq!(headers["accept-language"], "ko");
        assert_eq!(headers["content-type"], "application/x-www-form-urlencoded");
        assert!(!headers.contains_key("authorization"));
        let fields: std::collections::BTreeMap<_, _> = url::form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect();
        assert_eq!(fields.len(), 6);
        assert_eq!(fields["password"], "a+&=한글space");
        assert_eq!(fields["forced"], "false");
        assert_eq!(fields["permanent"], "true");
        let saved = std::fs::read_to_string(dir.path().join("qr-handoff.json")).unwrap();
        assert!(saved.contains("synthetic-session"));
        assert!(!saved.contains("synthetic@example.test"));
        assert!(!saved.contains("a+&="));
        assert!(crate::qr_auth::Attempt::begin_password(&store).is_err());
        task.abort();
    }
    #[tokio::test]
    async fn rejection_can_be_explicitly_retried_with_same_identity() {
        let (_dir, store) = setup();
        let (transport, task) = mock(Router::new().route(
            "/android/account/login.json",
            post(|| async { r#"{"status":12,"message":"synthetic-sensitive"}"# }),
        ))
        .await;
        let credentials =
            Credentials::new("synthetic@example.test".into(), "synthetic".into()).unwrap();
        let first = authorize_with(&store, &credentials, &transport)
            .await
            .unwrap();
        let identity = store.qr_wire_show().unwrap();
        assert_eq!(first.server_status, Some(12));
        assert!(!first.auth.recovery_required);
        let second = authorize_with(&store, &credentials, &transport)
            .await
            .unwrap();
        assert!(!serde_json::to_string(&second)
            .unwrap()
            .contains("synthetic-sensitive"));
        assert_eq!(identity, store.qr_wire_show().unwrap());
        task.abort();
    }
    #[tokio::test]
    async fn redirect_invalid_success_and_oversize_keep_recovery_lock() {
        for (status, body) in [
            (StatusCode::FOUND, "".to_owned()),
            (StatusCode::BAD_REQUEST, r#"{"status":0}"#.into()),
            (StatusCode::OK, "x".repeat(65537)),
            (StatusCode::OK, r#"{"status":0}"#.into()),
        ] {
            let (_dir, store) = setup();
            let (transport, task) = mock(Router::new().route(
                "/android/account/login.json",
                post(move || {
                    let body = body.clone();
                    async move { (status, body) }
                }),
            ))
            .await;
            assert!(authorize_with(
                &store,
                &Credentials::new("synthetic@example.test".into(), "synthetic".into()).unwrap(),
                &transport
            )
            .await
            .is_err());
            assert!(store.auth_status().unwrap().recovery_required);
            assert!(crate::qr_auth::Attempt::begin_password(&store).is_err());
            task.abort();
        }
    }
    #[tokio::test]
    async fn full_device_approval_preserves_original_login_and_request_contracts() {
        let (_dir, store) = setup();
        let events = Arc::new(Mutex::new(Vec::<(String, HeaderMap, String)>::new()));
        let capture = events.clone();
        let (transport,task)=mock(Router::new().route("/android/account/{operation}",post(move |axum::extract::Path(path):axum::extract::Path<String>,headers:HeaderMap,body:String| {
            let capture=capture.clone(); async move {
                let mut events=capture.lock().unwrap();
                let count=events.iter().filter(|(p,_,_)|p==&path).count();
                events.push((path.clone(),headers,body));
                if path=="login.json" && count==0 { r#"{"status":-100}"# } else { r#"{"status":0,"userId":42,"countryIso":"KR","access_token":"synthetic-access","refresh_token":"synthetic-refresh","token_type":"Bearer"}"# }
            }
        })).route("/android/account/passcodeLogin/{operation}",post({let capture=events.clone(); move |axum::extract::Path(path):axum::extract::Path<String>,headers:HeaderMap,body:String| {
            let capture=capture.clone(); async move {
                let mut events=capture.lock().unwrap();
                let count=events.iter().filter(|(p,_,_)|p==&path).count();
                events.push((path.clone(),headers,body));
                match path.as_str() {
                    "generate"=>r#"{"status":0,"passcode":"0123","remainingSeconds":60}"#,
                    "registerDevice" if count==0=>r#"{"status":-100,"nextRequestIntervalInSeconds":1,"remainingSeconds":59}"#,
                    "registerDevice"=>r#"{"status":0}"#,
                    _=>panic!("unexpected route"),
                }
            }
        }}))).await;
        let mut codes = Vec::new();
        let start = Instant::now();
        let credentials =
            Credentials::new("synthetic@example.test".into(), "synthetic-secret".into()).unwrap();
        let result = run(
            &store,
            &credentials,
            &transport,
            Duration::from_secs(10),
            std::future::pending(),
            |Notice::Passcode { value, .. }| codes.push(value),
        )
        .await
        .unwrap();
        assert_eq!(result.outcome, "authorized_bootstrap_pending");
        assert!(start.elapsed() >= Duration::from_secs(1));
        assert_eq!(codes, ["0123"]);
        let events = events.lock().unwrap();
        assert_eq!(
            events.iter().map(|e| e.0.as_str()).collect::<Vec<_>>(),
            [
                "login.json",
                "generate",
                "registerDevice",
                "registerDevice",
                "login.json"
            ]
        );
        assert_eq!(events[0].2, events[4].2);
        let generated: serde_json::Value = serde_json::from_str(&events[1].2).unwrap();
        assert_eq!(
            generated["device"]["uuid"],
            store.qr_wire_show().unwrap().uuid()
        );
        assert_eq!(generated["device"]["osVersion"], "13");
        assert_eq!(generated["permanent"], true);
        assert_eq!(generated["password"], "synthetic-secret");
        assert_eq!(generated["device"].as_object().unwrap().len(), 4);
        for event in &events[1..4] {
            assert_eq!(event.1["content-type"], "application/json");
            assert_eq!(event.1["user-agent"], "KT/26.3.2 An/13 ko");
            assert_eq!(event.1["x-vc"], "10b25b934c84f88a");
            assert!(!event.1.contains_key("accept-language"));
            assert!(!event.1.contains_key("authorization"));
        }
        let poll: serde_json::Value = serde_json::from_str(&events[2].2).unwrap();
        assert_eq!(poll.as_object().unwrap().len(), 3);
        assert_eq!(poll["device"].as_object().unwrap().len(), 1);
        task.abort();
    }
    #[tokio::test]
    async fn timeout_between_polls_cancels_once_but_uncertain_cancel_keeps_lock() {
        for cancellation_status in [0, -500] {
            let (_dir, store) = setup();
            let calls = Arc::new(Mutex::new(Vec::<String>::new()));
            let capture = calls.clone();
            let (transport,task)=mock(Router::new().route("/android/account/login.json",post(|| async {r#"{"status":-100}"#}))
                .route("/android/account/passcodeLogin/{operation}",post(move |axum::extract::Path(path):axum::extract::Path<String>| {
                    let capture=capture.clone(); async move {
                        capture.lock().unwrap().push(path.clone());
                        match path.as_str() {
                            "generate"=>r#"{"status":0,"passcode":"0123","remainingSeconds":60}"#.to_owned(),
                            "registerDevice"=>r#"{"status":-100,"nextRequestIntervalInSeconds":1}"#.to_owned(),
                            "cancel"=>format!(r#"{{"status":{cancellation_status}}}"#),
                            _=>panic!("unexpected route"),
                        }
                    }
                }))).await;
            let credentials =
                Credentials::new("synthetic@example.test".into(), "synthetic-secret".into())
                    .unwrap();
            let error = run(
                &store,
                &credentials,
                &transport,
                Duration::from_millis(300),
                std::future::pending(),
                |_| {},
            )
            .await
            .err()
            .unwrap();
            assert_eq!(error.code, AuthErrorCode::OverallTimeout);
            assert_eq!(
                *calls.lock().unwrap(),
                ["generate", "registerDevice", "cancel"]
            );
            assert_eq!(
                store.auth_status().unwrap().recovery_required,
                cancellation_status != 0
            );
            task.abort();
        }
    }
}
