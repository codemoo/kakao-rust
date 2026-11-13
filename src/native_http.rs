//! Fixed-destination Android requests and conditional token refresh.
//! No automatic login, redirect, payload logging or unrestricted URL dispatch.
use crate::{session::Session, Error, Result, Store};
use serde::Deserialize;
use std::time::Duration;
use zeroize::Zeroizing;

pub struct Response {
    pub http_status: u16,
    pub server_status: Option<i64>,
    gateway: bool,
    pub body: Zeroizing<Vec<u8>>,
}
#[derive(Clone, Copy)]
enum Headers {
    Legacy,
    Brewery,
    Pilsner,
}
pub struct Client {
    #[cfg(test)]
    test_origin: Option<url::Url>,
    client: reqwest::Client,
    listen_client: reqwest::Client,
}
#[derive(Clone, Copy)]
pub enum Operation<'a> {
    TextSettings {
        revision: i64,
    },
    BackupList,
    LessSettings,
    MoreSettings {
        include_adid: bool,
    },
    Friend {
        id: i64,
    },
    FriendsDiff {
        ids: &'a [i64],
    },
    FriendsSync {
        since: i64,
    },
    WalletStatus {
        has_certificate: bool,
    },
    DrawerUserInfo,
    DrawerChatBackupCompleted,
    DrawerMediaBackupCompleted,
    DrawerBackupInfo,
    DrawerContactSnapshot,
    ContactSnapshots {
        offset: Option<&'a str>,
        count: i32,
    },
    Contacts {
        snapshot: &'a str,
        offset: Option<i64>,
    },
    DrawerRestoreCompleted,
    DrawerRecordingStart,
    DrawerRecordingUsage,
    DrawerRecordingComplete,
    DrawerLogMeta {
        chat_id: i64,
        from: i64,
        to: i64,
    },
    DrawerKeySync,
    DrawerChats {
        last_chat_id: Option<i64>,
    },
    DrawerLogs {
        last_row_key: Option<&'a str>,
    },
    DrawerPinKey,
    DrawerPinSalt,
    DrawerPinVerify {
        hashed_pin: &'a str,
    },
    PilsnerPing,
}
impl Client {
    pub async fn open_listen(
        &self,
        session: &Session,
        last_subscribed: i64,
    ) -> Result<reqwest::Response> {
        let authorization = Zeroizing::new(format!(
            "{}-{}",
            session.access_token.as_str(),
            session.wire.uuid()
        ));
        for attempt in 0..2 {
            let response = self
                .listen_client
                .get("https://talk-pilsner.kakao.com/listen")
                .header("Authorization", authorization.as_str())
                .header("talk-agent", "android/26.3.2")
                .header("talk-language", "ko")
                .header("talk-last-subscribed", last_subscribed.to_string())
                .header("User-Agent", "okhttp/4.12.0")
                .header("Accept-Encoding", "gzip")
                .header("Connection", "Keep-Alive")
                .send()
                .await
                .map_err(|_| failure())?;
            if response.status().is_success() {
                return Ok(response);
            }
            if response.status().as_u16() == 403 || attempt == 1 {
                return Err(Error::Invalid("pilsner listen rejected".into()));
            }
            // Close an unsuccessful non-403 response and retry exactly once,
            // without delay; transport errors are not retried here.
            drop(response);
        }
        unreachable!()
    }
    pub async fn pilsner_ping(&self, store: &Store, session: &mut Session) -> Result<()> {
        let response = self.execute(store, session, Operation::PilsnerPing).await?;
        if !(200..300).contains(&response.http_status) {
            return Err(failure());
        }
        Ok(())
    }

    pub fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .referer(false)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(20))
            .gzip(true)
            .build()
            .map_err(|_| failure())?;
        // Use an idle-read timeout, not a deadline that kills an
        // otherwise healthy stream every30min. This client has no total timeout.
        let listen_client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .referer(false)
            .connect_timeout(Duration::from_secs(10))
            .read_timeout(Duration::from_secs(30 * 60))
            .gzip(true)
            .build()
            .map_err(|_| failure())?;
        Ok(Self {
            #[cfg(test)]
            test_origin: None,
            client,
            listen_client,
        })
    }
    pub async fn execute(
        &self,
        store: &Store,
        session: &mut Session,
        operation: Operation<'_>,
    ) -> Result<Response> {
        let correlation = uuid::Uuid::new_v4().to_string();
        let response = self.once(session, operation, &correlation).await?;
        if !needs_refresh(&response, operation) {
            return Ok(response);
        }
        self.refresh(store, session).await?;
        // Replace only Authorization and retry the original operation.
        self.once(session, operation, &correlation).await
    }
    async fn once(
        &self,
        session: &Session,
        operation: Operation<'_>,
        correlation: &str,
    ) -> Result<Response> {
        let pilsner = matches!(
            operation,
            Operation::TextSettings { .. }
                | Operation::FriendsSync { .. }
                | Operation::WalletStatus { .. }
                | Operation::DrawerUserInfo
                | Operation::DrawerChatBackupCompleted
                | Operation::DrawerMediaBackupCompleted
                | Operation::DrawerBackupInfo
                | Operation::DrawerContactSnapshot
                | Operation::ContactSnapshots { .. }
                | Operation::Contacts { .. }
                | Operation::DrawerRestoreCompleted
                | Operation::DrawerRecordingStart
                | Operation::DrawerRecordingUsage
                | Operation::DrawerRecordingComplete
                | Operation::DrawerLogMeta { .. }
                | Operation::DrawerKeySync
                | Operation::DrawerChats { .. }
                | Operation::DrawerLogs { .. }
                | Operation::DrawerPinKey
                | Operation::DrawerPinSalt
                | Operation::DrawerPinVerify { .. }
                | Operation::PilsnerPing
        );
        let request = match operation {
            Operation::TextSettings { revision } => self
                .client
                .get("https://talk-pilsner.kakao.com/chat/linkify/settings")
                .query(&[("revision", revision)]),
            Operation::LessSettings => self
                .client
                .get("https://katalk.kakao.com/android/account/less_settings.json"),
            Operation::MoreSettings { include_adid } => {
                let request = self
                    .client
                    .get("https://katalk.kakao.com/android/account/more_settings.json")
                    .query(&[
                        ("os_version", session.wire.os_version()),
                        ("model", session.wire.model()),
                        ("since", "0"),
                    ]);
                if include_adid {
                    request.query(&[("adid", ""), ("adid_status", "-1")])
                } else {
                    request
                }
            }
            Operation::Friend { id } => self.client.get(format!(
                "https://katalk.kakao.com/android/friends/{id}.json"
            )),
            Operation::FriendsDiff { ids } => self
                .client
                .post("https://katalk.kakao.com/android/friends/diff.json")
                .form(&[(
                    "friend_ids",
                    format!(
                        "[{}]",
                        ids.iter()
                            .map(i64::to_string)
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                )]),
            Operation::FriendsSync { since } => {
                let request = self
                    .client
                    .get("https://talk-pilsner.kakao.com/talk/friends/sync")
                    .query(&[("since", since)]);
                if since == 0 {
                    request.header("talk-priority-level", "critical")
                } else {
                    request
                }
            }

            Operation::WalletStatus { has_certificate } => self
                .client
                .get("https://talk-pilsner.kakao.com/zert/api/v2/status")
                .query(&[("hasCertificate", has_certificate)]),
            Operation::DrawerUserInfo => self
                .client
                .get("https://talk-pilsner.kakao.com/drawer/user/info"),
            Operation::DrawerChatBackupCompleted => self
                .client
                .get("https://talk-pilsner.kakao.com/drawer/backup/chatLogs/completed"),
            Operation::DrawerMediaBackupCompleted => self
                .client
                .get("https://talk-pilsner.kakao.com/drawer/backup/mediaFiles/completed"),
            Operation::DrawerBackupInfo => self
                .client
                .get("https://talk-pilsner.kakao.com/drawer/backup/info"),
            Operation::ContactSnapshots { offset, count } => {
                let request = self
                    .client
                    .get("https://talk-pilsner.kakao.com/drawer/contactSnapshot/list")
                    .query(&[("fetchCount", count)])
                    .timeout(Duration::from_secs(60));
                if let Some(offset) = offset {
                    request.query(&[("offset", offset)])
                } else {
                    request
                }
            }
            Operation::Contacts { snapshot, offset } => {
                let request = self
                    .client
                    .get("https://talk-pilsner.kakao.com/drawer/contact/list")
                    .query(&[("snapshotId", snapshot)])
                    .query(&[("fetchCount", 1000)])
                    .timeout(Duration::from_secs(60));
                if let Some(offset) = offset {
                    request.query(&[("offset", offset)])
                } else {
                    request
                }
            }
            Operation::DrawerContactSnapshot => self
                .client
                .get("https://talk-pilsner.kakao.com/drawer/contactSnapshot/list")
                .query(&[("fetchCount", 1)]),
            Operation::DrawerRestoreCompleted => self
                .client
                .post("https://talk-pilsner.kakao.com/drawer/backup/restore/completed")
                .body(Vec::new()),
            Operation::DrawerRecordingStart | Operation::DrawerRecordingComplete => self
                .client
                .post(if matches!(operation, Operation::DrawerRecordingStart) {
                    "https://talk-pilsner.kakao.com/drawer/recording/restore/start"
                } else {
                    "https://talk-pilsner.kakao.com/drawer/recording/restore/complete"
                })
                .header("Content-Type", "application/json")
                .body(r#"{"type":"KAKAOTALK"}"#),
            Operation::DrawerRecordingUsage => self
                .client
                .get("https://talk-pilsner.kakao.com/drawer/recording/usage"),
            Operation::DrawerLogMeta { chat_id, from, to } => self
                .client
                .get(format!(
                    "https://talk-pilsner.kakao.com/messaging/chats/{chat_id}/chat-log/meta"
                ))
                .query(&[("from", from), ("to", to)])
                .query(&[("desc", true)]),
            Operation::DrawerKeySync => self
                .client
                .get("https://talk-pilsner.kakao.com/me/pin/v1/isSynced")
                .query(&[("serviceCode", "drawer"), ("syncTarget", "PIN_TKN")]),
            Operation::DrawerChats { last_chat_id } => {
                let request = self
                    .client
                    .get("https://talk-pilsner.kakao.com/alcatraz/drawer/chats")
                    .query(&[("fetchCount", 100)]);
                if let Some(id) = last_chat_id {
                    request.query(&[("lastChatId", id)])
                } else {
                    request
                }
            }
            Operation::DrawerLogs { last_row_key } => {
                let request = self
                    .client
                    .get("https://talk-pilsner.kakao.com/alcatraz/drawer/chatLogs")
                    .query(&[("fetchCount", 500)]);
                if let Some(key) = last_row_key {
                    request.query(&[("encLastRowKey", key)])
                } else {
                    request
                }
            }
            Operation::DrawerPinKey => self
                .client
                .get("https://talk-pilsner.kakao.com/me/pin/v1/requestKey")
                .query(&[("serviceCode", "drawer"), ("method", "pin")]),
            Operation::DrawerPinSalt => self
                .client
                .get("https://talk-pilsner.kakao.com/me/pin/v1/salt"),
            Operation::DrawerPinVerify { hashed_pin } => {
                #[derive(serde::Serialize)]
                struct Verify<'a> {
                    #[serde(rename = "hashedPin")]
                    hashed_pin: &'a str,
                }
                let body = Zeroizing::new(serde_json::to_vec(&Verify { hashed_pin })?);
                self.client
                    .post("https://talk-pilsner.kakao.com/me/pin/v1/verify")
                    .header("Content-Type", "application/json")
                    .body(body.to_vec())
            }
            Operation::PilsnerPing => self.client.get("https://talk-pilsner.kakao.com/ping"),
            Operation::BackupList => {
                use sha1::{Digest, Sha1};
                let account = session.account_id.ok_or_else(|| {
                    Error::Storage("backup precheck requires saved account ID".into())
                })?;
                let seed =
                    Zeroizing::new(format!("{}{account}ZA6GpHD9pAL2pcaGEPP5", session.user_id));
                let key = Zeroizing::new(hex::encode(Sha1::digest(seed.as_bytes())));
                let form = url::form_urlencoded::Serializer::new(String::new())
                    .append_pair("client_key", &key)
                    .finish();
                self.client
                    .post("https://katalk.kakao.com/android/backup/list.json")
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(form)
            }
        };
        self.send(
            session,
            request,
            if matches!(
                operation,
                Operation::FriendsDiff { .. } | Operation::Friend { .. }
            ) {
                Headers::Brewery
            } else if pilsner {
                Headers::Pilsner
            } else {
                Headers::Legacy
            },
            false,
            match operation {
                Operation::DrawerRestoreCompleted
                | Operation::PilsnerPing
                | Operation::DrawerRecordingStart
                | Operation::DrawerRecordingComplete => None,
                Operation::Contacts { .. }
                | Operation::FriendsSync { .. }
                | Operation::FriendsDiff { .. }
                | Operation::Friend { .. }
                | Operation::DrawerChats { .. }
                | Operation::DrawerLogs { .. }
                | Operation::DrawerLogMeta { .. } => Some(32 * 1024 * 1024),
                _ => Some(1024 * 1024),
            },
            Some(correlation),
        )
        .await
    }
    async fn send(
        &self,
        session: &Session,
        request: reqwest::RequestBuilder,
        headers: Headers,
        close: bool,
        response_limit: Option<usize>,
        correlation: Option<&str>,
    ) -> Result<Response> {
        let authorization = Zeroizing::new(format!(
            "{}-{}",
            session.access_token.as_str(),
            session.wire.uuid()
        ));
        let use_c = matches!(headers, Headers::Legacy);
        let use_a = !matches!(headers, Headers::Pilsner);
        let generated_correlation = uuid::Uuid::new_v4().to_string();
        let correlation = correlation.unwrap_or(&generated_correlation);
        let request = request
            .header("Authorization", authorization.as_str())
            .header("Accept-Encoding", "gzip")
            .header("Connection", if close { "Close" } else { "Keep-Alive" });
        let mut request = if use_a {
            request
                .header(
                    "User-Agent",
                    format!("KT/26.3.2 An/{} ko", session.wire.os_version()),
                )
                .header("A", "android/26.3.2/ko")
                .header("Accept-Language", "ko")
        } else {
            request
                .header("User-Agent", "okhttp/4.12.0")
                .header("talk-agent", "android/26.3.2")
                .header("talk-language", "ko")
        };
        if use_c {
            request = request.header("C", correlation);
        }
        let request = request.build().map_err(|_| failure())?;
        #[cfg(test)]
        let request = {
            let mut request = request;
            if let Some(origin) = &self.test_origin {
                assert_eq!(origin.host_str(), Some("127.0.0.1"));
                let url = request.url_mut();
                url.set_scheme(origin.scheme()).map_err(|_| failure())?;
                url.set_host(origin.host_str()).map_err(|_| failure())?;
                url.set_port(origin.port()).map_err(|_| failure())?;
            }
            request
        };
        let mut response = self.client.execute(request).await.map_err(|_| failure())?;
        if response.status().is_redirection() {
            return Err(Error::Invalid("native HTTP redirect refused".into()));
        }
        let http_status = response.status().as_u16();
        let gateway = response
            .headers()
            .get("talk-served-by")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("gateway"));
        if use_c {
            if response
                .headers()
                .get("C")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| !v.trim().is_empty() && v != correlation)
            {
                return Err(Error::Invalid("native HTTP correlation mismatch".into()));
            }
            if response
                .headers()
                .get("Kakao")
                .and_then(|v| v.to_str().ok())
                != Some("Talk")
            {
                return Err(Error::Invalid(
                    "native HTTP Kakao response header missing".into(),
                ));
            }
        }
        if response_limit.is_none() {
            // These operations discard the response body, including non-JSON success bodies.
            // Header-based gateway401 remains available to retry.
            return Ok(Response {
                http_status,
                server_status: None,
                gateway,
                body: Zeroizing::new(Vec::new()),
            });
        }
        let mut body = Zeroizing::new(Vec::new());
        while let Some(chunk) = response.chunk().await.map_err(|_| failure())? {
            if chunk.len()
                > response_limit
                    .unwrap_or(1024 * 1024)
                    .saturating_sub(body.len())
            {
                return Err(Error::Invalid("native HTTP response too large".into()));
            }
            body.extend_from_slice(&chunk);
        }
        #[derive(Deserialize)]
        struct Envelope {
            status: Option<i64>,
        }
        let envelope = if body.is_empty()
            || (http_status == 401 && gateway && matches!(headers, Headers::Pilsner))
        {
            Envelope { status: None }
        } else {
            serde_json::from_slice::<Envelope>(&body)
                .map_err(|_| Error::Invalid("native HTTP response invalid".into()))?
        };
        if !(200..300).contains(&http_status)
            && envelope.status.is_none_or(|s| s == 0)
            && !(http_status == 401 && gateway && matches!(headers, Headers::Pilsner))
        {
            return Err(failure());
        }
        Ok(Response {
            http_status,
            server_status: envelope.status,
            gateway,
            body,
        })
    }
    pub(crate) async fn refresh(&self, store: &Store, session: &mut Session) -> Result<()> {
        // The runtime lease excludes other processes; clones of its Store share
        // this gate so the listener and bootstrap request cannot rotate in parallel.
        let mut last_refresh = store.refresh_gate.lock().await;
        let current = store.session_load()?;
        if current.access_token != session.access_token
            || current.refresh_token != session.refresh_token
            || last_refresh.is_some_and(|at| at.elapsed() < Duration::from_secs(20))
        {
            *session = current;
            return Ok(());
        }

        #[derive(serde::Serialize)]
        struct Request<'a> {
            access_token: &'a str,
            refresh_token: &'a str,
            grant_type: &'static str,
        }
        let body = Zeroizing::new(serde_json::to_vec(&Request {
            access_token: &session.access_token,
            refresh_token: &session.refresh_token,
            grant_type: "refresh_token",
        })?);
        let request = self
            .client
            .post("https://katalk.kakao.com/android/account/oauth2_token.json")
            .header("Content-Type", "application/json")
            .body(body.to_vec());
        let response = self
            .send(
                session,
                request,
                Headers::Legacy,
                true,
                Some(1024 * 1024),
                None,
            )
            .await?;
        if !(200..300).contains(&response.http_status)
            || response.server_status.is_some_and(|s| s != 0)
        {
            return Err(Error::Unauthorized);
        }
        #[derive(Deserialize)]
        struct Tokens {
            access_token: String,
            refresh_token: String,
            token_type: String,
        }
        let tokens: Tokens = serde_json::from_slice(&response.body)
            .map_err(|_| Error::Invalid("invalid refresh response".into()))?;
        let access = Zeroizing::new(tokens.access_token);
        let refresh = Zeroizing::new(tokens.refresh_token);
        store.rotate_tokens(session, &access, &refresh, &tokens.token_type)?;
        *session = store.session_load()?;
        *last_refresh = Some(std::time::Instant::now());
        Ok(())
    }
}
impl Default for Client {
    fn default() -> Self {
        Self::new().expect("native HTTP TLS initialization")
    }
}
fn failure() -> Error {
    Error::Invalid("native HTTP request failed; inspect local step state".into())
}

fn needs_refresh(response: &Response, operation: Operation<'_>) -> bool {
    response.http_status == 401
        && if matches!(
            operation,
            Operation::BackupList
                | Operation::MoreSettings { .. }
                | Operation::LessSettings
                | Operation::FriendsDiff { .. }
                | Operation::Friend { .. }
        ) {
            response.server_status == Some(-950)
        } else {
            response.gateway
        }
}
#[cfg(test)]
mod tests {
    use super::*;
    async fn refresh_fixture(
        replies: Vec<(u16, &'static str, &'static str)>,
    ) -> (Client, tokio::task::JoinHandle<Vec<(String, String)>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let mut requests = Vec::new();
            for (status, headers, body) in replies {
                let (mut socket, _) =
                    tokio::time::timeout(Duration::from_secs(3), listener.accept())
                        .await
                        .unwrap()
                        .unwrap();
                let mut bytes = Vec::new();
                let mut one = [0];
                while !bytes.ends_with(b"\r\n\r\n") {
                    socket.read_exact(&mut one).await.unwrap();
                    bytes.push(one[0]);
                    assert!(bytes.len() < 16384);
                }
                let head = String::from_utf8(bytes).unwrap();
                let length = head
                    .lines()
                    .find_map(|l| {
                        l.to_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                let mut payload = vec![0; length];
                socket.read_exact(&mut payload).await.unwrap();
                requests.push((head, String::from_utf8(payload).unwrap()));
                let response=format!("HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\nKakao: Talk\r\n{headers}\r\n{body}",body.len());
                socket.write_all(response.as_bytes()).await.unwrap();
            }
            requests
        });
        (
            Client {
                test_origin: Some(url::Url::parse(&origin).unwrap()),
                client: reqwest::Client::builder()
                    .no_proxy()
                    .redirect(reqwest::redirect::Policy::none())
                    .timeout(Duration::from_secs(3))
                    .build()
                    .unwrap(),
                listen_client: reqwest::Client::new(),
            },
            task,
        )
    }
    #[tokio::test]
    async fn rejected_request_rotates_persisted_pair_and_replays_exactly_once() {
        let (_dir, store) = crate::runtime::tests::setup();
        let mut session = store.session_load().unwrap();
        let (client,server)=refresh_fixture(vec![(401,"",r#"{"status":-950}"#),(200,"",r#"{"access_token":"new-access","refresh_token":"new-refresh","token_type":"bearer"}"#),(200,"",r#"{"status":0}"#)]).await;
        let response = client
            .execute(
                &store,
                &mut session,
                Operation::MoreSettings { include_adid: true },
            )
            .await
            .unwrap();
        assert_eq!(response.http_status, 200);
        let requests = server.await.unwrap();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].0.lines().next(), requests[2].0.lines().next());
        let header = |index: usize, key: &str| {
            requests[index]
                .0
                .lines()
                .find(|l| l.to_lowercase().starts_with(key))
                .unwrap()
                .to_owned()
        };
        assert_eq!(header(0, "c:"), header(2, "c:"));
        assert!(header(0, "authorization:").contains("initial-access-"));
        assert!(header(2, "authorization:").contains("new-access-"));
        assert!(requests[1]
            .0
            .starts_with("POST /android/account/oauth2_token.json "));
        let payload: serde_json::Value = serde_json::from_str(&requests[1].1).unwrap();
        assert_eq!(payload["grant_type"], "refresh_token");
        assert_eq!(payload["access_token"], "initial-access");
        assert_eq!(
            store.session_load().unwrap().refresh_token.as_str(),
            "new-refresh"
        );
    }
    #[tokio::test]
    async fn refresh_rejection_or_invalid_pair_retains_session_and_never_replays() {
        for (status, body) in [
            (401, r#"{"status":-950}"#),
            (
                200,
                r#"{"access_token":"new","refresh_token":"","token_type":"bearer"}"#,
            ),
            (200, "broken"),
        ] {
            let (_dir, store) = crate::runtime::tests::setup();
            let mut session = store.session_load().unwrap();
            let (client, server) = refresh_fixture(vec![
                (401, "talk-served-by: gateway\r\n", r#"{}"#),
                (status, "", body),
            ])
            .await;
            assert!(client
                .execute(&store, &mut session, Operation::FriendsSync { since: 17 })
                .await
                .is_err());
            assert_eq!(server.await.unwrap().len(), 2);
            assert_eq!(
                store.session_load().unwrap().access_token.as_str(),
                "initial-access"
            );
            assert!(store.refresh_gate.lock().await.is_none());
        }
    }
    #[tokio::test]
    async fn brewery_gateway_header_preserves_legacy_expiry_status_and_exact_request() {
        for operation in [
            Operation::Friend {
                id: 9007199254740993,
            },
            Operation::FriendsDiff {
                ids: &[1, 9007199254740993],
            },
        ] {
            let (_dir, store) = crate::runtime::tests::setup();
            let mut session = store.session_load().unwrap();
            let (client,server)=refresh_fixture(vec![(401,"talk-served-by: gateway\r\n",r#"{"status":-950}"#),(200,"",r#"{"access_token":"new-access","refresh_token":"new-refresh","token_type":"bearer"}"#),(200,"",r#"{"status":0}"#)]).await;
            assert_eq!(
                client
                    .execute(&store, &mut session, operation)
                    .await
                    .unwrap()
                    .http_status,
                200
            );
            let requests = server.await.unwrap();
            assert_eq!(requests.len(), 3);
            assert_eq!(requests[0].0.lines().next(), requests[2].0.lines().next());
            assert_eq!(requests[0].1, requests[2].1);
            let first = requests[0].0.to_lowercase();
            let last = requests[2].0.to_lowercase();
            assert!(!first.contains("\r\nc:"));
            assert!(first.contains("\r\na: android/26.3.2/ko"));
            assert!(!first.contains("talk-agent:"));
            assert!(last.contains("authorization: new-access-"));
            if matches!(operation, Operation::FriendsDiff { .. }) {
                assert_eq!(requests[0].1, "friend_ids=%5B1%2C+9007199254740993%5D");
            } else {
                assert!(first.starts_with("get /android/friends/9007199254740993.json "));
            }
            let (client, server) = refresh_fixture(vec![(
                401,
                "talk-served-by: gateway\r\n",
                r#"{"status":-123}"#,
            )])
            .await;
            assert_eq!(
                client
                    .execute(&store, &mut session, operation)
                    .await
                    .unwrap()
                    .http_status,
                401
            );
            assert_eq!(server.await.unwrap().len(), 1);
        }
    }
    #[tokio::test]
    async fn replayed_rejection_does_not_loop_and_wrong_auth_failure_never_refreshes() {
        let (_dir, store) = crate::runtime::tests::setup();
        let mut session = store.session_load().unwrap();
        let (client,server)=refresh_fixture(vec![(401,"talk-served-by: gateway\r\n",r#"{}"#),(200,"",r#"{"access_token":"new-access","refresh_token":"new-refresh","token_type":"bearer"}"#),(401,"talk-served-by: gateway\r\n",r#"{}"#)]).await;
        assert_eq!(
            client
                .execute(&store, &mut session, Operation::FriendsSync { since: 17 })
                .await
                .unwrap()
                .http_status,
            401
        );
        let requests = server.await.unwrap();
        assert_eq!(requests.len(), 3);
        assert!(requests[0]
            .0
            .starts_with("GET /talk/friends/sync?since=17 "));
        assert!(requests[2]
            .0
            .starts_with("GET /talk/friends/sync?since=17 "));
        for (status, headers, body) in [
            (403, "talk-served-by: gateway\r\n", r#"{}"#),
            (401, "", r#"{}"#),
        ] {
            let (client, server) = refresh_fixture(vec![(status, headers, body)]).await;
            assert!(client
                .execute(&store, &mut session, Operation::FriendsSync { since: 17 })
                .await
                .is_err());
            assert_eq!(server.await.unwrap().len(), 1);
        }
    }
    #[test]
    fn legacy_and_gateway_refresh_have_distinct_triggers() {
        let mut r = Response {
            http_status: 200,
            server_status: Some(-950),
            gateway: false,
            body: Zeroizing::new(vec![]),
        };
        assert!(!needs_refresh(&r, Operation::BackupList));
        r.http_status = 401;
        assert!(needs_refresh(&r, Operation::BackupList));
        assert!(!needs_refresh(&r, Operation::DrawerUserInfo));
        r.server_status = None;
        r.gateway = true;
        assert!(needs_refresh(&r, Operation::PilsnerPing));
        assert!(!needs_refresh(&r, Operation::BackupList));
        r.http_status = 403;
        assert!(!needs_refresh(&r, Operation::PilsnerPing));
    }
    #[test]
    fn counted_pin_rejection_is_distinct_from_gateway_authentication() {
        let operation = Operation::DrawerPinVerify {
            hashed_pin: "synthetic",
        };
        for status in [401, 402, 404] {
            for http in [200, 401, 403] {
                let response = Response {
                    http_status: http,
                    server_status: Some(status),
                    gateway: false,
                    body: Zeroizing::new(vec![]),
                };
                assert!(!needs_refresh(&response, operation));
            }
        }
        // Refresh rejected gateway authentication before the same
        // supplied PIN request is replayed; VerifyPin has no handler override.
        let response = Response {
            http_status: 401,
            server_status: None,
            gateway: true,
            body: Zeroizing::new(vec![]),
        };
        assert!(needs_refresh(&response, operation));
    }
    #[tokio::test]
    async fn concurrent_refresh_reuses_rotated_pair_and_twenty_second_result() {
        let (_dir, store) = crate::runtime::tests::setup();
        let mut stale = store.session_load().unwrap();
        store
            .rotate_tokens(&stale, "rotated-access", "rotated-refresh", "bearer")
            .unwrap();
        // Any accidental HTTP attempt fails against a local closed proxy.
        let client = Client {
            test_origin: None,
            listen_client: reqwest::Client::new(),
            client: reqwest::Client::builder()
                .proxy(reqwest::Proxy::all("http://127.0.0.1:9").unwrap())
                .timeout(Duration::from_millis(50))
                .build()
                .unwrap(),
        };
        client.refresh(&store, &mut stale).await.unwrap();
        assert_eq!(stale.access_token.as_str(), "rotated-access");
        *store.refresh_gate.lock().await = Some(std::time::Instant::now());
        client.refresh(&store, &mut stale).await.unwrap();
        assert_eq!(stale.refresh_token.as_str(), "rotated-refresh");
    }
    #[tokio::test]
    async fn unit_responses_accept_non_json_and_pilsner_headers_stay_separate() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (_dir, store) = crate::runtime::tests::setup();
        let session = store.session_load().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let mut one = [0];
            while !bytes.ends_with(b"\r\n\r\n") {
                socket.read_exact(&mut one).await.unwrap();
                bytes.push(one[0]);
                assert!(bytes.len() < 8192);
            }
            let request = String::from_utf8(bytes).unwrap().to_lowercase();
            assert!(request.contains("talk-agent: android/26.3.2"));
            assert!(request.contains("authorization: initial-access-"));
            assert!(!request.contains("\r\na:"));
            assert!(!request.contains("\r\nc:"));
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
                )
                .await
                .unwrap();
        });
        // Local plaintext exists only in this synthetic transport fixture.
        let client = Client {
            test_origin: None,
            listen_client: reqwest::Client::new(),
            client: reqwest::Client::builder().no_proxy().build().unwrap(),
        };
        let response = client
            .send(
                &session,
                client
                    .client
                    .post(format!("http://{address}/unit"))
                    .body(Vec::new()),
                Headers::Pilsner,
                false,
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(response.http_status, 200);
        assert!(response.body.is_empty());
        server.await.unwrap();
    }
    #[tokio::test]
    async fn brewery_headers_do_not_require_legacy_correlation_or_pilsner_headers() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (_dir, store) = crate::runtime::tests::setup();
        let session = store.session_load().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let mut one = [0];
            while !bytes.ends_with(b"\r\n\r\n") {
                socket.read_exact(&mut one).await.unwrap();
                bytes.push(one[0]);
                assert!(bytes.len() < 8192);
            }
            let request = String::from_utf8(bytes).unwrap().to_lowercase();
            assert!(!request.contains("talk-agent:"));
            assert!(request.contains("user-agent: kt/26.3.2 an/"));
            assert!(request.contains("authorization: initial-access-"));
            assert!(request.contains("\r\na: android/26.3.2/ko"));
            assert!(!request.contains("\r\nc:"));
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                .await
                .unwrap();
        });
        // Local plaintext exists only in this synthetic transport fixture.
        let client = Client {
            test_origin: None,
            listen_client: reqwest::Client::new(),
            client: reqwest::Client::builder().no_proxy().build().unwrap(),
        };
        let response = client
            .send(
                &session,
                client
                    .client
                    .post(format!("http://{address}/unit"))
                    .body(Vec::new()),
                Headers::Brewery,
                false,
                Some(1024),
                None,
            )
            .await
            .unwrap();
        assert_eq!(response.http_status, 200);
        assert_eq!(response.body.as_slice(), b"{}");
        server.await.unwrap();
    }
}
