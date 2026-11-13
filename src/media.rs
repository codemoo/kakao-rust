//! Metadata-only ingestion. Network content is fetched exclusively by API demand.
use crate::{Error, Result, Store};
use rusqlite::{params, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const MAX_DOWNLOAD: u64 = 512 * 1024 * 1024;
#[derive(Serialize)]
pub struct Attachment {
    pub index: usize,
    pub kind: &'static str,
    pub name: Option<String>,
    pub mime_type: Option<String>,
    pub size: Option<u64>,
    pub expires_at_ms: Option<i64>,
    pub available: bool,
    pub unavailable_reason: Option<&'static str>,
    #[serde(skip)]
    pub(crate) url: Option<String>,
    #[serde(skip)]
    pub(crate) token: Option<String>,
    #[serde(skip)]
    pub(crate) relay_kind: i32,
}
#[derive(Serialize)]
pub struct DownloadPlan {
    pub attachment: Attachment,
    #[serde(skip)]
    pub(crate) fingerprint: String,
    #[serde(skip)]
    pub(crate) drawer: bool,
}
fn value_str(v: &Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}
pub fn allowed_url(raw: &str) -> bool {
    let Ok(u) = url::Url::parse(raw) else {
        return false;
    };
    u.scheme() == "https"
        && u.username().is_empty()
        && u.password().is_none()
        && u.fragment().is_none()
        && u.port_or_known_default() == Some(443)
        && matches!(
            u.host_str(),
            Some(
                "dn-m.talk.kakao.com"
                    | "dn-v.talk.kakao.com"
                    | "dn.talk.kakao.com"
                    | "dn-a.talk.kakao.com"
                    | "kage.talk.kakao.com"
                    | "dn-api1-kage.kakao.com"
            )
        )
}
pub(crate) fn parse(kind: i32, raw: &str, now: i64) -> Result<Vec<Attachment>> {
    let value: Value =
        serde_json::from_str(raw).map_err(|_| Error::Unavailable("attachment_metadata_invalid"))?;
    if !value.is_object() {
        return Err(Error::Unavailable("attachment_metadata_invalid"));
    }
    let name = match kind {
        2 => "image",
        3 => "video",
        5 => "audio",
        18 => "file",
        27 => "image",
        _ => return Err(Error::Unavailable("attachment_type_unsupported")),
    };
    let secret = value.get("csk").is_some_and(|v| !v.is_null());
    let count = if kind == 27 {
        value
            .get("wl")
            .and_then(Value::as_array)
            .map_or(0, Vec::len)
    } else {
        1
    };
    if count > 1000 {
        return Err(Error::Unavailable("attachment_metadata_invalid"));
    }
    let mut out = Vec::new();
    for index in 0..count {
        let at = |key: &str| {
            value
                .get(key)
                .and_then(Value::as_array)
                .and_then(|v| v.get(index))
        };
        let url = if kind == 27 {
            at("imageUrls")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        } else {
            value_str(&value, "urlh")
                .or_else(|| value_str(&value, "url"))
                .or_else(|| value_str(&value, "path"))
        };
        let token = if kind == 27 {
            at("kl").and_then(Value::as_str).map(str::to_owned)
        } else {
            value_str(&value, "k")
                .or_else(|| value_str(&value, "tkh"))
                .or_else(|| value_str(&value, "tk"))
        }
        .filter(|v| valid_token(v))
        .or_else(|| {
            url.as_deref().filter(|u| allowed_url(u)).map(|u| {
                format!(
                    "{}/{}",
                    hex::encode(Sha256::digest(u.as_bytes())),
                    u.rsplit('/').next().unwrap_or("")
                )
            })
        });
        let expires = value
            .get("expire")
            .and_then(Value::as_i64)
            .filter(|v| *v > 0);
        let mime = if kind == 27 {
            at("mtl").and_then(Value::as_str).map(str::to_owned)
        } else {
            value_str(&value, "mt")
        };
        let size = if kind == 27 {
            at("sl").and_then(Value::as_u64)
        } else if kind == 18 {
            value.get("size").and_then(Value::as_u64)
        } else {
            value
                .get("sh")
                .or_else(|| value.get("s"))
                .or_else(|| value.get("size_3gp"))
                .and_then(Value::as_u64)
        };
        let reason = if secret {
            Some("encrypted_media_unsupported")
        } else if size.is_some_and(|s| s > MAX_DOWNLOAD) {
            Some("download_too_large")
        } else if expires.is_some_and(|t| t < now)
            || (kind == 18 && expires.is_none_or(|t| t <= 1_447_376_136_000))
        {
            Some("expired")
        } else if token.is_none() && !url.as_deref().is_some_and(allowed_url) {
            Some("download_host_unsupported")
        } else {
            None
        };
        out.push(Attachment {
            index,
            kind: name,
            name: value_str(&value, "name"),
            mime_type: mime,
            size,
            expires_at_ms: expires,
            available: reason.is_none(),
            unavailable_reason: reason,
            url,
            token,
            relay_kind: if kind == 27 { 2 } else { kind },
        });
    }
    Ok(out)
}
pub(crate) fn capture(
    tx: &Transaction<'_>,
    account: &str,
    chat: i64,
    id: i64,
    revision: i64,
    kind: i32,
    log: &bson::Document,
) -> Result<()> {
    let valid = matches!(kind, 2 | 3 | 5 | 18 | 27)
        && log
            .get("sInfo")
            .is_none_or(|v| matches!(v, bson::Bson::Null));
    let fields = log
        .get_str("attachment")
        .ok()
        .zip(log.get_i32("sendAt").ok().filter(|v| *v >= 0))
        .filter(|_| valid);
    let Some((attachment, sent)) = fields else {
        tx.execute("DELETE FROM message_media WHERE account_id=?1 AND chat_id=?2 AND log_id=?3 AND revision<=?4",params![account,chat,id,revision])?;
        return Ok(());
    };
    tx.execute("INSERT INTO message_media VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'native_loco') ON CONFLICT(account_id,chat_id,log_id) DO UPDATE SET revision=excluded.revision,kind=excluded.kind,sent_at_ms=excluded.sent_at_ms,sender_id=excluded.sender_id,attachment=excluded.attachment,source=CASE WHEN message_media.source='native_drawer' AND message_media.revision=excluded.revision AND message_media.attachment=excluded.attachment THEN message_media.source ELSE excluded.source END WHERE excluded.revision>=message_media.revision",params![account,chat,id,revision,kind,i64::from(sent)*1000,log.get_i64("authorId").ok(),attachment])?;
    Ok(())
}
impl Store {
    pub fn attachments(&self, account: &str, room: &str, message: &str) -> Result<Vec<Attachment>> {
        let (kind, raw, source, revision, sent) = self.media_raw(account, room, message)?;
        let _ = revision;
        let mut items = parse(kind, &raw, chrono::Utc::now().timestamp_millis())?;
        for item in &mut items {
            self.drawer_eligibility(account, item, &source, sent)?;
        }
        Ok(items)
    }
    fn media_raw(
        &self,
        account: &str,
        room: &str,
        message: &str,
    ) -> Result<(i32, String, String, i64, i64)> {
        let chat: i64 = room.parse().map_err(|_| Error::NotFound)?;
        let id: i64 = message.parse().map_err(|_| Error::NotFound)?;
        self.lock()?.query_row("SELECT kind,attachment,source,revision,sent_at_ms FROM message_media a WHERE account_id=?1 AND chat_id=?2 AND log_id=?3 AND NOT EXISTS(SELECT 1 FROM native_tombstones t WHERE t.account_id=a.account_id AND t.chat_id=a.chat_id AND t.log_id=a.log_id) AND NOT EXISTS(SELECT 1 FROM drawer_tombstones t WHERE t.account_id=a.account_id AND t.chat_id=a.chat_id AND t.log_id=a.log_id) AND NOT EXISTS(SELECT 1 FROM messages m WHERE m.account_id=a.account_id AND m.room_id=?4 AND m.message_id=?5 AND m.deleted=1)",params![account,chat,id,room,message],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?.ok_or(Error::NotFound)
    }
    fn drawer_eligibility(
        &self,
        account: &str,
        item: &mut Attachment,
        source: &str,
        sent: i64,
    ) -> Result<bool> {
        let seconds: Option<i64> = self
            .lock()?
            .query_row(
                "SELECT CAST(value AS INTEGER) FROM metadata WHERE key=?1",
                [format!("media_expiry_seconds:{account}")],
                |r| r.get(0),
            )
            .optional()?;
        let now = chrono::Utc::now().timestamp_millis();
        let expired = item.expires_at_ms.is_some_and(|t| t > 0 && t < now)
            || seconds.is_some_and(|t| t >= 0 && now > sent.saturating_add(t.saturating_mul(1000)));
        let eligible = source == "native_drawer"
            && expired
            && item.unavailable_reason.is_none_or(|r| r == "expired")
            && item.token.as_deref().is_some_and(valid_token)
            && item.size.is_none_or(|n| n <= MAX_DOWNLOAD)
            && self.native_flag("activated")? == Some(true);
        if eligible {
            item.available = true;
            item.unavailable_reason = None;
        }
        Ok(eligible)
    }
    pub fn download_plan(
        &self,
        account: &str,
        room: &str,
        message: &str,
        index: usize,
    ) -> Result<DownloadPlan> {
        let (kind, raw, source, revision, sent) = self.media_raw(account, room, message)?;
        let mut attachment = parse(kind, &raw, chrono::Utc::now().timestamp_millis())?
            .into_iter()
            .find(|a| a.index == index)
            .ok_or(Error::NotFound)?;
        let drawer = self.drawer_eligibility(account, &mut attachment, &source, sent)?;
        if let Some(reason) = attachment.unavailable_reason {
            return Err(Error::Unavailable(reason));
        }
        Ok(DownloadPlan {
            attachment,
            drawer,
            fingerprint: hex::encode(Sha256::digest(serde_json::to_vec(&(
                kind, revision, source, raw,
            ))?)),
        })
    }
}
fn valid_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 4096
        && token
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"/-_.".contains(&c))
        && !token.split('/').any(|s| s == "." || s == "..")
        && !token.starts_with("//")
}

// A short-lived, private DB mailbox crosses the API/collector process boundary.
// It contains references and token IDs, never API secrets or caller-supplied URLs.
#[derive(Serialize, Deserialize)]
pub(crate) struct RelayJob {
    pub account: String,
    pub room: String,
    pub message: String,
    pub index: usize,
    pub credential: String,
    pub fingerprint: String,
    pub expires: i64,
    pub endpoint: Option<(String, u16)>,
    pub failed: bool,
}
impl RelayJob {
    pub(crate) fn authorize(&self, store: &Store) -> Result<DownloadPlan> {
        use crate::auth::Scope;
        let now = chrono::Utc::now().timestamp();
        if now >= self.expires {
            return Err(Error::Unauthorized);
        }
        let valid = store.token_list()?.into_iter().any(|p| {
            p.id == self.credential
                && p.account_id == self.account
                && p.revoked_at.is_none()
                && p.expires_at > now
                && p.scopes.contains(&Scope::Attachments)
                && p.scopes.contains(&Scope::Messages)
                && p.rooms.is_none_or(|r| r.contains(&self.room))
        });
        if !valid {
            return Err(Error::Unauthorized);
        }
        let plan = store.download_plan(&self.account, &self.room, &self.message, self.index)?;
        if plan.fingerprint != self.fingerprint {
            return Err(Error::NotFound);
        }
        Ok(plan)
    }
}
impl Store {
    fn drawer_download_base(&self) -> Result<String> {
        let conn = self.lock()?;
        let mut stmt=conn.prepare("SELECT payload FROM native_events WHERE source='bootstrap_http' ORDER BY sequence DESC LIMIT 64")?;
        for row in stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))? {
            let Ok(value) = serde_json::from_slice::<Value>(&row?) else {
                continue;
            };
            if let Some(raw) = value.get("downloadBaseUrl").and_then(Value::as_str) {
                let url = url::Url::parse(raw)
                    .map_err(|_| Error::Unavailable("drawer_download_config"))?;
                if url.scheme() != "https"
                    || url.host_str() != Some("drawer-cdn.kakao.com")
                    || !url.username().is_empty()
                    || url.password().is_some()
                    || url.port_or_known_default() != Some(443)
                    || url.query().is_some()
                    || url.fragment().is_some()
                    || !url.path().starts_with("/dnd/drawer/media_file")
                    || !valid_token(url.path())
                {
                    return Err(Error::Unavailable("drawer_download_config"));
                }
                // Normalize the configured download base to end with a slash.
                return Ok(format!("{}/", raw.trim_end_matches('/')));
            }
        }
        Ok("https://drawer-cdn.kakao.com/dnd/drawer/media_file".into())
    }
    pub(crate) fn relay_next(&self, account: &str) -> Result<Option<(String, RelayJob)>> {
        let conn = self.lock()?;
        conn.execute("DELETE FROM metadata WHERE key LIKE 'relay_job:%' AND CAST(json_extract(value,'$.expires') AS INTEGER)<=?1",[chrono::Utc::now().timestamp()])?;
        let mut stmt=conn.prepare("SELECT key,value FROM metadata WHERE key LIKE 'relay_job:%' AND json_extract(value,'$.account')=?1 AND json_extract(value,'$.endpoint') IS NULL AND json_extract(value,'$.failed')=0 ORDER BY key LIMIT 1")?;
        let raw: Option<(String, String)> = stmt
            .query_row([account], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?;
        raw.map(|(key, value)| Ok((key, serde_json::from_str(&value)?)))
            .transpose()
    }
    pub(crate) fn relay_finish(&self, key: &str, job: &RelayJob) -> Result<()> {
        self.lock()?.execute(
            "UPDATE metadata SET value=?2 WHERE key=?1",
            params![key, serde_json::to_string(job)?],
        )?;
        Ok(())
    }
}
struct Mailbox {
    store: Store,
    key: String,
}
impl Drop for Mailbox {
    fn drop(&mut self) {
        if let Ok(conn) = self.store.lock() {
            let _ = conn.execute("DELETE FROM metadata WHERE key=?1", [&self.key]);
        }
    }
}
pub(crate) enum Content {
    Http {
        response: reqwest::Response,
        expected: Option<u64>,
        bytes: u64,
    },
    Relay {
        connection: crate::loco::transport::Connection,
        remaining: u64,
    },
}
impl Content {
    pub(crate) async fn chunk(&mut self) -> Result<Option<axum::body::Bytes>> {
        match self {
            Self::Http {
                response,
                expected,
                bytes,
            } => {
                let chunk = response
                    .chunk()
                    .await
                    .map_err(|_| Error::Unavailable("download_interrupted"))?;
                if let Some(chunk) = &chunk {
                    *bytes += chunk.len() as u64;
                    if *bytes > MAX_DOWNLOAD || expected.is_some_and(|n| *bytes > n) {
                        return Err(Error::Unavailable("download_length_mismatch"));
                    }
                } else if expected.is_some_and(|n| *bytes != n) {
                    return Err(Error::Unavailable("download_length_mismatch"));
                }
                Ok(chunk)
            }
            Self::Relay {
                connection,
                remaining,
            } => {
                if *remaining == 0 {
                    return Ok(None);
                }
                let bytes = connection
                    .raw_chunk(*remaining)
                    .await
                    .map_err(|_| Error::Unavailable("download_interrupted"))?;
                *remaining -= bytes.len() as u64;
                Ok(Some(bytes.into()))
            }
        }
    }
}
pub(crate) async fn open(store: &Store, job: RelayJob, plan: &DownloadPlan) -> Result<Content> {
    use std::time::Duration;
    job.authorize(store)?;
    let session = store.session_load()?;
    if session.user_id().to_string() != job.account {
        return Err(Error::Forbidden);
    }
    let client = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .no_gzip()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .connect_timeout(Duration::from_secs(15))
        .read_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(600))
        .build()
        .map_err(|_| Error::Unavailable("download_transport"))?;
    let url = if plan.drawer {
        let token = plan
            .attachment
            .token
            .as_deref()
            .filter(|t| valid_token(t))
            .ok_or(Error::Unavailable("attachment_token_invalid"))?;
        Some(format!("{}{token}", store.drawer_download_base()?))
    } else {
        plan.attachment.url.clone().filter(|u| allowed_url(u))
    };
    if let Some(url) = url {
        let mut request = client
            .get(&url)
            .header(
                "User-Agent",
                format!("KT/26.3.2 An/{} ko", session.wire.os_version()),
            )
            .header("Accept-Language", "ko");
        if plan.drawer {
            let mut auth = reqwest::header::HeaderValue::from_str(&format!(
                "MALDIVE {}-{}",
                session.access_token.as_str(),
                session.wire.uuid()
            ))
            .map_err(|_| Error::Unavailable("download_credentials"))?;
            auth.set_sensitive(true);
            request = request
                .header("A", "android/26.3.2/ko")
                .header("Authorization", auth);
        }
        if let Ok(response) = request.send().await {
            if response.status() == reqwest::StatusCode::OK {
                if response.content_length().is_some_and(|s| s > MAX_DOWNLOAD) {
                    return Err(Error::Unavailable("download_too_large"));
                }
                let expected = plan
                    .attachment
                    .size
                    .filter(|s| *s > 0)
                    .or(response.content_length());
                if matches!((expected,response.content_length()),(Some(a),Some(b)) if a!=b) {
                    return Err(Error::Unavailable("download_length_mismatch"));
                }
                return Ok(Content::Http {
                    response,
                    expected,
                    bytes: 0,
                });
            }
        }
        if plan.drawer {
            return Err(Error::Unavailable("download_unavailable"));
        }
    }
    let token = plan
        .attachment
        .token
        .as_deref()
        .ok_or(Error::Unavailable("relay_required"))?;
    let key = format!("relay_job:{}", uuid::Uuid::new_v4());
    store.lock()?.execute(
        "INSERT INTO metadata(key,value) VALUES(?1,?2)",
        params![key, serde_json::to_string(&job)?],
    )?;
    let mailbox = Mailbox {
        store: store.clone(),
        key,
    };
    let endpoint = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let raw: String = store.lock()?.query_row(
                "SELECT value FROM metadata WHERE key=?1",
                [&mailbox.key],
                |r| r.get(0),
            )?;
            let reply: RelayJob = serde_json::from_str(&raw)?;
            if reply.failed {
                return Err(Error::Unavailable("relay_unavailable"));
            }
            if let Some(endpoint) = reply.endpoint {
                return Ok(endpoint);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .map_err(|_| Error::Unavailable("collector_unavailable"))??;
    drop(mailbox);
    job.authorize(store)?;
    let mut connection = crate::loco::transport::Connection::discovered(&endpoint.0, endpoint.1)
        .await
        .map_err(|_| Error::Unavailable("relay_connect"))?;
    job.authorize(store)?;
    let packet=crate::loco::codec::Packet::request(1,"DOWN",bson::doc!{"u":session.user_id(),"k":token,"o":0_i64,"mm":"","nt":0,"os":"android","av":"26.3.2","c":job.room.parse::<i64>().map_err(|_|Error::NotFound)?,"rt":false}).map_err(|_|Error::Unavailable("relay_request"))?;
    let response = connection
        .exchange(&packet)
        .await
        .map_err(|_| Error::Unavailable("relay_transport"))?;
    if response.header.status != 0 {
        return Err(Error::Unavailable("relay_unavailable"));
    }
    let size = response
        .body
        .get_i32("s")
        .ok()
        .filter(|s| *s > 0)
        .ok_or(Error::Unavailable("relay_response"))? as u64;
    if response.header.status != 0
        || size > MAX_DOWNLOAD
        || plan.attachment.size.is_some_and(|s| s > 0 && s != size)
    {
        return Err(Error::Unavailable("relay_response"));
    }
    Ok(Content::Relay {
        connection,
        remaining: size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn metadata_changes_invalidate_download_jobs_and_equal_revision_removal() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let store = Store::initialize(dir.path()).unwrap();
        store
            .capture_native(
                "bootstrap_http",
                br#"{"downloadBaseUrl":"https://drawer-cdn.kakao.com/dnd/drawer/media_file/v1"}"#,
            )
            .unwrap();
        assert_eq!(
            store.drawer_download_base().unwrap(),
            "https://drawer-cdn.kakao.com/dnd/drawer/media_file/v1/"
        );
        store
            .capture_native(
                "bootstrap_http",
                br#"{"downloadBaseUrl":"https://example.invalid/dnd/drawer/media_file/v1"}"#,
            )
            .unwrap();
        assert!(store.drawer_download_base().is_err());
        let credential = store
            .token_issue(
                "test".into(),
                "42".into(),
                [
                    crate::auth::Scope::Messages,
                    crate::auth::Scope::Attachments,
                ]
                .into_iter()
                .collect(),
                None,
                chrono::Utc::now().timestamp() + 3600,
                chrono::Utc::now().timestamp(),
            )
            .unwrap();
        let log = bson::doc! {"attachment":r#"{"k":"synthetic/token","s":3}"#,"sendAt":1700000000,"authorId":43_i64};
        {
            let mut conn = store.lock().unwrap();
            let tx = conn.transaction().unwrap();
            capture(&tx, "42", 7, 100, 0, 2, &log).unwrap();
            tx.commit().unwrap();
        }
        let plan = store.download_plan("42", "7", "100", 0).unwrap();
        let job = RelayJob {
            account: "42".into(),
            room: "7".into(),
            message: "100".into(),
            index: 0,
            credential: credential.metadata.id,
            fingerprint: plan.fingerprint,
            expires: chrono::Utc::now().timestamp() + 60,
            endpoint: None,
            failed: false,
        };
        assert!(job.authorize(&store).is_ok());
        store
            .lock()
            .unwrap()
            .execute("UPDATE message_media SET revision=1", [])
            .unwrap();
        assert!(job.authorize(&store).is_err());
        {
            let mut conn = store.lock().unwrap();
            let tx = conn.transaction().unwrap();
            capture(&tx, "42", 7, 100, 1, 1, &bson::doc! {}).unwrap();
            tx.commit().unwrap();
        }
        assert!(matches!(
            store.attachments("42", "7", "100"),
            Err(Error::NotFound)
        ));
    }
    #[tokio::test]
    async fn http_clean_eof_must_match_expected_length() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            let received = stream.read(&mut request).await.unwrap();
            assert!(received > 0);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc")
                .await
                .unwrap();
        });
        let response = reqwest::Client::new()
            .get(format!("http://{addr}"))
            .send()
            .await
            .unwrap();
        let mut content = Content::Http {
            response,
            expected: Some(10),
            bytes: 0,
        };
        assert_eq!(content.chunk().await.unwrap().unwrap().as_ref(), b"abc");
        assert!(content.chunk().await.is_err());
        task.await.unwrap();
    }
    #[test]
    fn oversized_expired_media_and_unsafe_drawer_tokens_are_rejected() {
        let items = parse(
            2,
            &serde_json::json!({"expire":1,"s":MAX_DOWNLOAD+1,"k":"safe/token"}).to_string(),
            2,
        )
        .unwrap();
        assert_eq!(items[0].unavailable_reason, Some("download_too_large"));
        for token in ["//other/host", "/../secret", "x?y", "x#z", "%2e%2e", "a\\b"] {
            assert!(!valid_token(token));
        }
    }
    #[test]
    fn explicit_hosts_and_multi_image_indices_preserve_missing_entries() {
        for url in [
            "http://dn.talk.kakao.com/f",
            "https://dn.talk.kakao.com.evil.test/f",
            "https://user@dn.talk.kakao.com/f",
            "https://127.0.0.1/f",
            "https://dn.talk.kakao.com:8443/f",
            "relay://x",
        ] {
            assert!(!allowed_url(url))
        }
        assert!(allowed_url("https://dn.talk.kakao.com/f?token=synthetic"));
        let items=parse(27,r#"{"wl":[10,20,30],"imageUrls":["https://dn.talk.kakao.com/a","","https://dn.talk.kakao.com/c"],"sl":[1,2,3]}"#,0).unwrap();
        assert_eq!(items.len(), 3);
        assert!(!items[1].available);
        assert_eq!(items[2].index, 2);
        assert!(!serde_json::to_string(&items).unwrap().contains("https://"));
        assert_eq!(
            parse(2, r#"{"url":"https://dn.talk.kakao.com/a","csk":{}}"#, 0).unwrap()[0]
                .unavailable_reason,
            Some("encrypted_media_unsupported")
        );
    }
}
