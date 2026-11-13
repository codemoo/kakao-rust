//! Authenticated queries, text sends and on-demand media transfers. No payload logging.
use crate::{
    auth::{Principal, Scope},
    Error, Result, Store,
};
use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::get,
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rusqlite::{named_params, Row};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;

#[derive(Clone)]
struct ApiState {
    store: Store,
    capacity: Arc<Semaphore>,
    sse_capacity: Arc<Semaphore>,
    download_capacity: Arc<Semaphore>,
    rates: Arc<Mutex<HashMap<String, (Instant, u32)>>>,
}

pub fn router(store: Store) -> Router {
    Router::new()
        .route("/v1/status", get(status))
        .route("/v1/events", get(events))
        .route("/v1/rooms", get(rooms))
        .route("/v1/rooms/{id}/members", get(members))
        .route("/v1/rooms/{id}/gaps", get(gaps))
        .route(
            "/v1/rooms/{id}/messages",
            get(messages)
                .post(send_text)
                .layer(DefaultBodyLimit::max(64 * 1024)),
        )
        .route("/v1/rooms/{id}/outgoing/{request_id}", get(outgoing_status))
        .route("/v1/messages", get(all_messages))
        .route("/v1/rooms/{id}/messages/{message_id}", get(single_message))
        .route("/v1/search", get(search))
        .route("/v1/friends", get(friends))
        .route("/v1/blocked-users", get(blocked_users))
        .route("/v1/attachments", get(attachment_messages))
        .route(
            "/v1/rooms/{id}/messages/{message_id}/attachments",
            get(attachments),
        )
        .route(
            "/v1/rooms/{id}/messages/{message_id}/attachments/{index}/content",
            get(attachment_content),
        )
        .fallback(|| async { Error::NotFound })
        .method_not_allowed_fallback(|| async { Error::MethodNotAllowed })
        .layer(middleware::from_fn(no_store))
        .with_state(ApiState {
            store,
            capacity: Arc::new(Semaphore::new(32)),
            sse_capacity: Arc::new(Semaphore::new(8)),
            download_capacity: Arc::new(Semaphore::new(2)),
            rates: Arc::new(Mutex::new(HashMap::new())),
        })
}
async fn no_store(request: axum::extract::Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}
async fn run<T, F>(
    state: ApiState,
    headers: HeaderMap,
    scope: Scope,
    function: F,
) -> Result<Json<T>>
where
    T: Serialize + Send + 'static,
    F: FnOnce(&Store, Principal) -> Result<T> + Send + 'static,
{
    // Bound waiting work; no tasks queue indefinitely behind the single SQLite writer.
    let permit = state
        .capacity
        .try_acquire_owned()
        .map_err(|_| Error::Busy)?;
    let mut authorization = headers.get_all(header::AUTHORIZATION).iter();
    let value = authorization.next().ok_or(Error::Unauthorized)?;
    if authorization.next().is_some() {
        return Err(Error::Unauthorized);
    }
    let token = value
        .to_str()
        .ok()
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or(Error::Unauthorized)?
        .to_string();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let principal = state
            .store
            .authenticate(&token, chrono::Utc::now().timestamp())?;
        principal.require(scope)?;
        {
            let mut rates = state.rates.lock().map_err(|_| Error::Worker)?;
            rates.retain(|_, (start, _)| start.elapsed() < Duration::from_secs(60));
            if rates.len() >= 10_000 && !rates.contains_key(&principal.credential_id) {
                return Err(Error::Busy);
            }
            let (_, requests) = rates
                .entry(principal.credential_id.clone())
                .or_insert((Instant::now(), 0));
            if *requests >= 120 {
                return Err(Error::Busy);
            }
            *requests += 1;
        }
        function(&state.store, principal).map(Json)
    })
    .await
    .map_err(|_| Error::Worker)?
}
async fn status(State(state): State<ApiState>, headers: HeaderMap) -> Result<Json<Value>> {
    run(state, headers, Scope::Status, |store, principal| {
        let live=store.live_status(&principal.account_id)?;
        let maintenance=store.maintenance_status(&principal.account_id)?;
        let conn=store.lock()?;
        let native_rows:i64=conn.query_row("SELECT EXISTS(SELECT 1 FROM sync_cursors WHERE account_id=?1 AND source='native_loco')",[&principal.account_id],|r|r.get(0))?;
        let drawer_rows:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM drawer_records WHERE account_id=?1)",[&principal.account_id],|r|r.get(0))?;
        let source=if native_rows>0 || drawer_rows {"native_partial"} else {"offline_import"};
        Ok(json!({
            "native_auth":{"state":if live.connected {"connected"} else {"not_connected"},"qr_authorization":"experimental","password_authorization":"experimental","bootstrap_implemented":false,"verified":false},
            "source":source, "live_connected":live.connected,"collector":live,"maintenance":maintenance,
            "history_coverage":if native_rows>0 {"native_text_projection_partial"} else if drawer_rows {"drawer_history_partial"} else {"caller_supplied_only_unverified"},
            "capabilities":{"text_messages":true,"revisions":true,"terminal_tombstones":true,
                "search":"case_sensitive_unicode_substring",
                "search_index":"fts5_case_sensitive_trigram",
                "search_short_terms":"bounded_scan_under_3_non_nul_unicode_characters","sse":true,"native_sync":true,"native_sync_scope":"text_and_replies_raw_inbox_for_other_types",
                "text_sending":"ordinary_short_text", "attachments":"on_demand","members":"roster_with_coverage","pagination":"ascending_keyset_no_snapshot",
                "request_limit_per_credential_per_minute":120,"max_concurrent_requests":32,"search_timeout_seconds":2}
        }))
    })
    .await
}

/// Message change metadata only. Consumers fetch authorized message content
/// separately; long-lived streams revalidate expiration/revocation every batch.
async fn events(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<
    axum::response::Sse<
        impl futures_util::Stream<
            Item = std::result::Result<axum::response::sse::Event, std::convert::Infallible>,
        >,
    >,
> {
    let _ = run(state.clone(), headers.clone(), Scope::Messages, |_, _| {
        Ok(())
    })
    .await?;
    let permit = state
        .sse_capacity
        .clone()
        .try_acquire_owned()
        .map_err(|_| Error::Busy)?;
    let token = zeroize::Zeroizing::new(
        headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(Error::Unauthorized)?
            .to_owned(),
    );
    let after = match headers.get("Last-Event-ID") {
        None => 0,
        Some(value) => value
            .to_str()
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .filter(|v| *v >= 0)
            .ok_or_else(|| Error::Invalid("invalid event cursor".into()))?,
    };
    struct StreamState {
        store: Store,
        token: zeroize::Zeroizing<String>,
        after: i64,
        _permit: tokio::sync::OwnedSemaphorePermit,
    }
    let stream = futures_util::stream::unfold(
        StreamState {
            store: state.store,
            token,
            after,
            _permit: permit,
        },
        |mut state| async move {
            loop {
                let store = state.store.clone();
                let token = state.token.clone();
                let after = state.after;
                let result=tokio::task::spawn_blocking(move || -> Result<(i64,Option<Value>)> {
                    let principal=store.authenticate(&token,chrono::Utc::now().timestamp())?;
                    principal.require(Scope::Messages)?;
                    let conn=store.lock()?;
                    // Bound BEFORE room filtering; use outbox_account index.
                    let mut statement=conn.prepare("SELECT sequence,room_id,entity_id,kind,revision,source FROM outbox WHERE account_id=:account AND sequence>:after ORDER BY sequence LIMIT 128")?;
                    let mut rows=statement.query(named_params!{":account":principal.account_id,":after":after})?;
                    let mut scanned=after;
                    while let Some(row)=rows.next()? {
                        scanned=row.get(0)?;
                        let room:Option<String>=row.get(1)?;
                        let kind:String=row.get(3)?;
                        if let Some(room)=room.filter(|room|principal.allows_room(room)) {
                            if matches!(kind.as_str(),"message_upserted"|"message_deleted"|"message_projection_removed") {
                                return Ok((scanned,Some(json!({"room_id":room,"message_id":row.get::<_,String>(2)?,"kind":kind,"revision":row.get::<_,i64>(4)?,"source":row.get::<_,String>(5)?}))));
                            }
                        }
                    }
                    Ok((scanned,None))
                }).await;
                match result {
                    Ok(Ok((sequence, Some(value)))) => {
                        state.after = sequence;
                        let event = axum::response::sse::Event::default()
                            .id(sequence.to_string())
                            .event("message_changed")
                            .json_data(value)
                            .ok()?;
                        return Some((Ok(event), state));
                    }
                    Ok(Ok((scanned, None))) => {
                        state.after = scanned;
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                    _ => return None,
                }
            }
        },
    );
    Ok(axum::response::Sse::new(stream)
        .keep_alive(axum::response::sse::KeepAlive::new().interval(Duration::from_secs(15))))
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PageQuery {
    cursor: Option<String>,
    limit: Option<usize>,
}
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct MessageQuery {
    q: Option<String>,
    room_id: Option<String>,
    sender_id: Option<String>,
    from_ms: Option<i64>,
    to_ms: Option<i64>,
    cursor: Option<String>,
    limit: Option<usize>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    version: u8,
    route: String,
    account_id: String,
    filter_hash: String,
    last: Vec<String>,
}
fn limit(limit: Option<usize>) -> Result<usize> {
    match limit.unwrap_or(50) {
        n @ 1..=200 => Ok(n),
        _ => Err(Error::Invalid("limit must be 1..200".into())),
    }
}
fn filter_hash(value: &impl Serialize) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}
fn decode_cursor(
    raw: Option<&str>,
    route: &str,
    account: &str,
    filter: &str,
    fields: usize,
) -> Result<Option<Vec<String>>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    if raw.len() > 4096 {
        return Err(Error::Invalid("cursor too long".into()));
    }
    let data = URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|_| Error::Invalid("invalid cursor encoding".into()))?;
    let cursor: Cursor =
        serde_json::from_slice(&data).map_err(|_| Error::Invalid("invalid cursor".into()))?;
    if cursor.version != 1
        || cursor.route != route
        || cursor.account_id != account
        || cursor.filter_hash != filter
        || cursor.last.len() != fields
    {
        return Err(Error::Invalid(
            "cursor does not match this query/account".into(),
        ));
    }
    for field in &cursor.last {
        crate::error::valid_id(field, "cursor field")?;
    }
    Ok(Some(cursor.last))
}
fn page(
    mut items: Vec<Value>,
    n: usize,
    route: &str,
    account: &str,
    filter: &str,
    keys: &[&str],
) -> Result<Value> {
    let more = items.len() > n;
    items.truncate(n);
    let next = if more {
        let item = items.last().ok_or(Error::Worker)?;
        let last = keys
            .iter()
            .map(|key| match &item[*key] {
                Value::String(v) => Ok(v.clone()),
                Value::Number(v) => Ok(v.to_string()),
                _ => Err(Error::Worker),
            })
            .collect::<Result<Vec<_>>>()?;
        Some(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&Cursor {
            version: 1,
            route: route.into(),
            account_id: account.into(),
            filter_hash: filter.into(),
            last,
        })?))
    } else {
        None
    };
    Ok(json!({"items":items,"next_cursor":next}))
}
fn invalid_query(_: axum::extract::rejection::QueryRejection) -> Error {
    Error::Invalid("invalid query parameters".into())
}

async fn rooms(
    State(state): State<ApiState>,
    headers: HeaderMap,
    query: std::result::Result<Query<PageQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<Value>> {
    let Query(query) = query.map_err(invalid_query)?;
    let n = limit(query.limit)?;
    run(state,headers,Scope::Rooms,move |store,p| {
        let cursor = decode_cursor(query.cursor.as_deref(),"rooms",&p.account_id,"",1)?;
        let after = cursor.as_ref().map(|v| v[0].as_str());
        let acl = p.rooms_json()?;
        let connection = store.lock()?;
        let mut stmt = connection.prepare("SELECT room_id,display_name,name_source,observed_at_ms,source,EXISTS(SELECT 1 FROM messages m WHERE m.account_id=rooms.account_id AND m.room_id=rooms.room_id AND m.source IN ('native_drawer','native_loco')) FROM rooms WHERE account_id=:account AND (:acl IS NULL OR room_id IN (SELECT value FROM json_each(:acl))) AND (:after IS NULL OR room_id>:after) ORDER BY room_id LIMIT :limit")?;
        let items = stmt.query_map(named_params!{":account":p.account_id,":acl":acl,":after":after,":limit":(n+1) as i64}, |r| Ok(json!({"room_id":r.get::<_,String>(0)?,"display_name":r.get::<_,Option<String>>(1)?,"name_source":r.get::<_,Option<String>>(2)?,"observed_at_ms":r.get::<_,Option<i64>>(3)?,"source":r.get::<_,String>(4)?,"coverage":if r.get::<_,bool>(5)? {"native_partial"} else {"caller_supplied_only_unverified"},"sync_state":if r.get::<_,bool>(5)? {"stored_history"} else {"offline_import"}})))?.collect::<std::result::Result<Vec<_>,_>>()?;
        page(items,n,"rooms",&p.account_id,"",&["room_id"])
    }).await
}
struct QueryBudget<'a>(&'a rusqlite::Connection);
impl<'a> QueryBudget<'a> {
    fn new(connection: &'a rusqlite::Connection) -> Self {
        let started = Instant::now();
        connection.progress_handler(
            1000,
            Some(move || started.elapsed() > Duration::from_secs(2)),
        );
        Self(connection)
    }
}
impl Drop for QueryBudget<'_> {
    fn drop(&mut self) {
        self.0.progress_handler(0, None::<fn() -> bool>);
    }
}
fn message_row(r: &Row<'_>) -> rusqlite::Result<Value> {
    Ok(
        json!({"room_id":r.get::<_,String>(0)?,"message_id":r.get::<_,String>(1)?,"revision":r.get::<_,i64>(2)?,"sent_at_ms":r.get::<_,i64>(3)?,"sender_id":r.get::<_,Option<String>>(4)?,"body":r.get::<_,Option<String>>(5)?,"source":r.get::<_,String>(6)?,"source_local_pk":r.get::<_,Option<String>>(7)?,"sender_name":r.get::<_,Option<String>>(8)?,"sender_name_source":r.get::<_,Option<String>>(9)?,"sender_name_observed_at_ms":r.get::<_,Option<i64>>(10)?}),
    )
}
fn cursor_time(cursor: &Option<Vec<String>>) -> Result<Option<i64>> {
    cursor
        .as_ref()
        .map(|v| {
            v[0].parse::<i64>()
                .ok()
                .filter(|t| *t >= 0)
                .ok_or_else(|| Error::Invalid("invalid cursor time".into()))
        })
        .transpose()
}
async fn messages(
    State(state): State<ApiState>,
    Path(room): Path<String>,
    headers: HeaderMap,
    query: std::result::Result<Query<MessageQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<Value>> {
    let Query(mut query) = query.map_err(invalid_query)?;
    if query.room_id.as_ref().is_some_and(|id| id != &room) {
        return Err(Error::Invalid("room filter conflicts with path".into()));
    }
    query.room_id = Some(room);
    query_messages(state, headers, query, "room_messages", true).await
}
async fn all_messages(
    State(state): State<ApiState>,
    headers: HeaderMap,
    query: std::result::Result<Query<MessageQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<Value>> {
    query_messages(
        state,
        headers,
        query.map_err(invalid_query)?.0,
        "messages",
        false,
    )
    .await
}
async fn single_message(
    State(state): State<ApiState>,
    Path((room, message)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<Value>> {
    crate::error::valid_id(&room, "room ID")?;
    crate::error::valid_id(&message, "message ID")?;
    run(state, headers, Scope::Messages, move |store, p| {
        p.require_room(&room)?;
        let conn = store.lock()?;
        let sql = format!("SELECT {MESSAGE_FIELDS} FROM messages m {FRIEND_JOIN} WHERE m.account_id=:account AND m.room_id=:room AND m.message_id=:message AND m.deleted=0");
        let mut stmt = conn.prepare(&sql)?;
        let item = stmt.query_row(named_params!{":account":p.account_id, ":room":room, ":message":message, ":names":p.scopes.contains(&Scope::Friends)}, message_row);
        match item {
            Err(rusqlite::Error::QueryReturnedNoRows) => Err(Error::NotFound),
            result => Ok(result?),
        }
    }).await
}
const FRIEND_JOIN: &str =
    "LEFT JOIN room_identity_context rc ON rc.account_id=m.account_id AND CAST(rc.chat_id AS TEXT)=m.room_id LEFT JOIN friends f ON :names AND (rc.room_type NOT IN ('OD','OM') OR (rc.room_type IS NULL AND m.source='offline_import')) AND f.account_id=m.account_id AND f.user_id=m.sender_id LEFT JOIN room_members rm ON :names AND rm.account_id=m.account_id AND CAST(rm.chat_id AS TEXT)=m.room_id AND CAST(rm.user_id AS TEXT)=m.sender_id AND ((rc.room_type IS NULL AND m.source='offline_import') OR EXISTS(SELECT 1 FROM room_member_origins ro WHERE ro.account_id=rm.account_id AND ro.chat_id=rm.chat_id AND ro.user_id=rm.user_id AND ro.room_type=rc.room_type AND ro.link_id=rc.link_id AND (rc.room_type NOT IN ('OD','OM') OR rc.link_id>0)))";
const MESSAGE_FIELDS: &str = "m.room_id,m.message_id,m.revision,m.sent_at_ms,m.sender_id,m.body,m.source,m.source_local_pk,coalesce(f.display_name,rm.nickname),CASE WHEN f.display_name IS NOT NULL THEN f.name_source WHEN rm.nickname IS NOT NULL THEN CASE WHEN rc.room_type IN ('OD','OM') THEN 'kakao_open_profile' ELSE 'kakao_room_member' END ELSE NULL END,coalesce(f.observed_at_ms,rm.updated_at_ms)";
// Trigrams count Unicode scalar values, not UTF-8 bytes. SQLite's tokenizer
// skips NULs, so remove them from the candidate only; instr still checks the
// original exact literal. Terms with fewer than three indexed characters use
// the same two-second budget as indexed searches.
fn search_candidate(query: &str) -> Option<String> {
    let text = query.replace('\0', "");
    (text.chars().count() >= 3).then(|| format!("\"{}\"", text.replace('"', "\"\"")))
}
fn search_sql(indexed: bool) -> String {
    // CROSS JOIN fixes the loop order: visit MATCH candidates then fetch each
    // canonical row by rowid, instead of scanning an account's entire history.
    let source = if indexed {
        "(SELECT rowid FROM message_text WHERE message_text MATCH :match) AS hits CROSS JOIN messages AS m ON m.rowid=hits.rowid"
    } else {
        "messages AS m"
    };
    let match_guard = if indexed {
        ":match IS NOT NULL"
    } else {
        ":match IS NULL"
    };
    format!("SELECT {MESSAGE_FIELDS} FROM {source} {FRIEND_JOIN} WHERE {match_guard} AND m.account_id=:account AND m.deleted=0 AND (:acl IS NULL OR m.room_id IN (SELECT value FROM json_each(:acl))) AND (:room IS NULL OR m.room_id=:room) AND (:sender IS NULL OR m.sender_id=:sender) AND (:from IS NULL OR m.sent_at_ms>=:from) AND (:to IS NULL OR m.sent_at_ms<=:to) AND (:query IS NULL OR instr(m.body,:query)>0) AND (:time IS NULL OR (m.sent_at_ms,m.room_id,m.message_id)>(:time,:after_room,:id)) ORDER BY m.sent_at_ms,m.room_id,m.message_id LIMIT :limit")
}
async fn search(
    State(state): State<ApiState>,
    headers: HeaderMap,
    query: std::result::Result<Query<MessageQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<Value>> {
    let query = query.map_err(invalid_query)?.0;
    if query.q.is_none() {
        return Err(Error::Invalid("search requires q".into()));
    }
    query_messages(state, headers, query, "search", false).await
}
async fn query_messages(
    state: ApiState,
    headers: HeaderMap,
    query: MessageQuery,
    route: &'static str,
    require_room: bool,
) -> Result<Json<Value>> {
    let n = limit(query.limit)?;
    if query
        .q
        .as_ref()
        .is_some_and(|q| q.is_empty() || q.len() > 1024)
        || query.from_ms.is_some_and(|t| t < 0)
        || query.to_ms.is_some_and(|t| t < 0)
        || matches!((query.from_ms,query.to_ms),(Some(a),Some(b)) if a>b)
    {
        return Err(Error::Invalid(
            "query must be 1..1024 bytes with a valid inclusive time range".into(),
        ));
    }
    if let Some(id) = &query.room_id {
        crate::error::valid_id(id, "room ID")?;
    }
    if let Some(id) = &query.sender_id {
        crate::error::valid_id(id, "sender ID")?;
    }
    run(state,headers,Scope::Messages,move |store,p| {
        if let Some(room)=&query.room_id { p.require_room(room)?; }
        let filter = filter_hash(&(&query.q,&query.room_id,&query.sender_id,query.from_ms,query.to_ms))?;
        let cursor = decode_cursor(query.cursor.as_deref(),route,&p.account_id,&filter,3)?;
        let after_time = cursor_time(&cursor)?;
        let after_room = cursor.as_ref().map(|v| v[1].as_str());
        let after_id = cursor.as_ref().map(|v| v[2].as_str());
        let acl = p.rooms_json()?;
        let connection = store.lock()?;
        let _budget = QueryBudget::new(&connection);
        if require_room {
            let exists: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM rooms WHERE account_id=?1 AND room_id=?2)", rusqlite::params![p.account_id,query.room_id], |r| r.get(0))?;
            if !exists { return Err(Error::NotFound); }
        }
        let candidate = query.q.as_deref().and_then(search_candidate);
        let mut stmt = connection.prepare(&search_sql(candidate.is_some()))?;
        let items = stmt.query_map(named_params!{":account":p.account_id,":acl":acl,":room":query.room_id,":sender":query.sender_id,":from":query.from_ms,":to":query.to_ms,":query":query.q,":match":candidate,":time":after_time,":after_room":after_room,":id":after_id,":limit":(n+1) as i64,":names":p.scopes.contains(&Scope::Friends)},message_row)?.collect::<std::result::Result<Vec<_>,_>>()?;
        page(items,n,route,&p.account_id,&filter,&["sent_at_ms","room_id","message_id"])
    }).await
}
async fn friends(
    State(state): State<ApiState>,
    headers: HeaderMap,
    query: std::result::Result<Query<PageQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<Value>> {
    let Query(query) = query.map_err(invalid_query)?;
    let n = limit(query.limit)?;
    run(state,headers,Scope::Friends,move |store,p| {
        if p.rooms.is_some() { return Err(Error::Forbidden); }
        let cursor = decode_cursor(query.cursor.as_deref(),"friends",&p.account_id,"",1)?;
        let after = cursor.as_ref().map(|v| v[0].as_str());
        let connection=store.lock()?;
        let mut stmt=connection.prepare("SELECT f.user_id,f.display_name,f.name_source,f.observed_at_ms,f.source,n.relation,n.is_channel,n.profile_name,n.friend_name,n.hidden,n.purged,n.is_current,ff.favorite,CASE WHEN EXISTS(SELECT 1 FROM blocked_users b WHERE b.account_id=f.account_id AND b.user_id=f.user_id AND (n.is_channel IS NULL OR b.is_channel=n.is_channel)) THEN 1 WHEN n.is_channel IS NOT NULL AND EXISTS(SELECT 1 FROM block_sync_state bs WHERE bs.account_id=f.account_id AND bs.is_channel=n.is_channel AND bs.complete=1) THEN 0 WHEN n.is_channel IS NULL AND (SELECT count(*) FROM block_sync_state bs WHERE bs.account_id=f.account_id AND bs.complete=1)=2 THEN 0 END,(SELECT max(b.profile_block) FROM blocked_users b WHERE b.account_id=f.account_id AND b.user_id=f.user_id AND (n.is_channel IS NULL OR b.is_channel=n.is_channel)) FROM friends f LEFT JOIN native_friend_profiles n ON n.account_id=f.account_id AND n.user_id=f.user_id LEFT JOIN friend_favorites ff ON ff.account_id=f.account_id AND ff.user_id=f.user_id WHERE f.account_id=:account AND (:after IS NULL OR f.user_id>:after) ORDER BY f.user_id LIMIT :limit")?;
        let items=stmt.query_map(named_params!{":account":p.account_id,":after":after,":limit":(n+1) as i64},|r| Ok(json!({"user_id":r.get::<_,String>(0)?,"display_name":r.get::<_,Option<String>>(1)?,"name_source":r.get::<_,Option<String>>(2)?,"observed_at_ms":r.get::<_,Option<i64>>(3)?,"source":r.get::<_,String>(4)?,"relation":r.get::<_,Option<i32>>(5)?,"is_friend":r.get::<_,Option<bool>>(11)?,"is_channel":r.get::<_,Option<bool>>(6)?,"profile_name":r.get::<_,Option<String>>(7)?,"friend_name":r.get::<_,Option<String>>(8)?,"hidden":r.get::<_,Option<bool>>(9)?,"purged":r.get::<_,Option<bool>>(10)?,"favorite":r.get::<_,Option<bool>>(12)?,"is_blocked":r.get::<_,Option<bool>>(13)?,"profile_block":r.get::<_,Option<bool>>(14)?})))?.collect::<std::result::Result<Vec<_>,_>>()?;
        page(items,n,"friends",&p.account_id,"",&["user_id"])
    }).await
}

async fn blocked_users(
    State(state): State<ApiState>,
    headers: HeaderMap,
    query: std::result::Result<Query<PageQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<Value>> {
    let Query(query) = query.map_err(invalid_query)?;
    let n = limit(query.limit)?;
    run(state,headers,Scope::Friends,move |store,p| {
        if p.rooms.is_some() { return Err(Error::Forbidden); }
        let cursor=decode_cursor(query.cursor.as_deref(),"blocked-users",&p.account_id,"",2)?;
        let conn=store.lock()?;
        let mut stmt=conn.prepare("SELECT b.user_id,CAST(b.is_channel AS TEXT),b.profile_block,coalesce(f.display_name,bp.nickname),CASE WHEN f.display_name IS NOT NULL THEN f.name_source WHEN bp.nickname IS NOT NULL THEN 'kakao_block_member' END FROM blocked_users b LEFT JOIN friends f ON f.account_id=b.account_id AND f.user_id=b.user_id LEFT JOIN blocked_profiles bp USING(account_id,user_id,is_channel) WHERE b.account_id=:account AND (:after IS NULL OR (b.user_id,CAST(b.is_channel AS TEXT))>(:after,:channel)) ORDER BY b.user_id,b.is_channel LIMIT :limit")?;
        let items=stmt.query_map(named_params!{":account":p.account_id,":after":cursor.as_ref().map(|v|&v[0]),":channel":cursor.as_ref().map(|v|&v[1]),":limit":n+1},|r|Ok(json!({"user_id":r.get::<_,String>(0)?,"kind":r.get::<_,String>(1)?,"profile_block":r.get::<_,bool>(2)?,"display_name":r.get::<_,Option<String>>(3)?,"name_source":r.get::<_,Option<String>>(4)?})))?.collect::<std::result::Result<Vec<_>,_>>()?;
        let mut result=page(items,n,"blocked-users",&p.account_id,"",&["user_id","kind"])?;
        let mut states=conn.prepare("SELECT is_channel,complete FROM block_sync_state WHERE account_id=?1 ORDER BY is_channel")?;
        result["coverage"]=serde_json::to_value(states.query_map([&p.account_id],|r|Ok(json!({"is_channel":r.get::<_,bool>(0)?,"complete":r.get::<_,bool>(1)?})))?.collect::<std::result::Result<Vec<_>,_>>()?)?;
        // Cursor uses the exact wire-independent key, while the public category is a bool.
        for item in result["items"].as_array_mut().into_iter().flatten() {
            item["is_channel"]=json!(item["kind"]=="1");item.as_object_mut().unwrap().remove("kind");
        }
        Ok(result)
    }).await
}

async fn attachments(
    State(state): State<ApiState>,
    Path((room, message)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<Value>> {
    run(state,headers,Scope::Messages,move |store,p|{
        p.require_room(&room)?;
        Ok(json!({"room_id":room,"message_id":message,"items":store.attachments(&p.account_id,&room,&message)?}))
    }).await
}
async fn attachment_messages(
    State(state): State<ApiState>,
    headers: HeaderMap,
    query: std::result::Result<Query<MessageQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<Value>> {
    let Query(query) = query.map_err(invalid_query)?;
    if query.q.is_some() {
        return Err(Error::Invalid("attachment search does not accept q".into()));
    }
    let n = limit(query.limit)?;
    let hash = filter_hash(&(&query.room_id, &query.sender_id, query.from_ms, query.to_ms))?;
    run(state,headers,Scope::Messages,move |store,p|{
        if let Some(room)=&query.room_id {p.require_room(room)?;}
        if query.from_ms.is_some_and(|v|v<0)||query.to_ms.is_some_and(|v|v<0)||matches!((query.from_ms,query.to_ms),(Some(a),Some(b)) if a>b){return Err(Error::Invalid("invalid time range".into()))}
        let cursor=decode_cursor(query.cursor.as_deref(),"attachments",&p.account_id,&hash,3)?;
        let after=cursor_time(&cursor)?;
        let acl=p.rooms_json()?;
        let conn=store.lock()?;
        let mut stmt=conn.prepare("SELECT a.chat_id,a.log_id,a.sent_at_ms,a.sender_id,a.kind,a.revision,a.attachment,a.source FROM message_media a WHERE a.account_id=:account AND (:acl IS NULL OR CAST(a.chat_id AS TEXT) IN (SELECT value FROM json_each(:acl))) AND (:room IS NULL OR CAST(a.chat_id AS TEXT)=:room) AND (:sender IS NULL OR CAST(a.sender_id AS TEXT)=:sender) AND (:from IS NULL OR a.sent_at_ms>=:from) AND (:to IS NULL OR a.sent_at_ms<=:to) AND (:after IS NULL OR (a.sent_at_ms,CAST(a.chat_id AS TEXT),CAST(a.log_id AS TEXT))>(:after,:ar,:am)) AND NOT EXISTS(SELECT 1 FROM native_tombstones t WHERE t.account_id=a.account_id AND t.chat_id=a.chat_id AND t.log_id=a.log_id) AND NOT EXISTS(SELECT 1 FROM drawer_tombstones t WHERE t.account_id=a.account_id AND t.chat_id=a.chat_id AND t.log_id=a.log_id) AND NOT EXISTS(SELECT 1 FROM messages m WHERE m.account_id=a.account_id AND m.room_id=CAST(a.chat_id AS TEXT) AND m.message_id=CAST(a.log_id AS TEXT) AND m.deleted=1) ORDER BY a.sent_at_ms,CAST(a.chat_id AS TEXT),CAST(a.log_id AS TEXT) LIMIT :limit")?;
        let mut items=stmt.query_map(named_params!{":account":p.account_id,":acl":acl,":room":query.room_id,":sender":query.sender_id,":from":query.from_ms,":to":query.to_ms,":after":after,":ar":cursor.as_ref().map(|v|&v[1]),":am":cursor.as_ref().map(|v|&v[2]),":limit":n+1},|r|{
            let kind=r.get::<_,i32>(4)?;let raw=r.get::<_,String>(6)?;
            Ok(json!({"room_id":r.get::<_,i64>(0)?.to_string(),"message_id":r.get::<_,i64>(1)?.to_string(),"sent_at_ms":r.get::<_,i64>(2)?,"sender_id":r.get::<_,Option<i64>>(3)?.map(|v|v.to_string()),"message_type":kind,"revision":r.get::<_,i64>(5)?,"source":r.get::<_,String>(7)?,"attachments":crate::media::parse(kind,&raw,chrono::Utc::now().timestamp_millis()).unwrap_or_default()}))
        })?.collect::<std::result::Result<Vec<_>,_>>()?;
        drop(stmt); drop(conn);
        for item in &mut items {
            let attachments=store.attachments(&p.account_id,item["room_id"].as_str().ok_or(Error::NotFound)?,item["message_id"].as_str().ok_or(Error::NotFound)?);
            item["attachments"]=serde_json::to_value(attachments.unwrap_or_default())?;
        }
        page(items,n,"attachments",&p.account_id,&hash,&["sent_at_ms","room_id","message_id"])
    }).await
}
async fn attachment_content(
    State(state): State<ApiState>,
    Path((room, message, index)): Path<(String, String, usize)>,
    headers: HeaderMap,
) -> Result<Response> {
    // Permission checks precede DNS, connection and any upstream content request.
    let verify_room = room.clone();
    let verify_message = message.clone();
    let Json((account, credential, plan)) = run(
        state.clone(),
        headers.clone(),
        Scope::Attachments,
        move |store, p| {
            p.require(Scope::Messages)?;
            p.require_room(&verify_room)?;
            let plan = store.download_plan(&p.account_id, &verify_room, &verify_message, index)?;
            Ok((p.account_id, p.credential_id, plan))
        },
    )
    .await?;
    let permit = state
        .download_capacity
        .clone()
        .try_acquire_owned()
        .map_err(|_| Error::Busy)?;
    let job = crate::media::RelayJob {
        account: account.clone(),
        room: room.clone(),
        message: message.clone(),
        index,
        credential,
        fingerprint: plan.fingerprint.clone(),
        expires: chrono::Utc::now().timestamp() + 60,
        endpoint: None,
        failed: false,
    };
    let response = crate::media::open(&state.store, job, &plan).await?;
    let secret = zeroize::Zeroizing::new(
        headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(Error::Unauthorized)?
            .to_owned(),
    );
    struct Transfer {
        response: crate::media::Content,
        deadline: Instant,
        store: Store,
        account: String,
        room: String,
        message: String,
        index: usize,
        fingerprint: String,
        secret: zeroize::Zeroizing<String>,
        bytes: u64,
        _permit: tokio::sync::OwnedSemaphorePermit,
    }
    let transfer = Transfer {
        response,
        deadline: Instant::now() + Duration::from_secs(600),
        store: state.store,
        account,
        room,
        message,
        index,
        fingerprint: plan.fingerprint,
        secret,
        bytes: 0,
        _permit: permit,
    };
    let stream = futures_util::stream::try_unfold(transfer, |mut t| async move {
        if Instant::now() >= t.deadline {
            return Err(Error::Unavailable("download_timeout"));
        }
        let chunk = t.response.chunk().await?;
        let (mut t, chunk) = tokio::task::spawn_blocking(move || -> Result<_> {
            if Instant::now() >= t.deadline {
                return Err(Error::Unavailable("download_timeout"));
            }
            let p = t
                .store
                .authenticate(&t.secret, chrono::Utc::now().timestamp())?;
            p.require(Scope::Attachments)?;
            p.require(Scope::Messages)?;
            p.require_room(&t.room)?;
            if p.account_id != t.account
                || t.store
                    .download_plan(&t.account, &t.room, &t.message, t.index)?
                    .fingerprint
                    != t.fingerprint
            {
                return Err(Error::NotFound);
            }
            Ok((t, chunk))
        })
        .await
        .map_err(|_| Error::Unavailable("download_interrupted"))??;
        match chunk {
            Some(chunk) => {
                t.bytes += chunk.len() as u64;
                if t.bytes > crate::media::MAX_DOWNLOAD {
                    return Err(Error::Unavailable("download_too_large"));
                }
                Ok(Some((chunk, t)))
            }
            None => Ok(None),
        }
    });
    let mut out = Response::new(axum::body::Body::from_stream(stream));
    out.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    out.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment"),
    );
    Ok(out)
}

async fn members(
    State(state): State<ApiState>,
    Path(room): Path<String>,
    headers: HeaderMap,
    query: std::result::Result<Query<PageQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<Value>> {
    let Query(query) = query.map_err(invalid_query)?;
    let n = limit(query.limit)?;
    run(state,headers,Scope::Rooms,move |store,p|{
        p.require_room(&room)?;
        let cursor=decode_cursor(query.cursor.as_deref(),"members",&p.account_id,&room,1)?;
        let conn=store.lock()?;
        let exists:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM rooms WHERE account_id=?1 AND room_id=?2)",rusqlite::params![p.account_id,room],|r|r.get(0))?;
        if !exists{return Err(Error::NotFound)}
        let mut stmt=conn.prepare("WITH ids AS (SELECT user_id FROM room_members WHERE account_id=:account AND CAST(chat_id AS TEXT)=:room UNION SELECT user_id FROM room_active_members WHERE account_id=:account AND CAST(chat_id AS TEXT)=:room) SELECT CAST(ids.user_id AS TEXT),CASE WHEN :names THEN coalesce(f.display_name,m.nickname) END,CASE WHEN :names AND coalesce(f.display_name,m.nickname) IS NOT NULL THEN coalesce(f.name_source,CASE WHEN rc.room_type IN ('OD','OM') THEN 'kakao_open_profile' ELSE 'kakao_room_member' END) END,coalesce(m.updated_at_ms,s.updated_at_ms),coalesce(m.member_type,-1),w.watermark,CASE WHEN a.user_id IS NOT NULL AND s.complete=1 THEN 'active' WHEN s.complete=1 THEN 'inactive' ELSE 'observed' END FROM ids LEFT JOIN room_identity_context rc ON rc.account_id=:account AND CAST(rc.chat_id AS TEXT)=:room LEFT JOIN room_members m ON m.account_id=:account AND CAST(m.chat_id AS TEXT)=:room AND m.user_id=ids.user_id AND ((rc.room_type IS NULL AND EXISTS(SELECT 1 FROM rooms rr WHERE rr.account_id=:account AND rr.room_id=:room AND rr.source='offline_import')) OR EXISTS(SELECT 1 FROM room_member_origins ro WHERE ro.account_id=m.account_id AND ro.chat_id=m.chat_id AND ro.user_id=m.user_id AND ro.room_type=rc.room_type AND ro.link_id=rc.link_id AND (rc.room_type NOT IN ('OD','OM') OR rc.link_id>0))) LEFT JOIN room_active_members a ON a.account_id=:account AND CAST(a.chat_id AS TEXT)=:room AND a.user_id=ids.user_id LEFT JOIN room_roster_state s ON s.account_id=:account AND CAST(s.chat_id AS TEXT)=:room LEFT JOIN room_read_watermarks w ON w.account_id=:account AND CAST(w.chat_id AS TEXT)=:room AND w.user_id=ids.user_id LEFT JOIN friends f ON (rc.room_type NOT IN ('OD','OM') OR (rc.room_type IS NULL AND EXISTS(SELECT 1 FROM rooms rr WHERE rr.account_id=:account AND rr.room_id=:room AND rr.source='offline_import'))) AND f.account_id=:account AND f.user_id=CAST(ids.user_id AS TEXT) WHERE (:after IS NULL OR CAST(ids.user_id AS TEXT)>:after) ORDER BY CAST(ids.user_id AS TEXT) LIMIT :limit")?;
        let items=stmt.query_map(named_params!{":account":p.account_id,":room":room,":names":p.scopes.contains(&Scope::Friends),":after":cursor.as_ref().map(|v|&v[0]),":limit":n+1},|r|Ok(json!({"user_id":r.get::<_,String>(0)?,"display_name":r.get::<_,Option<String>>(1)?,"name_source":r.get::<_,Option<String>>(2)?,"observed_at_ms":r.get::<_,Option<i64>>(3)?,"member_type":r.get::<_,i32>(4)?,"membership":r.get::<_,String>(6)?,"observed_read_message_id":r.get::<_,Option<i64>>(5)?.map(|v|v.to_string())})))?.collect::<std::result::Result<Vec<_>,_>>()?;
        let observed:i64=conn.query_row("SELECT count(*) FROM room_members WHERE account_id=?1 AND CAST(chat_id AS TEXT)=?2",rusqlite::params![p.account_id,room],|r|r.get(0))?;
        let active:i64=conn.query_row("SELECT count(*) FROM room_active_members WHERE account_id=?1 AND CAST(chat_id AS TEXT)=?2",rusqlite::params![p.account_id,room],|r|r.get(0))?;
        use rusqlite::OptionalExtension;
        let roster:Option<(bool,i64)>=conn.query_row("SELECT complete,updated_at_ms FROM room_roster_state WHERE account_id=?1 AND CAST(chat_id AS TEXT)=?2",rusqlite::params![p.account_id,room],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        let raw:Option<Vec<u8>>=conn.query_row("SELECT raw FROM room_details WHERE account_id=?1 AND CAST(chat_id AS TEXT)=?2",rusqlite::params![p.account_id,room],|r|r.get(0)).optional()?;
        let expected=raw.and_then(|b|bson::from_slice::<bson::Document>(&b).ok()).and_then(|d|d.get_i32("activeMembersCount").ok());
        let mut result=page(items,n,"members",&p.account_id,&room,&["user_id"])?;
        result["coverage"]=json!({"complete":roster.is_some_and(|v|v.0),"observed_count":observed,"active_count":active,"reported_active_count":expected,"as_of_ms":roster.map(|v|v.1)});
        Ok(result)
    }).await
}
async fn gaps(
    State(state): State<ApiState>,
    Path(room): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>> {
    run(state,headers,Scope::Messages,move |store,p|{
        p.require_room(&room)?;
        let conn=store.lock()?;
        use rusqlite::OptionalExtension;
        let range:Option<(i64,i64)>=conn.query_row("SELECT cursor,target FROM loco_rooms WHERE account_id=?1 AND CAST(chat_id AS TEXT)=?2",rusqlite::params![p.account_id,room],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        let (cursor,target)=range.ok_or(Error::NotFound)?;
        let chat=room.parse::<i64>().map_err(|_|Error::NotFound)?;
        let mut stmt=conn.prepare("SELECT l.log_id,l.prev_id FROM loco_logs l WHERE l.account_id=?1 AND l.chat_id=?2 AND l.prev_id>0 AND NOT EXISTS(SELECT 1 FROM loco_logs p WHERE p.account_id=l.account_id AND p.chat_id=l.chat_id AND p.log_id=l.prev_id) AND NOT EXISTS(SELECT 1 FROM drawer_records p WHERE p.account_id=l.account_id AND p.chat_id=l.chat_id AND p.log_id=l.prev_id) ORDER BY l.log_id LIMIT 101")?;
        let mut missing=stmt.query_map(rusqlite::params![p.account_id,chat],|r|Ok(json!({"anchor_id":r.get::<_,i64>(0)?.to_string(),"missing_predecessor_id":r.get::<_,i64>(1)?.to_string()})))?.collect::<std::result::Result<Vec<_>,_>>()?;
        let truncated=missing.len()>100; missing.truncate(100);
        Ok(json!({"room_id":room,"recovery_cursor":cursor.to_string(),"target":target.to_string(),"pending":target>cursor,"history_complete":false,"scope":"since_collection_boundary","missing_predecessors":missing,"missing_predecessors_truncated":truncated}))
    }).await
}

async fn send_text(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(room): Path<String>,
    input: std::result::Result<
        Json<crate::outgoing::TextInput>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Result<(StatusCode, Json<crate::outgoing::SendStatus>)> {
    let Json(input) = input.map_err(|_| Error::Invalid("invalid text send request".into()))?;
    let mut keys = headers.get_all("idempotency-key").iter();
    let key = keys
        .next()
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| Error::Invalid("Idempotency-Key required".into()))?
        .to_owned();
    if keys.next().is_some() {
        return Err(Error::Invalid("multiple Idempotency-Key headers".into()));
    }
    let result = run(state, headers, Scope::MessagesWrite, move |store, p| {
        store.enqueue_text(
            &p,
            &room,
            &key,
            input,
            chrono::Utc::now().timestamp_millis(),
        )
    })
    .await?;
    let status = if matches!(result.0.state.as_str(), "queued" | "dispatching") {
        StatusCode::ACCEPTED
    } else {
        StatusCode::OK
    };
    Ok((status, result))
}
async fn outgoing_status(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path((room, id)): Path<(String, String)>,
) -> Result<Json<crate::outgoing::SendStatus>> {
    run(state, headers, Scope::MessagesWrite, move |store, p| {
        store.outgoing_status(&p, &room, &id)
    })
    .await
}

#[cfg(test)]
mod search_plan_tests {
    #[test]
    fn indexed_search_visits_fts_candidates_then_canonical_rowids() {
        let temp = tempfile::Builder::new()
            .permissions(
                <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
            )
            .tempdir()
            .unwrap();
        let store = crate::Store::initialize(temp.path()).unwrap();
        let connection = store.lock().unwrap();
        let mut stmt = connection
            .prepare(&format!("EXPLAIN QUERY PLAN {}", super::search_sql(true)))
            .unwrap();
        let mut rows = stmt.raw_query();
        let mut details = Vec::new();
        while let Some(row) = rows.next().unwrap() {
            details.push(row.get::<_, String>(3).unwrap());
        }
        assert!(
            details
                .iter()
                .any(|d| d.contains("message_text VIRTUAL TABLE INDEX") && d.contains(":M1")),
            "{details:?}"
        );
        assert!(
            details
                .iter()
                .any(|d| d.contains("SEARCH m USING INTEGER PRIMARY KEY (rowid=?)")),
            "{details:?}"
        );
        assert!(
            !details.iter().any(|d| d.starts_with("SCAN m ")),
            "{details:?}"
        );
    }
}
