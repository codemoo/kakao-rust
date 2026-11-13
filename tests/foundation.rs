use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use chrono::NaiveDate;
use http_body_util::BodyExt;
use kakao_rust::{
    api,
    auth::{IssuedCredential, Scope},
    device::Catalog,
    Error, Store,
};
use rusqlite::Connection;
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    io::Cursor,
    sync::{Arc, Barrier},
};
use tempfile::TempDir;
use tower::ServiceExt;

fn setup() -> (TempDir, Store) {
    let temp = tempfile::Builder::new()
        .prefix("kakao-rust-test-")
        .permissions(<std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700))
        .tempdir()
        .unwrap();
    let store = Store::initialize(temp.path()).unwrap();
    (temp, store)
}
fn catalog() -> Catalog {
    serde_json::from_str(include_str!("../config/device-catalog.json")).unwrap()
}
fn date(value: &str) -> NaiveDate {
    NaiveDate::parse_from_str(value, "%Y-%m-%d").unwrap()
}
fn message(
    account: &str,
    room: &str,
    id: &str,
    revision: i64,
    pos: i64,
    body: Option<&str>,
) -> Value {
    json!({"schema_version":1,"account_id":account,"event_id":format!("event-{pos}"),"source":"offline_import","stream_id":"s","position":pos,"cursor":pos.to_string(),"payload":{"type":"message","room_id":room,"message_id":id,"revision":revision,"sent_at_ms":1700000000000_i64,"sender_id":"user","body":body,"deleted":body.is_none(),"source_local_pk":null}})
}
fn import(store: &Store, events: &[Value]) -> kakao_rust::Result<kakao_rust::ingest::ImportReport> {
    let lines = events
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    store.import_jsonl(Cursor::new(lines))
}
fn token(
    store: &Store,
    account: &str,
    rooms: Option<&[&str]>,
    scopes: &[Scope],
) -> IssuedCredential {
    let now = chrono::Utc::now().timestamp();
    store
        .token_issue(
            "test service".into(),
            account.into(),
            scopes.iter().copied().collect(),
            rooms.map(|r| r.iter().map(|v| v.to_string()).collect()),
            now + 3600,
            now,
        )
        .unwrap()
}
async fn request(router: &Router, uri: &str, token: Option<&str>) -> (StatusCode, Value) {
    let mut request = Request::builder().uri(uri);
    if let Some(token) = token {
        request = request.header("Authorization", format!("Bearer {token}"));
    }
    let response = router
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.headers()["cache-control"], "no-store");
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap())
}
fn search_uri(q: &str) -> String {
    format!(
        "/v1/search?{}",
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("q", q)
            .finish()
    )
}

#[tokio::test]
async fn members_api_distinguishes_active_history_unknown_names_and_enforces_scope() {
    let (dir, store) = setup();
    let db = Connection::open(dir.path().join("state.sqlite3")).unwrap();
    db.execute(
        "INSERT INTO rooms(account_id,room_id,revision,source) VALUES('42','7',0,'native_loco')",
        [],
    )
    .unwrap();
    db.execute(
        "INSERT INTO room_roster_state VALUES('42',7,55,1,1,1000)",
        [],
    )
    .unwrap();
    db.execute(
        "INSERT INTO room_active_members VALUES('42',7,42),('42',7,44)",
        [],
    )
    .unwrap();
    db.execute(
        "INSERT INTO room_members VALUES('42',7,43,'Historical',3,X'00',1000,1)",
        [],
    )
    .unwrap();
    db.execute(
        "INSERT INTO room_member_origins VALUES('42',7,43,0,'MultiChat')",
        [],
    )
    .unwrap();
    db.execute(
        "INSERT OR IGNORE INTO room_identity_context VALUES('42',7,'MultiChat',0,0)",
        [],
    )
    .unwrap();
    let scoped = token(&store, "42", Some(&["7"]), &[Scope::Rooms]);
    let names = token(&store, "42", None, &[Scope::Rooms, Scope::Friends]);
    let denied = token(&store, "42", Some(&["8"]), &[Scope::Rooms]);
    let router = api::router(store);
    let (status, value) =
        request(&router, "/v1/rooms/7/members", Some(scoped.token.as_str())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["coverage"]["complete"], true);
    assert_eq!(value["coverage"]["active_count"], 2);
    let rows = value["items"].as_array().unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0]["membership"], "active");
    assert_eq!(rows[1]["membership"], "inactive");
    assert!(rows.iter().all(|v| v["display_name"].is_null()));
    let (_, value) = request(&router, "/v1/rooms/7/members", Some(names.token.as_str())).await;
    assert_eq!(value["items"][1]["display_name"], "Historical");
    assert!(value["items"][2]["display_name"].is_null());
    assert_eq!(
        request(&router, "/v1/rooms/7/members", Some(denied.token.as_str()))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    db.execute("UPDATE room_roster_state SET complete=0", [])
        .unwrap();
    let (_, value) = request(&router, "/v1/rooms/7/members", Some(names.token.as_str())).await;
    assert_eq!(value["coverage"]["complete"], false);
    assert!(value["items"]
        .as_array()
        .unwrap()
        .iter()
        .all(|v| v["membership"] == "observed"));
}

#[test]
fn private_paths_and_missing_store_are_rejected() {
    let temp = tempfile::Builder::new()
        .permissions(<std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700))
        .tempdir()
        .unwrap();
    assert!(Store::open(&temp.path().join("missing")).is_err());
    assert!(Store::initialize(std::path::Path::new("relative")).is_err());
    assert!(Store::initialize(&temp.path().join("Dropbox/private")).is_err());
    assert!(!temp.path().join("Dropbox").exists());
    assert!(Store::initialize(std::path::Path::new(env!("CARGO_MANIFEST_DIR"))).is_err());
    #[cfg(unix)]
    {
        use std::os::unix::fs::{symlink, PermissionsExt};
        symlink(env!("CARGO_MANIFEST_DIR"), temp.path().join("alias")).unwrap();
        assert!(Store::initialize(&temp.path().join("alias/private")).is_err());
        let broad = temp.path().join("broad");
        std::fs::create_dir(&broad).unwrap();
        std::fs::set_permissions(&broad, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Store::initialize(&broad).is_err());
    }
}

#[tokio::test]
async fn open_room_names_never_fall_back_to_contacts_or_cross_link_boundaries() {
    let (dir, store) = setup();
    import(
        &store,
        &[
            message("42", "7", "1", 0, 1, Some("Open message")),
            message("42", "8", "2", 0, 2, Some("Normal message")),
        ],
    )
    .unwrap();
    let db = Connection::open(dir.path().join("state.sqlite3")).unwrap();
    db.execute("UPDATE messages SET sender_id='43'", [])
        .unwrap();
    db.execute("INSERT INTO friends(account_id,user_id,revision,display_name,name_source,source,payload_hash) VALUES('42','43',0,'Private contact','drawer_contact_name','native_drawer','synthetic')",[]).unwrap();
    db.execute(
        "INSERT INTO room_identity_context VALUES('42',7,'OM',100,1),('42',8,'MultiChat',0,1)",
        [],
    )
    .unwrap();
    db.execute(
        "INSERT INTO room_members VALUES('42',7,43,'Open nickname',1000,X'00',1000,2)",
        [],
    )
    .unwrap();
    db.execute(
        "INSERT INTO room_member_origins VALUES('42',7,43,100,'OM')",
        [],
    )
    .unwrap();
    let access = token(
        &store,
        "42",
        None,
        &[Scope::Rooms, Scope::Messages, Scope::Friends],
    );
    let router = api::router(store);
    for path in [
        "/v1/rooms/7/messages/1",
        "/v1/messages?room_id=7",
        "/v1/search?q=Open",
    ] {
        let (status, value) = request(&router, path, Some(&access.token)).await;
        assert_eq!(status, StatusCode::OK);
        let row = if value.get("items").is_some() {
            &value["items"][0]
        } else {
            &value
        };
        assert_eq!(row["sender_name"], "Open nickname");
        assert_eq!(row["sender_name_source"], "kakao_open_profile");
    }
    let (_, normal) = request(&router, "/v1/rooms/8/messages/2", Some(&access.token)).await;
    assert_eq!(normal["sender_name"], "Private contact");
    let (_, members) = request(&router, "/v1/rooms/7/members", Some(&access.token)).await;
    assert_eq!(members["items"][0]["display_name"], "Open nickname");
    db.execute(
        "UPDATE room_identity_context SET link_id=200 WHERE chat_id=7",
        [],
    )
    .unwrap();
    let (_, message) = request(&router, "/v1/rooms/7/messages/1", Some(&access.token)).await;
    assert!(message["sender_name"].is_null());
    let (_, members) = request(&router, "/v1/rooms/7/members", Some(&access.token)).await;
    assert!(members["items"][0]["display_name"].is_null());
    db.execute("DELETE FROM friends", []).unwrap();
    db.execute(
        "UPDATE room_identity_context SET room_type='MultiChat',link_id=0 WHERE chat_id=7",
        [],
    )
    .unwrap();
    let (_, message) = request(&router, "/v1/rooms/7/messages/1", Some(&access.token)).await;
    assert!(message["sender_name"].is_null());
    let (_, members) = request(&router, "/v1/rooms/7/members", Some(&access.token)).await;
    assert!(members["items"][0]["display_name"].is_null());
    db.execute("INSERT INTO friends(account_id,user_id,revision,display_name,name_source,source,payload_hash) VALUES('42','43',0,'Private contact','drawer_contact_name','native_drawer','synthetic')",[]).unwrap();
    db.execute("DELETE FROM room_identity_context WHERE chat_id=7", [])
        .unwrap();
    db.execute(
        "UPDATE rooms SET source='native_loco' WHERE room_id='7'",
        [],
    )
    .unwrap();
    db.execute(
        "UPDATE messages SET source='native_loco' WHERE room_id='7'",
        [],
    )
    .unwrap();
    let (_, members) = request(&router, "/v1/rooms/7/members", Some(&access.token)).await;
    assert!(members["items"][0]["display_name"].is_null());
    let (_, message) = request(&router, "/v1/rooms/7/messages/1", Some(&access.token)).await;
    assert!(message["sender_name"].is_null());
}

#[tokio::test]
async fn blocked_users_are_account_and_scope_bound_with_composite_pagination() {
    let (dir, store) = setup();
    let db = Connection::open(dir.path().join("state.sqlite3")).unwrap();
    db.execute(
        "INSERT INTO blocked_users VALUES('42','43',0,1,1),('42','43',1,0,1),('99','secret',0,1,1)",
        [],
    )
    .unwrap();
    db.execute(
        "INSERT INTO block_sync_state VALUES('42',0,1,1,1),('42',1,1,1,1)",
        [],
    )
    .unwrap();
    db.execute(
        "INSERT INTO blocked_profiles VALUES('42','43',0,'Blocked profile',1)",
        [],
    )
    .unwrap();
    db.execute("INSERT INTO friends(account_id,user_id,revision,display_name,source,payload_hash) VALUES('42','43',0,'Known history','native_drawer','synthetic'),('42','44',0,'Unknown scope','native_drawer','synthetic')",[]).unwrap();
    let access = token(&store, "42", None, &[Scope::Friends]);
    let denied = token(&store, "42", None, &[Scope::Messages]);
    let router = api::router(store);
    assert_eq!(
        request(&router, "/v1/blocked-users", Some(&denied.token))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let (status, first) = request(&router, "/v1/blocked-users?limit=1", Some(&access.token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["items"][0]["display_name"], "Known history");
    assert_eq!(first["items"][0]["is_channel"], false);
    let uri = format!(
        "/v1/blocked-users?limit=1&cursor={}",
        first["next_cursor"].as_str().unwrap()
    );
    let (status, second) = request(&router, &uri, Some(&access.token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(second["items"][0]["is_channel"], true);
    assert_eq!(second["items"][0]["display_name"], "Known history");
    assert!(second["next_cursor"].is_null());
    db.execute("DELETE FROM blocked_users WHERE is_channel=0", [])
        .unwrap();
    let (_, friends) = request(&router, "/v1/friends", Some(&access.token)).await;
    assert_eq!(friends["items"][0]["is_blocked"], true);
    assert_eq!(friends["items"][1]["is_blocked"], false);
    db.execute("DELETE FROM block_sync_state WHERE is_channel=1", [])
        .unwrap();
    let (_, friends) = request(&router, "/v1/friends", Some(&access.token)).await;
    assert!(friends["items"][1]["is_blocked"].is_null());
}

#[test]
fn profile_calendar_window_persistence_and_corruption() {
    let (temp, store) = setup();
    let catalog = catalog();
    assert_eq!(catalog.eligible(date("2026-11-13")).unwrap().len(), 2);
    assert_eq!(catalog.eligible(date("2027-08-11")).unwrap().len(), 2);
    assert!(catalog.eligible(date("2027-08-12")).unwrap().is_empty());
    assert!(catalog.eligible(date("2023-08-10")).unwrap().is_empty());
    let profile = store
        .device_initialize(&catalog, date("2026-11-13"))
        .unwrap();
    assert!(profile.android_id.is_none());
    assert!(!profile.native_auth_ready);
    assert!(catalog.devices.contains(&profile.model));
    assert_eq!(
        store
            .device_initialize(
                &Catalog {
                    version: "unused".into(),
                    devices: vec![]
                },
                date("2035-01-01")
            )
            .unwrap(),
        profile
    );
    drop(store);
    let reopened = Store::open(temp.path()).unwrap();
    assert_eq!(reopened.device_show().unwrap(), profile);
    assert_eq!(
        reopened
            .device_initialize(&catalog, date("2040-01-01"))
            .unwrap(),
        profile
    );
    let raw = Connection::open(temp.path().join("state.sqlite3")).unwrap();
    raw.execute("UPDATE device_profile SET json='broken'", [])
        .unwrap();
    assert!(reopened.device_show().is_err());
    assert!(reopened
        .device_initialize(&catalog, date("2026-11-13"))
        .is_err());
    raw.execute("DELETE FROM device_profile", []).unwrap();
    assert!(reopened
        .device_initialize(&catalog, date("2026-11-13"))
        .is_err());
}

#[test]
fn profile_initialization_is_atomic_across_connections() {
    let (temp, store) = setup();
    let path = temp.path().to_path_buf();
    let barrier = Arc::new(Barrier::new(8));
    let workers = (0..8)
        .map(|_| {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let store = Store::open(&path).unwrap();
                barrier.wait();
                store
                    .device_initialize(&catalog(), date("2026-11-13"))
                    .unwrap()
            })
        })
        .collect::<Vec<_>>();
    let profiles = workers
        .into_iter()
        .map(|w| w.join().unwrap())
        .collect::<Vec<_>>();
    assert!(profiles.iter().all(|p| p == &profiles[0]));
    assert_eq!(store.device_show().unwrap(), profiles[0]);
}

#[test]
fn catalog_validates_sources_and_calendar_leap_boundary() {
    let mut data = catalog();
    data.devices[0].source_urls = vec!["https://samsung.com.evil.example/model".into()];
    assert!(data.validate().is_err());
    data = catalog();
    data.devices[0].release_date = date("2020-02-29");
    assert_eq!(data.eligible(date("2024-02-29")).unwrap().len(), 2);
    assert_eq!(data.eligible(date("2024-03-01")).unwrap().len(), 1);
    data.devices[0].model_code = data.devices[1].model_code.clone();
    assert!(data.validate().is_err());
}

#[test]
fn import_replay_revision_delete_and_transaction_rollback() {
    let (temp, store) = setup();
    let first = message("a", "r", "9007199254740993", 1, 1, Some("old secret 안녕"));
    assert_eq!(
        import(&store, std::slice::from_ref(&first))
            .unwrap()
            .changed,
        1
    );
    assert_eq!(
        import(&store, std::slice::from_ref(&first))
            .unwrap()
            .replayed,
        1
    );
    let edit = message("a", "r", "9007199254740993", 3, 2, Some("new text"));
    let stale = message("a", "r", "9007199254740993", 2, 3, Some("stale"));
    let report = import(&store, &[edit, stale]).unwrap();
    assert_eq!((report.changed, report.stale_or_unchanged), (1, 1));
    let connection = Connection::open(temp.path().join("state.sqlite3")).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT body FROM messages", [], |r| r.get::<_, String>(0))
            .unwrap(),
        "new text"
    );
    let conflicting = message("a", "r", "9007199254740993", 3, 4, Some("conflicting"));
    assert!(matches!(
        import(&store, &[conflicting]),
        Err(Error::Conflict(_))
    ));
    assert_eq!(store.sync_cursor("a", "s").unwrap().unwrap().position, 3);
    let valid = message("a", "r", "second", 1, 4, Some("must rollback"));
    let bad = format!("{valid}\n{{bad-json");
    assert!(store.import_jsonl(Cursor::new(bad)).is_err());
    assert_eq!(
        connection
            .query_row("SELECT count(*) FROM messages", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row("SELECT count(*) FROM outbox", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert_eq!(store.sync_cursor("a", "s").unwrap().unwrap().position, 3);
    let delete = message("a", "r", "9007199254740993", 4, 4, None);
    assert_eq!(import(&store, &[delete]).unwrap().changed, 1);
    assert!(connection
        .query_row("SELECT body FROM messages", [], |r| r
            .get::<_, Option<String>>(0))
        .unwrap()
        .is_none());
    assert!(import(
        &store,
        &[message(
            "a",
            "r",
            "9007199254740993",
            5,
            5,
            Some("resurrect")
        )]
    )
    .is_err());
    assert_eq!(store.sync_cursor("a", "s").unwrap().unwrap().position, 4);
    let mut replay_conflict = first;
    replay_conflict["payload"]["body"] = json!("different");
    assert!(matches!(
        import(&store, &[replay_conflict]),
        Err(Error::Conflict(_))
    ));
    assert_eq!(
        connection
            .query_row("SELECT count(*) FROM ingest_events", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        4
    );
    drop(store);
    assert_eq!(
        Store::open(temp.path())
            .unwrap()
            .sync_cursor("a", "s")
            .unwrap()
            .unwrap()
            .position,
        4
    );
}

#[test]
fn replay_ten_thousand_events_keeps_canonical_count_and_namespace() {
    let (temp, store) = setup();
    let events = (0..10_000)
        .map(|i| {
            message(
                "a",
                &format!("room-{}", i % 7),
                &i.to_string(),
                1,
                i,
                Some("합성 corpus Rust 👋"),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(import(&store, &events).unwrap().changed, 10_000);
    assert_eq!(import(&store, &events).unwrap().replayed, 10_000);
    import(
        &store,
        &[
            message("b", "room-0", "0", 1, 0, Some("other account")),
            message("a", "another-room", "0", 1, 10_000, Some("other room")),
        ],
    )
    .unwrap();
    let connection = Connection::open(temp.path().join("state.sqlite3")).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT count(*) FROM messages", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        10_002
    );
    assert_eq!(
        connection
            .query_row("SELECT count(*) FROM outbox", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        10_002
    );
}

#[tokio::test]
async fn bearer_auth_expiration_revocation_and_scope() {
    let (_temp, store) = setup();
    let router = api::router(store.clone());
    assert_eq!(
        request(&router, "/v1/status", None).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request(&router, "/v1/status", Some("invalid")).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert!(matches!(
        store.authenticate(&format!("kr_{}{}", "あ".repeat(31), "abcd"), 0),
        Err(Error::Unauthorized)
    ));
    let issued = token(&store, "a", None, &[Scope::Status]);
    assert_eq!(issued.token.len(), 100);
    let status = request(&router, "/v1/status", Some(&issued.token)).await;
    assert_eq!(status.0, StatusCode::OK);
    assert_eq!(status.1["native_auth"]["state"], "not_connected");
    assert_eq!(status.1["native_auth"]["qr_authorization"], "experimental");
    assert_eq!(status.1["live_connected"], false);
    assert_eq!(
        request(&router, "/v1/rooms", Some(&issued.token)).await.0,
        StatusCode::FORBIDDEN
    );
    let metadata = serde_json::to_string(&store.token_list().unwrap()).unwrap();
    assert!(!metadata.contains(&issued.token));
    assert!(!metadata.contains("token_hash"));
    let now = chrono::Utc::now().timestamp();
    let expired = store
        .token_issue(
            "expired".into(),
            "a".into(),
            BTreeSet::from([Scope::Status]),
            None,
            now - 10,
            now - 20,
        )
        .unwrap();
    assert_eq!(
        request(&router, "/v1/status", Some(&expired.token)).await.0,
        StatusCode::UNAUTHORIZED
    );
    store.token_revoke(&issued.metadata.id, now).unwrap();
    assert_eq!(
        request(&router, "/v1/status", Some(&issued.token)).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn acl_is_applied_before_pages_search_and_room_existence() {
    let (_temp, store) = setup();
    import(
        &store,
        &[
            message("a", "0-hidden", "x", 1, 1, Some("안녕 secret")),
            message(
                "a",
                "1-visible",
                "9007199254740993",
                1,
                2,
                Some("안녕 allowed"),
            ),
            message(
                "a",
                "1-visible",
                "9007199254740994",
                1,
                3,
                Some("안녕 allowed2"),
            ),
            message("b", "1-visible", "x", 1, 1, Some("안녕 other-account")),
        ],
    )
    .unwrap();
    let issued = token(
        &store,
        "a",
        Some(&["1-visible"]),
        &[Scope::Rooms, Scope::Messages],
    );
    let router = api::router(store.clone());
    let (_, rooms) = request(&router, "/v1/rooms?limit=1", Some(&issued.token)).await;
    assert_eq!(rooms["items"].as_array().unwrap().len(), 1);
    assert_eq!(rooms["items"][0]["room_id"], "1-visible");
    assert!(rooms["next_cursor"].is_null());
    assert_eq!(
        request(&router, "/v1/rooms/0-hidden/messages", Some(&issued.token))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(
            &router,
            "/v1/rooms/never-existed/messages",
            Some(&issued.token)
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let (_, first) = request(
        &router,
        "/v1/rooms/1-visible/messages?limit=1",
        Some(&issued.token),
    )
    .await;
    assert_eq!(first["items"][0]["message_id"], "9007199254740993");
    let next = first["next_cursor"].as_str().unwrap();
    let (_, second) = request(
        &router,
        &format!("/v1/rooms/1-visible/messages?limit=1&cursor={next}"),
        Some(&issued.token),
    )
    .await;
    assert_eq!(second["items"][0]["message_id"], "9007199254740994");
    assert!(second["next_cursor"].is_null());
    let (_, results) = request(&router, &search_uri("안녕"), Some(&issued.token)).await;
    assert_eq!(results["items"].as_array().unwrap().len(), 2);
    assert!(results["items"]
        .as_array()
        .unwrap()
        .iter()
        .all(|v| v["room_id"] == "1-visible"));
    assert!(!results.to_string().contains("secret"));
    let (_, injection) = request(&router, &search_uri("' OR 1=1 --"), Some(&issued.token)).await;
    assert!(injection["items"].as_array().unwrap().is_empty());
    assert_eq!(
        request(
            &router,
            "/v1/search?q=x&room_id=0-hidden",
            Some(&issued.token)
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(&router, "/v1/rooms?limit=201", Some(&issued.token))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        request(&router, "/v1/rooms?cursor=broken", Some(&issued.token))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        request(&router, "/v1/friends", Some(&issued.token)).await.0,
        StatusCode::FORBIDDEN
    );
    let no_rooms = token(&store, "a", Some(&[]), &[Scope::Rooms, Scope::Messages]);
    assert!(
        request(&router, "/v1/rooms", Some(&no_rooms.token)).await.1["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(request(&router, &search_uri("안녕"), Some(&no_rooms.token))
        .await
        .1["items"]
        .as_array()
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn edit_and_delete_remove_search_content_and_cursor_is_query_bound() {
    let (_temp, store) = setup();
    import(
        &store,
        &[
            message("a", "r", "m1", 1, 1, Some("원본 Rust 👋")),
            message("a", "r", "m2", 1, 2, Some("원본 second")),
        ],
    )
    .unwrap();
    let issued = token(&store, "a", None, &[Scope::Messages]);
    let router = api::router(store.clone());
    let (_, first) = request(
        &router,
        &format!("{}&limit=1", search_uri("원본")),
        Some(&issued.token),
    )
    .await;
    let cursor = first["next_cursor"].as_str().unwrap();
    assert_eq!(
        request(
            &router,
            &format!("{}&cursor={cursor}", search_uri("different")),
            Some(&issued.token)
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    import(&store, &[message("a", "r", "m1", 2, 3, Some("수정됨"))]).unwrap();
    let (_, old) = request(&router, &search_uri("Rust"), Some(&issued.token)).await;
    assert!(old["items"].as_array().unwrap().is_empty());
    assert_eq!(
        request(&router, &search_uri("수정"), Some(&issued.token))
            .await
            .1["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    import(&store, &[message("a", "r", "m1", 3, 4, None)]).unwrap();
    assert!(request(&router, &search_uri("수정"), Some(&issued.token))
        .await
        .1["items"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(
        request(&router, "/v1/rooms/r/messages", Some(&issued.token))
            .await
            .1["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn request_rate_limit_is_per_credential_and_method_errors_are_json() {
    let (_temp, store) = setup();
    let first = token(&store, "a", None, &[Scope::Status]);
    let second = token(&store, "a", None, &[Scope::Status]);
    let router = api::router(store);
    for _ in 0..120 {
        assert_eq!(
            request(&router, "/v1/status", Some(&first.token)).await.0,
            StatusCode::OK
        );
    }
    assert_eq!(
        request(&router, "/v1/status", Some(&first.token)).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        request(&router, "/v1/status", Some(&second.token)).await.0,
        StatusCode::OK
    );
    let request = Request::builder()
        .method("POST")
        .uri("/v1/status")
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap()["error"]["code"],
        "method_not_allowed"
    );
}

#[tokio::test]
async fn names_keep_provenance_and_friends_need_account_wide_permission() {
    let (_temp, store) = setup();
    let mut room = message("a", "r", "unused", 1, 1, Some("unused"));
    room["payload"] = json!({"type":"room","room_id":"r","revision":1,"display_name":"이름","name_source":"explicit_room_title","observed_at_ms":1});
    let mut friend = room.clone();
    friend["event_id"] = json!("friend");
    friend["position"] = json!(2);
    friend["cursor"] = json!("2");
    friend["payload"] = json!({"type":"friend","user_id":"f","revision":1,"display_name":"별명","name_source":"friend_nickname","observed_at_ms":2});
    import(&store, &[room, friend]).unwrap();
    let issued = token(&store, "a", None, &[Scope::Rooms, Scope::Friends]);
    let router = api::router(store.clone());
    assert_eq!(
        request(&router, "/v1/rooms", Some(&issued.token)).await.1["items"][0]["name_source"],
        "explicit_room_title"
    );
    assert_eq!(
        request(&router, "/v1/friends", Some(&issued.token)).await.1["items"][0]["name_source"],
        "friend_nickname"
    );
    let now = chrono::Utc::now().timestamp();
    assert!(store
        .token_issue(
            "limited friends".into(),
            "a".into(),
            BTreeSet::from([Scope::Friends]),
            Some(BTreeSet::from(["r".into()])),
            now + 3600,
            now
        )
        .is_err());
}

#[test]
fn initialize_never_replaces_truncated_deleted_or_preexisting_empty_database() {
    for truncated in [true, false] {
        let (temp, store) = setup();
        store
            .device_initialize(&catalog(), date("2026-11-13"))
            .unwrap();
        drop(store);
        let database = temp.path().join("state.sqlite3");
        if truncated {
            std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&database)
                .unwrap();
        } else {
            std::fs::remove_file(&database).unwrap();
        }
        assert!(Store::initialize(temp.path()).is_err());
        assert!(Store::open(temp.path()).is_err());
        if truncated {
            assert_eq!(std::fs::metadata(&database).unwrap().len(), 0);
        } else {
            assert!(!database.exists());
        }
        assert_eq!(
            std::fs::read_to_string(temp.path().join("store.initialized")).unwrap(),
            "kakao-rust-store-v1:ready\n"
        );
    }
    // A zero-version file without a marker might be a damaged legacy store.
    // Only a file exclusively created by this initializer may receive schema v1.
    let temp = tempfile::Builder::new()
        .permissions(<std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700))
        .tempdir()
        .unwrap();
    let database = temp.path().join("state.sqlite3");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(&database).unwrap();
    assert!(Store::initialize(temp.path()).is_err());
    assert_eq!(std::fs::metadata(&database).unwrap().len(), 0);
    assert!(!temp.path().join("store.initialized").exists());
}

#[test]
fn repeated_concurrent_initialize_and_legacy_enrollment_preserve_identity() {
    let temp = tempfile::Builder::new()
        .permissions(<std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700))
        .tempdir()
        .unwrap();
    let path = temp.path().to_path_buf();
    let barrier = Arc::new(Barrier::new(8));
    let workers = (0..8)
        .map(|_| {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let store = Store::initialize(&path).unwrap();
                store
                    .device_initialize(&catalog(), date("2026-11-13"))
                    .unwrap()
            })
        })
        .collect::<Vec<_>>();
    let profiles = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();
    assert!(profiles.iter().all(|profile| profile == &profiles[0]));
    assert_eq!(
        Store::initialize(temp.path())
            .unwrap()
            .device_show()
            .unwrap(),
        profiles[0]
    );
    // Existing valid v1 stores from before this marker was introduced stay valid.
    std::fs::remove_file(path.join("store.initialized")).unwrap();
    assert_eq!(
        Store::initialize(temp.path())
            .unwrap()
            .device_show()
            .unwrap(),
        profiles[0]
    );
    assert_eq!(
        Store::open(temp.path()).unwrap().device_show().unwrap(),
        profiles[0]
    );
    assert!(path.join("store.initialized").is_file());
}

#[test]
fn interrupted_initialization_fails_closed_before_database_creation() {
    for bytes in [
        b"kakao-rust-store-v1:initializing\n".as_slice(),
        b"corrupt".as_slice(),
    ] {
        let temp = tempfile::Builder::new()
            .permissions(
                <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
            )
            .tempdir()
            .unwrap();
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        use std::io::Write;
        options
            .open(temp.path().join("store.initialized"))
            .unwrap()
            .write_all(bytes)
            .unwrap();
        assert!(Store::initialize(temp.path()).is_err());
        assert!(!temp.path().join("state.sqlite3").exists());
    }
    let temp = tempfile::Builder::new()
        .permissions(<std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700))
        .tempdir()
        .unwrap();
    std::fs::create_dir(temp.path().join(".initialization-lock")).unwrap();
    assert!(Store::initialize(temp.path()).is_err());
    assert!(!temp.path().join("state.sqlite3").exists());
    assert!(temp.path().join(".initialization-lock").exists());
}

#[tokio::test]
async fn sse_enforces_room_account_scope_cursor_and_revocation() {
    let (_temp, store) = setup();
    let mut events = vec![message(
        "other",
        "allowed",
        "foreign",
        0,
        1,
        Some("private"),
    )];
    for pos in 1..=260 {
        events.push(message(
            "mine",
            "denied",
            &format!("denied-{pos}"),
            0,
            pos,
            Some("private"),
        ));
    }
    events.push(message(
        "mine",
        "allowed",
        "first",
        0,
        261,
        Some("text must not be in notification"),
    ));
    events.push(message(
        "mine",
        "allowed",
        "second",
        0,
        262,
        Some("also private"),
    ));
    import(&store, &events).unwrap();
    let credential = token(&store, "mine", Some(&["allowed"]), &[Scope::Messages]);
    let app = api::router(store.clone());
    let open = |last: Option<String>| {
        let app = app.clone();
        let secret = credential.token.clone();
        async move {
            let mut req = Request::builder()
                .uri("/v1/events")
                .header("Authorization", format!("Bearer {secret}"));
            if let Some(last) = last {
                req = req.header("Last-Event-ID", last);
            }
            app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap()
        }
    };
    let response = open(None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let mut body = response.into_body();
    let bytes = tokio::time::timeout(std::time::Duration::from_secs(5), body.frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(text.contains("first"));
    assert!(!text.contains("private"));
    assert!(!text.contains("foreign"));
    assert!(!text.contains("denied"));
    let cursor = text
        .lines()
        .find_map(|line| line.strip_prefix("id:").map(str::trim))
        .unwrap()
        .to_owned();
    drop(body);
    let mut resumed = open(Some(cursor)).await.into_body();
    let next = resumed.frame().await.unwrap().unwrap().into_data().unwrap();
    assert!(String::from_utf8(next.to_vec()).unwrap().contains("second"));
    // Consumers must invalidate cached text when a newer unsupported revision
    // removes its projection, just as they do for deletion notifications.
    Connection::open(_temp.path().join("state.sqlite3")).unwrap().execute(
        "INSERT INTO outbox(account_id,room_id,entity_id,kind,revision,source) VALUES('mine','allowed','second','message_projection_removed',1,'native_loco')",[]).unwrap();
    let removed = tokio::time::timeout(std::time::Duration::from_secs(5), resumed.frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert!(String::from_utf8(removed.to_vec())
        .unwrap()
        .contains("message_projection_removed"));
    store
        .token_revoke(&credential.metadata.id, chrono::Utc::now().timestamp())
        .unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(5), resumed.frame())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(open(None).await.status(), StatusCode::UNAUTHORIZED);
    let limited = token(&store, "mine", None, &[Scope::Status]);
    assert_eq!(
        request(&app, "/v1/events", Some(&limited.token)).await.0,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn message_filters_sender_names_single_lookup_and_acl() {
    let (_dir, store) = setup();
    let mut a = message("account", "room-a", "m1", 1, 1, Some("test text"));
    a["payload"]["sent_at_ms"] = json!(1000);
    let mut b = message("account", "room-b", "m2", 1, 2, Some("test text"));
    b["payload"]["sent_at_ms"] = json!(2000);
    let mut c = message("account", "room-a", "m3", 1, 3, Some("test text"));
    c["payload"]["sender_id"] = json!("other");
    c["payload"]["sent_at_ms"] = json!(2000);
    let friend = json!({"schema_version":1,"account_id":"account","event_id":"friend","source":"offline_import","stream_id":"s","position":4,"cursor":"4","payload":{"type":"friend","user_id":"user","revision":1,"display_name":"Phone contact","name_source":"synthetic_contact","observed_at_ms":3000}});
    let other_account = json!({"schema_version":1,"account_id":"another","event_id":"friend","source":"offline_import","stream_id":"s","position":1,"cursor":"1","payload":{"type":"friend","user_id":"user","revision":1,"display_name":"Do not leak","name_source":"synthetic_contact","observed_at_ms":3000}});
    import(&store, &[a, b, c, friend, other_account]).unwrap();
    let full = token(&store, "account", None, &[Scope::Messages, Scope::Friends]);
    let narrow = token(&store, "account", Some(&["room-a"]), &[Scope::Messages]);
    let router = api::router(store);
    let (status, result) = request(
        &router,
        "/v1/messages?sender_id=user&from_ms=1000&to_ms=2000&limit=1",
        Some(&full.token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(result["items"][0]["sender_name"], "Phone contact");
    assert_eq!(result["items"][0]["message_id"], "m1");
    let cursor = result["next_cursor"].as_str().unwrap();
    let (_, next) = request(
        &router,
        &format!("/v1/messages?sender_id=user&from_ms=1000&to_ms=2000&limit=1&cursor={cursor}"),
        Some(&full.token),
    )
    .await;
    assert_eq!(next["items"][0]["message_id"], "m2");
    assert_eq!(
        request(
            &router,
            &format!("/v1/messages?sender_id=other&cursor={cursor}"),
            Some(&full.token)
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let (_, restricted) =
        request(&router, "/v1/messages?sender_id=user", Some(&narrow.token)).await;
    assert_eq!(restricted["items"].as_array().unwrap().len(), 1);
    assert!(restricted["items"][0]["sender_name"].is_null());
    assert_eq!(
        request(&router, "/v1/messages?room_id=room-b", Some(&narrow.token))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let (_, item) = request(&router, "/v1/rooms/room-a/messages/m1", Some(&full.token)).await;
    assert_eq!(item["sender_name_source"], "synthetic_contact");
    assert_eq!(
        request(&router, "/v1/rooms/room-b/messages/m2", Some(&narrow.token))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(
            &router,
            "/v1/rooms/room-a/messages/missing",
            Some(&full.token)
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let (_, room) = request(
        &router,
        "/v1/rooms/room-a/messages?sender_id=other&from_ms=2000&to_ms=2000",
        Some(&full.token),
    )
    .await;
    assert_eq!(room["items"].as_array().unwrap().len(), 1);
    assert!(room["items"][0]["sender_name"].is_null());
    assert_eq!(
        request(&router, "/v1/messages?from_ms=3&to_ms=2", Some(&full.token))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        request(&router, "/v1/search", Some(&full.token)).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        request(&router, "/v1/messages", None).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn attachments_are_metadata_only_and_content_requires_account_room_and_scopes() {
    let (dir, store) = setup();
    let conn = Connection::open(dir.path().join("state.sqlite3")).unwrap();
    conn.execute(
        "INSERT INTO message_media VALUES('42',7,100,0,2,1700000000000,43,?1,'native_loco')",
        [r#"{"url":"https://dn.talk.kakao.com/synthetic","k":"synthetic/token","s":10}"#],
    )
    .unwrap();
    let router = api::router(store.clone());
    let read = token(&store, "42", Some(&["7"]), &[Scope::Messages]);
    let full = token(
        &store,
        "42",
        Some(&["8"]),
        &[Scope::Messages, Scope::Attachments],
    );
    let other = token(&store, "99", None, &[Scope::Messages, Scope::Attachments]);
    let content = "/v1/rooms/7/messages/100/attachments/0/content";
    assert_eq!(
        request(&router, content, None).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request(&router, content, Some(&read.token)).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(&router, content, Some(&full.token)).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(&router, content, Some(&other.token)).await.0,
        StatusCode::NOT_FOUND
    );
    let (status, body) = request(
        &router,
        "/v1/rooms/7/messages/100/attachments",
        Some(&read.token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"][0]["available"], true);
    assert!(!body.to_string().contains("synthetic"));
    assert_eq!(
        request(&router, "/v1/attachments", Some(&read.token))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM metadata WHERE key LIKE 'relay_job:%'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    conn.execute("INSERT INTO native_tombstones VALUES('42',7,100,1)", [])
        .unwrap();
    assert_eq!(
        request(
            &router,
            "/v1/rooms/7/messages/100/attachments",
            Some(&read.token)
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
}
