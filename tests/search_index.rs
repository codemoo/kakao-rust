use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use chrono::NaiveDate;
use http_body_util::BodyExt;
use kakao_rust::{api, auth::Scope, device::Catalog, Store};
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::{collections::BTreeSet, io::Cursor};
use tower::ServiceExt;

const DROP_SEARCH: &str = "DROP TRIGGER messages_text_insert; DROP TRIGGER messages_text_update; DROP TRIGGER messages_text_delete; DROP TABLE message_text;";
fn setup() -> (tempfile::TempDir, Store) {
    let temp = tempfile::Builder::new()
        .prefix("kakao-index-test-")
        .permissions(<std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700))
        .tempdir()
        .unwrap();
    let store = Store::initialize(temp.path()).unwrap();
    (temp, store)
}
fn message(
    account: &str,
    room: &str,
    id: &str,
    revision: i64,
    position: i64,
    body: Option<&str>,
) -> Value {
    json!({"schema_version":1,"account_id":account,"event_id":format!("e-{position}"),"source":"offline_import","stream_id":"s","position":position,"cursor":position.to_string(),"payload":{"type":"message","room_id":room,"message_id":id,"revision":revision,"sent_at_ms":1000,"sender_id":"sender","body":body,"deleted":body.is_none(),"source_local_pk":null}})
}
fn import(store: &Store, events: &[Value]) -> kakao_rust::Result<kakao_rust::ingest::ImportReport> {
    store.import_jsonl(Cursor::new(
        events
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    ))
}
fn token(store: &Store, account: &str, rooms: Option<&[&str]>) -> String {
    let now = chrono::Utc::now().timestamp();
    store
        .token_issue(
            "index-test".into(),
            account.into(),
            BTreeSet::from([Scope::Messages, Scope::Status]),
            rooms.map(|r| r.iter().map(|v| v.to_string()).collect()),
            now + 3600,
            now,
        )
        .unwrap()
        .token
}
fn uri(q: &str) -> String {
    format!(
        "/v1/search?{}",
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("q", q)
            .finish()
    )
}
async fn request(router: &Router, uri: &str, token: &str) -> (StatusCode, Value) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap())
}
fn indexed_ids(db: &Connection, term: &str) -> Vec<String> {
    let literal = format!("\"{}\"", term.replace('"', "\"\""));
    db.prepare("SELECT m.message_id FROM message_text CROSS JOIN messages m ON m.rowid=message_text.rowid WHERE message_text MATCH ?1 ORDER BY m.message_id").unwrap().query_map([literal], |r| r.get(0)).unwrap().collect::<Result<_,_>>().unwrap()
}

#[tokio::test]
async fn unicode_and_literals_match_exact_substrings_for_indexed_and_short_queries() {
    let (temp, store) = setup();
    let long = format!("prefix {} suffix", "\"OR 👋 한글_% ".repeat(35));
    assert!(long.len() <= 1024);
    let bodies = [
        "앞부분 한글검색어 뒷부분",
        "Rust rust RUST",
        "👋🌏🚀 emoji 👋",
        "a\"b literal OR NOT NEAR(foo) - + : * \"\"\" quote",
        "école e\u{301}cole percent_% ' OR 1=1 --",
        "spaces   and\nnewlines",
        "ab\0cd\0ef xyz\0abc",
        "\0ab\0",
        "🧑‍💻 developer",
        &long,
        "head\0afterneedle",
    ];
    let events = bodies
        .iter()
        .enumerate()
        .map(|(i, b)| message("a", "r", &format!("m{i}"), 1, i as i64, Some(b)))
        .collect::<Vec<_>>();
    import(&store, &events).unwrap();
    let issued = token(&store, "a", None);
    let router = api::router(store);
    let db = Connection::open(temp.path().join("state.sqlite3")).unwrap();
    for q in [
        "한글검색",
        "글검",
        "한",
        "Rust",
        "rust",
        "RUS",
        "Ru",
        "👋🌏🚀",
        "🌏🚀",
        "👋",
        "a\"b",
        "\"",
        "OR NOT",
        "NEAR(foo)",
        "*",
        " - ",
        "éco",
        "e\u{301}c",
        "_%",
        "percent_%",
        "\"\"\"",
        "' OR 1=1 --",
        "spaces   ",
        "and\nnew",
        "ab\0cd",
        "xyz\0abc",
        "\0ab\0",
        "🧑‍💻",
        "absent",
        "\" OR body:*",
        "\0\0\0",
        "afterneedle",
        "head\0afterneedle",
        "headafterneedle",
        "cdef",
        "cd\0ef",
        long.as_str(),
    ] {
        let (status, response) = request(&router, &uri(q), &issued).await;
        assert_eq!(status, StatusCode::OK, "{q:?}: {response}");
        let actual = response["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["message_id"].as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        let mut expected = bodies
            .iter()
            .enumerate()
            .filter(|(_, b)| b.contains(q))
            .map(|(i, _)| format!("m{i}"))
            .collect::<Vec<_>>();
        expected.sort();
        let baseline = db
            .prepare("SELECT message_id FROM messages WHERE account_id='a' AND deleted=0 AND instr(body,?1)>0 ORDER BY sent_at_ms,room_id,message_id")
            .unwrap()
            .query_map([q], |r| r.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(baseline, expected, "instr baseline: {q:?}");
        assert_eq!(actual, baseline, "{q:?}");
    }
    assert_eq!(indexed_ids(&db, "한글검색"), vec!["m0"]);
    let (_, status) = request(&router, "/v1/status", &issued).await;
    assert_eq!(
        status["capabilities"]["search_index"],
        "fts5_case_sensitive_trigram"
    );
    assert_eq!(status["capabilities"]["search_timeout_seconds"], 2);
}

#[tokio::test]
async fn indexed_acl_filters_keyset_and_cursor_binding_are_applied_before_pagination() {
    let (_temp, store) = setup();
    import(
        &store,
        &[
            message("a", "0-hidden", "hidden", 1, 0, Some("needle secret")),
            message("a", "r", "m1", 1, 1, Some("needle first")),
            message("a", "r", "m2", 1, 2, Some("needle second")),
            message("a", "z", "m3", 1, 3, Some("needle third")),
            message("b", "r", "other", 1, 0, Some("needle other-account")),
        ],
    )
    .unwrap();
    let issued = token(&store, "a", Some(&["r", "z"]));
    let empty = token(&store, "a", Some(&[]));
    let other = token(&store, "b", None);
    let router = api::router(store);
    let base = format!(
        "{}&sender_id=sender&from_ms=1000&to_ms=1000&limit=1",
        uri("needle")
    );
    let (status, first) = request(&router, &base, &issued).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["items"][0]["message_id"], "m1");
    let cursor = first["next_cursor"].as_str().unwrap();
    assert!(!first.to_string().contains("secret"));
    let (_, second) = request(&router, &format!("{base}&cursor={cursor}"), &issued).await;
    assert_eq!(second["items"][0]["message_id"], "m2");
    let next = second["next_cursor"].as_str().unwrap();
    let (_, third) = request(&router, &format!("{base}&cursor={next}"), &issued).await;
    assert_eq!(third["items"][0]["message_id"], "m3");
    assert!(third["next_cursor"].is_null());
    for changed in [
        format!("{}&cursor={cursor}", uri("different")),
        format!("{base}&room_id=r&cursor={cursor}"),
        format!("{}&sender_id=other&cursor={cursor}", uri("needle")),
        format!("{}&from_ms=999&cursor={cursor}", uri("needle")),
    ] {
        assert_eq!(
            request(&router, &changed, &issued).await.0,
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        request(&router, &format!("{base}&cursor={cursor}"), &other)
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        request(
            &router,
            &format!("{}&room_id=0-hidden", uri("needle")),
            &issued
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert!(request(&router, &uri("needle"), &empty).await.1["items"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(request(
        &router,
        &format!("{}&sender_id=absent", uri("needle")),
        &issued
    )
    .await
    .1["items"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(
        request(&router, &format!("{}&to_ms=999", uri("needle")), &issued)
            .await
            .1["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn index_revisions_deletions_replay_and_import_rollback_are_atomic() {
    let (temp, store) = setup();
    let db = Connection::open(temp.path().join("state.sqlite3")).unwrap();
    let original = message("a", "r", "m", 1, 0, Some("original needle"));
    import(&store, std::slice::from_ref(&original)).unwrap();
    assert_eq!(indexed_ids(&db, "original"), vec!["m"]);
    assert_eq!(
        import(&store, std::slice::from_ref(&original))
            .unwrap()
            .replayed,
        1
    );
    import(
        &store,
        &[message("a", "r", "m", 2, 1, Some("edited needle"))],
    )
    .unwrap();
    assert!(indexed_ids(&db, "original").is_empty());
    assert_eq!(indexed_ids(&db, "edited"), vec!["m"]);
    let valid = message("a", "r", "m", 3, 2, Some("rollback needle"));
    let conflict = message("a", "r", "m", 3, 3, Some("conflicting needle"));
    assert!(import(&store, &[valid, conflict]).is_err());
    assert!(indexed_ids(&db, "rollback").is_empty());
    assert!(indexed_ids(&db, "conflicting").is_empty());
    assert_eq!(indexed_ids(&db, "edited"), vec!["m"]);
    assert_eq!(store.sync_cursor("a", "s").unwrap().unwrap().position, 1);
    import(
        &store,
        &[message("a", "r", "m", 1, 2, Some("stale needle"))],
    )
    .unwrap();
    assert!(indexed_ids(&db, "stale").is_empty());
    import(&store, &[message("a", "r", "m", 3, 3, None)]).unwrap();
    assert!(indexed_ids(&db, "edited").is_empty());
    assert!(import(
        &store,
        &[message("a", "r", "m", 4, 4, Some("resurrect needle"))]
    )
    .is_err());
    assert!(indexed_ids(&db, "resurrect").is_empty());
    import(
        &store,
        &[message("a", "r", "physical", 1, 4, Some("physical needle"))],
    )
    .unwrap();
    assert_eq!(indexed_ids(&db, "physical"), vec!["physical"]);
    db.execute("DELETE FROM messages WHERE message_id='physical'", [])
        .unwrap();
    assert!(indexed_ids(&db, "physical").is_empty());
    db.execute(
        "INSERT INTO message_text(message_text) VALUES('integrity-check')",
        [],
    )
    .unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM message_text", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn v2_migration_backfills_only_live_text_preserves_device_and_wire_and_rolls_back_failure() {
    let (temp, store) = setup();
    let catalog: Catalog =
        serde_json::from_str(include_str!("../config/device-catalog.json")).unwrap();
    let device = store
        .device_initialize(&catalog, NaiveDate::from_ymd_opt(2026, 11, 13).unwrap())
        .unwrap();
    let wire = store.qr_wire_initialize(1_700_000_000_000).unwrap();
    import(
        &store,
        &[
            message("a", "r", "live", 1, 0, Some("migration needle")),
            message("a", "r", "gone", 1, 1, None),
        ],
    )
    .unwrap();
    drop(store);
    let db = Connection::open(temp.path().join("state.sqlite3")).unwrap();
    db.execute_batch(DROP_SEARCH).unwrap();
    db.execute_batch("DROP TABLE outgoing_attempts; DROP TABLE outgoing_messages; DROP TABLE blocked_profile_retry; DROP TABLE blocked_profiles; DROP TABLE block_sync_state; DROP TABLE blocked_users; DROP TABLE room_member_origins; DROP TABLE room_identity_context; DROP TABLE domain_tokens; DROP TABLE friend_favorites; DROP TABLE friend_refresh; DROP TABLE pilsner_accounts; DROP TABLE room_active_members; DROP TABLE room_roster_state; DROP TABLE room_read_watermarks; DROP TABLE loco_requests; DROP TABLE message_refresh; DROP TABLE native_tombstones; DROP TABLE room_details; DROP TABLE room_members; DROP TABLE room_refresh; DROP TABLE message_media; DROP TABLE live_status; DROP TABLE loco_inbox; DROP TABLE loco_logs; DROP TABLE loco_rooms; DROP TABLE contact_snapshot_state; DROP TABLE contact_names; DROP TABLE native_friend_profiles; DROP TABLE native_friend_sync; DROP INDEX messages_sender_time; DROP TABLE qr_auth_attempt; PRAGMA user_version=2; CREATE TRIGGER messages_text_insert AFTER INSERT ON messages BEGIN SELECT 1; END;").unwrap();
    assert!(Store::open(temp.path()).is_err());
    assert_eq!(
        db.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM sqlite_master WHERE name IN ('message_text','qr_auth_attempt')",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    db.execute_batch("DROP TRIGGER messages_text_insert")
        .unwrap();
    let migrated = Store::open(temp.path()).unwrap();
    assert_eq!(migrated.device_show().unwrap(), device);
    assert_eq!(migrated.qr_wire_show().unwrap(), wire);
    assert_eq!(
        db.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
            .unwrap(),
        14
    );
    assert_eq!(indexed_ids(&db, "migration"), vec!["live"]);
    assert_eq!(
        db.query_row("SELECT count(*) FROM message_text", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    drop(migrated);
    assert_eq!(
        Store::open(temp.path()).unwrap().device_show().unwrap(),
        device
    );
    assert_eq!(indexed_ids(&db, "migration"), vec!["live"]);
}

#[test]
fn v3_migration_preserves_auth_attempt_and_namespace_backfill() {
    let (temp, store) = setup();
    import(
        &store,
        &[
            message("a", "r", "a", 1, 0, Some("shared needle")),
            message("b", "r", "b", 1, 0, Some("shared needle")),
        ],
    )
    .unwrap();
    drop(store);
    let db = Connection::open(temp.path().join("state.sqlite3")).unwrap();
    db.execute_batch(DROP_SEARCH).unwrap();
    db.execute(
        "INSERT INTO qr_auth_attempt VALUES(1,?1,'stopped',1000,'synthetic_stop',NULL)",
        params!["synthetic-attempt"],
    )
    .unwrap();
    db.execute_batch("DROP TABLE outgoing_attempts; DROP TABLE outgoing_messages; DROP TABLE blocked_profile_retry; DROP TABLE blocked_profiles; DROP TABLE block_sync_state; DROP TABLE blocked_users; DROP TABLE room_member_origins; DROP TABLE room_identity_context; DROP TABLE domain_tokens; DROP TABLE friend_favorites; DROP TABLE friend_refresh; DROP TABLE pilsner_accounts; DROP TABLE room_active_members; DROP TABLE room_roster_state; DROP TABLE room_read_watermarks; DROP TABLE loco_requests; DROP TABLE message_refresh; DROP TABLE native_tombstones; DROP TABLE room_details; DROP TABLE room_members; DROP TABLE room_refresh; DROP TABLE message_media; DROP TABLE live_status; DROP TABLE loco_inbox; DROP TABLE loco_logs; DROP TABLE loco_rooms; DROP TABLE contact_snapshot_state; DROP TABLE contact_names; DROP TABLE native_friend_profiles; DROP TABLE native_friend_sync; DROP INDEX messages_sender_time;").unwrap();
    db.pragma_update(None, "user_version", 3).unwrap();
    let reopened = Store::open(temp.path()).unwrap();
    assert_eq!(
        db.query_row("SELECT attempt_id FROM qr_auth_attempt", [], |r| r
            .get::<_, String>(0))
            .unwrap(),
        "synthetic-attempt"
    );
    assert_eq!(indexed_ids(&db, "shared"), vec!["a", "b"]);
    drop(reopened);
}
