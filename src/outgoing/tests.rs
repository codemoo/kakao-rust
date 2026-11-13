use super::*;
use crate::loco::codec::Packet;
use bson::doc;
pub(crate) fn setup() -> (tempfile::TempDir, Store, Principal, String) {
    let (dir, store) = crate::runtime::tests::setup();
    let now = chrono::Utc::now().timestamp();
    let token = store
        .token_issue(
            "synthetic sender".into(),
            "42".into(),
            [Scope::MessagesWrite].into(),
            Some(["7".into()].into()),
            now + 3600,
            now,
        )
        .unwrap();
    let principal = store.authenticate(&token.token, now).unwrap();
    store.lock().unwrap().execute("INSERT INTO loco_rooms(account_id,chat_id,cursor,target,read_log_id) VALUES('42',7,100,100,80)",[]).unwrap();
    store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO room_identity_context VALUES('42',7,'MultiChat',0,1)",
            [],
        )
        .unwrap();
    store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO metadata VALUES('write_retry_seconds:42','300')",
            [],
        )
        .unwrap();
    store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO metadata VALUES('text_config:42',?1)",
            [serde_json::json!({"revision":0,"settings":{"keywords":[]}}).to_string()],
        )
        .unwrap();
    store
        .live_phase("42", "g", "connected", None, None)
        .unwrap();
    (dir, store, principal, token.token)
}
pub(crate) fn enqueue(store: &Store, p: &Principal, key: &str) -> SendStatus {
    store
        .enqueue_text(
            p,
            "7",
            key,
            TextInput {
                text: "synthetic send".into(),
            },
            chrono::Utc::now().timestamp_millis(),
        )
        .unwrap()
}
fn dispatch(store: &Store, p: &Principal, key: &str, packet: i32) -> SendStatus {
    let s = enqueue(store, p, key);
    let now = chrono::Utc::now().timestamp_millis();
    let job = store.next_outgoing("42", "g", now).unwrap().unwrap();
    assert!(store
        .prepare_outgoing("42", "g", &job, 123 + packet as i64, packet, now)
        .unwrap());
    s
}
fn apply(store: &Store, generation: &str, packet: Packet) {
    let seq = store.live_capture("42", generation, &packet).unwrap();
    store.live_apply("42", seq, &packet).unwrap();
}
#[test]
fn idempotency_revocation_expiry_and_account_boundaries() {
    let (_dir, store, p, _) = setup();
    let first = enqueue(&store, &p, "key");
    assert_eq!(enqueue(&store, &p, "key").request_id, first.request_id);
    let now = chrono::Utc::now().timestamp_millis();
    assert!(matches!(
        store.enqueue_text(
            &p,
            "7",
            "key",
            TextInput {
                text: "different".into()
            },
            now
        ),
        Err(Error::Conflict(_))
    ));
    let mut other = p.clone();
    other.account_id = "99".into();
    assert!(matches!(
        store.outgoing_status(&other, "7", &first.request_id),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        store.outgoing_status(&p, "8", &first.request_id),
        Err(Error::Forbidden)
    ));
    let job = store.next_outgoing("42", "g", now).unwrap().unwrap();
    store.token_revoke(&p.credential_id, now / 1000).unwrap();
    assert!(!store
        .prepare_outgoing("42", "g", &job, 123, 1, now)
        .unwrap());
    assert!(store.next_outgoing("42", "g", now).unwrap().is_none());
    assert_eq!(
        store
            .outgoing_status(&p, "7", &first.request_id)
            .unwrap()
            .state,
        "cancelled"
    );
    let (_dir, store, p, _) = setup();
    let first = enqueue(&store, &p, "key");
    assert!(store
        .next_outgoing("42", "g", now + 61_000)
        .unwrap()
        .is_none());
    assert_eq!(
        store
            .outgoing_status(&p, "7", &first.request_id)
            .unwrap()
            .state,
        "cancelled"
    );
    store
        .live_phase("42", "g", "reconnecting", None, None)
        .unwrap();
    assert!(matches!(
        store.enqueue_text(
            &p,
            "7",
            "new",
            TextInput {
                text: "text".into()
            },
            now
        ),
        Err(Error::ServiceUnavailable(_))
    ));
}
#[test]
fn reply_and_echo_converge_in_both_orders_without_read_advancement() {
    for echo_first in [false, true] {
        let (_dir, store, p, _) = setup();
        let s = dispatch(&store, &p, "key", 1);
        let log = doc! {"chatId":7_i64,"logId":101_i64,"prevId":100_i64,"type":1,"authorId":42_i64,"msgId":124_i64,"sendAt":1700000000,"message":"synthetic send","attachment":"{}"};
        let echo = Packet::request(55, "MSG", doc! {"chatId":7_i64,"chatLog":log.clone()}).unwrap();
        let reply = Packet::request(
            1,
            "WRITE",
            doc! {"status":0,"chatId":7_i64,"logId":101_i64,"chatLog":log},
        )
        .unwrap();
        if echo_first {
            apply(&store, "g", echo);
            apply(&store, "g", reply);
        } else {
            apply(&store, "g", reply);
            apply(&store, "g", echo);
        }
        store.live_replay("42").unwrap();
        let sent = store.outgoing_status(&p, "7", &s.request_id).unwrap();
        assert_eq!(sent.state, "sent");
        assert_eq!(sent.message_id.as_deref(), Some("101"));
        let conn = store.lock().unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM messages", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM outbox WHERE kind='message_upserted'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row("SELECT read_log_id FROM loco_rooms", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            80
        );
    }
}
#[test]
fn stale_echo_wrong_generation_and_body_rejections_cannot_confirm_send() {
    let (_dir, store, p, _) = setup();
    let s = dispatch(&store, &p, "key", 1);
    apply(
        &store,
        "other",
        Packet::request(1, "WRITE", doc! {"status":0,"chatId":7_i64,"logId":101_i64}).unwrap(),
    );
    apply(&store,"g",Packet::request(44,"MSG",doc!{"chatId":7_i64,"chatLog":{"chatId":7_i64,"logId":99_i64,"prevId":98_i64,"type":1,"authorId":42_i64,"msgId":124_i64,"sendAt":1700000000,"message":"synthetic send"}}).unwrap());
    assert_eq!(
        store.outgoing_status(&p, "7", &s.request_id).unwrap().state,
        "dispatching"
    );
    apply(
        &store,
        "g",
        Packet::request(1, "WRITE", doc! {"status":-203}).unwrap(),
    );
    let status = store.outgoing_status(&p, "7", &s.request_id).unwrap();
    assert_eq!(status.state, "rejected");
    assert_eq!(status.server_status, Some(-203));
    let s = dispatch(&store, &p, "key2", 2);
    apply(
        &store,
        "g",
        Packet::request(2, "WRITE", doc! {"chatId":7_i64,"logId":102_i64}).unwrap(),
    );
    assert_eq!(
        store.outgoing_status(&p, "7", &s.request_id).unwrap().state,
        "unknown"
    );
    store.recover_outgoing("42").unwrap();
    assert!(store
        .next_outgoing("42", "new", chrono::Utc::now().timestamp_millis())
        .unwrap()
        .is_none());
}
#[test]
fn transport_retry_preserves_identity_and_echo_cancels_retry() {
    let (_dir, store, p, _) = setup();
    store
        .capture_native("more_settings", br#"{"available":1048576}"#)
        .unwrap();
    let s = dispatch(&store, &p, "key", 1);
    store
        .outgoing_transport_failure("42", &s.request_id, true)
        .unwrap();
    let now = chrono::Utc::now().timestamp_millis();
    let job = store.next_outgoing("42", "new", now).unwrap().unwrap();
    assert_eq!(job.client_id, Some(124));
    assert!(store
        .prepare_outgoing("42", "new", &job, 124, 1001, now)
        .unwrap());
    // A late captured response remains bound to its original attempt.
    apply(
        &store,
        "g",
        Packet::request(
            1,
            "WRITE",
            doc! {"status":0,"chatId":7_i64,"logId":101_i64,"prevId":100_i64,"sendAt":1700000000},
        )
        .unwrap(),
    );
    store
        .outgoing_transport_failure("42", &s.request_id, true)
        .unwrap();
    assert!(store.next_outgoing("42", "new", now).unwrap().is_none());
    assert_eq!(
        store.outgoing_status(&p, "7", &s.request_id).unwrap().state,
        "sent"
    );
    let s = dispatch(&store, &p, "key2", 2);
    store
        .outgoing_transport_failure("42", &s.request_id, false)
        .unwrap();
    assert_eq!(
        store.outgoing_status(&p, "7", &s.request_id).unwrap().state,
        "unknown"
    );
}
#[tokio::test]
async fn authenticated_api_requires_write_scope_room_acl_and_stable_key() {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    let (_dir, store, p, token) = setup();
    let now = chrono::Utc::now().timestamp();
    let reader = store
        .token_issue(
            "reader".into(),
            "42".into(),
            [Scope::Messages].into(),
            None,
            now + 60,
            now,
        )
        .unwrap();
    let router = crate::api::router(store.clone());
    for (credential, room, key, expected) in [
        (&reader.token, "7", Some("k"), StatusCode::FORBIDDEN),
        (&token, "8", Some("k"), StatusCode::FORBIDDEN),
        (&token, "7", None, StatusCode::BAD_REQUEST),
        (&token, "7", Some("k"), StatusCode::ACCEPTED),
        (&token, "7", Some("k"), StatusCode::ACCEPTED),
    ] {
        let mut request = Request::builder()
            .method("POST")
            .uri(format!("/v1/rooms/{room}/messages"))
            .header("Authorization", format!("Bearer {credential}"))
            .header("Content-Type", "application/json");
        if let Some(key) = key {
            request = request.header("Idempotency-Key", key);
        }
        let response = router
            .clone()
            .oneshot(
                request
                    .body(Body::from(r#"{"text":"synthetic send"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert!(!String::from_utf8_lossy(&bytes).contains("synthetic send"));
    }
    assert_eq!(
        store
            .lock()
            .unwrap()
            .query_row("SELECT count(*) FROM outgoing_messages", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    store.token_revoke(&p.credential_id, now).unwrap();
}
#[test]
fn sparse_reply_never_fixes_timestamp_to_zero_or_overwrites_rich_echo() {
    for echo_first in [false, true] {
        let (_dir, store, p, _) = setup();
        let s = dispatch(&store, &p, "key", 1);
        let echo=Packet::request(55,"MSG",doc!{"chatId":7_i64,"chatLog":{"chatId":7_i64,"logId":101_i64,"prevId":100_i64,"type":1,"authorId":42_i64,"msgId":124_i64,"sendAt":1700000000,"message":"synthetic send"}}).unwrap();
        let reply =
            Packet::request(1, "WRITE", doc! {"status":0,"chatId":7_i64,"logId":101_i64}).unwrap();
        if echo_first {
            apply(&store, "g", echo);
            apply(&store, "g", reply);
        } else {
            apply(&store, "g", reply);
            assert_eq!(
                store
                    .lock()
                    .unwrap()
                    .query_row("SELECT count(*) FROM messages", [], |r| r.get::<_, i64>(0))
                    .unwrap(),
                0
            );
            apply(&store, "g", echo);
        }
        store.live_replay("42").unwrap();
        assert_eq!(
            store.outgoing_status(&p, "7", &s.request_id).unwrap().state,
            "sent"
        );
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row("SELECT sent_at_ms FROM messages", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1700000000000
        );
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row("SELECT projected FROM loco_logs", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
}
#[test]
fn initial_dispatch_rechecks_settings_and_retries_preserve_payload() {
    let (_dir, store, p, _) = setup();
    let s = enqueue(&store, &p, "key");
    let now = chrono::Utc::now().timestamp_millis();
    let job = store.next_outgoing("42", "g", now).unwrap().unwrap();
    store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO metadata VALUES('text_config_requested:42','1')",
            [],
        )
        .unwrap();
    assert!(!store
        .prepare_outgoing("42", "g", &job, 124, 1, now)
        .unwrap());
    assert_eq!(
        store.outgoing_status(&p, "7", &s.request_id).unwrap().state,
        "queued"
    );
    store.lock().unwrap().execute("UPDATE metadata SET value=?1 WHERE key='text_config:42'",[serde_json::json!({"revision":1,"settings":{"keywords":[{"keywords":["synthetic"]}]}}).to_string()]).unwrap();
    assert!(!store
        .prepare_outgoing("42", "g", &job, 124, 1, now)
        .unwrap());
    assert_eq!(
        store.outgoing_status(&p, "7", &s.request_id).unwrap().state,
        "cancelled"
    );
    assert_eq!(
        store
            .lock()
            .unwrap()
            .query_row("SELECT count(*) FROM outgoing_attempts", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    let (_dir, store, p, _) = setup();
    let s = dispatch(&store, &p, "key", 1);
    store
        .capture_native("more_settings", br#"{"available":1048576}"#)
        .unwrap();
    store
        .outgoing_transport_failure("42", &s.request_id, true)
        .unwrap();
    store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO metadata VALUES('text_config_requested:42','1')",
            [],
        )
        .unwrap();
    let job = store.next_outgoing("42", "new", now).unwrap().unwrap();
    assert!(store
        .prepare_outgoing("42", "new", &job, 124, 2, now)
        .unwrap());
}
#[test]
fn migration_from_thirteen_preserves_credentials_and_rolls_back_on_conflict() {
    let (dir, store, p, _) = setup();
    drop(store);
    let conn = rusqlite::Connection::open(dir.path().join("state.sqlite3")).unwrap();
    conn.execute_batch("DROP TABLE outgoing_attempts; DROP TABLE outgoing_messages; PRAGMA user_version=13; CREATE TABLE outgoing_attempts(x TEXT);").unwrap();
    assert!(Store::open(dir.path()).is_err());
    assert_eq!(
        conn.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
            .unwrap(),
        13
    );
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM sqlite_master WHERE name='outgoing_messages'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    conn.execute_batch("DROP TABLE outgoing_attempts").unwrap();
    let store = Store::open(dir.path()).unwrap();
    assert_eq!(store.token_list().unwrap()[0].id, p.credential_id);
    assert_eq!(
        conn.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
            .unwrap(),
        14
    );
}
