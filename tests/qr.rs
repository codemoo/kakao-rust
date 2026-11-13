//! Synthetic protocol fixtures only, never live credentials or captured messages.
use chrono::NaiveDate;
use kakao_rust::{
    device::Catalog,
    qr::{self, ErrorCode, LoginOutcome, Session, Stage, WireProfile},
    Error, Store,
};
use rusqlite::Connection;
use serde_json::{json, Value};
use std::sync::{Arc, Barrier};
use tempfile::TempDir;
use uuid::Uuid;
fn setup() -> (TempDir, Store, WireProfile) {
    let temp = tempfile::Builder::new()
        .prefix("kakao-qr-test-")
        .permissions(<std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700))
        .tempdir()
        .unwrap();
    let store = Store::initialize(temp.path()).unwrap();
    let catalog: Catalog =
        serde_json::from_str(include_str!("../config/device-catalog.json")).unwrap();
    store
        .device_initialize(&catalog, NaiveDate::from_ymd_opt(2026, 11, 13).unwrap())
        .unwrap();
    let wire = store.qr_wire_initialize(1_700_000_000_000).unwrap();
    (temp, store, wire)
}
fn response(value: Value) -> Vec<u8> {
    serde_json::to_vec(&value).unwrap()
}
fn started(wire: WireProfile) -> Session {
    let mut session = Session::new(wire).unwrap();
    session.prepare_generate(None, 100).unwrap();
    let challenge=session.receive_generate(&response(json!({"status":0,"url":"synthetic://qr?id=synthetic-id","remainingSeconds":120,"unknown":"allowed"})),200).unwrap();
    assert_eq!(challenge.expires_at_ms, 120_200);
    assert_eq!(challenge.expose_qr_url(), "synthetic://qr?id=synthetic-id");
    session
}
fn successful() -> Value {
    json!({"status":0,"user":{"userId":9007199254740993_i64,"countryIso":"KR","accountId":9007199254740995_i64,"displayAccountId":"synthetic-account","future":true},"accessToken":"synthetic-access-NOT-A-REAL-TOKEN","refreshToken":"synthetic-refresh-NOT-A-REAL-TOKEN","tokenType":"Bearer","extra":"ignored"})
}

#[test]
fn deterministic_app_digest_and_literal_identifier_extraction() {
    let uuid = Uuid::parse_str("123e4567-e89b-42d3-a456-426614174000").unwrap();
    assert_eq!(
        qr::derive_wire_uuid(uuid, 1_700_000_000_000).unwrap(),
        "e21f9c1f806633f4f77db29b241fc0d5bfe726ade2fe7b5cb991f8e5df6c7c4c"
    );
    assert_eq!(
        qr::derive_wire_uuid(uuid, -1).unwrap_err().code,
        ErrorCode::InvalidInput
    );
    assert!(qr::derive_wire_uuid(Uuid::nil(), 0).is_err());
    assert!(qr::derive_wire_uuid(uuid, i64::MAX).is_err());
    for (input, expected) in [
        ("not-a-url", None),
        ("synthetic://host?id=abc&other=1", Some("abc&other=1")),
        ("prefixid=oneid=two", Some("one")),
        ("id=", Some("")),
        ("ID=upper", None),
        ("id=%2F%3D", Some("%2F%3D")),
        ("id=one#tail", Some("one#tail")),
    ] {
        assert_eq!(
            qr::extract_qr_id_literal(input).unwrap().as_deref(),
            expected
        );
    }
    assert!(qr::extract_qr_id_literal(&"x".repeat(8193)).is_err());
}

#[test]
fn request_contracts_omit_optional_fields_and_reuse_persistent_wire_identity() {
    let (temp, store, wire) = setup();
    let app = store.device_show().unwrap();
    assert_ne!(wire.uuid(), app.app_instance_id.to_string());
    assert!(matches!(wire.model(), "SM-X710" | "SM-X810"));
    assert_eq!(wire.name(), wire.model());
    assert_eq!(wire.os_version(), "13");
    assert!(!wire.native_auth_ready());
    assert!(!app.native_auth_ready);
    assert!(app.android_id.is_none());
    let generation = serde_json::to_value(wire.generate_request(None).unwrap()).unwrap();
    assert_eq!(
        generation,
        json!({"device":{"name":wire.model(),"uuid":wire.uuid(),"model":wire.model(),"osVersion":"13"}})
    );
    let login = serde_json::to_value(wire.login_request(None).unwrap()).unwrap();
    assert_eq!(login, json!({"device":{"uuid":wire.uuid()}}));
    let cancel = serde_json::to_value(wire.cancel_request(Some("synthetic-id")).unwrap()).unwrap();
    assert_eq!(
        cancel,
        json!({"device":{"uuid":wire.uuid()},"id":"synthetic-id"})
    );
    assert_eq!(
        serde_json::to_value(wire.generate_request(Some("previous")).unwrap()).unwrap()
            ["previousId"],
        "previous"
    );
    assert!(wire.generate_request(Some("")).is_err());
    assert!(wire.login_request(Some(&"a".repeat(4097))).is_err());
    assert!(wire.cancel_request(Some("id\nsecret")).is_err());
    assert_eq!(qr::A_HEADER, "android/26.3.2/ko");
    assert_eq!(qr::REQUEST_METHOD, "POST");
    assert_eq!(qr::GENERATE_PATH, "qrCodeLogin/generate");
    assert_eq!(qr::LOGIN_PATH, "qrCodeLogin/login");
    assert_eq!(qr::CANCEL_PATH, "qrCodeLogin/cancel");
    drop(store);
    let reopened = Store::open(temp.path()).unwrap();
    assert_eq!(reopened.qr_wire_show().unwrap(), wire);
    // No wall-clock/catalog-triggered identity rotation, even with invalid new input.
    assert_eq!(reopened.qr_wire_initialize(-1).unwrap(), wire);
    assert_eq!(reopened.device_show().unwrap(), app);
}

#[test]
fn wire_identity_concurrent_initialization_is_once_per_saved_device() {
    let (temp, store, _) = setup();
    let raw = Connection::open(temp.path().join("state.sqlite3")).unwrap();
    raw.execute("DELETE FROM qr_wire_profile", []).unwrap();
    raw.execute(
        "UPDATE metadata SET value='0' WHERE key='qr_wire_initialized'",
        [],
    )
    .unwrap();
    let barrier = Arc::new(Barrier::new(8));
    let workers = (0..8)
        .map(|index| {
            let path = temp.path().to_path_buf();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let store = Store::open(&path).unwrap();
                barrier.wait();
                store.qr_wire_initialize(1_700_000_000_000 + index).unwrap()
            })
        })
        .collect::<Vec<_>>();
    let profiles = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();
    assert!(profiles.iter().all(|p| p == &profiles[0]));
    assert_eq!(store.qr_wire_show().unwrap(), profiles[0]);
}

#[test]
fn wire_identity_corruption_and_missing_state_never_regenerate() {
    for mutation in [
        "DELETE FROM qr_wire_profile",
        "UPDATE qr_wire_profile SET json='corrupt synthetic'",
        "DELETE FROM metadata WHERE key='qr_wire_initialized'",
        "UPDATE metadata SET value='0' WHERE key='qr_wire_initialized'",
        "UPDATE qr_wire_profile SET json=json_set(json,'$.uuid','BAD')",
        "UPDATE qr_wire_profile SET json=json_set(json,'$.os_version','14')",
        "UPDATE device_profile SET json=json_set(json,'$.app_instance_id','123e4567-e89b-42d3-a456-426614174000')",
    ]{
        let (temp,store,_)=setup();
        let connection=Connection::open(temp.path().join("state.sqlite3")).unwrap();
        connection.execute(mutation,[]).unwrap();
        assert!(store.qr_wire_show().is_err(),"{mutation}");
        assert!(store.qr_wire_initialize(1_800_000_000_000).is_err(),"{mutation}");
    }
    let temp = tempfile::Builder::new()
        .permissions(<std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700))
        .tempdir()
        .unwrap();
    let store = Store::initialize(temp.path()).unwrap();
    assert!(matches!(store.qr_wire_show(), Err(Error::NotFound)));
    assert!(store.qr_wire_initialize(1_700_000_000_000).is_err());
    assert!(matches!(store.qr_wire_show(), Err(Error::NotFound)));
}

#[test]
fn schema_v1_migration_preserves_device_without_implicitly_creating_wire_identity() {
    let (temp, store, wire) = setup();
    let device = store.device_show().unwrap();
    drop(store);
    let raw = Connection::open(temp.path().join("state.sqlite3")).unwrap();
    raw.execute_batch("DROP TABLE outgoing_attempts; DROP TABLE outgoing_messages; DROP TABLE blocked_profile_retry; DROP TABLE blocked_profiles; DROP TABLE block_sync_state; DROP TABLE blocked_users; DROP TABLE room_member_origins; DROP TABLE room_identity_context; DROP TABLE domain_tokens; DROP TABLE friend_favorites; DROP TABLE friend_refresh; DROP TABLE pilsner_accounts; DROP TABLE room_active_members; DROP TABLE room_roster_state; DROP TABLE room_read_watermarks; DROP TABLE loco_requests; DROP TABLE message_refresh; DROP TABLE native_tombstones; DROP TABLE room_details; DROP TABLE room_members; DROP TABLE room_refresh; DROP TABLE message_media; DROP TABLE live_status; DROP TABLE loco_inbox; DROP TABLE loco_logs; DROP TABLE loco_rooms; DROP TABLE contact_snapshot_state; DROP TABLE contact_names; DROP TABLE native_friend_profiles; DROP TABLE native_friend_sync; DROP INDEX messages_sender_time; DROP TABLE qr_auth_attempt; DROP TRIGGER messages_text_insert; DROP TRIGGER messages_text_update; DROP TRIGGER messages_text_delete; DROP TABLE message_text; DROP TABLE qr_wire_profile; DELETE FROM metadata WHERE key='qr_wire_initialized'; PRAGMA user_version=1;").unwrap();
    drop(raw);
    let store = Store::open(temp.path()).unwrap();
    assert_eq!(store.device_show().unwrap(), device);
    assert!(matches!(store.qr_wire_show(), Err(Error::NotFound)));
    let new_wire = store.qr_wire_initialize(1_700_000_000_001).unwrap();
    assert_ne!(new_wire.uuid(), wire.uuid());
    assert_eq!(new_wire.model(), wire.model());
    assert_eq!(store.device_show().unwrap(), device);
}

#[test]
fn approval_passcode_and_success_are_explicit_offline_transitions() {
    let (_temp, _store, wire) = setup();
    let mut session = started(wire.clone());
    assert_eq!(session.stage(), Stage::WaitingApproval);
    assert_eq!(session.next_poll_at_ms(), Some(200));
    let request = serde_json::to_value(session.prepare_login(200).unwrap()).unwrap();
    assert_eq!(
        request,
        json!({"device":{"uuid":wire.uuid()},"id":"synthetic-id"})
    );
    let waiting = session
        .receive_login(
            &response(json!({"status":-150,"nextRequestIntervalInSeconds":3,"unknown":true})),
            250,
        )
        .unwrap();
    match waiting {
        LoginOutcome::Waiting { next_poll_at_ms } => assert_eq!(next_poll_at_ms, 3250),
        _ => panic!("expected waiting"),
    };
    match session.prepare_login(3249) {
        Err(e) => assert_eq!(e.code, ErrorCode::TooEarly),
        Ok(_) => panic!("early request emitted"),
    };
    assert_eq!(session.stage(), Stage::WaitingApproval);
    session.prepare_login(3250).unwrap();
    let outcome=session.receive_login(&response(json!({"status":-100,"nextRequestIntervalInSeconds":2,"remainingSeconds":180,"passcode":"synthetic-1234"})),3300).unwrap();
    match outcome {
        LoginOutcome::Passcode(passcode) => {
            assert_eq!(passcode.expose_passcode(), "synthetic-1234");
            assert_eq!(passcode.expires_at_ms, 183_300);
            assert_eq!(passcode.next_poll_at_ms, 5300);
        }
        _ => panic!("expected passcode"),
    }
    assert_eq!(session.stage(), Stage::PasscodeRequired);
    assert_eq!(session.expires_at_ms(), Some(183_300));
    session.prepare_login(5300).unwrap();
    match session
        .receive_login(&response(successful()), 5400)
        .unwrap()
    {
        LoginOutcome::Authorized(handoff) => {
            assert_eq!(handoff.user.user_id, "9007199254740993");
            assert_eq!(handoff.user.account_id.as_deref(), Some("9007199254740995"));
            assert_eq!(
                handoff.expose_access_token(),
                "synthetic-access-NOT-A-REAL-TOKEN"
            );
            assert_eq!(
                handoff.expose_refresh_token(),
                "synthetic-refresh-NOT-A-REAL-TOKEN"
            );
            assert_eq!(handoff.token_type(), "Bearer");
            assert!(!handoff.native_sync_verified());
        }
        _ => panic!("expected handoff"),
    }
    assert_eq!(session.stage(), Stage::AuthorizationHandoff);
    assert!(session.prepare_login(5500).is_err());
    assert!(session.prepare_generate(None, 5500).is_err());
}

#[test]
fn terminal_statuses_are_redacted_and_never_retry_or_regenerate() {
    let (_temp, _store, wire) = setup();
    for (status, code) in [
        (-151, ErrorCode::Denied),
        (-132, ErrorCode::AllowlistRequired),
        (-101, ErrorCode::LoginConflict),
        (-999, ErrorCode::UnknownStatus),
        (1, ErrorCode::UnknownStatus),
        (-500, ErrorCode::UnknownStatus),
    ] {
        let mut session = started(wire.clone());
        session.prepare_login(200).unwrap();
        let result=session.receive_login(&response(json!({"status":status,"message":"secret server body","accessToken":"sensitive synthetic","passcode":"secret-passcode"})),300);
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("unexpected success"),
        };
        assert_eq!(error.code, code);
        assert_eq!(error.status, Some(status));
        assert!(!format!("{error:?} {error}").contains("secret"));
        assert!(!serde_json::to_string(&error).unwrap().contains("sensitive"));
        assert_eq!(session.stage(), Stage::Stopped);
        assert_eq!(session.terminal_error(), Some(error));
        assert!(session.prepare_login(400).is_err());
        assert!(session.prepare_generate(None, 400).is_err());
        assert_eq!(session.terminal_error(), Some(error));
    }
}

#[test]
fn malformed_missing_and_oversized_responses_stop_without_payload_in_errors() {
    let (_temp, _store, wire) = setup();
    for bytes in [
        b"{\"status\": \"synthetic-secret\"}".to_vec(),
        b"{bad synthetic-secret json".to_vec(),
        response(json!({"accessToken":"synthetic-secret"})),
        response(json!({"status":-150})),
        response(json!({"status":-150,"nextRequestIntervalInSeconds":0})),
        response(json!({"status":-150,"nextRequestIntervalInSeconds":3601})),
        response(json!({"status":-150,"nextRequestIntervalInSeconds":u64::MAX})),
        response(json!({"status":-100,"nextRequestIntervalInSeconds":1,"remainingSeconds":1})),
        response(
            json!({"status":-100,"nextRequestIntervalInSeconds":1,"remainingSeconds":-1,"passcode":"synthetic-secret"}),
        ),
        response(
            json!({"status":-100,"nextRequestIntervalInSeconds":1,"remainingSeconds":86401,"passcode":"synthetic-secret"}),
        ),
        response(
            json!({"status":-100,"nextRequestIntervalInSeconds":1,"remainingSeconds":1,"passcode":"x".repeat(129)}),
        ),
        response(
            json!({"status":0,"user":{"userId":1,"countryIso":"KR"},"accessToken":"synthetic-secret"}),
        ),
        vec![b'x'; 65537],
    ] {
        let mut session = started(wire.clone());
        session.prepare_login(200).unwrap();
        let error = match session.receive_login(&bytes, 300) {
            Err(error) => error,
            Ok(_) => panic!("invalid response accepted"),
        };
        assert_eq!(session.stage(), Stage::Stopped);
        assert!(!format!("{error:?} {error}").contains("synthetic-secret"));
    }
    let mut session = started(wire);
    session.prepare_login(200).unwrap();
    let error = match session.receive_login(b"{}", 300) {
        Err(error) => error,
        Ok(_) => panic!("missing status accepted"),
    };
    assert_eq!(error.code, ErrorCode::MissingStatus);
}

#[test]
fn generation_validation_expiry_clock_and_cancel_are_bounded() {
    let (_temp, _store, wire) = setup();
    for body in [
        json!({"url":"synthetic://qr?id=a","remainingSeconds":1}),
        json!({"status":0,"url":"synthetic://qr?id=","remainingSeconds":1}),
        json!({"status":0,"url":"synthetic://no-id","remainingSeconds":1}),
        json!({"status":0,"url":"synthetic://qr?id=a","remainingSeconds":0}),
        json!({"status":0,"url":"synthetic://qr?id=a","remainingSeconds":u64::MAX}),
        json!({"status":-151}),
    ] {
        let mut session = Session::new(wire.clone()).unwrap();
        session.prepare_generate(None, 0).unwrap();
        assert!(session.receive_generate(&response(body), 0).is_err());
        assert_eq!(session.stage(), Stage::Stopped);
    }
    let mut session = started(wire.clone());
    match session.prepare_login(120_200) {
        Err(error) => assert_eq!(error.code, ErrorCode::Expired),
        Ok(_) => panic!("expired request emitted"),
    };
    let mut session = started(wire.clone());
    session.prepare_login(300).unwrap();
    let error = match session.receive_login(&response(successful()), 299) {
        Err(error) => error,
        Ok(_) => panic!("clock regressed"),
    };
    assert_eq!(error.code, ErrorCode::ClockRegression);
    let mut session = Session::new(wire.clone()).unwrap();
    match session.prepare_generate(None, u64::MAX) {
        Err(error) => assert_eq!(error.code, ErrorCode::Bounds),
        Ok(_) => panic!("unbounded clock"),
    };
    let mut session = started(wire.clone());
    let cancel = serde_json::to_value(session.prepare_cancel(300).unwrap()).unwrap();
    assert_eq!(
        cancel,
        json!({"device":{"uuid":wire.uuid()},"id":"synthetic-id"})
    );
    assert_eq!(session.stage(), Stage::Stopped);
    assert_eq!(session.terminal_error().unwrap().code, ErrorCode::Cancelled);
    assert!(session.prepare_login(400).is_err());
    assert!(session.prepare_cancel(400).is_err());
}
