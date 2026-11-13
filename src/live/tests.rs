use super::*;
use crate::loco::transport::Connection;
use bson::doc;
fn setup() -> (tempfile::TempDir, Store) {
    let dir = tempfile::Builder::new()
        .permissions(<std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700))
        .tempdir()
        .unwrap();
    let store = Store::initialize(dir.path()).unwrap();
    (dir, store)
}
fn message(id: i32, log: i64, prev: i64) -> Packet {
    Packet::request(id,"MSG",doc!{"chatId":7_i64,"chatLog":{"chatId":7_i64,"logId":log,"prevId":prev,"type":1,"message":"synthetic new text","authorId":43_i64,"sendAt":1700000000}}).unwrap()
}
#[tokio::test]
async fn interleaved_push_is_durable_before_ack_and_rpc_correlation_survives() {
    let (_dir, store) = setup();
    store
        .live_phase("42", "test", "connected", None, None)
        .unwrap();
    let (a, b) = tokio::io::duplex(8192);
    let mut server = Connection::test_socket(b);
    let (_tx, stop) = watch::channel(false);
    let mut worker = Worker {
        message_ids: Arc::new(std::sync::Mutex::new(
            crate::loco::outgoing::MessageIds::new("synthetic", 1),
        )),
        recovery_scans: Default::default(),
        store: store.clone(),
        account: "42".into(),
        generation: "test".into(),
        socket: Connection::test_socket(a).into_live().unwrap(),
        ids: PacketIds::default(),
        stop,
        write_timeout: Duration::from_secs(20),
        heartbeat: Duration::from_secs(600),
        ping_at: Instant::now() + Duration::from_secs(600),
    };
    let observed = store.clone();
    let task = tokio::spawn(async move {
        let req = server.receive().await.unwrap();
        assert_eq!(req.header.command, "PING");
        server.send(&message(55, 100, 0)).await.unwrap();
        let ack = server.receive().await.unwrap();
        assert_eq!(ack.header.packet_id, 55);
        assert_eq!(ack.header.command, "MSG");
        assert!(!ack.body.get_bool("notiRead").unwrap());
        assert_eq!(
            observed
                .lock()
                .unwrap()
                .query_row(
                    "SELECT count(*) FROM messages WHERE source='native_loco'",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            1
        );
        server
            .send(&Packet::request(req.header.packet_id, "PING", doc! {}).unwrap())
            .await
            .unwrap();
    });
    let (packet, seq) = worker.rpc("PING", doc! {}).await.unwrap();
    store.live_apply("42", seq, &packet).unwrap();
    task.await.unwrap();
    worker.socket.close().await;
    assert!(store
        .live_range("42", &Default::default())
        .unwrap()
        .is_none());
    let rows: Vec<String> = store
        .lock()
        .unwrap()
        .prepare("SELECT command FROM loco_inbox ORDER BY sequence")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<std::result::Result<_, _>>()
        .unwrap();
    assert_eq!(rows, vec!["MSG", "PING"]);
}
#[tokio::test]
async fn outgoing_uses_existing_socket_and_handles_interleaved_self_echo() {
    let (_dir, store, principal, _) = crate::outgoing::tests::setup();
    let queued = crate::outgoing::tests::enqueue(&store, &principal, "wire-test");
    let (a, b) = tokio::io::duplex(8192);
    let mut server = Connection::test_socket(b);
    let (_stop_tx, stop) = watch::channel(false);
    let mut worker = Worker {
        store: store.clone(),
        account: "42".into(),
        generation: "g".into(),
        socket: Connection::test_socket(a).into_live().unwrap(),
        ids: PacketIds::default(),
        stop,
        heartbeat: Duration::from_secs(600),
        write_timeout: Duration::from_secs(20),
        ping_at: Instant::now() + Duration::from_secs(600),
        recovery_scans: Default::default(),
        message_ids: Arc::new(std::sync::Mutex::new(
            crate::loco::outgoing::MessageIds::new("synthetic", 1),
        )),
    };
    let observed = store.clone();
    let server_task = tokio::spawn(async move {
        let request = server.receive().await.unwrap();
        assert_eq!(request.header.command, "WRITE");
        let client_id = request.body.get_i64("msgId").unwrap();
        assert_eq!(
            request.body,
            doc! {"chatId":7_i64,"msgId":client_id,"msg":"synthetic send","type":1_i32,"noSeen":true,"extra":"{}","scope":1_i32,"silence":false}
        );
        assert_eq!(
            observed
                .lock()
                .unwrap()
                .query_row("SELECT state FROM outgoing_messages", [], |r| r
                    .get::<_, String>(0))
                .unwrap(),
            "dispatching"
        );
        let log = doc! {"chatId":7_i64,"logId":101_i64,"prevId":100_i64,"type":1,"authorId":42_i64,"msgId":client_id,"sendAt":1700000000,"message":"synthetic send","attachment":"{}"};
        server
            .send(&Packet::request(55, "MSG", doc! {"chatId":7_i64,"chatLog":log.clone()}).unwrap())
            .await
            .unwrap();
        let ack = server.receive().await.unwrap();
        assert_eq!(ack.header.command, "MSG");
        assert_eq!(ack.header.packet_id, 55);
        assert_eq!(ack.body, doc! {"notiRead":false});
        assert_eq!(
            observed
                .lock()
                .unwrap()
                .query_row("SELECT state FROM outgoing_messages", [], |r| r
                    .get::<_, String>(0))
                .unwrap(),
            "sent"
        );
        server
            .send(
                &Packet::request(
                    request.header.packet_id,
                    "WRITE",
                    doc! {"status":0,"chatId":7_i64,"logId":101_i64,"chatLog":log},
                )
                .unwrap(),
            )
            .await
            .unwrap();
    });
    worker.send_next().await.unwrap();
    server_task.await.unwrap();
    worker.socket.close().await;
    assert_eq!(
        store
            .outgoing_status(&principal, "7", &queued.request_id)
            .unwrap()
            .state,
        "sent"
    );
    assert_eq!(store.live_inputs("42").unwrap(), (vec![7], vec![80]));
}
#[tokio::test]
async fn stalled_write_is_bounded_and_shutdown_preserves_uncertain_outcome() {
    for stop_early in [false, true] {
        let (_dir, store, p, _) = crate::outgoing::tests::setup();
        let s = crate::outgoing::tests::enqueue(&store, &p, "stalled");
        let (a, _unread) = tokio::io::duplex(1);
        let (tx, stop) = watch::channel(false);
        let mut worker = Worker {
            store: store.clone(),
            account: "42".into(),
            generation: "g".into(),
            socket: Connection::test_socket(a).into_live().unwrap(),
            ids: PacketIds::default(),
            stop,
            heartbeat: Duration::from_secs(600),
            write_timeout: Duration::from_millis(40),
            ping_at: Instant::now() + Duration::from_secs(600),
            recovery_scans: Default::default(),
            message_ids: Arc::new(std::sync::Mutex::new(
                crate::loco::outgoing::MessageIds::new("synthetic", 1),
            )),
        };
        let signal = tokio::spawn(async move {
            if stop_early {
                tokio::time::sleep(Duration::from_millis(5)).await;
                tx.send(true).unwrap();
            } else {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });
        let result = tokio::time::timeout(Duration::from_secs(1), worker.send_next())
            .await
            .unwrap();
        assert!(if stop_early {
            matches!(result, Err(Failure::Shutdown))
        } else {
            matches!(result, Err(Failure::Timeout))
        });
        assert_eq!(
            store.outgoing_status(&p, "7", &s.request_id).unwrap().state,
            "unknown"
        );
        worker.socket.close().await;
        signal.await.unwrap();
    }
}
#[test]
fn metadata_business_rejections_preserve_roster_and_do_not_block_replay() {
    let (_dir, store) = setup();
    store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO room_roster_state VALUES('42',7,1,1,0,1000)",
            [],
        )
        .unwrap();
    store
        .lock()
        .unwrap()
        .execute("INSERT INTO room_active_members VALUES('42',7,43)", [])
        .unwrap();
    for (i, command) in ["CHATINFO", "GETMEM", "MEMLIST", "MEMBER"]
        .into_iter()
        .enumerate()
    {
        let packet = Packet::request(i as i32 + 1, command, doc! {"status": -203_i32}).unwrap();
        assert!(!crate::room_sync::response_ok(&packet));
        let seq = store.live_capture("42", "g", &packet).unwrap();
        store.live_apply("42", seq, &packet).unwrap();
    }
    let packet = message(10, 100, 0);
    store.live_capture("42", "g", &packet).unwrap();
    store.live_replay("42").unwrap();
    let conn = store.lock().unwrap();
    assert!(conn
        .query_row(
            "SELECT complete FROM room_roster_state WHERE account_id='42' AND chat_id=7",
            [],
            |r| r.get::<_, bool>(0)
        )
        .unwrap());
    assert_eq!(
        conn.query_row("SELECT count(*) FROM room_active_members", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(conn.query_row("SELECT count(*) FROM loco_inbox WHERE applied=0 AND command IN ('CHATINFO','GETMEM','MEMLIST','MEMBER')", [], |r| r.get::<_, i64>(0)).unwrap(), 4);
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM messages WHERE source='native_loco'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    drop(conn);
    let malformed = Packet::request(12, "MEMLIST", doc! {"status": 0_i32}).unwrap();
    store
        .record_request("42", "g", 12, "MEMLIST", &request::memlist(7))
        .unwrap();
    let seq = store.live_capture("42", "g", &malformed).unwrap();
    assert!(store.live_apply("42", seq, &malformed).is_err());
}

#[test]
fn read_pushes_are_monotonic_and_do_not_change_collection_or_membership() {
    let (_dir, store) = setup();
    store.lock().unwrap().execute("INSERT INTO loco_rooms(account_id,chat_id,cursor,target,read_log_id) VALUES('42',7,100,110,80)",[]).unwrap();
    store
        .lock()
        .unwrap()
        .execute("INSERT INTO room_roster_state VALUES('42',7,0,1,0,0)", [])
        .unwrap();
    store
        .lock()
        .unwrap()
        .execute("INSERT INTO room_active_members VALUES('42',7,43)", [])
        .unwrap();
    for (id, user, mark) in [
        (1, 42, 95),
        (2, 42, 85),
        (3, 43, 99),
        (4, 43, 88),
        (5, 99, 120),
    ] {
        let packet = Packet::request(
            id,
            "DECUNREAD",
            doc! {"chatId":7_i64,"userId":user as i64,"watermark":mark as i64},
        )
        .unwrap();
        let seq = store.live_capture("42", "g", &packet).unwrap();
        store.live_apply("42", seq, &packet).unwrap();
    }
    assert_eq!(
        store
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM room_read_watermarks WHERE user_id=99",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
    store
        .lock()
        .unwrap()
        .execute("UPDATE room_roster_state SET complete=0", [])
        .unwrap();
    let p = Packet::request(
        6,
        "DECUNREAD",
        doc! {"chatId":7_i64,"userId":43_i64,"watermark":150_i64},
    )
    .unwrap();
    let seq = store.live_capture("42", "g", &p).unwrap();
    store.live_apply("42", seq, &p).unwrap();
    let typing = Packet::request(
        5,
        "SYNCACTION",
        doc! {"chatId":7_i64,"userId":43_i64,"type":1,"logId":120_i64},
    )
    .unwrap();
    let seq = store.live_capture("42", "g", &typing).unwrap();
    store.live_apply("42", seq, &typing).unwrap();
    let state = store
        .lock()
        .unwrap()
        .query_row(
            "SELECT cursor,target,read_log_id FROM loco_rooms",
            [],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(state, (100, 110, 95));
    assert_eq!(
        store
            .lock()
            .unwrap()
            .query_row(
                "SELECT watermark FROM room_read_watermarks WHERE user_id=43",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        99
    );
    assert_eq!(
        store
            .lock()
            .unwrap()
            .query_row("SELECT count(*) FROM room_members", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    let left = Packet::request(6, "LEFT", doc! {"chatId":7_i64,"lastTokenId":123_i64}).unwrap();
    let seq = store.live_capture("42", "g", &left).unwrap();
    store.live_apply("42", seq, &left).unwrap();
    assert!(!store
        .lock()
        .unwrap()
        .query_row("SELECT active FROM loco_rooms", [], |r| r.get::<_, bool>(0))
        .unwrap());
    store.live_replay("42").unwrap();
    assert_eq!(
        store
            .lock()
            .unwrap()
            .query_row("SELECT cursor FROM loco_rooms", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        100
    );
}
#[test]
fn malformed_optional_sync_does_not_poison_message_replay() {
    let (_dir, store) = setup();
    for (command, body) in [
        ("BLSYNC", doc! {"r":1,"f":true,"l":[1_i32]}),
        ("GETTOKEN", doc! {"ts":[4],"os":[1_i32]}),
        ("SPUSH", doc! {"t":4,"o":"bad"}),
    ] {
        let p = Packet::request(0, command, body).unwrap();
        let seq = store.live_capture("42", "g", &p).unwrap();
        store.live_apply_optional("42", seq, &p).unwrap();
    }
    let p = message(1, 101, 100);
    store.live_capture("42", "g", &p).unwrap();
    store.live_replay("42").unwrap();
    store.live_replay("42").unwrap();
    assert_eq!(
        store
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM messages WHERE message_id='101'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
    assert_eq!(
        store
            .lock()
            .unwrap()
            .query_row("SELECT count(*) FROM loco_inbox WHERE applied=0", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        3
    );
    assert_eq!(
        store
            .lock()
            .unwrap()
            .query_row("SELECT count(*) FROM blocked_users", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}
#[test]
fn recovery_counts_all_logs_replays_once_and_does_not_raise_read_position() {
    let (_dir, store) = setup();
    store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO loco_rooms(account_id,chat_id,cursor,read_log_id) VALUES('42',7,100,80)",
            [],
        )
        .unwrap();
    let p = message(1, 103, 102);
    let seq = store.live_capture("42", "g1", &p).unwrap();
    store.live_apply("42", seq, &p).unwrap();
    let range = store
        .live_range("42", &Default::default())
        .unwrap()
        .unwrap();
    assert_eq!((range.cur, range.max, range.count), (100, 103, 1));
    let p=Packet::request(1000,"SYNCMSG",doc!{"isOK":true,"chatLogs":[message(0,101,100).body.get_document("chatLog").unwrap().clone(),message(0,102,101).body.get_document("chatLog").unwrap().clone()]}).unwrap();
    let (_, next) = validate_sync(&p, range).unwrap();
    assert_eq!(next, 102);
    let seq = store.live_capture("42", "g1", &p).unwrap();
    store.live_apply("42", seq, &p).unwrap();
    store.live_advance("42", range, next).unwrap();
    let again = message(1, 103, 102);
    let seq = store.live_capture("42", "g2", &again).unwrap();
    store.live_apply("42", seq, &again).unwrap();
    assert!(store
        .live_range("42", &Default::default())
        .unwrap()
        .is_none());
    assert_eq!(store.live_inputs("42").unwrap(), (vec![7], vec![80]));
    let conn = store.lock().unwrap();
    assert_eq!(
        conn.query_row("SELECT count(*) FROM messages", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        3
    );
    assert_eq!(
        conn.query_row("SELECT count(*) FROM outbox", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        3
    );
    let bad = Packet::request(
        0,
        "SYNCMSG",
        doc! {"isOK":true,"chatLogs":[{"chatId":8_i64,"logId":101_i64}]},
    )
    .unwrap();
    assert!(validate_sync(&bad, range).is_err());
}
#[test]
fn unsupported_messages_stay_pending_and_failed_projection_cannot_erase_capture() {
    let (_dir, store) = setup();
    let mut p = message(1, 1, 0);
    p.body
        .get_document_mut("chatLog")
        .unwrap()
        .insert("type", 2);
    let seq = store.live_capture("42", "g", &p).unwrap();
    store.live_apply("42", seq, &p).unwrap();
    assert_eq!(store.live_status("42").unwrap().pending_packets, 1);
    let p=Packet::request(2,"SYNCMSG",doc!{"isOK":true,"chatLogs":[message(0,2,1).body.get_document("chatLog").unwrap().clone(),doc!{"chatId":7_i64}]}).unwrap();
    let seq = store.live_capture("42", "g", &p).unwrap();
    assert!(store.live_apply("42", seq, &p).is_err());
    let conn = store.lock().unwrap();
    assert_eq!(
        conn.query_row("SELECT count(*) FROM native_events", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert_eq!(
        conn.query_row("SELECT count(*) FROM messages", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
}
#[test]
fn restart_replays_captured_messages_and_superseded_text_is_removed() {
    let (dir, store) = setup();
    let p = message(1, 100, 0);
    store.live_capture("42", "old", &p).unwrap();
    drop(store);
    let store = Store::open(dir.path()).unwrap();
    store.live_replay("42").unwrap();
    store.live_replay("42").unwrap();
    assert_eq!(store.live_status("42").unwrap().pending_packets, 0);
    assert!(store
        .live_range("42", &Default::default())
        .unwrap()
        .is_none());
    let mut newer = message(1, 100, 0);
    let log = newer.body.get_document_mut("chatLog").unwrap();
    log.insert("revision", 1);
    log.insert("type", 2);
    let seq = store.live_capture("42", "new", &newer).unwrap();
    store.live_apply("42", seq, &newer).unwrap();
    store.live_replay("42").unwrap();
    let conn = store.lock().unwrap();
    assert_eq!(
        conn.query_row("SELECT count(*) FROM messages", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        conn.query_row("SELECT projected FROM loco_logs", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        conn.query_row("SELECT count(*) FROM outbox", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert!(serde_json::from_str::<crate::ingest::Source>("\"native_loco\"").is_err());
}
#[test]
fn replay_rejects_failed_msg_and_sync_without_success_flag() {
    for mut packet in [
        message(1, 1, 0),
        Packet::request(2, "SYNCMSG", doc! {}).unwrap(),
    ] {
        let (_dir, store) = setup();
        if packet.header.command == "MSG" {
            packet.header.status = -1;
        }
        store.live_capture("42", "old", &packet).unwrap();
        assert!(store.live_replay("42").is_err());
        assert_eq!(store.live_status("42").unwrap().pending_packets, 1);
    }
}
#[tokio::test(flavor = "current_thread")]
async fn dropping_socket_holds_lease_until_reader_task_exits() {
    let (_dir, store) = setup();
    let lease = Arc::new(RuntimeLease::acquire(&store).unwrap());
    let (a, _b) = tokio::io::duplex(8192);
    let live = Connection::test_socket(a)
        .into_live_guarded(Some(lease.clone()))
        .unwrap();
    drop(lease);
    drop(live);
    assert!(RuntimeLease::acquire(&store).is_err());
    tokio::task::yield_now().await;
    assert!(RuntimeLease::acquire(&store).is_ok());
}
#[tokio::test]
async fn partial_response_at_target_requires_final_empty_range_request() {
    let (_dir, store) = setup();
    store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO loco_rooms(account_id,chat_id,cursor,target) VALUES('42',7,10,20)",
            [],
        )
        .unwrap();
    let (a, b) = tokio::io::duplex(8192);
    let mut server = Connection::test_socket(b);
    let (_tx, stop) = watch::channel(false);
    let mut worker = Worker {
        message_ids: Arc::new(std::sync::Mutex::new(
            crate::loco::outgoing::MessageIds::new("synthetic", 1),
        )),
        recovery_scans: Default::default(),
        store: store.clone(),
        account: "42".into(),
        generation: "g".into(),
        socket: Connection::test_socket(a).into_live().unwrap(),
        ids: PacketIds::default(),
        stop,
        write_timeout: Duration::from_secs(20),
        heartbeat: Duration::from_secs(600),
        ping_at: Instant::now() + Duration::from_secs(600),
    };
    let observed = store.clone();
    let task = tokio::spawn(async move {
        let first = server.receive().await.unwrap();
        assert_eq!(first.body.get_i64("cur").unwrap(), 10);
        server.send(&Packet::request(first.header.packet_id,"SYNCMSG",doc!{"isOK":false,"chatLogs":[message(0,20,10).body.get_document("chatLog").unwrap().clone()]}).unwrap()).await.unwrap();
        let final_request = server.receive().await.unwrap();
        assert_eq!(
            final_request.body,
            doc! {"chatId":7_i64,"cur":20_i64,"max":20_i64,"cnt":0}
        );
        assert_eq!(
            observed
                .live_range("42", &Default::default())
                .unwrap()
                .unwrap()
                .cur,
            10
        );
        server
            .send(
                &Packet::request(
                    final_request.header.packet_id,
                    "SYNCMSG",
                    doc! {"isOK":true,"chatLogs":bson::Bson::Null},
                )
                .unwrap(),
            )
            .await
            .unwrap();
    });
    worker
        .catch_up(
            store
                .live_range("42", &Default::default())
                .unwrap()
                .unwrap(),
        )
        .await
        .unwrap();
    task.await.unwrap();
    worker.socket.close().await;
    assert!(store
        .live_range("42", &Default::default())
        .unwrap()
        .is_none());
}
#[test]
fn rejected_login_replay_and_deferred_history_do_not_block_other_work() {
    let (_dir, store) = setup();
    let mut rejected = Packet::request(1, "LOGINLIST", doc! {}).unwrap();
    rejected.header.status = -950;
    store.live_capture("42", "old", &rejected).unwrap();
    let mut incomplete = message(2, 20, 10);
    incomplete
        .body
        .get_document_mut("chatLog")
        .unwrap()
        .remove("message");
    let old = store.live_capture("42", "old", &incomplete).unwrap();
    store.live_apply("42", old, &incomplete).unwrap();
    let complete = message(3, 20, 10);
    let latest = store.live_capture("42", "new", &complete).unwrap();
    store.live_apply("42", latest, &complete).unwrap();
    store.live_replay("42").unwrap();
    let conn = store.lock().unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT capture_sequence,projected FROM loco_logs",
            [],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
        )
        .unwrap(),
        (latest, 1)
    );
    conn.execute(
        "INSERT INTO loco_rooms(account_id,chat_id,target) VALUES('42',8,30)",
        [],
    )
    .unwrap();
    drop(conn);
    let deferred = std::collections::HashSet::from([7_i64]);
    assert_eq!(store.live_range("42", &deferred).unwrap().unwrap().chat, 8);
    assert_eq!(store.live_status("42").unwrap().pending_rooms, 2);
}
#[test]
fn sync_empty_and_partial_failure_rules_do_not_skip_ranges() {
    let range = Range {
        chat: 7,
        cur: 10,
        max: 30,
        count: 0,
        target: 30,
    };
    let p = Packet::request(1, "SYNCMSG", doc! {"isOK":true}).unwrap();
    assert_eq!(validate_sync(&p, range).unwrap(), (true, 30));
    let null =
        Packet::request(1, "SYNCMSG", doc! {"isOK":true,"chatLogs":bson::Bson::Null}).unwrap();
    assert_eq!(validate_sync(&null, range).unwrap(), (true, 30));
    let (_dir, store) = setup();
    let seq = store.live_capture("42", "null-list", &null).unwrap();
    store.live_apply("42", seq, &null).unwrap();
    let p = Packet::request(1, "SYNCMSG", doc! {"isOK":false}).unwrap();
    assert_eq!(validate_sync(&p, range).unwrap(), (false, 10));
    let p = Packet::request(
        1,
        "SYNCMSG",
        doc! {"isOK":false,"chatLogs":[{"chatId":7_i64,"logId":20_i64}]},
    )
    .unwrap();
    assert_eq!(validate_sync(&p, range).unwrap(), (false, 20));
}
