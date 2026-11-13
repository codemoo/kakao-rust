use super::*;

fn packet(body: Document) -> Packet {
    Packet::request(1, "WRITE", body).unwrap()
}

fn reply(body: Document) -> WriteReply {
    parse_reply(&packet(body), 7, 123, 42, "outgoing", "outgoing-extra")
}

fn success() -> Document {
    doc! {"status":0_i32,"chatId":7_i64,"logId":456_i64}
}

#[test]
fn device_hash_uses_wrapping_utf16_and_signed_remainder() {
    assert_eq!(MessageIds::new("", 0).device_hash, 0);
    assert_eq!(MessageIds::new("😀", 0).device_hash, 99);
    assert_eq!(MessageIds::new("polygenelubricants", 0).device_hash, -48);
    assert_eq!(MessageIds::new("polygenelubricants", 1234).last_id, 1152);
}

#[test]
fn same_time_and_rollback_have_strict_clock_and_distinct_ids() {
    let mut ids = MessageIds::new("", 1000);
    assert_eq!(ids.next(1000), 1100);
    assert_eq!(ids.last_time_ms, 1000);
    assert_eq!(ids.next(1000), 1200);
    assert_eq!(ids.last_time_ms, 1001);
    assert_eq!(ids.next(900), 1300);
    assert_eq!(ids.last_time_ms, 1002);
    assert_eq!(ids.next(1800), 1800);
}

#[test]
fn period_wrap_and_increment_overflow_preserve_generator_rules() {
    let mut ids = MessageIds::new("", 2_147_483_500);
    assert_eq!(ids.next(2_147_483_500), 2_147_483_600);
    assert_eq!(ids.next(2_147_483_501), 100);
    assert_eq!(ids.next(2_147_483_547), 0);
    assert_eq!(ids.next(2_147_483_548), 100);
    let mut negative = MessageIds::new("polygenelubricants", 0);
    assert_eq!(negative.next(1), 52);
}

#[test]
fn request_has_exact_fields_and_bson_widths() {
    let body = text_request(7, 123, "synthetic", "{}");
    let expected = doc! {
        "chatId":7_i64,"msgId":123_i64,"msg":"synthetic","type":1_i32,
        "noSeen":true,"extra":"{}","scope":1_i32,"silence":false
    };
    assert_eq!(body, expected);
    let encoded = bson::to_vec(&body).unwrap();
    assert_eq!(
        Document::from_reader(&mut encoded.as_slice()).unwrap(),
        expected
    );
    for client_id in [0, -1] {
        let body = text_request(7, client_id, "synthetic", "");
        assert_eq!(body.len(), 7);
        assert!(!body.contains_key("msgId"));
    }
}

#[test]
fn logical_rejections_require_body_status_even_with_zero_header() {
    assert!(matches!(
        reply(doc! {"status":-321_i32}),
        WriteReply::Rejected(-321)
    ));
    for body in [doc! {}, doc! {"status":0_i64}, doc! {"status":null}] {
        assert!(matches!(reply(body), WriteReply::Invalid));
    }
    let mut packet = packet(success());
    packet.header.status = -99;
    assert!(matches!(
        parse_reply(&packet, 7, 123, 42, "", ""),
        WriteReply::Rejected(-99)
    ));
}

#[test]
fn response_ids_and_types_cannot_rebind_the_pending_send() {
    for (key, value) in [
        ("chatId", Bson::Int64(8)),
        ("chatId", Bson::Int32(7)),
        ("logId", Bson::Int64(0)),
        ("logId", Bson::Int32(456)),
        ("msgId", Bson::Int64(124)),
        ("msgId", Bson::Int64(-1)),
        ("msgId", Bson::Int32(123)),
        ("sendAt", Bson::Int64(1234)),
        ("chatLog", Bson::Array(vec![])),
    ] {
        let mut body = success();
        body.insert(key, value);
        assert!(matches!(reply(body), WriteReply::Invalid), "{key}");
    }
    for (key, value) in [
        ("chatId", Bson::Int64(8)),
        ("logId", Bson::Int64(457)),
        ("authorId", Bson::Int64(43)),
        ("userId", Bson::Int64(43)),
        ("type", Bson::Int32(2)),
        ("scope", Bson::Int64(1)),
        ("threadId", Bson::Int64(44)),
        ("message", Bson::Int32(1)),
        ("msgId", Bson::Int64(124)),
    ] {
        let mut body = success();
        let mut nested = doc! {"chatId":7_i64,"logId":456_i64,"type":1_i32,"prevId":0_i64};
        nested.insert(key, value);
        body.insert("chatLog", nested);
        assert!(matches!(reply(body), WriteReply::Invalid), "nested {key}");
    }
}

#[test]
fn nested_content_has_priority_and_outer_previous_id_wins() {
    let mut body = success();
    body.insert("sendAt", 11_i32);
    body.insert("msgId", 123_i64);
    body.insert("prevId", 3_i64);
    body.insert(
        "chatLog",
        doc! {
            "chatId":7_i64,"logId":456_i64,"authorId":42_i64,"type":1_i32,
            "message":"server text","attachment":"server extra","sendAt":22_i32,
            "msgId":123_i64,"prevId":2_i64
        },
    );
    let WriteReply::Accepted { log_id, log } = reply(body.clone()) else {
        panic!("accepted reply expected")
    };
    assert_eq!(log_id, 456);
    assert_eq!(log.get_i64("logId").unwrap(), 456);
    assert_eq!(log.get_str("message").unwrap(), "server text");
    assert_eq!(log.get_str("attachment").unwrap(), "server extra");
    assert_eq!(log.get_i32("sendAt").unwrap(), 22);
    assert_eq!(log.get_i64("prevId").unwrap(), 3);
    body.remove("prevId");
    let WriteReply::Accepted { log, .. } = reply(body) else {
        panic!("accepted reply expected")
    };
    assert_eq!(log.get_i64("prevId").unwrap(), 2);
    let WriteReply::Accepted { log, .. } = reply(success()) else {
        panic!("accepted reply expected")
    };
    assert_eq!(log.get_str("message").unwrap(), "outgoing");
    assert_eq!(log.get_str("attachment").unwrap(), "outgoing-extra");
    assert_eq!(log.get_i32("sendAt").unwrap(), 0);
    assert_eq!(log.get_i64("msgId").unwrap(), 0);
}

#[test]
fn nested_required_fields_and_nullable_content_follow_wire_shape() {
    let nested = doc! {"chatId":7_i64,"logId":456_i64,"type":1_i32,"prevId":0_i64,"revision":2_i32,"extension":"synthetic"};
    for required in ["chatId", "logId", "type", "prevId"] {
        let mut incomplete = nested.clone();
        incomplete.remove(required);
        let mut body = success();
        body.insert("chatLog", incomplete);
        assert!(matches!(reply(body), WriteReply::Invalid), "{required}");
    }
    let mut body = success();
    body.insert("sendAt", 11_i32);
    body.insert("msgId", 123_i64);
    body.insert("chatLog", nested);
    let WriteReply::Accepted { log, .. } = reply(body) else {
        panic!("accepted reply expected")
    };
    assert_eq!(log.get("message"), Some(&Bson::Null));
    assert_eq!(log.get("attachment"), Some(&Bson::Null));
    assert_eq!(log.get_i32("sendAt").unwrap(), 0);
    assert_eq!(log.get_i64("msgId").unwrap(), 0);
    assert_eq!(log.get_i32("revision").unwrap(), 2);
    assert_eq!(log.get_str("extension").unwrap(), "synthetic");
}
