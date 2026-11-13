//! Observed feature tokens are not completed native feature cursors.
use crate::{Error, Result};
use bson::Document;
use rusqlite::{params, OptionalExtension, Transaction};

fn invalid() -> Error {
    Error::Invalid("invalid domain token notification; previous state retained".into())
}
pub(crate) fn apply(
    tx: &Transaction<'_>,
    account: &str,
    seq: i64,
    command: &str,
    body: &Document,
) -> Result<()> {
    let tokens = if command == "GETTOKEN" {
        let kinds = body.get_array("ts").map_err(|_| invalid())?;
        let values = body.get_array("os").map_err(|_| invalid())?;
        if kinds.len() != values.len() || kinds.len() > 1000 {
            return Err(invalid());
        }
        kinds
            .iter()
            .zip(values)
            .map(|(k, v)| {
                Ok((
                    k.as_i32().ok_or_else(invalid)?,
                    v.as_i64().ok_or_else(invalid)?,
                ))
            })
            .collect::<Result<Vec<_>>>()?
    } else {
        vec![(
            body.get_i32("t").map_err(|_| invalid())?,
            body.get_i64("o").map_err(|_| invalid())?,
        )]
    };
    let mut seen = std::collections::HashSet::new();
    for (kind, token) in tokens {
        if kind <= 0 || token < 0 || !seen.insert(kind) {
            return Err(invalid());
        }
        let previous: Option<i64> = tx
            .query_row(
                "SELECT observed_token FROM domain_tokens WHERE account_id=?1 AND kind=?2",
                params![account, kind],
                |r| r.get(0),
            )
            .optional()?;
        if previous.is_some_and(|old| old >= token) {
            continue;
        }
        tx.execute("INSERT INTO domain_tokens VALUES(?1,?2,?3,?4) ON CONFLICT(account_id,kind) DO UPDATE SET observed_token=excluded.observed_token,capture_sequence=excluded.capture_sequence",params![account,kind,token,seq])?;
        if kind == 4 && token > 0 {
            // A project-level refresh hint. Friend syncTime is NOT the legacy
            // friends/list token and does not acknowledge the native domain.
            tx.execute("INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=CAST(max(CAST(value AS INTEGER),CAST(excluded.value AS INTEGER)) AS TEXT)",params![format!("refresh_request:{account}:friends"),seq.to_string()])?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{loco::codec::Packet, runtime::tests::setup};
    use bson::doc;
    #[test]
    fn feature_tokens_queue_once_and_never_advance_global_cursors() {
        let (_dir, store) = setup();
        for (id, command, body) in [
            (1000, "GETTOKEN", doc! {"ts":[4,18],"os":[50_i64,70_i64]}),
            (0, "SPUSH", doc! {"t":4,"o":50_i64}),
            (1, "SPUSH", doc! {"t":4,"o":49_i64}),
        ] {
            let p = Packet::request(id, command, body).unwrap();
            let seq = store.live_capture("42", "g", &p).unwrap();
            store.live_apply("42", seq, &p).unwrap();
        }
        let requested = store.maintenance_requested("42", "friends").unwrap();
        assert!(requested > 0);
        store.live_replay("42").unwrap();
        assert_eq!(
            store.maintenance_requested("42", "friends").unwrap(),
            requested
        );
        assert_eq!(store.maintenance_requested("99", "friends").unwrap(), 0);
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row("SELECT count(*) FROM loco_inbox WHERE applied=0", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            3
        );
        let p = Packet::request(2, "SPUSH", doc! {"t":4,"o":51_i64}).unwrap();
        let seq = store.live_capture("42", "g", &p).unwrap();
        store.live_apply("42", seq, &p).unwrap();
        assert!(store.maintenance_requested("42", "friends").unwrap() > requested);
    }
    #[test]
    fn malformed_batch_rolls_back_all_tokens_and_refresh_hints() {
        let (_dir, store) = setup();
        for body in [
            doc! {"ts":[4,4],"os":[10_i64,11_i64]},
            doc! {"ts":[4,18],"os":[10_i64,-1_i64]},
            doc! {"ts":[4],"os":[10_i32]},
            doc! {"ts":[4],"os":[]},
        ] {
            let p = Packet::request(1000, "GETTOKEN", body).unwrap();
            let seq = store.live_capture("42", "g", &p).unwrap();
            assert!(store.live_apply("42", seq, &p).is_err());
            assert_eq!(
                store
                    .lock()
                    .unwrap()
                    .query_row("SELECT count(*) FROM domain_tokens", [], |r| r
                        .get::<_, i64>(0))
                    .unwrap(),
                0
            );
            assert_eq!(store.maintenance_requested("42", "friends").unwrap(), 0);
        }
    }
}
