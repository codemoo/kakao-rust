//! Receive-side block-list projection. Native block revisions stay unacknowledged
//! until all identity/recommendation consumers exist; history is never deleted.
use crate::{Error, Result, Store};
use bson::{Bson, Document};
use rusqlite::{params, OptionalExtension, Transaction};
fn invalid() -> Error {
    Error::Invalid("invalid block synchronization; prior state retained".into())
}
fn ids(body: &Document, key: &str) -> Result<Vec<i64>> {
    match body.get(key) {
        None | Some(Bson::Null) => Ok(vec![]),
        Some(Bson::Array(a)) if a.len() <= 100_000 => {
            let mut seen = std::collections::HashSet::new();
            a.iter()
                .map(|v| {
                    v.as_i64()
                        .filter(|id| *id > 0 && seen.insert(*id))
                        .ok_or_else(invalid)
                })
                .collect()
        }
        _ => Err(invalid()),
    }
}
pub(crate) fn apply_profiles(
    tx: &Transaction<'_>,
    account: &str,
    seq: i64,
    body: &Document,
) -> Result<bool> {
    let Some(request) = crate::room_sync::request(tx, account, seq)? else {
        return Ok(false);
    };
    for (channel, key) in [(false, "l"), (true, "pl")] {
        let requested = ids(&request, key)?;
        let empty = vec![];
        let entries = match body.get(key) {
            None | Some(Bson::Null) => &empty,
            Some(Bson::Array(a)) if a.len() <= 100 => a,
            _ => return Err(invalid()),
        };
        let mut seen = std::collections::HashSet::new();
        for value in entries {
            let member = value.as_document().ok_or_else(invalid)?;
            let id = member.get_i64("userId").map_err(|_| invalid())?;
            let name = member.get_str("nickName").map_err(|_| invalid())?;
            if !requested.contains(&id) || !seen.insert(id) || name.len() > 65536 {
                return Err(invalid());
            }
            tx.execute("INSERT INTO blocked_profiles VALUES(?1,?2,?3,?4,?5) ON CONFLICT(account_id,user_id,is_channel) DO UPDATE SET nickname=excluded.nickname,capture_sequence=excluded.capture_sequence WHERE excluded.capture_sequence>blocked_profiles.capture_sequence",params![account,id.to_string(),channel,name,seq])?;
        }
    }
    Ok(true)
}
impl Store {
    pub(crate) fn blocked_profile_request(&self, account: &str) -> Result<Option<Document>> {
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        let now = chrono::Utc::now().timestamp_millis();
        let rows=tx.prepare("SELECT b.user_id,b.is_channel FROM blocked_users b LEFT JOIN blocked_profiles p USING(account_id,user_id,is_channel) LEFT JOIN blocked_profile_retry q USING(account_id,user_id,is_channel) WHERE b.account_id=?1 AND p.user_id IS NULL AND coalesce(q.retry_at_ms,0)<=?2 ORDER BY b.user_id,b.is_channel LIMIT 100")?.query_map(params![account,now],|r|Ok((r.get::<_,String>(0)?,r.get::<_,bool>(1)?)))?.collect::<std::result::Result<Vec<_>,_>>()?;
        if rows.is_empty() {
            return Ok(None);
        }
        let (mut normal, mut channels) = (Vec::new(), Vec::new());
        for (id, channel) in rows {
            let number = id.parse::<i64>().map_err(|_| invalid())?;
            if channel {
                channels.push(number);
            } else {
                normal.push(number);
            }
            tx.execute("INSERT INTO blocked_profile_retry VALUES(?1,?2,?3,?4) ON CONFLICT(account_id,user_id,is_channel) DO UPDATE SET retry_at_ms=excluded.retry_at_ms",params![account,id,channel,now+300_000])?;
        }
        tx.commit()?;
        let mut body = Document::new();
        if !normal.is_empty() {
            body.insert("l", normal);
        }
        if !channels.is_empty() {
            body.insert("pl", channels);
        }
        Ok(Some(body))
    }
}
pub(crate) fn apply(tx: &Transaction<'_>, account: &str, seq: i64, body: &Document) -> Result<()> {
    for (channel, r, f, l, types, deleted) in [
        (false, "r", "f", "l", "ts", "dl"),
        (true, "pr", "pf", "pl", "pts", "pdl"),
    ] {
        let revision = match body.get(r) {
            None | Some(Bson::Null) => None,
            Some(Bson::Int32(v)) => Some(*v),
            _ => return Err(invalid()),
        };
        let full = match body.get(f) {
            None => false,
            Some(Bson::Boolean(v)) => *v,
            _ => return Err(invalid()),
        };
        let added = ids(body, l)?;
        let removed = ids(body, deleted)?;
        let kinds: Vec<i32> = match body.get(types) {
            None | Some(Bson::Null) => vec![],
            Some(Bson::Array(a)) if a.len() <= 100_000 => a
                .iter()
                .map(|v| v.as_i32().ok_or_else(invalid))
                .collect::<Result<_>>()?,
            _ => return Err(invalid()),
        };
        let prior:Option<(Option<i32>,i64)>=tx.query_row("SELECT observed_revision,capture_sequence FROM block_sync_state WHERE account_id=?1 AND is_channel=?2",params![account,channel],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        if prior.is_some_and(|(_, old)| old >= seq) {
            continue;
        }
        // Native revisions are signed opaque observations; receive order, not
        // numeric ordering, determines the current projection.
        if full {
            tx.execute(
                "DELETE FROM blocked_users WHERE account_id=?1 AND is_channel=?2",
                params![account, channel],
            )?;
        } else {
            for id in removed {
                tx.execute("DELETE FROM blocked_users WHERE account_id=?1 AND is_channel=?2 AND user_id=?3",params![account,channel,id.to_string()])?;
            }
        }
        if revision.is_some() {
            for (i, id) in added.iter().enumerate() {
                tx.execute("INSERT INTO blocked_users VALUES(?1,?2,?3,?4,?5) ON CONFLICT(account_id,user_id,is_channel) DO UPDATE SET profile_block=excluded.profile_block,capture_sequence=excluded.capture_sequence",params![account,id.to_string(),channel,kinds.get(i)==Some(&1),seq])?;
            }
        }
        tx.execute("INSERT INTO block_sync_state VALUES(?1,?2,?3,?4,?5) ON CONFLICT(account_id,is_channel) DO UPDATE SET observed_revision=coalesce(excluded.observed_revision,observed_revision),complete=CASE WHEN excluded.complete THEN 1 ELSE complete END,capture_sequence=excluded.capture_sequence",params![account,channel,revision,full && revision.is_some(),seq])?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use crate::{loco::codec::Packet, runtime::tests::setup, Store};
    use bson::{doc, Document};
    #[test]
    fn digest_lookup_is_bounded_request_bound_and_never_changes_relation() {
        let (_d, store) = setup();
        let all: Vec<i64> = (1..=101).collect();
        receive(&store, doc! {"r":1,"f":true,"l":all}).unwrap();
        let req = store.blocked_profile_request("42").unwrap().unwrap();
        assert_eq!(req.get_array("l").unwrap().len(), 100);
        store
            .record_request("42", "g", 1000, "BLMEMBER", &req)
            .unwrap();
        let id = req.get_array("l").unwrap()[0].as_i64().unwrap();
        let p = Packet::request(
            1000,
            "BLMEMBER",
            doc! {"l":[{"userId":id,"nickName":"Digest"}]},
        )
        .unwrap();
        let seq = store.live_capture("42", "g", &p).unwrap();
        store.live_apply("42", seq, &p).unwrap();
        let rest = store.blocked_profile_request("42").unwrap().unwrap();
        assert_eq!(rest.get_array("l").unwrap().len(), 1);
        assert!(store.blocked_profile_request("42").unwrap().is_none());
        let bad = Packet::request(
            1000,
            "BLMEMBER",
            doc! {"pl":[{"userId":id,"nickName":"Wrong scope"}]},
        )
        .unwrap();
        let seq = store.live_capture("42", "g", &bad).unwrap();
        assert!(store.live_apply("42", seq, &bad).is_err());
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row("SELECT count(*) FROM blocked_profiles", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row("SELECT count(*) FROM native_friend_profiles", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    fn receive(store: &Store, body: Document) -> crate::Result<()> {
        let p = Packet::request(0, "BLSYNC", body).unwrap();
        let seq = store.live_capture("42", "g", &p)?;
        store.live_apply("42", seq, &p)
    }
    #[test]
    fn full_and_delta_are_scope_isolated_replayable_and_keep_identity() {
        let (_d, store) = setup();
        store.lock().unwrap().execute("INSERT INTO friends(account_id,user_id,revision,display_name,source,payload_hash) VALUES('42','43',0,'History','native_loco','synthetic')",[]).unwrap();
        receive(
            &store,
            doc! {"r":1,"f":true,"l":[43_i64,44_i64],"ts":[1],"pr":2,"pf":true,"pl":[45_i64]},
        )
        .unwrap();
        receive(&store, doc! {"r":2,"dl":[43_i64],"l":[46_i64]}).unwrap();
        receive(&store, doc! {"r":3,"f":true}).unwrap();

        store.live_replay("42").unwrap();
        let conn = store.lock().unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM blocked_users WHERE is_channel=0",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM blocked_users WHERE is_channel=1",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row("SELECT count(*) FROM friends", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row("SELECT count(*) FROM loco_inbox WHERE applied=0", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            3
        );
    }
    #[test]
    fn invalid_second_scope_rolls_back_and_signed_revision_reset_applies_in_receive_order() {
        let (_d, store) = setup();
        receive(&store, doc! {"r":4,"f":true,"l":[43_i64],"ts":[1]}).unwrap();
        assert!(receive(&store, doc! {"r":5,"f":true,"pr":6,"pl":[9_i32]}).is_err());

        assert!(store
            .lock()
            .unwrap()
            .query_row(
                "SELECT profile_block FROM blocked_users WHERE user_id='43'",
                [],
                |r| r.get::<_, bool>(0)
            )
            .unwrap());
        receive(&store, doc! {"l":[99_i64]}).unwrap();
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row("SELECT count(*) FROM blocked_users", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        receive(&store, doc! {"r":-1,"f":true}).unwrap();
        store.live_replay("42").unwrap();
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
}
