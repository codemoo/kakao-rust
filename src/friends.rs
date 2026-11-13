//! Friend list synchronization. Phone contact labels are a separate source:
//! never relabel friendNickName as a phone contact name.
use crate::{
    native_http::{Client, Operation},
    runtime::{RuntimeLease, StepState},
    Error, Result, Store,
};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::HashSet, sync::Arc};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SyncResponse {
    status: i32,
    sync_time: i64,
    total: i32,
    friends: Vec<Value>,
    channels: Vec<Value>,
    purged_friends: Vec<Value>,
    new_badges: std::collections::HashMap<i32, i64>,
}
// Required DTO fields are validated even when not exposed by the read API.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct User {
    user_id: i64,
    account_id: i64,
    user_type: i32,
    #[serde(rename = "type")]
    relation: i32,
    suspended: bool,
    memorial: bool,
    nick_name: String,
    status_message: String,
    screen_token: i64,
    profile_image_url: String,
    full_profile_image_url: String,
    original_profile_image_url: String,
    phone_number: String,
    friend_nick_name: Option<String>,
    hidden: Option<bool>,
    purged: Option<bool>,
    favorite: Option<bool>,
}
fn invalid() -> Error {
    Error::Invalid("invalid friends response; sync cursor unchanged".into())
}
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct SyncStatus {
    pub since: i64,
    pub remote_total: i64,
    pub local_total: i64,
    pub reconciled: bool,
    pub identities_received: usize,
    pub contact_names_available: bool,
    #[serde(skip)]
    capture_sequence: i64,
    #[serde(skip)]
    sync_time: i64,
}
impl Store {
    pub(crate) fn friends_since(&self, account: &str) -> Result<i64> {
        Ok(self
            .lock()?
            .query_row(
                "SELECT since FROM native_friend_sync WHERE account_id=?1",
                [account],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(0))
    }
    /// Raw response, profiles, names, outbox, and cursor share one commit. Count
    /// mismatch leaves since=0 and preserves identities for later reconciliation.
    pub(crate) fn apply_friends(
        &self,
        account: &str,
        requested_since: i64,
        body: &[u8],
        country: &str,
    ) -> Result<SyncStatus> {
        let response: SyncResponse = serde_json::from_slice(body).map_err(|_| invalid())?;
        if response.status != 0
            || response.sync_time < requested_since
            || response.total < 0
            || response.friends.len() + response.channels.len() + response.purged_friends.len()
                > 100_000
        {
            return Err(invalid());
        }
        let _ = &response.new_badges; // Retained raw; badge subsystem is not marked applied.
        let mut users = Vec::new();
        let mut full_members = HashSet::new();
        let mut deactivated = 0;
        for (rows, channel, primary) in [
            (&response.friends, false, true),
            (&response.purged_friends, false, false),
            (&response.channels, true, false),
        ] {
            for raw in rows {
                let user: User = serde_json::from_value(raw.clone()).map_err(|_| invalid())?;
                if user.user_id <= 0
                    || user.nick_name.len() > 4096
                    || user
                        .friend_nick_name
                        .as_ref()
                        .is_some_and(|s| s.len() > 4096)
                {
                    return Err(invalid());
                }
                if primary || channel {
                    full_members.insert(user.user_id.to_string());
                }
                if primary && user.relation == 9 {
                    deactivated += 1;
                }
                // Validated and retained privately, not returned as contact/API data.
                let _ = (
                    &user.account_id,
                    &user.user_type,
                    &user.suspended,
                    &user.memorial,
                    &user.status_message,
                    &user.screen_token,
                    &user.profile_image_url,
                    &user.full_profile_image_url,
                    &user.original_profile_image_url,
                    &user.phone_number,
                );
                users.push((user, channel, serde_json::to_string(raw)?));
            }
        }
        let remote_total = i64::from(response.total) - deactivated;
        if remote_total < 0 {
            return Err(invalid());
        }
        let now = chrono::Utc::now().timestamp_millis();
        let mut conn = self.lock()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let current: i64 = tx
            .query_row(
                "SELECT since FROM native_friend_sync WHERE account_id=?1",
                [account],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(0);
        if current != requested_since {
            return Err(Error::Conflict(
                "friend cursor changed during request".into(),
            ));
        }
        tx.execute(
            "INSERT INTO native_events(source,received_at_ms,payload) VALUES('friends_sync',?1,?2)",
            params![now, body],
        )?;
        let sequence = tx.last_insert_rowid();
        for (user, channel, raw) in &users {
            let profile_name = user.nick_name.trim();
            let friend_name = user
                .friend_nick_name
                .as_deref()
                .filter(|v| !v.trim().is_empty());
            let user_id = user.user_id.to_string();
            let is_current = matches!(user.relation, 1..=3)
                && (requested_since != 0 || full_members.contains(&user_id));
            let phone_key = crate::contacts::phone_key(&user.phone_number, country);
            tx.execute("INSERT INTO native_friend_profiles(account_id,user_id,relation,is_channel,profile_name,friend_name,hidden,purged,raw_json,capture_sequence,is_current,phone_key) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12) ON CONFLICT(account_id,user_id) DO UPDATE SET relation=excluded.relation,is_channel=excluded.is_channel,profile_name=excluded.profile_name,friend_name=excluded.friend_name,hidden=excluded.hidden,purged=excluded.purged,raw_json=excluded.raw_json,capture_sequence=excluded.capture_sequence,is_current=excluded.is_current,phone_key=excluded.phone_key", params![account,user_id,user.relation,channel,profile_name,friend_name,user.hidden.unwrap_or(false),user.purged.unwrap_or(false),raw,sequence,is_current,phone_key])?;
            save_favorite(&tx, account, &user_id, user.favorite, sequence)?;
        }
        if requested_since == 0 {
            let members = serde_json::to_string(&full_members)?;
            let mut stmt = tx.prepare("SELECT user_id FROM native_friend_profiles WHERE account_id=?1 AND is_current=1 AND user_id NOT IN (SELECT value FROM json_each(?2))")?;
            let omitted = stmt
                .query_map(params![account, members], |r| r.get::<_, String>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            drop(stmt);
            for id in omitted {
                tx.execute("UPDATE native_friend_profiles SET is_current=0,capture_sequence=?3 WHERE account_id=?1 AND user_id=?2",params![account,id,sequence])?;
            }
        }
        // Phone ownership can change even for an identity omitted in this delta.
        // Reproject after the complete batch so ambiguity never sees partial state.
        let ids = tx
            .prepare("SELECT user_id FROM native_friend_profiles WHERE account_id=?1")?
            .query_map([account], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for id in ids {
            project_name(&tx, account, &id, sequence, now)?;
        }
        let local_total: i64 = tx.query_row(
            "SELECT count(*) FROM native_friend_profiles WHERE account_id=?1 AND is_current=1",
            [account],
            |r| r.get(0),
        )?;
        let reconciled = local_total == remote_total;
        let since = if reconciled { response.sync_time } else { 0 };
        tx.execute("INSERT INTO native_friend_sync(account_id,since,remote_total,local_total,reconciled,observed_at_ms,capture_sequence) VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(account_id) DO UPDATE SET since=excluded.since,remote_total=excluded.remote_total,local_total=excluded.local_total,reconciled=excluded.reconciled,observed_at_ms=excluded.observed_at_ms,capture_sequence=excluded.capture_sequence",params![account,since,remote_total,local_total,reconciled,now,sequence])?;
        tx.commit()?;
        drop(conn);
        Ok(SyncStatus {
            since,
            remote_total,
            local_total,
            reconciled,
            identities_received: users.len(),
            capture_sequence: sequence,
            sync_time: response.sync_time,
            contact_names_available: self.lock()?.query_row(
                "SELECT EXISTS(SELECT 1 FROM contact_snapshot_state WHERE account_id=?1)",
                [account],
                |r| r.get(0),
            )?,
        })
    }
}
#[derive(Deserialize)]
struct DiffResponse {
    #[serde(default)]
    added_friends: Option<Vec<Value>>,
    #[serde(default)]
    deleted_ids: Option<Vec<i64>>,
}
impl Store {
    fn friend_ids(&self, account: &str) -> Result<Vec<i64>> {
        let conn = self.lock()?;
        let mut statement=conn.prepare("SELECT CAST(user_id AS INTEGER) FROM native_friend_profiles WHERE account_id=?1 AND is_current=1 ORDER BY CAST(user_id AS INTEGER)")?;
        let ids = statement
            .query_map([account], |row| row.get(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if ids.len() > 100_000 {
            return Err(invalid());
        }
        Ok(ids)
    }
    fn apply_friends_diff(
        &self,
        account: &str,
        pending: &SyncStatus,
        body: &[u8],
        country: &str,
    ) -> Result<SyncStatus> {
        let diff: DiffResponse = serde_json::from_slice(body).map_err(|_| invalid())?;
        let added = diff.added_friends.unwrap_or_default();
        let deleted = diff.deleted_ids.unwrap_or_default();
        if added.len() + deleted.len() > 100_000 || deleted.iter().any(|id| *id <= 0) {
            return Err(invalid());
        }
        let mut users = Vec::new();
        for raw in added {
            let user: User = serde_json::from_value(raw.clone()).map_err(|_| invalid())?;
            if user.user_id <= 0
                || user.nick_name.len() > 4096
                || user
                    .friend_nick_name
                    .as_ref()
                    .is_some_and(|s| s.len() > 4096)
            {
                return Err(invalid());
            }
            if user.user_type != 9 {
                users.push((user, serde_json::to_string(&raw)?));
            }
        }
        let now = chrono::Utc::now().timestamp_millis();
        let mut conn = self.lock()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let current:(i64,bool,i64)=tx.query_row("SELECT capture_sequence,reconciled,remote_total FROM native_friend_sync WHERE account_id=?1",[account],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
        if current != (pending.capture_sequence, false, pending.remote_total) {
            return Err(Error::Conflict("friend diff snapshot changed".into()));
        }
        tx.execute(
            "INSERT INTO native_events(source,received_at_ms,payload) VALUES('friends_diff',?1,?2)",
            params![now, body],
        )?;
        let sequence = tx.last_insert_rowid();
        for (user, raw) in &users {
            let id = user.user_id.to_string();
            let channel = matches!(user.user_type, 1 | 2);
            let profile = user.nick_name.trim();
            let name = user
                .friend_nick_name
                .as_deref()
                .filter(|s| !s.trim().is_empty());
            let phone = crate::contacts::phone_key(&user.phone_number, country);
            tx.execute("INSERT INTO native_friend_profiles(account_id,user_id,relation,is_channel,profile_name,friend_name,hidden,purged,raw_json,capture_sequence,is_current,phone_key) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12) ON CONFLICT(account_id,user_id) DO UPDATE SET relation=excluded.relation,is_channel=excluded.is_channel,profile_name=excluded.profile_name,friend_name=excluded.friend_name,hidden=excluded.hidden,purged=excluded.purged,raw_json=excluded.raw_json,capture_sequence=excluded.capture_sequence,is_current=excluded.is_current,phone_key=excluded.phone_key",params![account,id,user.relation,channel,profile,name,user.hidden.unwrap_or(false),user.purged.unwrap_or(false),raw,sequence,matches!(user.relation,1..=3),phone])?;
            save_favorite(&tx, account, &id, user.favorite, sequence)?;
        }
        for id in deleted {
            tx.execute("UPDATE native_friend_profiles SET is_current=0,capture_sequence=?3 WHERE account_id=?1 AND user_id=?2",params![account,id.to_string(),sequence])?;
        }
        let ids = tx
            .prepare("SELECT user_id FROM native_friend_profiles WHERE account_id=?1")?
            .query_map([account], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for id in ids {
            project_name(&tx, account, &id, sequence, now)?;
        }
        let local: i64 = tx.query_row(
            "SELECT count(*) FROM native_friend_profiles WHERE account_id=?1 AND is_current=1",
            [account],
            |r| r.get(0),
        )?;
        let reconciled = local == pending.remote_total;
        let since = if reconciled { pending.sync_time } else { 0 };
        tx.execute("UPDATE native_friend_sync SET since=?2,local_total=?3,reconciled=?4,observed_at_ms=?5,capture_sequence=?6 WHERE account_id=?1",params![account,since,local,reconciled,now,sequence])?;
        tx.commit()?;
        Ok(SyncStatus {
            since,
            remote_total: pending.remote_total,
            local_total: local,
            reconciled,
            identities_received: pending.identities_received + users.len(),
            contact_names_available: pending.contact_names_available,
            capture_sequence: sequence,
            sync_time: pending.sync_time,
        })
    }
}

fn save_favorite(
    tx: &rusqlite::Transaction<'_>,
    account: &str,
    id: &str,
    favorite: Option<bool>,
    seq: i64,
) -> Result<()> {
    if let Some(favorite) = favorite {
        tx.execute("INSERT INTO friend_favorites VALUES(?1,?2,?3,?4) ON CONFLICT(account_id,user_id) DO UPDATE SET favorite=excluded.favorite,capture_sequence=excluded.capture_sequence WHERE excluded.capture_sequence>friend_favorites.capture_sequence",params![account,id,favorite,seq])?;
    }
    Ok(())
}
impl Store {
    fn apply_friend(
        &self,
        account: &str,
        id: i64,
        requested: i64,
        body: &[u8],
        country: &str,
    ) -> Result<()> {
        let value: Value = serde_json::from_slice(body).map_err(|_| invalid())?;
        if value.get("status").and_then(Value::as_i64) != Some(0) {
            return Err(invalid());
        }
        let raw = value.get("friend").ok_or_else(invalid)?;
        let user: User = serde_json::from_value(raw.clone()).map_err(|_| invalid())?;
        if user.user_id != id
            || id <= 0
            || user.nick_name.len() > 4096
            || user
                .friend_nick_name
                .as_ref()
                .is_some_and(|s| s.len() > 4096)
        {
            return Err(invalid());
        }
        let now = chrono::Utc::now().timestamp_millis();
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        tx.execute("INSERT INTO native_events(source,received_at_ms,payload,processed) VALUES('friend_profile',?1,?2,1)",params![now,body])?;
        let seq = tx.last_insert_rowid();
        let key = id.to_string();
        let name = user
            .friend_nick_name
            .as_deref()
            .filter(|s| !s.trim().is_empty());
        let phone = crate::contacts::phone_key(&user.phone_number, country);
        tx.execute("INSERT INTO native_friend_profiles(account_id,user_id,relation,is_channel,profile_name,friend_name,hidden,purged,raw_json,capture_sequence,is_current,phone_key) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12) ON CONFLICT(account_id,user_id) DO UPDATE SET relation=excluded.relation,is_channel=excluded.is_channel,profile_name=excluded.profile_name,friend_name=excluded.friend_name,hidden=excluded.hidden,purged=excluded.purged,raw_json=excluded.raw_json,capture_sequence=excluded.capture_sequence,is_current=excluded.is_current,phone_key=excluded.phone_key",params![account,key,user.relation,matches!(user.user_type,1|2),user.nick_name.trim(),name,user.hidden.unwrap_or(false),user.purged.unwrap_or(false),serde_json::to_string(raw)?,seq,matches!(user.relation,1..=3),phone])?;
        save_favorite(&tx, account, &key, user.favorite, seq)?;
        // Re-evaluate phone ownership across all identities after a single profile changes.
        let ids = tx
            .prepare("SELECT user_id FROM native_friend_profiles WHERE account_id=?1")?
            .query_map([account], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for id in ids {
            project_name(&tx, account, &id, seq, now)?;
        }
        tx.execute("UPDATE friend_refresh SET completed_sequence=max(completed_sequence,?3),retry_at_ms=0 WHERE account_id=?1 AND user_id=?2",params![account,id,requested])?;
        tx.commit()?;
        Ok(())
    }
}
pub(crate) async fn refresh_one(
    store: &Store,
    listener: &mut crate::pilsner::Listener,
    client: &Client,
) -> Result<()> {
    let mut session = store.session_load()?;
    let account = session.user_id.to_string();
    let pending:Option<(i64,i64)>=store.lock()?.query_row("SELECT user_id,requested_sequence FROM friend_refresh WHERE account_id=?1 AND requested_sequence>completed_sequence AND retry_at_ms<=?2 ORDER BY requested_sequence LIMIT 1",params![account,chrono::Utc::now().timestamp_millis()],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
    let Some((id, requested)) = pending else {
        return Ok(());
    };
    // Persist retry deadline before I/O so cancellation cannot create a tight loop.
    store.lock()?.execute(
        "UPDATE friend_refresh SET retry_at_ms=?3 WHERE account_id=?1 AND user_id=?2",
        params![account, id, chrono::Utc::now().timestamp_millis() + 300_000],
    )?;
    listener.ensure().await?;
    let response = client
        .execute(store, &mut session, Operation::Friend { id })
        .await?;
    if response.http_status != 200 {
        return Err(invalid());
    }
    store.apply_friend(
        &account,
        id,
        requested,
        &response.body,
        &session.country_iso,
    )
}

pub(crate) fn project_name(
    tx: &rusqlite::Transaction<'_>,
    account: &str,
    id: &str,
    sequence: i64,
    now: i64,
) -> Result<()> {
    let (profile, alias, relation, channel, current, hidden, purged, phone): (String, Option<String>,i32,bool,bool,bool,bool,Option<String>) = tx.query_row("SELECT profile_name,friend_name,relation,is_channel,is_current,hidden,purged,phone_key FROM native_friend_profiles WHERE account_id=?1 AND user_id=?2",params![account,id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?)))?;
    let contact: Option<String> = tx.query_row("SELECT CASE WHEN count(DISTINCT client_id)=1 THEN min(display_name) ELSE NULL END FROM contact_names WHERE account_id=?1 AND phone_key=?2 AND (SELECT count(*) FROM native_friend_profiles WHERE account_id=?1 AND phone_key=?2)=1",params![account,phone],|r|r.get(0))?;
    let (name, source) = if let Some(contact) = contact.as_deref() {
        (contact, "drawer_contact_name")
    } else if let Some(alias) = alias.as_deref() {
        (alias, "kakao_friend_nickname")
    } else {
        (profile.as_str(), "kakao_profile")
    };
    let hash = hex::encode(Sha256::digest(serde_json::to_vec(&(
        name, source, &profile, &alias, relation, channel, current, hidden, purged,
    ))?));
    let old: Option<String> = tx
        .query_row(
            "SELECT payload_hash FROM friends WHERE account_id=?1 AND user_id=?2",
            params![account, id],
            |r| r.get(0),
        )
        .optional()?;
    tx.execute("INSERT INTO friends(account_id,user_id,revision,display_name,name_source,observed_at_ms,source,payload_hash) VALUES(?1,?2,?3,?4,?5,?6,'native_friends',?7) ON CONFLICT(account_id,user_id) DO UPDATE SET revision=excluded.revision,display_name=excluded.display_name,name_source=excluded.name_source,observed_at_ms=excluded.observed_at_ms,source=excluded.source,payload_hash=excluded.payload_hash",params![account,id,sequence,name,source,now,hash])?;
    if old.as_deref() != Some(hash.as_str()) {
        tx.execute("INSERT INTO outbox(account_id,entity_id,kind,revision,source) VALUES(?1,?2,'friend_upserted',?3,'native_friends')",params![account,id,sequence])?;
    }
    Ok(())
}
pub async fn sync_once(store: &Store) -> Result<SyncStatus> {
    let lease = Arc::new(RuntimeLease::acquire(store)?);
    let mut listener = crate::pilsner::Listener::new(store.clone(), lease);
    let result = sync_with_listener(store, &mut listener).await;
    listener.close().await?;
    result
}
/// Caller owns the runtime lease and Pilsner request gate.
pub(crate) async fn sync_with_listener(
    store: &Store,
    listener: &mut crate::pilsner::Listener,
) -> Result<SyncStatus> {
    let mut session = store.session_load()?;
    let account = session.user_id.to_string();
    let since = store.friends_since(&account)?;
    let client = Client::new()?;
    store.native_step("friends_sync", StepState::Started, None, None)?;
    let result = async {
        listener.ensure().await?;
        let response = client
            .execute(store, &mut session, Operation::FriendsSync { since })
            .await?;
        if !(200..300).contains(&response.http_status) || response.server_status != Some(0) {
            return Err(invalid());
        }
        let pending = store.apply_friends(&account, since, &response.body, &session.country_iso)?;
        if pending.reconciled {
            return Ok(pending);
        }
        let ids = store.friend_ids(&account)?;
        listener.ensure().await?;
        let diff = client
            .execute(store, &mut session, Operation::FriendsDiff { ids: &ids })
            .await?;
        if diff.http_status != 200 || diff.server_status.is_some_and(|s| s != 0) {
            return Err(invalid());
        }
        store.apply_friends_diff(&account, &pending, &diff.body, &session.country_iso)
    }
    .await;
    store.native_step(
        "friends_sync",
        if result.as_ref().is_ok_and(|s| s.reconciled) {
            StepState::Completed
        } else {
            StepState::Failed
        },
        None,
        None,
    )?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    impl Store {
        fn test_apply_friends(&self, account: &str, since: i64, body: &[u8]) -> Result<SyncStatus> {
            self.apply_friends(account, since, body, "KR")
        }
    }
    fn user(id: i64, relation: i32, nickname: Option<&str>) -> Value {
        json!({"userId":id,"accountId":0,"userType":0,"type":relation,"suspended":false,"memorial":false,"nickName":" Profile ","statusMessage":"","screenToken":0,"profileImageUrl":"","fullProfileImageUrl":"","originalProfileImageUrl":"","phoneNumber":"","friendNickName":nickname})
    }
    fn page(time: i64, total: i32, users: Vec<Value>) -> Vec<u8> {
        serde_json::to_vec(&json!({"status":0,"syncTime":time,"total":total,"friends":users,"channels":[],"purgedFriends":[],"newBadges":{}})).unwrap()
    }
    #[test]
    fn single_friend_refresh_preserves_global_cursor_and_newer_queue_and_nullable_favorite() {
        let (_dir, store) = crate::runtime::tests::setup();
        store
            .apply_friends("42", 0, &page(100, 1, vec![user(1, 3, None)]), "KR")
            .unwrap();
        store.lock().unwrap().execute("INSERT INTO friend_refresh(account_id,user_id,requested_sequence) VALUES('42',1,20)",[]).unwrap();
        let mut profile = user(1, 3, Some("Alias"));
        profile["favorite"] = json!(true);
        store
            .apply_friend(
                "42",
                1,
                10,
                &serde_json::to_vec(&json!({"status":0,"friend":profile})).unwrap(),
                "KR",
            )
            .unwrap();
        profile["favorite"] = Value::Null;
        store
            .apply_friend(
                "42",
                1,
                10,
                &serde_json::to_vec(&json!({"status":0,"friend":profile})).unwrap(),
                "KR",
            )
            .unwrap();
        assert_eq!(store.friends_since("42").unwrap(), 100);
        let conn = store.lock().unwrap();
        assert!(conn
            .query_row(
                "SELECT favorite FROM friend_favorites WHERE user_id='1'",
                [],
                |r| r.get::<_, bool>(0)
            )
            .unwrap());
        assert_eq!(
            conn.query_row(
                "SELECT requested_sequence,completed_sequence FROM friend_refresh",
                [],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
            )
            .unwrap(),
            (20, 10)
        );
        drop(conn);
        for bad in [
            json!({"friend":profile}),
            json!({"status":0,"friend":user(2,3,None)}),
            json!({"status":0,"friend":null}),
        ] {
            assert!(store
                .apply_friend("42", 1, 20, &serde_json::to_vec(&bad).unwrap(), "KR")
                .is_err());
        }
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row("SELECT completed_sequence FROM friend_refresh", [], |r| r
                    .get::<_, i64>(
                    0
                ))
                .unwrap(),
            10
        );
    }
    #[test]
    fn diff_repairs_pending_snapshot_uses_original_total_and_rejects_stale_reply() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let store = Store::initialize(dir.path()).unwrap();
        let pending = store
            .test_apply_friends("42", 0, &page(100, 2, vec![user(1, 3, None)]))
            .unwrap();
        assert!(!pending.reconciled);
        let diff = serde_json::to_vec(
            &json!({"total_count":999,"added_friends":[user(2,3,Some("Alias"))]}),
        )
        .unwrap();
        let done = store
            .apply_friends_diff("42", &pending, &diff, "KR")
            .unwrap();
        assert!(done.reconciled);
        assert_eq!(done.since, 100);
        assert_eq!(done.local_total, 2);
        assert!(store
            .apply_friends_diff("42", &pending, &diff, "KR")
            .is_err());
        let pending = store
            .test_apply_friends("42", 100, &page(101, 1, vec![]))
            .unwrap();
        let before = store
            .lock()
            .unwrap()
            .query_row("SELECT count(*) FROM native_events", [], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap();
        assert!(store
            .apply_friends_diff("42", &pending, br#"{"added_friends":[{"userId":9}]}"#, "KR")
            .is_err());
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row("SELECT count(*) FROM native_events", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            before
        );
        let done = store
            .apply_friends_diff("42", &pending, br#"{"deleted_ids":[2]}"#, "KR")
            .unwrap();
        assert!(done.reconciled);
        assert_eq!(done.since, 101);
        assert!(!store
            .lock()
            .unwrap()
            .query_row(
                "SELECT is_current FROM native_friend_profiles WHERE user_id='2'",
                [],
                |r| r.get::<_, bool>(0)
            )
            .unwrap());
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row("SELECT count(*) FROM friends", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            2
        );
    }
    #[test]
    fn counts_cursor_names_and_incremental_identity_retention() {
        let dir = tempfile::Builder::new()
            .permissions(
                <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
            )
            .tempdir()
            .unwrap();
        let store = Store::initialize(dir.path()).unwrap();
        let status = store
            .test_apply_friends(
                "42",
                0,
                &page(100, 2, vec![user(1, 3, Some("Alias")), user(2, 9, None)]),
            )
            .unwrap();
        assert!(status.reconciled);
        assert_eq!(status.since, 100);
        let conn = store.lock().unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT name_source FROM friends WHERE user_id='1'",
                [],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
            "kakao_friend_nickname"
        );
        drop(conn);
        // Incremental omission is not deletion. Explicit deactivation preserves identity.
        assert!(
            store
                .test_apply_friends("42", 100, &page(101, 1, vec![]))
                .unwrap()
                .reconciled
        );
        let status = store
            .test_apply_friends("42", 101, &page(102, 1, vec![user(1, 9, None)]))
            .unwrap();
        assert!(status.reconciled);
        assert_eq!(status.local_total, 0);
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row("SELECT count(*) FROM friends", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            2
        );
    }
    #[test]
    fn mismatch_retries_full_and_invalid_response_is_atomic() {
        let dir = tempfile::Builder::new()
            .permissions(
                <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
            )
            .tempdir()
            .unwrap();
        let store = Store::initialize(dir.path()).unwrap();
        let status = store
            .test_apply_friends("42", 0, &page(100, 2, vec![user(1, 3, None)]))
            .unwrap();
        assert!(!status.reconciled);
        assert_eq!(status.since, 0);
        let mut malformed = user(2, 3, None);
        malformed.as_object_mut().unwrap().remove("nickName");
        assert!(store
            .test_apply_friends(
                "42",
                0,
                &page(101, 2, vec![user(1, 3, Some("Changed")), malformed])
            )
            .is_err());
        let conn = store.lock().unwrap();
        assert_eq!(
            conn.query_row("SELECT display_name FROM friends", [], |r| r
                .get::<_, String>(0))
                .unwrap(),
            "Profile"
        );
        assert_eq!(
            conn.query_row("SELECT count(*) FROM native_events", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
    #[test]
    fn full_membership_reconciles_omissions_but_keeps_names_and_accepts_overlap() {
        let dir = tempfile::Builder::new()
            .permissions(
                <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
            )
            .tempdir()
            .unwrap();
        let store = Store::initialize(dir.path()).unwrap();
        // Deliberately mismatched total forces the next call back through since=0.
        store
            .test_apply_friends(
                "42",
                0,
                &page(100, 3, vec![user(1, 3, None), user(2, 3, None)]),
            )
            .unwrap();
        let mut next: Value =
            serde_json::from_slice(&page(101, 1, vec![user(2, 3, None)])).unwrap();
        next["purgedFriends"] = json!([user(2, 3, Some("Overlap wins"))]);
        let status = store
            .test_apply_friends("42", 0, &serde_json::to_vec(&next).unwrap())
            .unwrap();
        assert!(status.reconciled);
        assert_eq!(status.since, 101);
        let conn = store.lock().unwrap();
        assert!(!conn
            .query_row(
                "SELECT is_current FROM native_friend_profiles WHERE user_id='1'",
                [],
                |r| r.get::<_, bool>(0)
            )
            .unwrap());
        assert_eq!(
            conn.query_row("SELECT count(*) FROM friends", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert_eq!(
            conn.query_row(
                "SELECT display_name FROM friends WHERE user_id='2'",
                [],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
            "Overlap wins"
        );
        let before: i64 = conn
            .query_row("SELECT count(*) FROM outbox", [], |r| r.get(0))
            .unwrap();
        drop(conn);
        let mut hidden = user(2, 3, Some("Overlap wins"));
        hidden["hidden"] = json!(true);
        assert!(
            store
                .test_apply_friends("42", 101, &page(102, 1, vec![hidden]))
                .unwrap()
                .reconciled
        );
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row("SELECT count(*) FROM outbox", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            before + 1
        );
    }
}
