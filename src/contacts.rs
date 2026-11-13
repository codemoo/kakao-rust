//! Read-only Drawer contact backup enrichment; never writes the host's contacts.
//! Phone normalization uses conservative matching rules.
use crate::{
    native_http::{Client, Operation},
    runtime::{RuntimeLease, StepState},
    session::Session,
    Error, Result, Store,
};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

fn invalid() -> Error {
    Error::Invalid("invalid or incomplete contact snapshot; prior names retained".into())
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Snapshots {
    has_more: bool,
    total_count: i32,
    items: Option<Vec<Snapshot>>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Snapshot {
    id: String,
    contact_count: i32,
    created_at: i64,
    device_name: String,
    backup_type: String,
    device_type: String,
    model_name: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Page {
    has_more: bool,
    items: Vec<Contact>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Contact {
    client_id: String,
    drawer_id: Option<i64>,
    display_name: Option<String>,
    phones: Option<Vec<Phone>>,
}
#[derive(Deserialize)]
struct Phone {
    value: String,
    #[serde(rename = "type")]
    kind: String,
}
#[derive(Debug, Serialize)]
pub struct ContactStatus {
    pub snapshot_available: bool,
    pub snapshot_created_at: Option<i64>,
    pub contacts: usize,
    pub matched_friends: i64,
    pub selection: &'static str,
}
/// Conservative matching: formatting only, E.164 or KR national numbers with
/// known account country. Other national numbers only match within that country.
pub(crate) fn phone_key(raw: &str, country: &str) -> Option<String> {
    if raw.len() > 100 || country.len() != 2 || !country.bytes().all(|b| b.is_ascii_alphabetic()) {
        return None;
    }
    let mut value = String::new();
    for c in raw.chars() {
        if c.is_ascii_digit() || c == '+' {
            value.push(c);
        } else if !(c.is_ascii_whitespace() || matches!(c, '(' | ')' | '-' | '.')) {
            return None;
        }
    }
    if let Some(number) = value.strip_prefix('+') {
        return ((8..=15).contains(&number.len())
            && !number.starts_with('0')
            && number.bytes().all(|b| b.is_ascii_digit()))
        .then_some(value);
    }
    if !(8..=15).contains(&value.len()) || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if country.eq_ignore_ascii_case("KR")
        && value.starts_with('0')
        && (9..=11).contains(&value.len())
    {
        return Some(format!("+82{}", &value[1..]));
    }
    Some(format!("local:{}:{value}", country.to_ascii_uppercase()))
}
fn insert_contact(contacts: &mut HashMap<String, Contact>, contact: Contact) -> Result<()> {
    crate::error::valid_id(&contact.client_id, "contact ID").map_err(|_| invalid())?;
    match contacts.entry(contact.client_id.clone()) {
        std::collections::hash_map::Entry::Vacant(entry) => {
            entry.insert(contact);
            Ok(())
        }
        std::collections::hash_map::Entry::Occupied(_) => Err(invalid()),
    }
}
async fn read(
    client: &Client,
    store: &Store,
    session: &mut Session,
    listener: &mut crate::pilsner::Listener,
    op: Operation<'_>,
) -> Result<Vec<u8>> {
    listener.ensure().await?;
    let response = client.execute(store, session, op).await?;
    if !(200..300).contains(&response.http_status) || response.server_status.is_some_and(|s| s != 0)
    {
        return Err(invalid());
    }
    Ok(response.body.to_vec())
}
fn validate_snapshot_page(
    page: Snapshots,
    total: &mut Option<i32>,
    seen: &mut HashSet<String>,
) -> Result<Vec<Snapshot>> {
    if page.total_count < 0 || total.is_some_and(|n| n != page.total_count) {
        return Err(invalid());
    }
    *total = Some(page.total_count);
    let items = page.items.unwrap_or_default();
    if items.len() > 50 || (page.has_more && items.is_empty()) {
        return Err(invalid());
    }
    for item in &items {
        if item.id.is_empty() || !seen.insert(item.id.clone()) {
            return Err(invalid());
        }
    }
    if seen.len() > page.total_count as usize
        || (!page.has_more && seen.len() != page.total_count as usize)
    {
        return Err(invalid());
    }
    Ok(items)
}
async fn select_snapshot(
    client: &Client,
    store: &Store,
    session: &mut Session,
    listener: &mut crate::pilsner::Listener,
    explicit: Option<&str>,
) -> Result<Option<Snapshot>> {
    let mut offset = None;
    let mut seen = HashSet::new();
    let mut selected: Option<Snapshot> = None;
    let mut total = None;
    for page_no in 0..1000 {
        let bytes = read(
            client,
            store,
            session,
            listener,
            Operation::ContactSnapshots {
                offset: offset.as_deref(),
                count: if page_no == 0 { 20 } else { 50 },
            },
        )
        .await?;
        let page: Snapshots = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        let has_more = page.has_more;
        let items = validate_snapshot_page(page, &mut total, &mut seen)?;
        offset = items.last().map(|s| s.id.clone());
        for item in items {
            crate::error::valid_id(&item.id, "snapshot ID").map_err(|_| invalid())?;
            if item.contact_count < 0 || item.created_at < 0 {
                return Err(invalid());
            }
            let _ = (
                &item.device_name,
                &item.backup_type,
                &item.device_type,
                &item.model_name,
            );
            if explicit.is_some_and(|id| id == item.id) {
                return Ok(Some(item));
            }
            if explicit.is_none()
                && selected
                    .as_ref()
                    .is_none_or(|s| (item.created_at, &item.id) > (s.created_at, &s.id))
            {
                selected = Some(item);
            }
        }
        if !has_more {
            if explicit.is_some() {
                return Err(Error::NotFound);
            }
            return Ok(selected);
        }
    }
    Err(invalid())
}
impl Store {
    fn replace_contacts(
        &self,
        account: &str,
        country: &str,
        snapshot: Option<&Snapshot>,
        contacts: &HashMap<String, Contact>,
        pages: &[Vec<u8>],
    ) -> Result<ContactStatus> {
        if snapshot.is_some_and(|s| s.contact_count as usize != contacts.len()) {
            return Err(invalid());
        }
        let now = chrono::Utc::now().timestamp_millis();
        let mut conn = self.lock()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        // Include snapshot metadata in private capture without reporting names publicly.
        let metadata = serde_json::to_vec(
            &serde_json::json!({"snapshot_id":snapshot.map(|s|&s.id),"contact_count":contacts.len()}),
        )?;
        tx.execute("INSERT INTO native_events(source,received_at_ms,payload) VALUES('contact_snapshot',?1,?2)",params![now,metadata])?;
        let sequence = tx.last_insert_rowid();
        for bytes in pages {
            tx.execute("INSERT INTO native_events(source,received_at_ms,payload) VALUES('contact_page',?1,?2)",params![now,bytes])?;
        }
        tx.execute("DELETE FROM contact_names WHERE account_id=?1", [account])?;
        tx.execute(
            "DELETE FROM contact_snapshot_state WHERE account_id=?1",
            [account],
        )?;
        if let Some(snapshot) = snapshot {
            for contact in contacts.values() {
                // All owners, including unnamed contacts, participate in ambiguity.
                let name = contact
                    .display_name
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty() && s.len() <= 4096);
                for phone in contact.phones.as_deref().unwrap_or_default() {
                    let _ = &phone.kind;
                    if let Some(key) = phone_key(&phone.value, country) {
                        tx.execute("INSERT INTO contact_names(account_id,client_id,phone_key,display_name,snapshot_id,observed_at_ms) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(account_id,client_id,phone_key) DO NOTHING",params![account,contact.client_id,key,name,snapshot.id,now])?;
                    }
                }
            }
        }
        let ids = tx
            .prepare("SELECT user_id FROM native_friend_profiles WHERE account_id=?1")?
            .query_map([account], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for id in ids {
            crate::friends::project_name(&tx, account, &id, sequence, now)?;
        }
        let matched: i64=tx.query_row("SELECT count(*) FROM friends WHERE account_id=?1 AND name_source='drawer_contact_name'",[account],|r|r.get(0))?;
        if let Some(s) = snapshot {
            tx.execute(
                "INSERT INTO contact_snapshot_state VALUES(?1,?2,?3,?4,?5,?6)",
                params![account, s.id, s.created_at, s.contact_count, matched, now],
            )?;
        }
        tx.commit()?;
        Ok(ContactStatus {
            snapshot_available: snapshot.is_some(),
            snapshot_created_at: snapshot.map(|s| s.created_at),
            contacts: contacts.len(),
            matched_friends: matched,
            selection: "newest_timestamp",
        })
    }
}
pub async fn sync_once(store: &Store, snapshot_id: Option<&str>) -> Result<ContactStatus> {
    if let Some(id) = snapshot_id {
        crate::error::valid_id(id, "snapshot ID")?;
    }
    let lease = Arc::new(RuntimeLease::acquire(store)?);
    let mut listener = crate::pilsner::Listener::new(store.clone(), lease);
    let result = sync_with_listener(store, &mut listener, snapshot_id).await;
    listener.close().await?;
    result
}
pub(crate) async fn sync_with_listener(
    store: &Store,
    listener: &mut crate::pilsner::Listener,
    snapshot_id: Option<&str>,
) -> Result<ContactStatus> {
    let mut session = store.session_load()?;
    let client = Client::new()?;
    store.native_step("contacts_sync", StepState::Started, None, None)?;
    let result = async {
        let snapshot = select_snapshot(&client, store, &mut session, listener, snapshot_id).await?;
        let mut contacts = HashMap::new();
        let mut pages = Vec::new();
        if let Some(snapshot) = &snapshot {
            let mut offset = None;
            let mut offsets = HashSet::new();
            let mut bytes_count = 0;
            loop {
                if pages.len() >= 1000 {
                    return Err(invalid());
                }
                let bytes = read(
                    &client,
                    store,
                    &mut session,
                    listener,
                    Operation::Contacts {
                        snapshot: &snapshot.id,
                        offset,
                    },
                )
                .await?;
                bytes_count += bytes.len();
                if bytes_count > 64 * 1024 * 1024 {
                    return Err(invalid());
                }
                let page: Page = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
                if page.items.len() > 1000 {
                    return Err(invalid());
                }
                let next = page.items.last().and_then(|c| c.drawer_id);
                if page.has_more && (next.is_none() || next == offset || !offsets.insert(next)) {
                    return Err(invalid());
                }
                for contact in page.items {
                    insert_contact(&mut contacts, contact)?;
                }
                if contacts.len() > 100_000 {
                    return Err(invalid());
                }
                pages.push(bytes);
                if !page.has_more {
                    break;
                }
                offset = next;
            }
        }
        let mut status = store.replace_contacts(
            &session.user_id.to_string(),
            &session.country_iso,
            snapshot.as_ref(),
            &contacts,
            &pages,
        )?;
        if snapshot_id.is_some() {
            status.selection = "explicit_snapshot";
        }
        Ok(status)
    }
    .await;
    store.native_step(
        "contacts_sync",
        if result.is_ok() {
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
    #[test]
    fn duplicate_page_identity_is_rejected_without_overwriting_prior_contact() {
        let contact = |name: &str| Contact {
            client_id: "same".into(),
            drawer_id: Some(1),
            display_name: Some(name.into()),
            phones: None,
        };
        let mut contacts = HashMap::new();
        insert_contact(&mut contacts, contact("Prior")).unwrap();
        assert!(insert_contact(&mut contacts, contact("Conflicting")).is_err());
        assert_eq!(contacts["same"].display_name.as_deref(), Some("Prior"));
    }
    #[test]
    fn phone_matching_never_uses_suffix_or_ambiguous_international_guess() {
        assert_eq!(
            phone_key("010-1234-5678", "KR"),
            phone_key("+82 (10) 1234 5678", "KR")
        );
        assert_ne!(
            phone_key("01012345678", "US"),
            phone_key("01012345678", "KR")
        );
        assert!(phone_key("+8201012345678 ext 12", "KR").is_none());
        assert!(phone_key("++821012345678", "KR").is_none());
        assert!(phone_key("1234", "KR").is_none());
    }
    #[test]
    fn contact_name_priority_ambiguity_stale_snapshot_and_atomic_replacement() {
        let dir = tempfile::Builder::new()
            .permissions(
                <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
            )
            .tempdir()
            .unwrap();
        let store = Store::initialize(dir.path()).unwrap();
        let friend = serde_json::json!({"userId":1,"accountId":0,"userType":0,"type":3,"suspended":false,"memorial":false,"nickName":"Profile","statusMessage":"","screenToken":0,"profileImageUrl":"","fullProfileImageUrl":"","originalProfileImageUrl":"","phoneNumber":"01012345678","friendNickName":"Alias"});
        let sync=serde_json::to_vec(&serde_json::json!({"status":0,"syncTime":100,"total":1,"friends":[friend.clone()],"channels":[],"purgedFriends":[],"newBadges":{}})).unwrap();
        store.apply_friends("42", 0, &sync, "KR").unwrap();
        let mut snapshot = Snapshot {
            id: "synthetic-snapshot".into(),
            contact_count: 1,
            created_at: 100,
            device_name: "synthetic".into(),
            backup_type: "synthetic".into(),
            device_type: "synthetic".into(),
            model_name: "synthetic".into(),
        };
        let contact = |id: &str, name: &str| Contact {
            client_id: id.into(),
            drawer_id: Some(1),
            display_name: Some(name.into()),
            phones: Some(vec![Phone {
                value: "+82 10 1234 5678".into(),
                kind: "mobile".into(),
            }]),
        };
        let mut contacts = HashMap::from([("a".into(), contact("a", "Contact label"))]);
        let name = || {
            store
                .lock()
                .unwrap()
                .query_row("SELECT display_name,name_source FROM friends", [], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                })
                .unwrap()
        };
        assert_eq!(
            store
                .replace_contacts("42", "KR", Some(&snapshot), &contacts, &[])
                .unwrap()
                .matched_friends,
            1
        );
        assert_eq!(
            name(),
            ("Contact label".into(), "drawer_contact_name".into())
        );
        // Subsequent friend sync preserves contact priority.
        store.apply_friends("42", 100, &sync, "KR").unwrap();
        assert_eq!(name().0, "Contact label");
        // Incomplete replacement must leave the prior name and state intact.
        snapshot.contact_count = 2;
        assert!(store
            .replace_contacts("42", "KR", Some(&snapshot), &contacts, &[])
            .is_err());
        assert_eq!(name().0, "Contact label");
        contacts.insert("b".into(), contact("b", ""));
        store
            .replace_contacts("42", "KR", Some(&snapshot), &contacts, &[])
            .unwrap();
        assert_eq!(name(), ("Alias".into(), "kakao_friend_nickname".into()));
        // Two friend identities sharing one phone must also remove stale labels.
        contacts.remove("b");
        snapshot.contact_count = 1;
        store
            .replace_contacts("42", "KR", Some(&snapshot), &contacts, &[])
            .unwrap();
        let mut second = friend;
        second["userId"] = serde_json::json!(2);
        let delta=serde_json::to_vec(&serde_json::json!({"status":0,"syncTime":101,"total":2,"friends":[second],"channels":[],"purgedFriends":[],"newBadges":{}})).unwrap();
        store.apply_friends("42", 100, &delta, "KR").unwrap();
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row(
                    "SELECT count(*) FROM friends WHERE name_source='drawer_contact_name'",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
        // A later complete snapshot without that number removes stale enrichment.
        snapshot.contact_count = 0;
        store
            .replace_contacts("42", "KR", Some(&snapshot), &HashMap::new(), &[])
            .unwrap();
        assert_eq!(name().0, "Alias");
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row("SELECT count(*) FROM contact_names", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    #[test]
    fn incomplete_snapshot_listing_cannot_clear_names_or_claim_latest() {
        let decode = |raw: &str| serde_json::from_str::<Snapshots>(raw).unwrap();
        assert!(validate_snapshot_page(
            decode(r#"{"hasMore":false,"totalCount":10,"items":null}"#),
            &mut None,
            &mut HashSet::new()
        )
        .is_err());
        assert!(validate_snapshot_page(
            decode(r#"{"hasMore":true,"totalCount":1,"items":[]}"#),
            &mut None,
            &mut HashSet::new()
        )
        .is_err());
        assert!(validate_snapshot_page(
            decode(r#"{"hasMore":false,"totalCount":0,"items":[]}"#),
            &mut None,
            &mut HashSet::new()
        )
        .unwrap()
        .is_empty());
        assert!(validate_snapshot_page(
            decode(r#"{"hasMore":false,"totalCount":0,"items":[]}"#),
            &mut Some(1),
            &mut HashSet::new()
        )
        .is_err());
    }
}
