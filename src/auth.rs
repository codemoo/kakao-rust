use crate::{error::valid_id, Error, Result, Store};
use rand::RngCore;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use subtle::ConstantTimeEq;
use uuid::Uuid;

#[derive(
    Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum,
)]
pub enum Scope {
    #[serde(rename = "status:read")]
    #[value(name = "status:read")]
    Status,
    #[serde(rename = "rooms:read")]
    #[value(name = "rooms:read")]
    Rooms,
    #[serde(rename = "messages:read")]
    #[value(name = "messages:read")]
    Messages,
    #[serde(rename = "messages:write")]
    #[value(name = "messages:write")]
    MessagesWrite,
    #[serde(rename = "friends:read")]
    #[value(name = "friends:read")]
    Friends,
    #[serde(rename = "attachments:read")]
    #[value(name = "attachments:read")]
    Attachments,
}

#[derive(Debug, Clone, Serialize)]
pub struct CredentialMetadata {
    pub id: String,
    pub label: String,
    pub prefix: String,
    pub account_id: String,
    pub scopes: BTreeSet<Scope>,
    pub rooms: Option<BTreeSet<String>>,
    pub created_at: i64,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
}
#[derive(Debug, Serialize)]
pub struct IssuedCredential {
    /// Returned only by issue. Listing and API responses never include this secret.
    pub token: String,
    pub metadata: CredentialMetadata,
}
#[derive(Debug, Clone)]
pub struct Principal {
    pub credential_id: String,
    pub account_id: String,
    pub scopes: BTreeSet<Scope>,
    pub rooms: Option<BTreeSet<String>>,
}
impl Principal {
    pub fn require(&self, scope: Scope) -> Result<()> {
        if self.scopes.contains(&scope) {
            Ok(())
        } else {
            Err(Error::Forbidden)
        }
    }
    pub fn allows_room(&self, room: &str) -> bool {
        self.rooms.as_ref().is_none_or(|rooms| rooms.contains(room))
    }
    pub fn require_room(&self, room: &str) -> Result<()> {
        if self.allows_room(room) {
            Ok(())
        } else {
            Err(Error::Forbidden)
        }
    }
    pub(crate) fn rooms_json(&self) -> Result<Option<String>> {
        self.rooms
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(Into::into)
    }
}
impl Store {
    pub fn token_issue(
        &self,
        label: String,
        account_id: String,
        scopes: BTreeSet<Scope>,
        rooms: Option<BTreeSet<String>>,
        expires_at: i64,
        now: i64,
    ) -> Result<IssuedCredential> {
        valid_id(&label, "credential label")?;
        valid_id(&account_id, "account ID")?;
        if scopes.is_empty() || expires_at <= now {
            return Err(Error::Invalid(
                "at least one scope and a future expiration are required".into(),
            ));
        }
        if let Some(rooms) = &rooms {
            if rooms.len() > 1000 {
                return Err(Error::Invalid(
                    "at most 1000 room IDs per credential".into(),
                ));
            }
            for room in rooms {
                valid_id(room, "allowed room")?;
            }
            if scopes.contains(&Scope::Friends) {
                return Err(Error::Invalid(
                    "friends:read requires an unrestricted account credential".into(),
                ));
            }
        }
        let id = Uuid::new_v4().simple().to_string();
        let mut secret = [0_u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        let token = format!("kr_{id}_{}", hex::encode(secret));
        let hash = Sha256::digest(token.as_bytes());
        let metadata = CredentialMetadata {
            id,
            label,
            prefix: token[..15].to_string(),
            account_id,
            scopes,
            rooms,
            created_at: now,
            expires_at,
            revoked_at: None,
        };
        self.lock()?.execute("INSERT INTO api_credentials(id,label,token_hash,prefix,account_id,scopes,rooms,created_at,expires_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)", params![metadata.id,metadata.label,hash.as_slice(),metadata.prefix,metadata.account_id,serde_json::to_string(&metadata.scopes)?,metadata.rooms.as_ref().map(serde_json::to_string).transpose()?,now,expires_at])?;
        Ok(IssuedCredential { token, metadata })
    }

    pub fn authenticate(&self, token: &str, now: i64) -> Result<Principal> {
        if !token.is_ascii()
            || token.len() != 100
            || !token.starts_with("kr_")
            || token.as_bytes()[35] != b'_'
            || !token[3..35].bytes().all(|b| b.is_ascii_hexdigit())
            || !token[36..].bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(Error::Unauthorized);
        }
        let connection = self.lock()?;
        let record = connection.query_row("SELECT token_hash,account_id,scopes,rooms,expires_at,revoked_at FROM api_credentials WHERE id=?1", [&token[3..35]], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, Option<String>>(3)?, r.get::<_, i64>(4)?, r.get::<_, Option<i64>>(5)?))).optional()?;
        let (expected, account_id, scopes, rooms, expiry, revoked) =
            record.ok_or(Error::Unauthorized)?;
        let actual = Sha256::digest(token.as_bytes());
        if !bool::from(expected.as_slice().ct_eq(actual.as_slice()))
            || expiry <= now
            || revoked.is_some()
        {
            return Err(Error::Unauthorized);
        }
        Ok(Principal {
            credential_id: token[3..35].to_string(),
            account_id,
            scopes: serde_json::from_str(&scopes)?,
            rooms: rooms.map(|v| serde_json::from_str(&v)).transpose()?,
        })
    }

    pub fn token_revoke(&self, id: &str, now: i64) -> Result<()> {
        let changed = self.lock()?.execute(
            "UPDATE api_credentials SET revoked_at=COALESCE(revoked_at,?2) WHERE id=?1",
            params![id, now],
        )?;
        if changed == 0 {
            Err(Error::NotFound)
        } else {
            Ok(())
        }
    }

    pub fn token_list(&self) -> Result<Vec<CredentialMetadata>> {
        let connection = self.lock()?;
        let mut statement = connection.prepare("SELECT id,label,prefix,account_id,scopes,rooms,created_at,expires_at,revoked_at FROM api_credentials ORDER BY created_at,id")?;
        let rows = statement.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, Option<String>>(5)?,
                r.get::<_, i64>(6)?,
                r.get::<_, i64>(7)?,
                r.get::<_, Option<i64>>(8)?,
            ))
        })?;
        rows.map(|row| {
            let (id, label, prefix, account_id, scopes, rooms, created_at, expires_at, revoked_at) =
                row?;
            Ok(CredentialMetadata {
                id,
                label,
                prefix,
                account_id,
                scopes: serde_json::from_str(&scopes)?,
                rooms: rooms.map(|v| serde_json::from_str(&v)).transpose()?,
                created_at,
                expires_at,
                revoked_at,
            })
        })
        .collect()
    }
}
