use crate::{Error, Result};
use rusqlite::{Connection, TransactionBehavior};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

#[derive(Clone)]
pub struct Store {
    pub(crate) connection: Arc<Mutex<Connection>>,
    pub(crate) data_dir: Arc<PathBuf>,
    pub(crate) refresh_gate: Arc<tokio::sync::Mutex<Option<Instant>>>,
}

impl Store {
    /// Create the private store. Repeated initialization preserves all state.
    pub fn initialize(data_dir: &Path) -> Result<Self> {
        Self::connect(data_dir, true)
    }
    /// Open an existing initialized store, never create a replacement.
    pub fn open(data_dir: &Path) -> Result<Self> {
        Self::connect(data_dir, false)
    }

    fn connect(data_dir: &Path, create: bool) -> Result<Self> {
        let dir = private_directory(data_dir, create)?;
        // A filesystem lock also covers the interval before SQLite exists. A crashed
        // initializer leaves the lock behind: recovery must be explicit, never a reset.
        let _initialization_lock = InitializationLock::acquire(&dir)?;
        let db_path = dir.join("state.sqlite3");
        let marker_path = dir.join("store.initialized");
        let marker_exists = match fs::symlink_metadata(&marker_path) {
            Ok(meta) => {
                validate_private_file(&meta, "initialization marker")?;
                if fs::read(&marker_path)? != b"kakao-rust-store-v1:ready\n" {
                    return Err(Error::Storage(
                        "initialization incomplete or marker damaged; explicit recovery required"
                            .into(),
                    ));
                }
                true
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
            Err(err) => return Err(err.into()),
        };
        let new_database = match fs::symlink_metadata(&db_path) {
            Ok(meta) => {
                validate_private_file(&meta, "database")?;
                false
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                if !create || marker_exists {
                    return Err(Error::Storage(
                        "database missing; restore the saved store, do not reinitialize".into(),
                    ));
                }
                if dir.join("state.sqlite3-wal").exists() || dir.join("state.sqlite3-shm").exists()
                {
                    return Err(Error::Storage(
                        "orphaned SQLite sidecars; explicit recovery required".into(),
                    ));
                }
                // Persist intent before creating the database. A failed/crashed first
                // initialization cannot later be mistaken for a pristine directory.
                write_marker(&dir, b"kakao-rust-store-v1:initializing\n")?;
                let mut options = OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                options.mode(0o600);
                options.open(&db_path)?.sync_all()?;
                File::open(&dir)?.sync_all()?;
                true
            }
            Err(err) => return Err(err.into()),
        };
        let flags =
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let mut connection = Connection::open_with_flags(db_path, flags)?;
        connection.busy_timeout(Duration::from_secs(10))?;
        if !new_database {
            let version: i64 =
                connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
            if version == 0 {
                return Err(Error::Storage(
                    "preexisting database is uninitialized or damaged; explicit recovery required"
                        .into(),
                ));
            }
        }
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "secure_delete", "ON")?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let version: i64 = tx.pragma_query_value(None, "user_version", |row| row.get(0))?;
        match version {
            0 if new_database => {
                tx.execute_batch(SCHEMA)?;
                tx.execute_batch(QR_SCHEMA)?;
                tx.execute_batch(AUTH_SCHEMA)?;
                tx.execute_batch(SEARCH_SCHEMA)?;
                tx.pragma_update(None, "user_version", 4)?;
            }
            1 => {
                tx.execute_batch(QR_SCHEMA)?;
                tx.execute_batch(AUTH_SCHEMA)?;
                tx.execute_batch(SEARCH_SCHEMA)?;
                tx.pragma_update(None, "user_version", 4)?;
            }
            2 => {
                tx.execute_batch(AUTH_SCHEMA)?;
                tx.execute_batch(SEARCH_SCHEMA)?;
                tx.pragma_update(None, "user_version", 4)?;
            }
            3 => {
                tx.execute_batch(SEARCH_SCHEMA)?;
                tx.pragma_update(None, "user_version", 4)?;
            }
            4..=14 => (),
            0 => {
                return Err(Error::Storage(
                    "uninitialized or damaged store; explicit recovery required".into(),
                ))
            }
            _ => return Err(Error::Storage("unsupported schema version".into())),
        }
        if version <= 4 {
            tx.execute_batch(NATIVE_SCHEMA)?;
            tx.pragma_update(None, "user_version", 5)?;
        }
        if version <= 5 {
            tx.execute_batch(DRAWER_SCHEMA)?;
            tx.pragma_update(None, "user_version", 6)?;
        }
        if version <= 6 {
            tx.execute_batch(DRAWER_FOLLOWUP_SCHEMA)?;
            tx.pragma_update(None, "user_version", 7)?;
        }
        if version <= 7 {
            tx.execute_batch(FRIENDS_SCHEMA)?;
            tx.pragma_update(None, "user_version", 8)?;
        }
        if version <= 8 {
            tx.execute_batch(LIVE_SCHEMA)?;
            tx.pragma_update(None, "user_version", 9)?;
        }
        if version <= 9 {
            tx.execute_batch(ENRICHMENT_SCHEMA)?;
            tx.pragma_update(None, "user_version", 10)?;
        }
        if version <= 10 {
            tx.execute_batch(READ_STATE_SCHEMA)?;
            tx.pragma_update(None, "user_version", 11)?;
        }
        if version <= 11 {
            tx.execute_batch(ROSTER_SCHEMA)?;
            tx.pragma_update(None, "user_version", 12)?;
        }
        if version <= 12 {
            tx.execute_batch(DOMAIN_SCHEMA)?;
            crate::room_sync::migrate_context(&tx)?;
            tx.pragma_update(None, "user_version", 13)?;
        }
        if version <= 13 {
            tx.execute_batch(crate::outgoing::SCHEMA)?;
            tx.pragma_update(None, "user_version", 14)?;
        }
        let initialized: String = tx.query_row(
            "SELECT value FROM metadata WHERE key='initialized'",
            [],
            |r| r.get(0),
        )?;
        if initialized != "1" {
            return Err(Error::Storage("invalid initialization marker".into()));
        }
        tx.commit()?;
        if !marker_exists {
            // Also enroll valid legacy v1 stores without changing their saved state.
            // A preexisting empty/user_version=0 file never reaches this point.
            write_marker(&dir, b"kakao-rust-store-v1:ready\n")?;
        }
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            data_dir: Arc::new(dir),
            refresh_gate: Arc::new(tokio::sync::Mutex::new(None)),
        })
    }

    pub(crate) fn lock(&self) -> Result<MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| Error::Storage("database lock poisoned".into()))
    }
}

fn validate_private_file(metadata: &fs::Metadata, label: &str) -> Result<()> {
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(Error::Storage(format!(
            "{label} must be a regular non-symlink file"
        )));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(Error::Storage(format!("{label} permissions must be 0600")));
    }
    Ok(())
}

fn write_marker(dir: &Path, bytes: &[u8]) -> Result<()> {
    let pending = dir.join("store.initialized.pending");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&pending)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&pending, dir.join("store.initialized"))?;
    File::open(dir)?.sync_all()?;
    Ok(())
}

struct InitializationLock {
    path: PathBuf,
}
impl InitializationLock {
    fn acquire(dir: &Path) -> Result<Self> {
        let path = dir.join(".initialization-lock");
        let started = Instant::now();
        loop {
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            builder.mode(0o700);
            match builder.create(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Match SQLite busy timeout: serialized migration/open may exceed
                    // two seconds on a contended host. Never steal a stale lock.
                    if started.elapsed() >= Duration::from_secs(10) {
                        return Err(Error::Storage("initialization is busy or was interrupted; inspect and explicitly recover the lock and saved state".into()));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(err) => return Err(err.into()),
            }
        }
    }
}
impl Drop for InitializationLock {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.path);
    }
}

fn reject_location(path: &Path) -> Result<()> {
    let project = Path::new(env!("CARGO_MANIFEST_DIR"));
    if path.starts_with(project) || path.components().any(|c| matches!(c, Component::Normal(n) if n.to_string_lossy().to_ascii_lowercase().contains("dropbox"))) {
        return Err(Error::Storage("private data must be outside Dropbox and the source checkout".into()));
    }
    Ok(())
}

fn private_directory(path: &Path, create: bool) -> Result<PathBuf> {
    if !path.is_absolute() || path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(Error::Storage(
            "--data-dir must be an absolute path without '..'".into(),
        ));
    }
    reject_location(path)?;
    // Resolve the existing ancestor before creating anything, including symlink aliases.
    let ancestor = path
        .ancestors()
        .find(|p| p.exists())
        .ok_or_else(|| Error::Storage("no existing path ancestor".into()))?;
    reject_location(&fs::canonicalize(ancestor)?)?;
    if !path.exists() {
        if !create {
            return Err(Error::Storage(
                "data directory missing; restore state or explicitly init".into(),
            ));
        }
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        builder.mode(0o700);
        builder.create(path)?;
    }
    let canonical = fs::canonicalize(path)?;
    reject_location(&canonical)?;
    let metadata = fs::metadata(&canonical)?;
    if !metadata.is_dir() {
        return Err(Error::Storage("data path must be a directory".into()));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(Error::Storage(
            "data directory must have private 0700 permissions".into(),
        ));
    }
    Ok(canonical)
}

const SCHEMA: &str = r#"
CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
INSERT INTO metadata VALUES ('initialized','1'),('device_initialized','0');
CREATE TABLE device_profile(id INTEGER PRIMARY KEY CHECK(id=1), json TEXT NOT NULL) STRICT;
CREATE TABLE api_credentials(
 id TEXT PRIMARY KEY, label TEXT NOT NULL, token_hash BLOB NOT NULL CHECK(length(token_hash)=32),
 prefix TEXT NOT NULL, account_id TEXT NOT NULL, scopes TEXT NOT NULL, rooms TEXT,
 created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, revoked_at INTEGER
) STRICT;
CREATE TABLE rooms(
 account_id TEXT NOT NULL, room_id TEXT NOT NULL, revision INTEGER NOT NULL,
 display_name TEXT, name_source TEXT, observed_at_ms INTEGER, source TEXT NOT NULL,
 payload_hash TEXT, PRIMARY KEY(account_id,room_id)
) STRICT;
CREATE TABLE friends(
 account_id TEXT NOT NULL, user_id TEXT NOT NULL, revision INTEGER NOT NULL,
 display_name TEXT, name_source TEXT, observed_at_ms INTEGER, source TEXT NOT NULL,
 payload_hash TEXT NOT NULL, PRIMARY KEY(account_id,user_id)
) STRICT;
CREATE TABLE messages(
 account_id TEXT NOT NULL, room_id TEXT NOT NULL, message_id TEXT NOT NULL,
 revision INTEGER NOT NULL CHECK(revision>=0), sent_at_ms INTEGER NOT NULL,
 sender_id TEXT, body TEXT, deleted INTEGER NOT NULL CHECK(deleted IN (0,1)),
 source TEXT NOT NULL, source_local_pk TEXT, payload_hash TEXT NOT NULL,
 PRIMARY KEY(account_id,room_id,message_id),
 FOREIGN KEY(account_id,room_id) REFERENCES rooms(account_id,room_id),
 CHECK(deleted=0 OR body IS NULL)
) STRICT;
CREATE INDEX messages_page ON messages(account_id,room_id,sent_at_ms,message_id) WHERE deleted=0;
CREATE INDEX messages_search ON messages(account_id,sent_at_ms,room_id,message_id) WHERE deleted=0;
CREATE TABLE ingest_events(
 account_id TEXT NOT NULL, source TEXT NOT NULL, stream_id TEXT NOT NULL,
 event_id TEXT NOT NULL, position INTEGER NOT NULL, event_hash TEXT NOT NULL,
 PRIMARY KEY(account_id,source,stream_id,event_id),
 UNIQUE(account_id,source,stream_id,position)
) STRICT;
CREATE TABLE sync_cursors(
 account_id TEXT NOT NULL, source TEXT NOT NULL, stream_id TEXT NOT NULL,
 position INTEGER NOT NULL, cursor TEXT NOT NULL,
 PRIMARY KEY(account_id,source,stream_id)
) STRICT;
CREATE TABLE outbox(
 sequence INTEGER PRIMARY KEY AUTOINCREMENT, account_id TEXT NOT NULL, room_id TEXT,
 entity_id TEXT NOT NULL, kind TEXT NOT NULL, revision INTEGER NOT NULL, source TEXT NOT NULL
) STRICT;
CREATE INDEX outbox_account ON outbox(account_id,sequence);
"#;

// Schema v2 adds a distinct, opt-in QR wire identity without touching device selection.
const QR_SCHEMA: &str = r#"
CREATE TABLE qr_wire_profile(id INTEGER PRIMARY KEY CHECK(id=1), json TEXT NOT NULL) STRICT;
INSERT INTO metadata VALUES ('qr_wire_initialized','0');
"#;

// Schema v3 tracks authorization attempts, not synchronized native sessions.
const AUTH_SCHEMA: &str = r#"
CREATE TABLE qr_auth_attempt(
 id INTEGER PRIMARY KEY CHECK(id=1), attempt_id TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('pending','stopped','authorized')),
 started_at_ms INTEGER NOT NULL, stop_code TEXT, handoff_hash TEXT
) STRICT;
"#;

// Schema v4 indexes only live text. Contentless FTS keeps canonical bodies in
// messages; its rowids follow the stable messages rowid across revision upserts.
// Triggers participate in the ingest transaction, including replay/conflict rollback.
const SEARCH_SCHEMA: &str = r#"
CREATE VIRTUAL TABLE message_text USING fts5(
 body, content='', tokenize='trigram case_sensitive 1'
);
CREATE TRIGGER messages_text_insert AFTER INSERT ON messages
WHEN new.deleted=0 AND new.body IS NOT NULL BEGIN
 INSERT INTO message_text(rowid,body) VALUES(new.rowid,new.body);
END;
CREATE TRIGGER messages_text_update AFTER UPDATE ON messages BEGIN
 INSERT INTO message_text(message_text,rowid,body)
 SELECT 'delete',old.rowid,old.body WHERE old.deleted=0 AND old.body IS NOT NULL;
 INSERT INTO message_text(rowid,body)
 SELECT new.rowid,new.body WHERE new.deleted=0 AND new.body IS NOT NULL;
END;
CREATE TRIGGER messages_text_delete AFTER DELETE ON messages
WHEN old.deleted=0 AND old.body IS NOT NULL BEGIN
 INSERT INTO message_text(message_text,rowid,body) VALUES('delete',old.rowid,old.body);
END;
INSERT INTO message_text(rowid,body)
 SELECT rowid,body FROM messages WHERE deleted=0 AND body IS NOT NULL;
"#;

// Schema v5: durable reception before application-specific dispatch. This is
// captured protocol data, not the canonical API message store.
const NATIVE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS native_events(
 sequence INTEGER PRIMARY KEY AUTOINCREMENT,
 source TEXT NOT NULL, received_at_ms INTEGER NOT NULL,
 payload BLOB NOT NULL, processed INTEGER NOT NULL DEFAULT 0 CHECK(processed IN(0,1))
) STRICT;
CREATE INDEX IF NOT EXISTS native_events_source ON native_events(source,sequence);
"#;

// Schema v6: private, resumable Drawer history. Canonical text uses the existing
// messages/FTS/outbox transaction; raw pages preserve unsupported record fields.
const DRAWER_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS drawer_pages(
 id INTEGER PRIMARY KEY AUTOINCREMENT, account_id TEXT NOT NULL,
 stage TEXT NOT NULL, request_cursor TEXT NOT NULL, next_cursor TEXT,
 is_last INTEGER NOT NULL, payload BLOB NOT NULL, received_at_ms INTEGER NOT NULL,
 UNIQUE(account_id,stage,request_cursor)
) STRICT;
CREATE TABLE IF NOT EXISTS drawer_rooms(
 account_id TEXT NOT NULL, chat_id INTEGER NOT NULL, payload TEXT NOT NULL,
 page_id INTEGER NOT NULL REFERENCES drawer_pages(id),
 PRIMARY KEY(account_id,chat_id)
) STRICT;
CREATE TABLE IF NOT EXISTS drawer_records(
 account_id TEXT NOT NULL, chat_id INTEGER NOT NULL, log_id INTEGER NOT NULL,
 revision INTEGER NOT NULL, raw_type INTEGER NOT NULL, author_id INTEGER NOT NULL,
 sent_at_ms INTEGER NOT NULL, message TEXT NOT NULL, deleted INTEGER NOT NULL,
 payload TEXT NOT NULL, page_id INTEGER NOT NULL REFERENCES drawer_pages(id),
 PRIMARY KEY(account_id,chat_id,log_id)
) STRICT;
CREATE TABLE IF NOT EXISTS drawer_tombstones(
 account_id TEXT NOT NULL, chat_id INTEGER NOT NULL, log_id INTEGER NOT NULL,
 reason TEXT NOT NULL, page_id INTEGER NOT NULL REFERENCES drawer_pages(id),
 PRIMARY KEY(account_id,chat_id,log_id)
) STRICT;
"#;

const DRAWER_FOLLOWUP_SCHEMA: &str = r#"
CREATE VIEW IF NOT EXISTS drawer_android_logs AS SELECT r.*,
 CASE WHEN raw_type=0 AND json_valid(message) THEN coalesce(json_extract(message,'$.feedType')=16,0) ELSE 0 END AS android_deleted,
 coalesce(json_extract(payload,'$.scope'),CASE WHEN json_valid(json_extract(payload,'$.supplement')) THEN json_extract(json_extract(payload,'$.supplement'),'$.scope') ELSE NULL END) AS scope,
 raw_type | CASE WHEN EXISTS(SELECT 1 FROM drawer_tombstones t WHERE t.account_id=r.account_id AND t.chat_id=r.chat_id AND t.log_id=r.log_id AND t.reason='delete_for_all') THEN 16384 ELSE 0 END AS android_type
 FROM drawer_records r;
CREATE TABLE IF NOT EXISTS drawer_room_state(
 account_id TEXT NOT NULL, chat_id INTEGER NOT NULL,
 first_log_id INTEGER NOT NULL, last_log_id INTEGER NOT NULL,
 last_seen_log_id INTEGER NOT NULL, last_read_log_id INTEGER NOT NULL,
 unread_count INTEGER NOT NULL, preview_log_id INTEGER,
 meta_to INTEGER NOT NULL, meta_done INTEGER NOT NULL,
 synced_meta_log_id INTEGER NOT NULL DEFAULT 0, meta_revision INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(account_id,chat_id)
) STRICT;
CREATE TABLE IF NOT EXISTS drawer_meta_pages(
 account_id TEXT NOT NULL, chat_id INTEGER NOT NULL, request_to INTEGER NOT NULL,
 payload BLOB NOT NULL, is_last INTEGER NOT NULL,
 PRIMARY KEY(account_id,chat_id,request_to)
) STRICT;
CREATE TABLE IF NOT EXISTS drawer_meta_stage(
 account_id TEXT NOT NULL, chat_id INTEGER NOT NULL, request_to INTEGER NOT NULL,
 ordinal INTEGER NOT NULL, log_id INTEGER NOT NULL, payload TEXT NOT NULL,
 PRIMARY KEY(account_id,chat_id,request_to,ordinal)
) STRICT;
CREATE TABLE IF NOT EXISTS drawer_log_meta(
 account_id TEXT NOT NULL, chat_id INTEGER NOT NULL, log_id INTEGER NOT NULL,
 type INTEGER NOT NULL, raw_type INTEGER NOT NULL, revision INTEGER NOT NULL,
 content TEXT NOT NULL, extra TEXT, extra_revision INTEGER NOT NULL,
 extra_state TEXT NOT NULL, payload TEXT NOT NULL,
 PRIMARY KEY(account_id,chat_id,log_id,type)
) STRICT;
"#;

// Schema v8 separates friend membership/profile provenance from message authors.
const FRIENDS_SCHEMA: &str = r#"
CREATE TABLE native_friend_profiles(
 account_id TEXT NOT NULL, user_id TEXT NOT NULL, relation INTEGER NOT NULL,
 is_channel INTEGER NOT NULL CHECK(is_channel IN(0,1)),
 is_current INTEGER NOT NULL CHECK(is_current IN(0,1)),
 profile_name TEXT NOT NULL, friend_name TEXT, phone_key TEXT, hidden INTEGER NOT NULL,
 purged INTEGER NOT NULL, raw_json TEXT NOT NULL, capture_sequence INTEGER NOT NULL,
 PRIMARY KEY(account_id,user_id)
) STRICT;
CREATE INDEX native_friend_phone ON native_friend_profiles(account_id,phone_key);
CREATE TABLE native_friend_sync(
 account_id TEXT PRIMARY KEY, since INTEGER NOT NULL, remote_total INTEGER NOT NULL,
 local_total INTEGER NOT NULL, reconciled INTEGER NOT NULL CHECK(reconciled IN(0,1)),
 observed_at_ms INTEGER NOT NULL, capture_sequence INTEGER NOT NULL
) STRICT;
CREATE TABLE contact_names(
 account_id TEXT NOT NULL, client_id TEXT NOT NULL, phone_key TEXT NOT NULL,
 display_name TEXT, snapshot_id TEXT NOT NULL, observed_at_ms INTEGER NOT NULL,
 PRIMARY KEY(account_id,client_id,phone_key)
) STRICT;
CREATE INDEX contact_names_phone ON contact_names(account_id,phone_key);
CREATE TABLE contact_snapshot_state(
 account_id TEXT PRIMARY KEY, snapshot_id TEXT NOT NULL, created_at INTEGER NOT NULL,
 contact_count INTEGER NOT NULL, matched_friends INTEGER NOT NULL, observed_at_ms INTEGER NOT NULL
) STRICT;
CREATE INDEX messages_sender_time ON messages(account_id,sender_id,sent_at_ms,room_id,message_id) WHERE deleted=0;
"#;

const LIVE_SCHEMA: &str = r#"
CREATE TABLE loco_rooms(
 account_id TEXT NOT NULL, chat_id INTEGER NOT NULL, read_log_id INTEGER NOT NULL DEFAULT 0,
 cursor INTEGER NOT NULL DEFAULT 0, target INTEGER NOT NULL DEFAULT 0,
 active INTEGER NOT NULL DEFAULT 1, raw BLOB,
 PRIMARY KEY(account_id,chat_id)
) STRICT;
CREATE TABLE loco_logs(
 account_id TEXT NOT NULL, chat_id INTEGER NOT NULL, log_id INTEGER NOT NULL,
 prev_id INTEGER NOT NULL, revision INTEGER NOT NULL, kind INTEGER NOT NULL,
 raw BLOB NOT NULL, capture_sequence INTEGER NOT NULL, projected INTEGER NOT NULL,
 PRIMARY KEY(account_id,chat_id,log_id)
) STRICT;
CREATE TABLE loco_inbox(
 sequence INTEGER PRIMARY KEY REFERENCES native_events(sequence), account_id TEXT NOT NULL,
 generation TEXT NOT NULL, command TEXT NOT NULL, packet_id INTEGER NOT NULL,
 applied INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE INDEX loco_inbox_account ON loco_inbox(account_id,sequence);
CREATE TABLE live_status(
 account_id TEXT PRIMARY KEY, phase TEXT NOT NULL, generation TEXT,
 updated_at_ms INTEGER NOT NULL, last_packet_at_ms INTEGER,
 connections INTEGER NOT NULL DEFAULT 0, messages_received INTEGER NOT NULL DEFAULT 0,
 error_category TEXT, server_status INTEGER
) STRICT;
"#;

const ENRICHMENT_SCHEMA: &str = r#"
CREATE TABLE loco_requests(account_id TEXT NOT NULL,generation TEXT NOT NULL,packet_id INTEGER NOT NULL,command TEXT NOT NULL,body BLOB NOT NULL,refresh_sequence INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(account_id,generation,packet_id)) STRICT;
CREATE TABLE message_refresh(account_id TEXT NOT NULL,chat_id INTEGER NOT NULL,log_id INTEGER NOT NULL,requested_sequence INTEGER NOT NULL,retry_at_ms INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(account_id,chat_id,log_id)) STRICT;
CREATE TABLE native_tombstones(account_id TEXT NOT NULL,chat_id INTEGER NOT NULL,log_id INTEGER NOT NULL,capture_sequence INTEGER NOT NULL,PRIMARY KEY(account_id,chat_id,log_id)) STRICT;
CREATE TABLE room_details(account_id TEXT NOT NULL,chat_id INTEGER NOT NULL,raw BLOB NOT NULL,member_token INTEGER,updated_at_ms INTEGER NOT NULL,capture_sequence INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(account_id,chat_id)) STRICT;
CREATE TABLE room_members(account_id TEXT NOT NULL,chat_id INTEGER NOT NULL,user_id INTEGER NOT NULL,nickname TEXT NOT NULL,member_type INTEGER NOT NULL,raw BLOB NOT NULL,updated_at_ms INTEGER NOT NULL,capture_sequence INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(account_id,chat_id,user_id)) STRICT;
CREATE TABLE room_refresh(account_id TEXT NOT NULL,chat_id INTEGER NOT NULL,requested_sequence INTEGER NOT NULL DEFAULT 0,completed_sequence INTEGER NOT NULL DEFAULT -1,retry_at_ms INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(account_id,chat_id)) STRICT;
CREATE TABLE message_media(account_id TEXT NOT NULL,chat_id INTEGER NOT NULL,log_id INTEGER NOT NULL,revision INTEGER NOT NULL,kind INTEGER NOT NULL,sent_at_ms INTEGER NOT NULL,sender_id INTEGER,attachment TEXT NOT NULL,source TEXT NOT NULL,PRIMARY KEY(account_id,chat_id,log_id)) STRICT;
CREATE INDEX message_media_time ON message_media(account_id,sent_at_ms,chat_id,log_id);
INSERT INTO message_media SELECT account_id,chat_id,log_id,revision,raw_type,sent_at_ms,author_id,json_extract(payload,'$.attachment'),'native_drawer' FROM drawer_records WHERE deleted=0 AND raw_type IN(2,3,5,18,27) AND json_valid(payload) AND json_type(payload,'$.attachment')='text';
"#;

const READ_STATE_SCHEMA: &str = r#"
CREATE TABLE room_read_watermarks(account_id TEXT NOT NULL,chat_id INTEGER NOT NULL,user_id INTEGER NOT NULL,watermark INTEGER NOT NULL,capture_sequence INTEGER NOT NULL,PRIMARY KEY(account_id,chat_id,user_id)) STRICT;
"#;

const ROSTER_SCHEMA: &str = r#"
ALTER TABLE loco_requests ADD COLUMN issued_sequence INTEGER NOT NULL DEFAULT 0;
CREATE TABLE room_roster_state(account_id TEXT NOT NULL,chat_id INTEGER NOT NULL,member_token INTEGER NOT NULL DEFAULT 0,complete INTEGER NOT NULL DEFAULT 0,capture_sequence INTEGER NOT NULL,updated_at_ms INTEGER NOT NULL,PRIMARY KEY(account_id,chat_id)) STRICT;
CREATE TABLE room_active_members(account_id TEXT NOT NULL,chat_id INTEGER NOT NULL,user_id INTEGER NOT NULL,PRIMARY KEY(account_id,chat_id,user_id)) STRICT;
CREATE TABLE pilsner_accounts(sequence INTEGER PRIMARY KEY REFERENCES native_events(sequence),account_id TEXT NOT NULL) STRICT;
CREATE INDEX pilsner_accounts_account ON pilsner_accounts(account_id,sequence);
CREATE TABLE friend_refresh(account_id TEXT NOT NULL,user_id INTEGER NOT NULL,requested_sequence INTEGER NOT NULL,completed_sequence INTEGER NOT NULL DEFAULT 0,retry_at_ms INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(account_id,user_id)) STRICT;
CREATE TABLE friend_favorites(account_id TEXT NOT NULL,user_id TEXT NOT NULL,favorite INTEGER NOT NULL,capture_sequence INTEGER NOT NULL,PRIMARY KEY(account_id,user_id)) STRICT;
"#;

const DOMAIN_SCHEMA: &str = r#"
CREATE TABLE blocked_users(account_id TEXT NOT NULL,user_id TEXT NOT NULL,is_channel INTEGER NOT NULL,profile_block INTEGER NOT NULL,capture_sequence INTEGER NOT NULL,PRIMARY KEY(account_id,user_id,is_channel)) STRICT;
CREATE TABLE block_sync_state(account_id TEXT NOT NULL,is_channel INTEGER NOT NULL,observed_revision INTEGER,complete INTEGER NOT NULL,capture_sequence INTEGER NOT NULL,PRIMARY KEY(account_id,is_channel)) STRICT;
CREATE TABLE blocked_profiles(account_id TEXT NOT NULL,user_id TEXT NOT NULL,is_channel INTEGER NOT NULL,nickname TEXT NOT NULL,capture_sequence INTEGER NOT NULL,PRIMARY KEY(account_id,user_id,is_channel)) STRICT;
CREATE TABLE blocked_profile_retry(account_id TEXT NOT NULL,user_id TEXT NOT NULL,is_channel INTEGER NOT NULL,retry_at_ms INTEGER NOT NULL,PRIMARY KEY(account_id,user_id,is_channel)) STRICT;
CREATE TABLE domain_tokens(account_id TEXT NOT NULL,kind INTEGER NOT NULL,observed_token INTEGER NOT NULL,capture_sequence INTEGER NOT NULL,PRIMARY KEY(account_id,kind)) STRICT;
CREATE TABLE room_identity_context(account_id TEXT NOT NULL,chat_id INTEGER NOT NULL,room_type TEXT NOT NULL,link_id INTEGER NOT NULL DEFAULT 0,capture_sequence INTEGER NOT NULL,PRIMARY KEY(account_id,chat_id)) STRICT;
CREATE TABLE room_member_origins(account_id TEXT NOT NULL,chat_id INTEGER NOT NULL,user_id INTEGER NOT NULL,link_id INTEGER NOT NULL,room_type TEXT NOT NULL,PRIMARY KEY(account_id,chat_id,user_id)) STRICT;
"#;
