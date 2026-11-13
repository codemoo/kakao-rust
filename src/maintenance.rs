//! Bounded background refresh independent of the receive socket.
//! Server polling intervals use local defaults; retry backoff is host policy.
use crate::{pilsner::Listener, Error, Result, Store};
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use tokio::{
    sync::watch,
    time::{Duration, Instant},
};

const JOBS: [&str; 5] = [
    "settings",
    "less_settings",
    "friends",
    "contacts",
    "text_config",
];
const MAX_POLL_SECONDS: i64 = 31_536_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JobStatus {
    pub job: String,
    pub phase: String,
    pub last_success_at_ms: Option<i64>,
    #[serde(default)]
    pub last_attempt_at_ms: Option<i64>,
    pub next_attempt_at_ms: i64,
    pub failures: u32,
    pub requested_sequence: i64,
    pub completed_sequence: i64,
}
impl JobStatus {
    fn new(job: &str) -> Self {
        Self {
            job: job.into(),
            phase: "pending".into(),
            last_success_at_ms: None,
            last_attempt_at_ms: None,
            next_attempt_at_ms: 0,
            failures: 0,
            requested_sequence: 0,
            completed_sequence: 0,
        }
    }
}
impl Store {
    fn maintenance_interval(&self, account: &str, job: &str) -> Result<i64> {
        let fallback = match job {
            "friends" => 600,
            "less_settings" | "contacts" => 21600,
            _ => 86400,
        };
        Ok(self
            .lock()?
            .query_row(
                "SELECT CAST(value AS INTEGER) FROM metadata WHERE key=?1",
                [format!("poll_seconds:{account}:{job}")],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
            .filter(|v| *v > 0 && *v <= MAX_POLL_SECONDS)
            .unwrap_or(fallback))
    }
    fn apply_poll_settings(&self, account: &str, value: &serde_json::Value) -> Result<()> {
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        for (field, job) in [
            ("friendsPollingInterval", "friends"),
            ("settingsPollingInterval", "settings"),
            ("lessSettingsPollingInterval", "less_settings"),
        ] {
            if let Some(seconds) = value
                .get(field)
                .and_then(|v| v.as_i64())
                .filter(|v| *v > 0 && *v <= MAX_POLL_SECONDS)
            {
                tx.execute("INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",rusqlite::params![format!("poll_seconds:{account}:{job}"),seconds.to_string()])?;
            }
        }
        if let Some(use_sub) = value.get("useSub").and_then(|v| v.as_bool()) {
            tx.execute("INSERT INTO metadata(key,value) VALUES('native_flag:useSub',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[use_sub.to_string()])?;
        }
        tx.execute("INSERT INTO metadata(key,value) VALUES(?1,'true') ON CONFLICT(key) DO UPDATE SET value=excluded.value",[format!("poll_settings_seen:{account}")])?;
        tx.commit()?;
        Ok(())
    }
    fn maintenance_job(&self, account: &str, job: &str) -> Result<JobStatus> {
        let raw: Option<String> = self
            .lock()?
            .query_row(
                "SELECT value FROM metadata WHERE key=?1",
                [format!("maintenance:{account}:{job}")],
                |r| r.get(0),
            )
            .optional()?;
        raw.map(|v| {
            serde_json::from_str(&v).map_err(|_| Error::Storage("invalid maintenance state".into()))
        })
        .unwrap_or_else(|| Ok(JobStatus::new(job)))
    }
    fn maintenance_save(&self, account: &str, job: &JobStatus) -> Result<()> {
        self.lock()?.execute("INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",rusqlite::params![format!("maintenance:{account}:{}",job.job),serde_json::to_string(job)?])?;
        Ok(())
    }
    pub fn maintenance_status(&self, account: &str) -> Result<Vec<JobStatus>> {
        JOBS.into_iter()
            .map(|job| self.maintenance_job(account, job))
            .collect()
    }
    pub(crate) fn maintenance_requested(&self, account: &str, job: &str) -> Result<i64> {
        Ok(self
            .lock()?
            .query_row(
                "SELECT CAST(value AS INTEGER) FROM metadata WHERE key=?1",
                [format!("refresh_request:{account}:{job}")],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(0))
    }
}
fn retry_delay(failures: u32) -> i64 {
    (30_i64.saturating_mul(1_i64 << failures.min(6))).min(1800) * 1000
}
/// The caller owns the session lease. This future is never detached: cancellation
/// stops HTTP work before the listener and its task-owned lease are closed.
pub(crate) async fn run(
    store: &Store,
    listener: &mut Listener,
    mut stop: watch::Receiver<bool>,
) -> Result<()> {
    let account = store.session_load()?.user_id().to_string();
    let mut next_gate = Instant::now();
    let mut sent_adid = false;
    let client = crate::native_http::Client::new()?;
    loop {
        if *stop.borrow() {
            return Ok(());
        }
        if Instant::now() >= next_gate {
            listener.ensure().await?;
            next_gate = Instant::now() + Duration::from_secs(30);
        }
        // A feature-specific single-user refresh never resets the global friend cursor.
        tokio::select! { _=stop.changed()=>return Ok(()), _=crate::friends::refresh_one(store,listener,&client)=>() }
        for name in JOBS {
            if name == "text_config" && store.maintenance_requested(&account, name)? == 0 {
                continue;
            }
            let interval = store.maintenance_interval(&account, name)?;
            let mut job = store.maintenance_job(&account, name)?;
            if name == "settings" && job.failures == 0 {
                let initialized: bool = store.lock()?.query_row(
                    "SELECT EXISTS(SELECT 1 FROM metadata WHERE key=?1)",
                    [format!("poll_settings_seen:{account}")],
                    |r| r.get(0),
                )?;
                if !initialized {
                    job.next_attempt_at_ms = 0;
                }
            }
            let now = chrono::Utc::now().timestamp_millis();
            let requested = store.maintenance_requested(&account, name)?;
            let triggered = requested > job.completed_sequence;
            if job.failures == 0 {
                if let Some(last) = job.last_success_at_ms {
                    job.next_attempt_at_ms = job
                        .next_attempt_at_ms
                        .min(last.saturating_add(interval * 1000));
                }
            }
            // Debounce trigger bursts and retry errors with bounded backoff.
            if now < job.next_attempt_at_ms
                && job.last_attempt_at_ms.is_none_or(|t| now >= t)
                && (!triggered
                    || job.failures > 0
                    || job.last_success_at_ms.is_some_and(|t| now - t < 30_000))
            {
                continue;
            }
            job.phase = "running".into();
            job.last_attempt_at_ms = Some(now);
            job.next_attempt_at_ms = now + interval * 1000;
            job.requested_sequence = requested;
            store.maintenance_save(&account, &job)?;
            let refresh = async {
                if name == "text_config" {
                    let revision: i64 = store.lock()?.query_row(
                        "SELECT CAST(value AS INTEGER) FROM metadata WHERE key=?1",
                        [format!("text_config_requested:{account}")],
                        |r| r.get(0),
                    )?;
                    let mut session = store.session_load()?;
                    let response = client
                        .execute(
                            store,
                            &mut session,
                            crate::native_http::Operation::TextSettings { revision },
                        )
                        .await?;
                    store.capture_native("text_settings", &response.body)?;
                    if response.http_status != 200 || response.server_status.is_some_and(|s| s != 0)
                    {
                        return Err(Error::Unavailable("text_settings_rejected"));
                    }
                    let value: serde_json::Value = serde_json::from_slice(&response.body)?;
                    if !value.is_object() {
                        return Err(Error::Unavailable("text_settings_invalid"));
                    }
                    let cached = serde_json::json!({"revision":revision,"settings":value});
                    store.lock()?.execute("INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",rusqlite::params![format!("text_config:{account}"),cached.to_string()])?;
                } else if name == "settings" {
                    let mut session = store.session_load()?;
                    let response = client
                        .execute(
                            store,
                            &mut session,
                            crate::native_http::Operation::MoreSettings {
                                include_adid: !sent_adid,
                            },
                        )
                        .await?;
                    sent_adid = true;
                    store.capture_native("more_settings", &response.body)?;
                    if response.http_status != 200 || response.server_status.is_some_and(|s| s != 0)
                    {
                        return Err(Error::Unavailable("settings_rejected"));
                    }
                    let value: serde_json::Value = serde_json::from_slice(&response.body)?;
                    store.apply_poll_settings(&account, &value)?;
                } else if name == "less_settings" {
                    let mut session = store.session_load()?;
                    let response = client
                        .execute(
                            store,
                            &mut session,
                            crate::native_http::Operation::LessSettings,
                        )
                        .await?;
                    store.capture_native("less_settings", &response.body)?;
                    if response.http_status != 200 || response.server_status.is_some_and(|s| s != 0)
                    {
                        return Err(Error::Unavailable("settings_rejected"));
                    }
                    let value: serde_json::Value = serde_json::from_slice(&response.body)?;
                    if !value.is_object() {
                        return Err(Error::Invalid("invalid less settings".into()));
                    }
                    // Persisted response is distinct from the global config cursor.
                } else if name == "friends" {
                    let status = crate::friends::sync_with_listener(store, listener).await?;
                    if !status.reconciled {
                        return Err(Error::Conflict(
                            "friend count reconciliation pending".into(),
                        ));
                    }
                } else {
                    crate::contacts::sync_with_listener(store, listener, None).await?;
                }
                Ok(())
            };
            let result = tokio::select! {
                _ = stop.changed() => return Ok(()),
                result = refresh => result,
            };
            let now = chrono::Utc::now().timestamp_millis();
            if result.is_ok() {
                job.phase = "idle".into();
                job.failures = 0;
                job.last_success_at_ms = Some(now);
                job.completed_sequence = requested;
                job.next_attempt_at_ms = now + store.maintenance_interval(&account, name)? * 1000;
            } else {
                job.phase = "retrying".into();
                job.failures = job.failures.saturating_add(1);
                job.next_attempt_at_ms = now + retry_delay(job.failures);
            }
            store.maintenance_save(&account, &job)?;
        }
        tokio::select! {_=stop.changed()=>return Ok(()),_=tokio::time::sleep(Duration::from_secs(5))=>()}
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn remote_polling_values_are_independent_and_invalid_values_preserve_state() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let store = Store::initialize(dir.path()).unwrap();
        store.apply_poll_settings("42",&serde_json::json!({"friendsPollingInterval":600,"settingsPollingInterval":518,"lessSettingsPollingInterval":21600,"contactsFullUploadPollingInterval":1})).unwrap();
        assert_eq!(store.maintenance_interval("42", "settings").unwrap(), 518);
        assert_eq!(store.maintenance_interval("42", "contacts").unwrap(), 21600);
        store
            .apply_poll_settings(
                "42",
                &serde_json::json!({"settingsPollingInterval":-1,"friendsPollingInterval":"bad"}),
            )
            .unwrap();
        assert_eq!(store.maintenance_interval("42", "settings").unwrap(), 518);
        assert_eq!(store.maintenance_interval("99", "settings").unwrap(), 86400);
    }
    #[test]
    fn schedule_is_durable_and_backoff_is_bounded() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let store = Store::initialize(d.path()).unwrap();
        store
            .capture_native("more_settings", br#"{"friendsPollingInterval":600}"#)
            .unwrap();
        let mut job = store.maintenance_job("42", "friends").unwrap();
        job.completed_sequence = 4;
        job.next_attempt_at_ms = 100;
        store.maintenance_save("42", &job).unwrap();
        drop(store);
        let store = Store::open(d.path()).unwrap();
        assert_eq!(
            store
                .maintenance_job("42", "friends")
                .unwrap()
                .completed_sequence,
            4
        );
        assert_eq!(retry_delay(1), 60_000);
        assert_eq!(retry_delay(99), 1_800_000);
    }
}
