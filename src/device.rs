use crate::{error::valid_id, Error, Result, Store};
use chrono::{Months, NaiveDate};
use rand::seq::SliceRandom;
use rusqlite::{OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use url::Url;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceCandidate {
    pub release_date: NaiveDate,
    pub model_code: String,
    pub manufacturer: String,
    pub name: String,
    pub source_urls: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub version: String,
    pub devices: Vec<DeviceCandidate>,
}

impl Catalog {
    pub fn validate(&self) -> Result<()> {
        valid_id(&self.version, "catalog version")?;
        if self.devices.is_empty() || self.devices.len() > 1000 {
            return Err(Error::Invalid("catalog requires 1..1000 devices".into()));
        }
        let mut codes = HashSet::new();
        for device in &self.devices {
            if device.manufacturer != "Samsung"
                || !device.name.starts_with("Galaxy Tab ")
                || !device.model_code.starts_with("SM-")
                || !device
                    .model_code
                    .bytes()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'-')
            {
                return Err(Error::Invalid(
                    "catalog requires Samsung Galaxy Tab model codes and names".into(),
                ));
            }
            valid_id(&device.model_code, "model code")?;
            valid_id(&device.name, "model name")?;
            if device.release_date < NaiveDate::from_ymd_opt(2010, 1, 1).unwrap()
                || !codes.insert(&device.model_code)
                || device.source_urls.is_empty()
                || device.source_urls.len() > 10
            {
                return Err(Error::Invalid(
                    "invalid release date, duplicate model, or missing source URLs".into(),
                ));
            }
            for source in &device.source_urls {
                let url =
                    Url::parse(source).map_err(|_| Error::Invalid("invalid source URL".into()))?;
                let host = url.host_str().unwrap_or_default();
                if url.scheme() != "https"
                    || !url.username().is_empty()
                    || url.password().is_some()
                    || !(host == "samsung.com"
                        || host.ends_with(".samsung.com")
                        || host == "samsungmobile.com"
                        || host.ends_with(".samsungmobile.com"))
                {
                    return Err(Error::Invalid(
                        "catalog source URLs must use official Samsung HTTPS hosts".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn eligible(&self, on: NaiveDate) -> Result<Vec<&DeviceCandidate>> {
        self.validate()?;
        let earliest = on
            .checked_sub_months(Months::new(48))
            .ok_or_else(|| Error::Invalid("selection date out of range".into()))?;
        Ok(self
            .devices
            .iter()
            .filter(|d| d.release_date >= earliest && d.release_date <= on)
            .collect())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceProfile {
    pub schema_version: u32,
    pub catalog_version: String,
    pub selected_on: NaiveDate,
    pub selected_at_utc: chrono::DateTime<chrono::Utc>,
    /// Locally generated application identity. It is not an Android or hardware identifier.
    pub app_instance_id: Uuid,
    pub model: DeviceCandidate,
    pub native_auth_ready: bool,
    pub android_id: Option<String>,
    pub build_fingerprint: Option<String>,
    pub attestation: Option<String>,
}

pub(crate) fn decode_profile(raw: &str) -> Result<DeviceProfile> {
    let profile: DeviceProfile = serde_json::from_str(raw).map_err(|_| {
        Error::Storage(
            "device profile corrupt; restore the saved identity, do not regenerate".into(),
        )
    })?;
    let catalog = Catalog {
        version: profile.catalog_version.clone(),
        devices: vec![profile.model.clone()],
    };
    if profile.schema_version != 1
        || profile.app_instance_id.is_nil()
        || profile.native_auth_ready
        || profile.android_id.is_some()
        || profile.build_fingerprint.is_some()
        || profile.attestation.is_some()
        || catalog.eligible(profile.selected_on)?.is_empty()
    {
        return Err(Error::Storage(
            "device profile inconsistent; explicit recovery required".into(),
        ));
    }
    Ok(profile)
}

impl Store {
    pub fn device_show(&self) -> Result<DeviceProfile> {
        let connection = self.lock()?;
        let marker: String = connection.query_row(
            "SELECT value FROM metadata WHERE key='device_initialized'",
            [],
            |r| r.get(0),
        )?;
        let raw: Option<String> = connection
            .query_row("SELECT json FROM device_profile WHERE id=1", [], |r| {
                r.get(0)
            })
            .optional()?;
        match (marker.as_str(), raw) {
            ("1", Some(raw)) => decode_profile(&raw),
            ("0", None) => Err(Error::NotFound),
            _ => Err(Error::Storage(
                "device state missing or inconsistent; explicit recovery required".into(),
            )),
        }
    }

    /// Select at most once. Existing profile takes priority even after the catalog ages out.
    pub fn device_initialize(&self, catalog: &Catalog, on: NaiveDate) -> Result<DeviceProfile> {
        let mut connection = self.lock()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let marker: String = tx.query_row(
            "SELECT value FROM metadata WHERE key='device_initialized'",
            [],
            |r| r.get(0),
        )?;
        let raw: Option<String> = tx
            .query_row("SELECT json FROM device_profile WHERE id=1", [], |r| {
                r.get(0)
            })
            .optional()?;
        match (marker.as_str(), raw) {
            ("1", Some(raw)) => return decode_profile(&raw),
            ("0", None) => (),
            _ => {
                return Err(Error::Storage(
                    "device state missing or inconsistent; explicit recovery required".into(),
                ))
            }
        }
        let eligible = catalog.eligible(on)?;
        let model = eligible.choose(&mut rand::rngs::OsRng).ok_or_else(|| {
            Error::Invalid(
                "no verified Galaxy Tab released within the previous four calendar years".into(),
            )
        })?;
        let profile = DeviceProfile {
            schema_version: 1,
            catalog_version: catalog.version.clone(),
            selected_on: on,
            selected_at_utc: chrono::Utc::now(),
            app_instance_id: Uuid::new_v4(),
            model: (*model).clone(),
            native_auth_ready: false,
            android_id: None,
            build_fingerprint: None,
            attestation: None,
        };
        tx.execute(
            "INSERT INTO device_profile(id,json) VALUES(1,?1)",
            [serde_json::to_string(&profile)?],
        )?;
        tx.execute(
            "UPDATE metadata SET value='1' WHERE key='device_initialized'",
            [],
        )?;
        tx.commit()?;
        Ok(profile)
    }
}
