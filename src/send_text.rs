//! Ordinary text preprocessing against the current server keyword configuration.
use crate::{Error, Result};
use rusqlite::{OptionalExtension, Transaction};

pub(crate) fn prepare_extra(tx: &Transaction<'_>, account: &str, text: &str) -> Result<String> {
    let requested: i64 = tx
        .query_row(
            "SELECT CAST(value AS INTEGER) FROM metadata WHERE key=?1",
            [format!("text_config_requested:{account}")],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or(0);
    let cached: Option<String> = tx
        .query_row(
            "SELECT value FROM metadata WHERE key=?1",
            [format!("text_config:{account}")],
            |r| r.get(0),
        )
        .optional()?;
    let cached = cached.ok_or(Error::ServiceUnavailable("text_settings_pending"))?;
    let cached: serde_json::Value = serde_json::from_str(&cached)?;
    if cached
        .get("revision")
        .and_then(|v| v.as_i64())
        .unwrap_or(-1)
        < requested
    {
        return Err(Error::ServiceUnavailable("text_settings_pending"));
    }
    check_keywords(&cached["settings"], text)?;
    Ok("{}".into())
}
fn check_keywords(settings: &serde_json::Value, text: &str) -> Result<()> {
    // Feature-bearing sends need their own context; never discard a detected effect.
    if let Some(groups) = settings.get("keywords").and_then(|v| v.as_array()) {
        for group in groups {
            let words = group
                .get("keywords")
                .and_then(|v| v.as_array())
                .ok_or(Error::ServiceUnavailable("text_settings_invalid"))?;
            for word in words {
                let word = word
                    .as_str()
                    .ok_or(Error::ServiceUnavailable("text_settings_invalid"))?;
                if !word.is_empty() && text.trim().contains(word) {
                    return Err(Error::Invalid(
                        "text requires an unsupported keyword effect".into(),
                    ));
                }
            }
        }
        Ok(())
    } else if settings.get("keywords").is_none_or(|v| v.is_null()) {
        Ok(())
    } else {
        Err(Error::ServiceUnavailable("text_settings_invalid"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn keyword_effects_are_never_silently_removed() {
        let settings = serde_json::json!({"keywords":[{"keywords":["birthday"]}]});
        assert!(check_keywords(&settings, "ordinary").is_ok());
        assert!(check_keywords(&settings, " happy birthday ").is_err());
        assert!(check_keywords(&serde_json::json!({"keywords":[{}]}), "ordinary").is_err());
    }
}
