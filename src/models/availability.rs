//! Probe state for free models.

use anyhow::{anyhow, Result};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use time::OffsetDateTime;

pub const FREE_MODEL_CHECK_INTERVAL: Duration = Duration::from_secs(60 * 60);
pub const FAILED_MODEL_CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EffortProbe {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub effort: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub protocol: String,
    #[serde(skip)]
    pub reset: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Availability {
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<OffsetDateTime>,
    #[serde(default)]
    pub next_check: Option<OffsetDateTime>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub channel: String,
    #[serde(default)]
    pub manual: bool,
    #[serde(skip)]
    pub generation: u64,
    #[serde(default)]
    pub probe_version: i32,
    #[serde(default)]
    pub auto_effort: EffortProbe,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effort_checked_at: Option<OffsetDateTime>,
}

pub struct AvailabilityRegistry {
    path: String,
    items: RwLock<HashMap<String, Availability>>,
}

impl AvailabilityRegistry {
    pub fn load(path: &str) -> Result<Self> {
        let mut items: HashMap<String, Availability> = HashMap::new();
        if !path.is_empty() {
            match std::fs::read(path) {
                Ok(data) => {
                    items = serde_json::from_slice(&data)?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        for item in items.values_mut() {
            if item.probe_version == 0 && item.disabled {
                item.disabled = false;
                item.next_check = None;
                item.reason = "legacy_probe_recheck".into();
            }
            if !item.disabled && !item.manual && item.reason == "manually_enabled" {
                item.manual = true;
            }
        }
        Ok(Self {
            path: path.to_string(),
            items: RwLock::new(items),
        })
    }

    pub fn get(&self, model: &str) -> Availability {
        let mut item = self.items.read().get(model).cloned().unwrap_or_default();
        item.model = model.to_string();
        item
    }

    pub fn disabled(&self, model: &str) -> bool {
        self.get(model).disabled
    }

    pub fn set_manual(&self, model: &str, manual: bool, now: OffsetDateTime) -> Result<()> {
        let mut items = self.items.write();
        let existed = items.contains_key(model);
        let mut item = items.get(model).cloned().unwrap_or_default();
        if item.manual == manual {
            return Ok(());
        }
        let previous = item.clone();
        item.model = model.to_string();
        item.manual = manual;
        item.generation += 1;
        item.probe_version = 1;
        if manual {
            item.disabled = false;
            item.reason = "manually_enabled".into();
            item.next_check = Some(now + time::Duration::seconds(FREE_MODEL_CHECK_INTERVAL.as_secs() as i64));
        } else {
            item.reason = "auto_probe".into();
            item.next_check = None;
        }
        items.insert(model.to_string(), item);
        let data = serde_json::to_vec_pretty(&*items)?;
        if let Err(error) = self.save(&data) {
            if existed {
                items.insert(model.to_string(), previous);
            } else {
                items.remove(model);
            }
            return Err(error);
        }
        Ok(())
    }

    pub fn restore(&self, model: &str, now: OffsetDateTime) -> Result<()> {
        self.set_manual(model, true, now)
    }

    pub fn schedule_sweep(&self) -> Result<()> {
        let mut items = self.items.write();
        for item in items.values_mut() {
            if item.manual {
                continue;
            }
            item.next_check = None;
        }
        let data = serde_json::to_vec_pretty(&*items)?;
        self.save(&data)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &self,
        model: &str,
        generation: u64,
        success: bool,
        reason: &str,
        channel: &str,
        now: OffsetDateTime,
        effort: EffortProbe,
    ) -> Result<()> {
        let mut items = self.items.write();
        let mut item = items.get(model).cloned().unwrap_or_default();
        if item.generation != generation || item.manual {
            return Ok(());
        }
        item.model = model.to_string();
        if success {
            item.disabled = false;
        } else if reason == "model_unavailable" {
            item.disabled = true;
        } else if item.disabled {
            item.checked_at = Some(now);
            item.probe_version = 1;
            if item.next_check.map(|next| !(next > now)).unwrap_or(true) {
                item.next_check = Some(
                    now + time::Duration::seconds(FAILED_MODEL_CHECK_INTERVAL.as_secs() as i64),
                );
            }
            items.insert(model.to_string(), item);
            let data = serde_json::to_vec_pretty(&*items)?;
            return self.save(&data);
        }
        item.checked_at = Some(now);
        item.reason = reason.to_string();
        item.channel = channel.to_string();
        item.probe_version = 1;
        if success && !effort.effort.is_empty() {
            item.auto_effort = effort;
            item.effort_checked_at = Some(now);
        } else if success && effort.reset {
            item.auto_effort = EffortProbe::default();
            item.effort_checked_at = None;
        }
        let interval = if !success && reason == "model_unavailable" {
            FAILED_MODEL_CHECK_INTERVAL
        } else {
            FREE_MODEL_CHECK_INTERVAL
        };
        item.next_check = Some(now + time::Duration::seconds(interval.as_secs() as i64));
        items.insert(model.to_string(), item);
        let data = serde_json::to_vec_pretty(&*items)?;
        self.save(&data)
    }

    pub fn record_passive_observation(
        &self,
        model: &str,
        success: bool,
        status: u16,
        body: &str,
        channel: &str,
        now: OffsetDateTime,
    ) -> Result<()> {
        let mut items = self.items.write();
        let mut item = items.get(model).cloned().unwrap_or_default();
        if item.manual {
            return Ok(());
        }
        item.model = model.to_string();
        item.probe_version = 1;
        item.checked_at = Some(now);
        item.channel = channel.to_string();
        if success {
            item.disabled = false;
            item.reason = "passive_traffic_succeeded".into();
            item.next_check = Some(
                now + time::Duration::seconds(FREE_MODEL_CHECK_INTERVAL.as_secs() as i64),
            );
        } else if is_model_unavailable_reason(status, body) {
            item.disabled = true;
            item.reason = "model_unavailable".into();
            item.next_check = Some(
                now + time::Duration::seconds(FAILED_MODEL_CHECK_INTERVAL.as_secs() as i64),
            );
        }
        items.insert(model.to_string(), item);
        let data = serde_json::to_vec_pretty(&*items)?;
        self.save(&data)
    }

    pub fn items(&self) -> HashMap<String, Availability> {
        self.items.read().clone()
    }

    fn save(&self, data: &[u8]) -> Result<()> {
        if self.path.is_empty() {
            return Ok(());
        }
        crate::config::persistence::save_bytes_atomic(&self.path, data)
            .map_err(|error| anyhow!("save availability: {error}"))
    }
}

pub fn is_model_unavailable_reason(status: u16, body: &str) -> bool {
    if !matches!(status, 400 | 404 | 410 | 422) {
        return false;
    }
    let text = body.to_ascii_lowercase();
    [
        "model_not_found",
        "model_not_available",
        "model_retired",
        "model_deprecated",
        "unknown model",
        "model does not exist",
        "model has been retired",
        "model is no longer available",
    ]
    .iter()
    .any(|marker| text.contains(marker))
}
