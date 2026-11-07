//! Model-rotation group configuration.

use anyhow::{bail, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

pub const SOTA_MODELS: [&str; 5] = [
    "deepseek-v4.1-flash",
    "glm-5.3",
    "grok-4.6",
    "kimi-k3",
    "qwen3.8-max",
];

pub fn is_sota(model: &str) -> bool {
    SOTA_MODELS.contains(&model)
}

pub fn default_sota_order() -> Vec<String> {
    SOTA_MODELS.iter().map(|value| value.to_string()).collect()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RotationGroup {
    pub alias: String,
    pub order: Vec<String>,
}

impl Default for RotationGroup {
    fn default() -> Self {
        Self {
            alias: String::new(),
            order: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RotationConfig {
    pub sota: RotationGroup,
    pub sweet: RotationGroup,
    pub first_output_seconds: i64,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            sota: RotationGroup::default(),
            sweet: RotationGroup::default(),
            first_output_seconds: 30,
        }
    }
}

impl RotationConfig {
    pub fn defaults(&mut self) {
        if self.sota.alias.is_empty() {
            self.sota.alias = "sota".to_string();
        }
        if self.sweet.alias.is_empty() {
            self.sweet.alias = "sweet".to_string();
        }
        if self.sota.order.is_empty() {
            self.sota.order = default_sota_order();
        }
        if self.first_output_seconds == 0 {
            self.first_output_seconds = 30;
        }
    }
}

fn alias_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$").unwrap())
}

pub fn validate_rotation(cfg: &RotationConfig, real_models: &[String]) -> Result<()> {
    if !(1..=300).contains(&cfg.first_output_seconds) {
        bail!("首个有效输出超时需为 1–300 秒");
    }
    if cfg.sota.alias == cfg.sweet.alias {
        bail!("两个分组的别名不能相同");
    }
    let pattern = alias_pattern();
    for (index, group) in [&cfg.sota, &cfg.sweet].into_iter().enumerate() {
        if !pattern.is_match(&group.alias) {
            bail!("别名需为 1–64 位英文字母、数字、点、短横线或下划线");
        }
        if real_models.iter().any(|model| model == &group.alias)
            || is_sota(&group.alias)
            || cfg.sweet.order.iter().any(|model| model == &group.alias)
        {
            bail!("别名不能与真实模型 ID 相同");
        }
        let mut seen = std::collections::HashSet::new();
        for model in &group.order {
            if model.is_empty()
                || !seen.insert(model.clone())
                || is_sota(model) != (index == 0)
            {
                bail!("模型顺序包含重复、空值或不属于该分组的模型");
            }
        }
        if index == 0 && group.order.len() != SOTA_MODELS.len() {
            bail!("SOTA 组必须包含指定的五个模型");
        }
    }
    Ok(())
}
