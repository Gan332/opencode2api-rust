//! Wire protocols served by the gateway and converted by the bridge.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    #[default]
    Chat,
    Responses,
    Anthropic,
    SystemOne,
}

impl Protocol {
    pub fn valid(self) -> bool {
        true
    }

    pub fn from_str(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "chat" => Some(Self::Chat),
            "responses" => Some(Self::Responses),
            "anthropic" => Some(Self::Anthropic),
            "systemone" => Some(Self::SystemOne),
            _ => None,
        }
    }

    pub fn path(self) -> &'static str {
        match self {
            Self::Responses => "/v1/responses",
            Self::Anthropic => "/v1/messages",
            Self::SystemOne => "/v1/systemone",
            Self::Chat => "/v1/chat/completions",
        }
    }
}

/// Token accounting shared by every protocol.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    /// Total prompt input, including cache reads and writes.
    pub input: i64,
    pub output: i64,
    pub total: i64,
    pub cached: i64,
    pub cache_creation: i64,
    pub reasoning: i64,
}

pub mod errors;
