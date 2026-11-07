use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerKeyMetadata {
    pub name: String,
    #[serde(skip_serializing_if = "is_false")]
    pub disabled: bool,
    #[serde(default, with = "time::serde::rfc3339::option", skip_serializing_if = "Option::is_none")]
    pub created_at: Option<OffsetDateTime>,
}

fn is_false(value: &bool) -> bool {
    !*value
}
