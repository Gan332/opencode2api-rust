//! Protocol error envelopes.

use crate::protocol::Protocol;

pub const OPENAI_ERROR_SHAPE: &str = "openai";

pub fn error_body(protocol: Protocol, message: &str, kind: &str) -> serde_json::Value {
    if protocol == Protocol::Anthropic {
        serde_json::json!({
            "type": "error",
            "error": {"type": kind, "message": message}
        })
    } else {
        serde_json::json!({
            "error": {"message": message, "type": kind, "param": null, "code": null}
        })
    }
}
