//! Accessors and encoders for decoded JSON values.
//!
//! The Go implementation decodes every request body into `map[string]any`.
//! `serde_json::Value` with its default (BTreeMap) map keeps the same sorted
//! key order when encoding. The helpers below mirror `internal/jsonutil`.

use serde::Serialize;
use serde_json::{Map, Value};

pub type JValue = Value;
pub type JMap = Map<String, Value>;

pub fn json<T: Serialize>(value: T) -> anyhow::Result<String> {
    Ok(serde_json::to_string(&value)?)
}

pub fn json_opt<T: Serialize>(value: &T) -> anyhow::Result<Vec<u8>> {
    Ok(serde_json::to_vec(value)?)
}

pub fn first_non_zero(values: &[i64]) -> i64 {
    values.iter().copied().find(|value| *value != 0).unwrap_or(0)
}

/// Decodes a JSON string, returning the decoded value when it parses and the
/// string itself otherwise. An empty string yields an empty object.
pub fn parse_json_or_string(value: &str) -> Value {
    if value.is_empty() {
        return Value::Object(JMap::new());
    }
    serde_json::from_str(value).unwrap_or_else(|_| Value::String(value.to_string()))
}

/// Sets `object[key]` unless the value is null.
pub fn put(object: &mut JMap, key: &str, value: Value) {
    if !value.is_null() {
        object.insert(key.to_string(), value);
    }
}

pub fn first_any(values: Vec<Value>) -> Value {
    values
        .into_iter()
        .find(|value| !value.is_null())
        .unwrap_or(Value::Null)
}

pub fn clone_map(input: &JMap) -> JMap {
    input.clone()
}

/// Returns a slice view: arrays unchanged, null as empty, any other value as a
/// one-element slice.
pub fn as_slice(value: &Value) -> Vec<Value> {
    match value {
        Value::Array(items) => items.clone(),
        Value::Null => Vec::new(),
        other => vec![other.clone()],
    }
}

pub fn slice_at<'a>(object: &'a JMap, path: &[&str]) -> Vec<Value> {
    match any_at(object, path) {
        Some(Value::Array(items)) => items.clone(),
        _ => Vec::new(),
    }
}

pub fn map_at<'a>(object: &'a JMap, path: &[&str]) -> Option<&'a JMap> {
    any_at(object, path).and_then(Value::as_object)
}

pub fn string_at(object: &JMap, path: &[&str]) -> String {
    any_at(object, path)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

pub fn bool_at(object: &JMap, path: &[&str]) -> bool {
    any_at(object, path)
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

pub fn int_at(object: &JMap, path: &[&str]) -> i64 {
    match any_at(object, path) {
        Some(Value::Number(number)) => number
            .as_i64()
            .or_else(|| number.as_f64().map(|value| value as i64))
            .unwrap_or(0),
        Some(Value::Bool(value)) => i64::from(*value),
        _ => 0,
    }
}

pub fn any_at<'a>(object: &'a JMap, path: &[&str]) -> Option<&'a Value> {
    if path.is_empty() {
        return None;
    }
    let mut value: Option<&Value> = None;
    for (index, key) in path.iter().enumerate() {
        let map = if index == 0 {
            object
        } else {
            value?.as_object()?
        };
        value = map.get(*key);
    }
    value
}

pub fn first_string(values: &[String]) -> String {
    values
        .iter()
        .map(|value| value.trim())
        .find(|value| !value.is_empty())
        .unwrap_or_default()
        .to_string()
}

/// Percent-encodes nothing; placeholders for the Go helpers that are not used
/// by the Rust port remain absent rather than duplicated.
