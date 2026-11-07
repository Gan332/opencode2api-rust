//! Stable session identities and request IDs sent to the upstream.

use crate::jsonutil::{self, JMap, JValue};
use http::HeaderMap;
use once_cell::sync::Lazy;
use rand::RngCore;
use regex::Regex;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use time::{Duration, OffsetDateTime};

#[derive(Clone, Debug, Default)]
pub struct RequestIDs {
    pub session: String,
    pub child_session: String,
    pub request: String,
    pub message: String,
    pub project: String,
    pub parent_session: String,
}

fn header(headers: &HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

pub fn derive_request_ids(headers: &HeaderMap, body: &JMap, scope: &str) -> RequestIDs {
    let mut signal = jsonutil::first_string(&[
        header(headers, "x-opencode-session"),
        header(headers, "x-opencode-session-id"),
        header(headers, "x-session-affinity"),
        header(headers, "x-session-id"),
        header(headers, "session_id"),
        header(headers, "conversation-id"),
        header(headers, "conversation_id"),
        jsonutil::string_at(body, &["conversation_id"]),
        jsonutil::string_at(body, &["metadata", "session_id"]),
        claude_code_session_id(&jsonutil::string_at(body, &["metadata", "user_id"])),
    ]);
    if signal.is_empty() {
        signal = conversation_seed(body);
    }
    if signal.is_empty() {
        signal = jsonutil::string_at(body, &["previous_response_id"]);
    }
    if signal.is_empty() || signal == "{}" {
        signal = random_id("fallback", 16);
    }
    let session = scoped_session_id(scope, &signal);
    let mut child_session = header(headers, "x-opencode-session-id");
    if !child_session.is_empty() {
        child_session = scoped_session_id(scope, &child_session);
    }
    let mut project_signal = jsonutil::first_string(&[
        header(headers, "x-opencode-project"),
        jsonutil::string_at(body, &["metadata", "project_id"]),
    ]);
    if project_signal.is_empty() {
        project_signal = random_project_id();
    }
    let mut parent_session = jsonutil::first_string(&[
        header(headers, "x-parent-session-id"),
        jsonutil::string_at(body, &["metadata", "parent_session_id"]),
    ]);
    if !parent_session.is_empty() {
        parent_session = scoped_session_id(scope, &parent_session);
    }
    RequestIDs {
        message: user_message_id(headers, body, &session),
        session,
        child_session,
        request: random_id("req", 16),
        project: project_signal,
        parent_session,
    }
}

fn scoped_session_id(scope: &str, signal: &str) -> String {
    if is_official_session_id(signal) {
        return signal.to_string();
    }
    let signal = if scope.is_empty() {
        signal.to_string()
    } else {
        format!("{scope}\0{signal}")
    };
    canonical_session_id(&signal)
}

static CLAUDE_SESSION: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"_session_([0-9A-Fa-f-]{36})$").unwrap());

fn claude_code_session_id(user_id: &str) -> String {
    if user_id.is_empty() {
        return String::new();
    }
    if let Some(captures) = CLAUDE_SESSION.captures(user_id) {
        return captures[1].to_string();
    }
    serde_json::from_str::<JMap>(user_id)
        .ok()
        .map(|value| jsonutil::string_at(&value, &["session_id"]))
        .unwrap_or_default()
}

fn conversation_seed(body: &JMap) -> String {
    let mut prelude: Vec<Value> = Vec::new();
    for field in ["system", "instructions"] {
        if let Some(value) = body.get(field) {
            if !value.is_null() {
                prelude.push(value.clone());
            }
        }
    }
    let Some(first) = first_user_turn(body, &mut prelude) else {
        return String::new();
    };
    prelude.push(first);
    serde_json::to_string(&prelude).unwrap_or_default()
}

fn first_user_turn(body: &JMap, prelude: &mut Vec<Value>) -> Option<Value> {
    if let Some(text) = body.get("input").and_then(Value::as_str) {
        if !text.is_empty() {
            return Some(Value::String(text.to_string()));
        }
    }
    for field in ["messages", "input"] {
        for raw in jsonutil::slice_at(body, &[field]) {
            let Some(item) = raw.as_object() else {
                continue;
            };
            match jsonutil::string_at(item, &["role"]).as_str() {
                "system" | "developer" => {
                    if let Some(content) = item.get("content") {
                        prelude.push(content.clone());
                    }
                }
                "user" => {
                    if let Some(content) = item.get("content") {
                        if !content.is_null() {
                            return Some(content.clone());
                        }
                    }
                }
                _ => {}
            }
        }
    }
    None
}

static CANONICAL_SESSION: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^ses_[0-9a-f]{12}[0-9A-Za-z]{14}$").unwrap());
static DESCENDING_TIME: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[0-9a-f]{9}f[c-f][0-9a-f]$").unwrap());

const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static BOOT_NONCE: Lazy<[u8; 16]> = Lazy::new(|| {
    let mut buf = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
});

pub fn canonical_session_id(signal: &str) -> String {
    if is_official_session_id(signal) {
        return signal.to_string();
    }
    let mut hasher = Sha256::new();
    hasher.update(b"ses\x00");
    hasher.update(&BOOT_NONCE[..]);
    hasher.update([0u8]);
    hasher.update(signal.as_bytes());
    let sum = hasher.finalize();
    let time_part = descending_time_part(now(), &sum[..6]);
    let value = sum[6..16].iter().fold(0u128, |acc, byte| (acc << 8) | u128::from(*byte));
    let random_part = base62_fixed(value, 14);
    format!("ses_{time_part}{random_part}")
}

pub fn is_official_session_id(signal: &str) -> bool {
    CANONICAL_SESSION.is_match(signal)
        && signal.len() >= 16
        && DESCENDING_TIME.is_match(&signal[4..16])
}

fn descending_time_part(now: OffsetDateTime, hash: &[u8]) -> String {
    let window = (30 * 24 * 60 * 60 * 1000u64) as u128;
    let offset = ((u128::from(hash[0]) << 24)
        | (u128::from(hash[1]) << 16)
        | (u128::from(hash[2]) << 8)
        | u128::from(hash[3]))
        % window;
    let midnight = now
        .to_offset(time::UtcOffset::UTC)
        .replace_time(time::Time::MIDNIGHT);
    let base = midnight - Duration::milliseconds(offset as i64);
    let current = ((base.unix_timestamp() as u128) * 1000) << 12 | 1;
    let inverted = (!current) & 0xFFFFFFFFFFFF;
    format!("{inverted:012x}")
}

fn base62_fixed(mut value: u128, width: usize) -> String {
    let mut out = vec![b'0'; width];
    for index in (0..width).rev() {
        out[index] = BASE62[(value % 62) as usize];
        value /= 62;
    }
    String::from_utf8(out).unwrap_or_default()
}

pub fn random_id(prefix: &str, size: usize) -> String {
    let mut buf = vec![0u8; size];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    format!("{prefix}_{}", hex::encode(buf))
}

pub fn random_project_id() -> String {
    let mut buf = [0u8; 20];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

static MESSAGE_ID: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^msg_[0-9a-f]{12}[0-9A-Za-z]{14}$").unwrap());

struct MessageEntry {
    id: String,
    seen: OffsetDateTime,
}

#[derive(Default)]
struct MessageStore {
    turns: std::collections::HashMap<String, MessageEntry>,
    latest: std::collections::HashMap<String, MessageEntry>,
}

static MESSAGES: Lazy<Mutex<MessageStore>> =
    Lazy::new(|| Mutex::new(MessageStore::default()));

const MESSAGE_TTL: Duration = Duration::hours(6);
const MESSAGE_STORE_LIMIT: usize = 8192;

pub fn user_message_id(headers: &HeaderMap, body: &JMap, session: &str) -> String {
    let id = header(headers, "x-opencode-request");
    if MESSAGE_ID.is_match(&id) {
        return id;
    }
    let mut store = MESSAGES.lock().expect("message store lock");
    let turn = user_turn(body);
    let now = OffsetDateTime::now_utc();
    let key = format!("{session}\0{turn}");
    let existing = if turn.is_empty() {
        store.latest.get(session)
    } else {
        store.turns.get(&key)
    };
    let fresh = existing
        .map(|entry| now - entry.seen <= MESSAGE_TTL)
        .unwrap_or(false);
    if !fresh {
        let id = ascending_id("msg", now);
        let entry = MessageEntry { id, seen: now };
        if !turn.is_empty() {
            store.turns.insert(key, MessageEntry { id: entry.id.clone(), seen: now });
        }
        store
            .latest
            .insert(session.to_string(), MessageEntry { id: entry.id.clone(), seen: now });
        if store.turns.len() > MESSAGE_STORE_LIMIT || store.latest.len() > MESSAGE_STORE_LIMIT {
            prune_messages(&mut store, now);
        }
        return entry.id;
    }
    if let Some(entry) = if turn.is_empty() {
        store.latest.get_mut(session)
    } else {
        store.turns.get_mut(&key)
    } {
        entry.seen = now;
        let id = entry.id.clone();
        store
            .latest
            .insert(session.to_string(), MessageEntry { id: id.clone(), seen: now });
        return id;
    }
    String::new()
}

fn prune_messages(store: &mut MessageStore, now: OffsetDateTime) {
    for entries in [&mut store.turns, &mut store.latest] {
        entries.retain(|_, entry| now - entry.seen <= MESSAGE_TTL);
        while entries.len() > MESSAGE_STORE_LIMIT * 3 / 4 {
            let Some(key) = entries.keys().next().cloned() else {
                break;
            };
            entries.remove(&key);
        }
    }
}

fn user_turn(body: &JMap) -> String {
    if let Some(input) = body.get("input").and_then(Value::as_str) {
        if !input.is_empty() {
            return turn_fingerprint(1, &Value::String(input.to_string()));
        }
    }
    let mut count = 0usize;
    let mut last: Option<Value> = None;
    for field in ["messages", "input"] {
        for raw in jsonutil::slice_at(body, &[field]) {
            let Some(item) = raw.as_object() else {
                continue;
            };
            if jsonutil::string_at(item, &["role"]) != "user" {
                continue;
            }
            let content = item.get("content");
            if content.map(carries_tool_result).unwrap_or(false) {
                continue;
            }
            count += 1;
            last = content.cloned();
        }
    }
    if count == 0 {
        return String::new();
    }
    turn_fingerprint(count, last.as_ref().unwrap_or(&Value::Null))
}

fn turn_fingerprint(count: usize, content: &Value) -> String {
    let encoded = serde_json::to_vec(content).unwrap_or_default();
    let sum = Sha256::digest(&encoded);
    format!("{count}:{}", hex::encode(&sum[..8]))
}

fn carries_tool_result(content: &Value) -> bool {
    content
        .as_array()
        .map(|blocks| {
            blocks.iter().any(|raw| {
                raw.as_object()
                    .map(|block| jsonutil::string_at(block, &["type"]) == "tool_result")
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

static ASCENDING: Lazy<Mutex<(i64, u64)>> = Lazy::new(|| Mutex::new((0, 0)));

pub fn ascending_id(prefix: &str, now: OffsetDateTime) -> String {
    let millis = now.unix_timestamp() * 1000 + i64::from(now.millisecond());
    let mut clock = ASCENDING.lock().expect("ascending lock");
    if millis != clock.0 {
        clock.0 = millis;
        clock.1 = 0;
    }
    clock.1 += 1;
    let value = (millis as u64) << 12 | clock.1;
    let time_part = format!("{:012x}", value & 0xFFFFFFFFFFFF);
    format!("{prefix}_{time_part}{}", random_base62(14))
}

fn random_base62(length: usize) -> String {
    let mut buf = vec![0u8; length];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf.into_iter()
        .map(|byte| BASE62[(byte as usize) % 62] as char)
        .collect()
}

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp_nanos(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos() as i128)
            .unwrap_or_default(),
    )
    .unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

pub fn fastrand_hex(size: usize) -> String {
    let mut buf = vec![0u8; size];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}
