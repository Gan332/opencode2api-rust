//! Argon2id password hashing in the `$argon2id$v=19$...` form.

use anyhow::{bail, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use rand::RngCore;

const MEMORY: u32 = 64 * 1024;
const ITERATIONS: u32 = 3;
const PARALLELISM: u32 = 2;
const SALT_LENGTH: usize = 16;
const KEY_LENGTH: usize = 32;

pub fn hash_password(password: &str) -> Result<String> {
    if password.len() < 10 {
        bail!("webui password must contain at least 10 characters");
    }
    let mut salt = [0u8; SALT_LENGTH];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let params = Params::new(MEMORY, ITERATIONS, PARALLELISM, Some(KEY_LENGTH))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut hash = [0u8; KEY_LENGTH];
    argon.hash_password_into(password.as_bytes(), &salt, &mut hash)?;
    Ok(format!(
        "$argon2id$v=19$m={MEMORY},t={ITERATIONS},p={PARALLELISM}${}${}",
        STANDARD_NO_PAD.encode(salt),
        STANDARD_NO_PAD.encode(hash)
    ))
}

pub fn verify_password(encoded: &str, password: &str) -> bool {
    let parts: Vec<&str> = encoded.split('$').collect();
    if parts.len() != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
        return false;
    }
    let parameters: Vec<&str> = parts[3].split(',').collect();
    if parameters.len() != 3 {
        return false;
    }
    let (Ok(memory), Ok(iterations), Ok(parallelism)) = (
        parse_parameter(parameters[0], "m"),
        parse_parameter(parameters[1], "t"),
        parse_parameter(parameters[2], "p"),
    ) else {
        return false;
    };
    if memory < 8 * parallelism
        || memory > 256 * 1024
        || !(1..=10).contains(&iterations)
        || !(1..=16).contains(&parallelism)
    {
        return false;
    }
    let Ok(salt) = STANDARD_NO_PAD.decode(parts[4]) else {
        return false;
    };
    let Ok(expected) = STANDARD_NO_PAD.decode(parts[5]) else {
        return false;
    };
    if !(8..=64).contains(&salt.len()) || !(16..=64).contains(&expected.len()) {
        return false;
    }
    let Ok(params) = Params::new(
        memory as u32,
        iterations as u32,
        parallelism as u32,
        Some(expected.len()),
    ) else {
        return false;
    };
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut actual = vec![0u8; expected.len()];
    if argon
        .hash_password_into(password.as_bytes(), &salt, &mut actual)
        .is_err()
    {
        return false;
    }
    bool::from(subtle::ConstantTimeEq::ct_eq(&actual[..], &expected[..]))
}

fn parse_parameter(value: &str, name: &str) -> Result<u64> {
    let prefix = format!("{name}=");
    let Some(rest) = value.strip_prefix(&prefix) else {
        bail!("invalid parameter");
    };
    Ok(rest.parse::<u64>()?)
}
