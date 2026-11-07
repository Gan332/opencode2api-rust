//! Cloudflare WARP egress over a userspace WireGuard device.

use anyhow::{bail, Result};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Stack {
    Ipv4,
    #[default]
    Ipv6,
    Dual,
}

impl Stack {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Dual => "dual",
        }
    }
}

pub fn parse_stack(value: &str) -> Result<Stack> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "ipv6" | "v6" => Ok(Stack::Ipv6),
        "ipv4" | "v4" => Ok(Stack::Ipv4),
        "dual" | "both" => Ok(Stack::Dual),
        other => bail!("unsupported WARP stack {other:?}; use ipv6, ipv4 or dual"),
    }
}
