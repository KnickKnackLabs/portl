//! Invite-code encoding for `portl peer pair` (v0.3.4+).
//!
//! Wire layout:
//!
//! ```text
//! version:1            = 1
//! inviter_eid:32       (ed25519 public key)
//! nonce:16             (random, single-use)
//! not_after:8 le u64   (unix seconds)
//! relay_hint_len:1     (0..=255)
//! relay_hint:<variable> (UTF-8 bytes; optional relay URL)
//! ```
//!
//! base32-encoded with the RFC-4648 alphabet (no pad), prefixed
//! with `PORTLINV-` so users can eyeball them as "portl invites"
//! instead of random-looking blobs.
//!
//! Invite codes aren't secrets per se — they bind to a single
//! inviter and carry their own TTL + nonce. The operator is
//! expected to share them over a trusted channel; the nonce +
//! TTL limit the damage from leaked codes.

use std::fmt;

use anyhow::{Context, Result, anyhow, bail};

pub const INVITE_PREFIX: &str = "PORTLINV-";
pub const INVITE_VERSION: u8 = 1;
pub const MAX_RELAY_HINT_LEN: usize = 255;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteCode {
    pub version: u8,
    pub inviter_eid: [u8; 32],
    pub nonce: [u8; 16],
    pub not_after_unix: u64,
    pub relay_hint: Option<String>,
}

impl InviteCode {
    #[must_use]
    pub fn new(
        inviter_eid: [u8; 32],
        nonce: [u8; 16],
        not_after_unix: u64,
        relay_hint: Option<String>,
    ) -> Self {
        Self {
            version: INVITE_VERSION,
            inviter_eid,
            nonce,
            not_after_unix,
            relay_hint,
        }
    }

    /// Encode to the canonical `PORTLINV-<base32>` string form.
    pub fn encode(&self) -> Result<String> {
        let relay_hint = self.relay_hint.as_deref().unwrap_or("");
        if relay_hint.len() > MAX_RELAY_HINT_LEN {
            bail!(
                "relay hint length {} exceeds cap {}",
                relay_hint.len(),
                MAX_RELAY_HINT_LEN
            );
        }
        let mut bytes = Vec::with_capacity(1 + 32 + 16 + 8 + 1 + relay_hint.len());
        bytes.push(self.version);
        bytes.extend_from_slice(&self.inviter_eid);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.not_after_unix.to_le_bytes());
        bytes.push(u8::try_from(relay_hint.len()).expect("cap checked above"));
        bytes.extend_from_slice(relay_hint.as_bytes());
        let b32 = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &bytes);
        Ok(format!("{INVITE_PREFIX}{b32}"))
    }

    /// Decode from the canonical string form. Tolerant of
    /// leading/trailing whitespace; case-insensitive for the
    /// base32 body.
    pub fn decode(s: &str) -> Result<Self> {
        let s = s.trim();
        let body = s
            .strip_prefix(INVITE_PREFIX)
            .ok_or_else(|| anyhow!("invite codes must start with {INVITE_PREFIX}"))?;
        let bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, body)
            .ok_or_else(|| anyhow!("invite body is not valid base32"))?;
        if bytes.len() < 1 + 32 + 16 + 8 + 1 {
            bail!("invite code too short ({} bytes)", bytes.len());
        }
        let version = bytes[0];
        if version != INVITE_VERSION {
            bail!("unsupported invite version {version} (this build speaks {INVITE_VERSION})");
        }
        let mut inviter_eid = [0u8; 32];
        inviter_eid.copy_from_slice(&bytes[1..33]);
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&bytes[33..49]);
        let mut not_after_bytes = [0u8; 8];
        not_after_bytes.copy_from_slice(&bytes[49..57]);
        let not_after_unix = u64::from_le_bytes(not_after_bytes);
        let hint_len = usize::from(bytes[57]);
        let hint_start = 58;
        let hint_end = hint_start + hint_len;
        if bytes.len() < hint_end {
            bail!(
                "invite code truncated: want {hint_end} bytes, have {}",
                bytes.len()
            );
        }
        let relay_hint = if hint_len == 0 {
            None
        } else {
            Some(
                std::str::from_utf8(&bytes[hint_start..hint_end])
                    .context("relay hint is not valid UTF-8")?
                    .to_owned(),
            )
        };
        Ok(Self {
            version,
            inviter_eid,
            nonce,
            not_after_unix,
            relay_hint,
        })
    }

    /// Short hex prefix of the nonce, convenient for `--revoke`
    /// matching and user-facing listings.
    #[must_use]
    pub fn nonce_hex(&self) -> String {
        hex::encode(self.nonce)
    }
}

impl fmt::Display for InviteCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.encode() {
            Ok(s) => f.write_str(&s),
            Err(e) => write!(f, "<invalid-invite-code: {e}>"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> InviteCode {
        InviteCode {
            version: 1,
            inviter_eid: [1u8; 32],
            nonce: [2u8; 16],
            not_after_unix: 1_800_000_000,
            relay_hint: Some("https://relay.example./".to_owned()),
        }
    }

    #[test]
    fn roundtrip_with_relay_hint() {
        let original = sample();
        let encoded = original.encode().unwrap();
        assert!(encoded.starts_with(INVITE_PREFIX));
        let decoded = InviteCode::decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn roundtrip_without_relay_hint() {
        let original = InviteCode {
            relay_hint: None,
            ..sample()
        };
        let encoded = original.encode().unwrap();
        let decoded = InviteCode::decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn decode_trims_whitespace() {
        let original = sample();
        let encoded = original.encode().unwrap();
        let padded = format!("  {encoded}\n");
        let decoded = InviteCode::decode(&padded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn decode_rejects_missing_prefix() {
        let original = sample();
        let encoded = original.encode().unwrap();
        let stripped = encoded.trim_start_matches(INVITE_PREFIX);
        let err = InviteCode::decode(stripped).unwrap_err();
        assert!(err.to_string().contains(INVITE_PREFIX));
    }

    #[test]
    fn decode_rejects_bad_version() {
        // Encode a v1 invite, then corrupt the version byte and
        // re-encode.
        let original = sample();
        let mut bytes = Vec::new();
        bytes.push(99u8); // bogus version
        bytes.extend_from_slice(&original.inviter_eid);
        bytes.extend_from_slice(&original.nonce);
        bytes.extend_from_slice(&original.not_after_unix.to_le_bytes());
        bytes.push(0u8);
        let b32 = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &bytes);
        let s = format!("{INVITE_PREFIX}{b32}");
        let err = InviteCode::decode(&s).unwrap_err();
        assert!(err.to_string().contains("unsupported invite version"));
    }

    #[test]
    fn decode_rejects_truncated_body() {
        let err = InviteCode::decode(&format!("{INVITE_PREFIX}AA")).unwrap_err();
        assert!(err.to_string().contains("too short"));
    }

    #[test]
    fn encode_rejects_oversized_relay_hint() {
        let mut hint = String::new();
        for _ in 0..=MAX_RELAY_HINT_LEN {
            hint.push('a');
        }
        let invite = InviteCode {
            relay_hint: Some(hint),
            ..sample()
        };
        let err = invite.encode().unwrap_err();
        assert!(err.to_string().contains("exceeds cap"));
    }

    #[test]
    fn nonce_hex_is_32_chars() {
        let invite = sample();
        assert_eq!(invite.nonce_hex().len(), 32);
    }
}
