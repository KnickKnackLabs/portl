//! `portl/pair/v1` — peer-pairing handshake.
//!
//! Dialed by `portl accept <code>` against the issuing agent. After TLS auth succeeds,
//! caller sends `PairRequest` with the nonce from the invite
//! code; server validates + mutates its peer store + replies
//! with `PairResponse`. Both sides end up with matching entries.
//!
//! v0.3.6 carries the inviter-chosen `InitiatorMode` from the
//! invite code. The server verifies it against its pending invite
//! before mutating either peer store.

use portl_core::pair_code::InitiatorMode;
use serde::{Deserialize, Serialize};

pub const ALPN_PAIR_V1: &[u8] = b"portl/pair/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairRequest {
    /// Protocol version; `1` today. Used for upgrading wire format
    /// without spinning a new ALPN.
    pub version: u8,
    /// The 16-byte nonce from the invite code. Must match a
    /// pending invite on the server side.
    pub nonce: [u8; 16],
    /// Inviter-chosen relationship shape from the invite code.
    pub initiator: InitiatorMode,
    /// Caller's preferred relay URL, if any. Advisory; server may
    /// ignore and prefer its own configured relays.
    pub caller_relay_hint: Option<String>,
    /// Caller's locally-chosen label for itself. Used as a hint
    /// for the inviter's auto-label; the inviter may rename.
    pub caller_label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PairResult {
    Ok,
    /// Nonce was known but its TTL elapsed before the call.
    NonceExpired,
    /// Nonce wasn't on file. Either never issued, already consumed,
    /// or revoked.
    NonceUnknown,
    /// Caller's `endpoint_id` already in the peer store; no change.
    AlreadyPaired {
        existing_label: String,
    },
    /// Server rejected the pair for a policy reason (e.g. pair
    /// disabled by operator). Message is human-readable.
    PolicyRejected(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairResponse {
    pub version: u8,
    pub result: PairResult,
    /// Server's preferred relay URL, if any. Advisory.
    pub responder_relay_hint: Option<String>,
    /// The label the server assigned to the caller. Useful when
    /// the caller sent `caller_label: None` and wants to surface
    /// the server-chosen label in `accept` output.
    pub responder_chosen_label: Option<String>,
    /// The server's own label (usually "self" or its hostname).
    /// Caller uses this as a hint when labeling the server locally.
    pub responder_self_label: Option<String>,
}

#[cfg(test)]
mod tests {
    use portl_core::pair_code::InitiatorMode;

    use super::{PairRequest, PairResponse, PairResult};

    #[test]
    fn request_roundtrips_via_postcard() {
        let req = PairRequest {
            version: 1,
            nonce: [7u8; 16],
            initiator: InitiatorMode::Me,
            caller_relay_hint: Some("https://relay.example/".to_owned()),
            caller_label: Some("friend-laptop".to_owned()),
        };
        let bytes = postcard::to_stdvec(&req).expect("encode");
        let decoded: PairRequest = postcard::from_bytes(&bytes).expect("decode");
        assert_eq!(decoded, req);
    }

    #[test]
    fn response_roundtrips_via_postcard() {
        let resp = PairResponse {
            version: 1,
            result: PairResult::Ok,
            responder_relay_hint: None,
            responder_chosen_label: Some("friend-laptop".to_owned()),
            responder_self_label: Some("max".to_owned()),
        };
        let bytes = postcard::to_stdvec(&resp).expect("encode");
        let decoded: PairResponse = postcard::from_bytes(&bytes).expect("decode");
        assert_eq!(decoded, resp);
    }

    #[test]
    fn result_variants_roundtrip() {
        for result in [
            PairResult::Ok,
            PairResult::NonceExpired,
            PairResult::NonceUnknown,
            PairResult::AlreadyPaired {
                existing_label: "max".to_owned(),
            },
            PairResult::PolicyRejected("pairing disabled".to_owned()),
        ] {
            let bytes = postcard::to_stdvec(&result).expect("encode");
            let decoded: PairResult = postcard::from_bytes(&bytes).expect("decode");
            assert_eq!(decoded, result);
        }
    }

    #[test]
    fn alpn_is_stable() {
        assert_eq!(super::ALPN_PAIR_V1, b"portl/pair/v1");
    }
}
