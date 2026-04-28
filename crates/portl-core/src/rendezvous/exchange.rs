//! Exchange envelope types.

use serde::{Deserialize, Deserializer, Serialize};

/// Schema identifier for the V1 portl exchange envelope.
pub const PORTL_EXCHANGE_SCHEMA_V1: &str = "portl.exchange.v1";

/// Length in hex characters of an endpoint id (32 bytes).
const ENDPOINT_ID_HEX_LEN: usize = 64;

/// V1 envelope for portl exchange payloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PortlExchangeEnvelopeV1 {
    pub schema: String,
    pub kind: ExchangeKind,
    pub created_at_unix: u64,
    pub not_after_unix: Option<u64>,
    pub sender: SenderHint,
    pub payload: ExchangePayload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExchangeKind {
    SessionShare,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SenderHint {
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "body", rename_all = "kebab-case")]
pub enum ExchangePayload {
    SessionShare(SessionShareEnvelopeV1),
}

/// V1 envelope for session share payloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionShareEnvelopeV1 {
    pub workspace_id: String,
    pub friendly_name: String,
    pub conflict_handle: String,
    pub origin_label_hint: Option<String>,
    #[serde(default)]
    pub target_label_hint: Option<String>,
    pub target_endpoint_id_hex: String,
    pub provider: Option<String>,
    pub provider_session: String,
    pub ticket: String,
    pub access_not_after_unix: u64,
}

/// Errors produced when validating an exchange envelope.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnvelopeValidationError {
    #[error("unsupported schema: expected `{expected}`, got `{actual}`")]
    UnsupportedSchema {
        expected: &'static str,
        actual: String,
    },
    #[error("envelope kind `{envelope:?}` does not match payload kind `{payload:?}`")]
    KindMismatch {
        envelope: ExchangeKind,
        payload: ExchangeKind,
    },
    #[error("not_after_unix ({not_after}) must be greater than created_at_unix ({created_at})")]
    NotAfterNotAfterCreatedAt { created_at: u64, not_after: u64 },
    #[error("target_endpoint_id_hex must be {expected} hex characters (32 bytes), got {actual}")]
    InvalidEndpointIdLength { expected: usize, actual: usize },
    #[error("target_endpoint_id_hex contains non-hex characters")]
    InvalidEndpointIdHex,
}

impl PortlExchangeEnvelopeV1 {
    pub fn session_share(
        share: SessionShareEnvelopeV1,
        created_at_unix: u64,
        not_after_unix: Option<u64>,
    ) -> Self {
        let label = share.origin_label_hint.clone();
        Self {
            schema: PORTL_EXCHANGE_SCHEMA_V1.to_owned(),
            kind: ExchangeKind::SessionShare,
            created_at_unix,
            not_after_unix,
            sender: SenderHint { label },
            payload: ExchangePayload::SessionShare(share),
        }
    }

    /// Validate the envelope's invariants. Called automatically by `Deserialize`.
    pub fn validate(&self) -> Result<(), EnvelopeValidationError> {
        if self.schema != PORTL_EXCHANGE_SCHEMA_V1 {
            return Err(EnvelopeValidationError::UnsupportedSchema {
                expected: PORTL_EXCHANGE_SCHEMA_V1,
                actual: self.schema.clone(),
            });
        }
        let payload_kind = self.payload.kind();
        if self.kind != payload_kind {
            return Err(EnvelopeValidationError::KindMismatch {
                envelope: self.kind,
                payload: payload_kind,
            });
        }
        if let Some(not_after) = self.not_after_unix
            && not_after <= self.created_at_unix
        {
            return Err(EnvelopeValidationError::NotAfterNotAfterCreatedAt {
                created_at: self.created_at_unix,
                not_after,
            });
        }
        match &self.payload {
            ExchangePayload::SessionShare(share) => share.validate()?,
        }
        Ok(())
    }
}

impl ExchangePayload {
    /// Returns the discriminant kind for this payload variant.
    pub fn kind(&self) -> ExchangeKind {
        match self {
            ExchangePayload::SessionShare(_) => ExchangeKind::SessionShare,
        }
    }
}

impl<'de> Deserialize<'de> for PortlExchangeEnvelopeV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Shadow {
            schema: String,
            kind: ExchangeKind,
            created_at_unix: u64,
            not_after_unix: Option<u64>,
            sender: SenderHint,
            payload: ExchangePayload,
        }
        let shadow = Shadow::deserialize(deserializer)?;
        let envelope = PortlExchangeEnvelopeV1 {
            schema: shadow.schema,
            kind: shadow.kind,
            created_at_unix: shadow.created_at_unix,
            not_after_unix: shadow.not_after_unix,
            sender: shadow.sender,
            payload: shadow.payload,
        };
        envelope.validate().map_err(serde::de::Error::custom)?;
        Ok(envelope)
    }
}

impl SessionShareEnvelopeV1 {
    pub fn import_label(&self) -> String {
        let machine = self
            .target_label_hint
            .as_deref()
            .map(str::trim)
            .filter(|label| !label.is_empty())
            .map_or_else(
                || crate::labels::machine_label(None, &self.target_endpoint_id_hex),
                ToOwned::to_owned,
            );
        crate::labels::session_share_label(&machine, &self.friendly_name)
    }

    fn validate(&self) -> Result<(), EnvelopeValidationError> {
        if self.target_endpoint_id_hex.len() != ENDPOINT_ID_HEX_LEN {
            return Err(EnvelopeValidationError::InvalidEndpointIdLength {
                expected: ENDPOINT_ID_HEX_LEN,
                actual: self.target_endpoint_id_hex.len(),
            });
        }
        if !self
            .target_endpoint_id_hex
            .bytes()
            .all(|b| b.is_ascii_hexdigit())
        {
            return Err(EnvelopeValidationError::InvalidEndpointIdHex);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_share() -> SessionShareEnvelopeV1 {
        SessionShareEnvelopeV1 {
            workspace_id: "ws_test".to_owned(),
            friendly_name: "dev".to_owned(),
            conflict_handle: "7k3p".to_owned(),
            origin_label_hint: Some("alice-laptop".to_owned()),
            target_label_hint: Some("max-b265".to_owned()),
            target_endpoint_id_hex: hex::encode([1u8; 32]),
            provider: Some("zmx".to_owned()),
            provider_session: "dev".to_owned(),
            ticket: "portltestticket".to_owned(),
            access_not_after_unix: 2_000_000,
        }
    }

    #[test]
    fn session_share_envelope_roundtrips_json() {
        let envelope =
            PortlExchangeEnvelopeV1::session_share(sample_share(), 1_000_000, Some(1_000_600));

        let encoded = serde_json::to_vec(&envelope).unwrap();
        let decoded: PortlExchangeEnvelopeV1 = serde_json::from_slice(&encoded).unwrap();

        assert_eq!(decoded.schema, PORTL_EXCHANGE_SCHEMA_V1);
        assert_eq!(decoded.kind, ExchangeKind::SessionShare);
        assert!(matches!(decoded.payload, ExchangePayload::SessionShare(_)));
    }

    #[test]
    fn session_share_envelope_serializes_to_expected_shape() {
        let envelope =
            PortlExchangeEnvelopeV1::session_share(sample_share(), 1_000_000, Some(1_000_600));
        let value = serde_json::to_value(&envelope).unwrap();
        let expected = json!({
            "schema": "portl.exchange.v1",
            "kind": "session-share",
            "created_at_unix": 1_000_000,
            "not_after_unix": 1_000_600,
            "sender": { "label": "alice-laptop" },
            "payload": {
                "kind": "session-share",
                "body": {
                    "workspace_id": "ws_test",
                    "friendly_name": "dev",
                    "conflict_handle": "7k3p",
                    "origin_label_hint": "alice-laptop",
                    "target_label_hint": "max-b265",
                    "target_endpoint_id_hex": "0101010101010101010101010101010101010101010101010101010101010101",
                    "provider": "zmx",
                    "provider_session": "dev",
                    "ticket": "portltestticket",
                    "access_not_after_unix": 2_000_000
                }
            }
        });
        assert_eq!(value, expected);
    }

    #[test]
    fn deserialize_rejects_unknown_schema() {
        let envelope =
            PortlExchangeEnvelopeV1::session_share(sample_share(), 1_000_000, Some(1_000_600));
        let mut value = serde_json::to_value(&envelope).unwrap();
        value["schema"] = json!("portl.exchange.v0");
        let err = serde_json::from_value::<PortlExchangeEnvelopeV1>(value).unwrap_err();
        assert!(err.to_string().contains("unsupported schema"));
    }

    #[test]
    fn validate_rejects_kind_mismatch() {
        // Construct an envelope where top-level kind disagrees with payload kind.
        // Since only one variant exists today, exercise the check via direct
        // construction once a future variant is added; for now ensure the
        // helper returns the matching kind.
        let envelope =
            PortlExchangeEnvelopeV1::session_share(sample_share(), 1_000_000, Some(1_000_600));
        assert_eq!(envelope.payload.kind(), envelope.kind);
        envelope.validate().unwrap();
    }

    #[test]
    fn deserialize_rejects_not_after_not_after_created_at() {
        let envelope =
            PortlExchangeEnvelopeV1::session_share(sample_share(), 1_000_000, Some(1_000_000));
        let value = serde_json::to_value(&envelope).unwrap();
        let err = serde_json::from_value::<PortlExchangeEnvelopeV1>(value).unwrap_err();
        assert!(err.to_string().contains("not_after_unix"));

        let envelope =
            PortlExchangeEnvelopeV1::session_share(sample_share(), 1_000_000, Some(999_999));
        let value = serde_json::to_value(&envelope).unwrap();
        serde_json::from_value::<PortlExchangeEnvelopeV1>(value).unwrap_err();
    }

    #[test]
    fn validate_allows_absent_not_after() {
        let envelope = PortlExchangeEnvelopeV1::session_share(sample_share(), 1_000_000, None);
        envelope.validate().unwrap();
        let value = serde_json::to_value(&envelope).unwrap();
        serde_json::from_value::<PortlExchangeEnvelopeV1>(value).unwrap();
    }

    #[test]
    fn deserialize_rejects_invalid_endpoint_id_length() {
        let mut share = sample_share();
        share.target_endpoint_id_hex = "deadbeef".to_owned();
        let envelope = PortlExchangeEnvelopeV1::session_share(share, 1_000_000, Some(1_000_600));
        let value = serde_json::to_value(&envelope).unwrap();
        let err = serde_json::from_value::<PortlExchangeEnvelopeV1>(value).unwrap_err();
        assert!(err.to_string().contains("hex characters"));
    }

    #[test]
    fn deserialize_rejects_non_hex_endpoint_id() {
        let mut share = sample_share();
        share.target_endpoint_id_hex = "z".repeat(64);
        let envelope = PortlExchangeEnvelopeV1::session_share(share, 1_000_000, Some(1_000_600));
        let value = serde_json::to_value(&envelope).unwrap();
        let err = serde_json::from_value::<PortlExchangeEnvelopeV1>(value).unwrap_err();
        assert!(err.to_string().contains("non-hex"));
    }

    #[test]
    fn imported_label_uses_target_machine_then_friendly_name() {
        let share = sample_share();
        assert_eq!(share.import_label(), "max-b265/dev");
    }

    #[test]
    fn imported_label_falls_back_to_endpoint_when_target_hint_missing() {
        let mut share = sample_share();
        share.target_label_hint = None;
        share.target_endpoint_id_hex = "bba96591b265".to_owned();
        assert_eq!(share.import_label(), "host-b265/dev");
    }

    #[test]
    fn imported_label_falls_back_when_target_hint_empty() {
        let mut share = sample_share();
        share.target_label_hint = Some(String::new());
        share.target_endpoint_id_hex = "bba96591b265".to_owned();
        assert_eq!(share.import_label(), "host-b265/dev");
    }
}
