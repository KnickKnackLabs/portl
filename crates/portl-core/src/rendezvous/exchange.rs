//! Exchange envelope types.

use serde::{Deserialize, Serialize};

/// V1 envelope for portl exchange payloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    pub target_endpoint_id_hex: String,
    pub provider: Option<String>,
    pub provider_session: String,
    pub ticket: String,
    pub access_not_after_unix: u64,
}

impl PortlExchangeEnvelopeV1 {
    pub fn session_share(
        share: SessionShareEnvelopeV1,
        created_at_unix: u64,
        not_after_unix: Option<u64>,
    ) -> Self {
        let label = share.origin_label_hint.clone();
        Self {
            schema: "portl.exchange.v1".to_owned(),
            kind: ExchangeKind::SessionShare,
            created_at_unix,
            not_after_unix,
            sender: SenderHint { label },
            payload: ExchangePayload::SessionShare(share),
        }
    }
}

impl SessionShareEnvelopeV1 {
    pub fn import_label(&self) -> String {
        match self.origin_label_hint.as_deref() {
            Some(origin) if !origin.is_empty() => format!("{}@{}", self.friendly_name, origin),
            _ => self.friendly_name.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_share_envelope_roundtrips_json() {
        let envelope = PortlExchangeEnvelopeV1::session_share(SessionShareEnvelopeV1 {
            workspace_id: "ws_test".to_owned(),
            friendly_name: "dev".to_owned(),
            conflict_handle: "7k3p".to_owned(),
            origin_label_hint: Some("alice-laptop".to_owned()),
            target_endpoint_id_hex: hex::encode([1u8; 32]),
            provider: Some("zmx".to_owned()),
            provider_session: "dev".to_owned(),
            ticket: "portltestticket".to_owned(),
            access_not_after_unix: 2_000_000,
        }, 1_000_000, Some(1_000_600));

        let encoded = serde_json::to_vec(&envelope).unwrap();
        let decoded: PortlExchangeEnvelopeV1 = serde_json::from_slice(&encoded).unwrap();

        assert_eq!(decoded.schema, "portl.exchange.v1");
        assert_eq!(decoded.kind, ExchangeKind::SessionShare);
        assert!(matches!(decoded.payload, ExchangePayload::SessionShare(_)));
    }

    #[test]
    fn imported_label_prefers_origin_hint() {
        let share = SessionShareEnvelopeV1 {
            workspace_id: "ws_test".to_owned(),
            friendly_name: "dev".to_owned(),
            conflict_handle: "7k3p".to_owned(),
            origin_label_hint: Some("alice-laptop".to_owned()),
            target_endpoint_id_hex: hex::encode([1u8; 32]),
            provider: Some("zmx".to_owned()),
            provider_session: "dev".to_owned(),
            ticket: "portltestticket".to_owned(),
            access_not_after_unix: 2_000_000,
        };

        assert_eq!(share.import_label(), "dev@alice-laptop");
    }
}
