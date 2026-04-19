pub use portl_core::wire::{AckReason, TicketAck, TicketOffer};

pub const ALPN_TICKET_V1: &[u8] = b"portl/ticket/v1";

#[cfg(test)]
mod tests {
    use super::{AckReason, TicketAck, TicketOffer};
    use portl_core::ticket::schema::{Capabilities, MetaCaps};

    #[test]
    fn offer_roundtrips_via_postcard() {
        let value = TicketOffer {
            ticket: vec![1, 2, 3],
            chain: vec![vec![4, 5], vec![6, 7, 8]],
            proof: Some([9; 64]),
            client_nonce: [10; 16],
        };

        let encoded = postcard::to_stdvec(&value).expect("encode offer");
        let decoded: TicketOffer = postcard::from_bytes(&encoded).expect("decode offer");
        assert_eq!(decoded, value);
    }

    #[test]
    fn ack_roundtrips_via_postcard() {
        let value = TicketAck {
            ok: true,
            reason: None,
            peer_token: Some([11; 16]),
            effective_caps: Some(Capabilities {
                presence: 0b0010_0000,
                shell: None,
                tcp: None,
                udp: None,
                fs: None,
                vpn: None,
                meta: Some(MetaCaps {
                    ping: true,
                    info: true,
                }),
            }),
            server_time: 1_735_689_600,
        };

        let encoded = postcard::to_stdvec(&value).expect("encode ack");
        let decoded: TicketAck = postcard::from_bytes(&encoded).expect("decode ack");
        assert_eq!(decoded, value);
    }

    #[test]
    fn ack_reason_roundtrips_via_postcard() {
        let value = AckReason::InternalError {
            detail: Some("boom".to_owned()),
        };

        let encoded = postcard::to_stdvec(&value).expect("encode reason");
        let decoded: AckReason = postcard::from_bytes(&encoded).expect("decode reason");
        assert_eq!(decoded, value);
    }
}
