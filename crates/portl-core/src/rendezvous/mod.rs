//! Short online exchange rendezvous for `PORTL-S-*` codes.

pub mod backend;
pub mod exchange;
pub mod mailbox;
pub mod memory;
pub mod short_code;
pub mod wormhole_crypto;
pub mod ws;

pub use backend::{
    AcceptOutcome, ExchangeOffer, OfferHandle, PORTL_EXCHANGE_APPID_V1,
    PORTL_RECIPIENT_HELLO_SCHEMA_V1, RecipientHelloV1, RendezvousBackend, RendezvousError,
    accept_over_mailbox, fresh_side, offer_over_mailbox, offer_pake_and_recv_hello,
    offer_send_envelope,
};
pub use exchange::{PortlExchangeEnvelopeV1, SessionShareEnvelopeV1};
pub use short_code::{ShortCode, ShortCodeParseError};
