//! Short online exchange rendezvous for `PORTL-S-*` codes.

pub mod backend;
pub mod exchange;
pub mod mailbox;
pub mod memory;
pub mod short_code;
pub mod wormhole_crypto;
pub mod ws;

pub use backend::{
    accept_over_mailbox, offer_over_mailbox, AcceptOutcome, ExchangeOffer, OfferHandle,
    RecipientHelloV1, RendezvousBackend, RendezvousError, PORTL_EXCHANGE_APPID_V1,
    PORTL_RECIPIENT_HELLO_SCHEMA_V1,
};
pub use exchange::{PortlExchangeEnvelopeV1, SessionShareEnvelopeV1};
pub use short_code::{ShortCode, ShortCodeParseError};
