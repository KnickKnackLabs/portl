//! `PORTL-S-*` short code parsing and formatting (skeleton).

/// Parsed short code identifier.
#[derive(Debug, Clone)]
pub struct ShortCode;

/// Errors produced when parsing a short code string.
#[derive(Debug, thiserror::Error)]
pub enum ShortCodeParseError {
    /// Placeholder until the real parser lands.
    #[error("short code parsing not yet implemented")]
    NotImplemented,
}
