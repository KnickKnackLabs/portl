//! `PORTL-S-*` short code parsing and formatting.

use rand::seq::SliceRandom;

const PREFIX: &str = "PORTL-S-";

const WORDLIST: &[&str] = &[
    "nebula", "involve", "harbor", "lantern", "meadow", "ripple", "summit",
    "willow", "ember", "orbit", "pebble", "quartz", "tundra", "violet",
];

/// Parsed short code identifier.
#[derive(Debug, Clone)]
pub struct ShortCode {
    nameplate: String,
    words: Vec<String>,
}

impl ShortCode {
    /// Parse a `PORTL-S-<nameplate>-<word>-<word>[-...]` string.
    pub fn parse(input: &str) -> Result<Self, ShortCodeParseError> {
        let rest = input
            .strip_prefix(PREFIX)
            .ok_or_else(|| ShortCodeParseError::WrongPrefix)?;
        let mut parts = rest.split('-');
        let nameplate = parts
            .next()
            .filter(|s| !s.is_empty())
            .ok_or(ShortCodeParseError::MissingComponents)?
            .to_string();
        if !nameplate.chars().all(|c| c.is_ascii_digit()) {
            return Err(ShortCodeParseError::InvalidNameplate);
        }
        let words: Vec<String> = parts.map(|s| s.to_string()).collect();
        if words.len() < 2 {
            return Err(ShortCodeParseError::MissingComponents);
        }
        for w in &words {
            if w.is_empty()
                || !w.chars().all(|c| c.is_ascii_lowercase())
            {
                return Err(ShortCodeParseError::InvalidWord(w.clone()));
            }
        }
        Ok(Self { nameplate, words })
    }

    /// Generate a short code with the given nameplate and two random words.
    pub fn generate_with_nameplate(
        nameplate: impl Into<String>,
    ) -> Result<Self, ShortCodeParseError> {
        let nameplate = nameplate.into();
        if nameplate.is_empty()
            || !nameplate.chars().all(|c| c.is_ascii_digit())
        {
            return Err(ShortCodeParseError::InvalidNameplate);
        }
        let mut rng = rand::thread_rng();
        let chosen: Vec<String> = WORDLIST
            .choose_multiple(&mut rng, 2)
            .map(|s| (*s).to_string())
            .collect();
        Ok(Self {
            nameplate,
            words: chosen,
        })
    }

    /// Nameplate portion (decimal digits).
    pub fn nameplate(&self) -> &str {
        &self.nameplate
    }

    /// Password portion (`<nameplate>-<words...>`), without the `PORTL-S-` prefix.
    pub fn password(&self) -> String {
        let mut out = self.nameplate.clone();
        for w in &self.words {
            out.push('-');
            out.push_str(w);
        }
        out
    }

    /// Full display form `PORTL-S-<password>`.
    pub fn display_code(&self) -> String {
        format!("{}{}", PREFIX, self.password())
    }
}

/// Errors produced when parsing a short code string.
#[derive(Debug, thiserror::Error)]
pub enum ShortCodeParseError {
    /// Input did not begin with the required `PORTL-S-` prefix.
    #[error("short code must start with PORTL-S-")]
    WrongPrefix,
    /// Input must contain a nameplate and at least two words.
    #[error("short code must contain a nameplate and at least two words")]
    MissingComponents,
    /// Nameplate must be nonempty ASCII decimal digits.
    #[error("short code nameplate must be ASCII decimal digits")]
    InvalidNameplate,
    /// Word must be lowercase ASCII letters.
    #[error("short code word must be lowercase ASCII letters: {0}")]
    InvalidWord(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_portl_short_code() {
        let code = ShortCode::parse("PORTL-S-2-nebula-involve").unwrap();
        assert_eq!(code.nameplate(), "2");
        assert_eq!(code.password(), "2-nebula-involve");
        assert_eq!(code.display_code(), "PORTL-S-2-nebula-involve");
    }

    #[test]
    fn rejects_wrong_prefix() {
        let err = ShortCode::parse("PORTL-WH-2-nebula-involve").unwrap_err();
        assert!(err.to_string().contains("PORTL-S-"));
    }

    #[test]
    fn rejects_missing_words() {
        let err = ShortCode::parse("PORTL-S-2").unwrap_err();
        assert!(err.to_string().contains("nameplate and at least two words"));
    }

    #[test]
    fn generated_codes_roundtrip() {
        let code = ShortCode::generate_with_nameplate("7").unwrap();
        let parsed = ShortCode::parse(&code.display_code()).unwrap();
        assert_eq!(parsed.nameplate(), "7");
        assert_eq!(parsed.password(), code.password());
    }
}
