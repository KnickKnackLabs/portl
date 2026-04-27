//! `PORTL-S-*` short code parsing and formatting.
//!
//! ## Parser/generator contract
//!
//! [`ShortCode::parse`] accepts any nonempty lowercase ASCII passphrase
//! (`a-z` only) for interoperability with manually-typed codes.
//! [`ShortCode::generate_with_nameplate`] is stricter: it draws words
//! uniformly from the canonical internal [`WORDLIST`] below.

use rand::seq::SliceRandom;

const PREFIX: &str = "PORTL-S-";

/// Canonical wordlist used by [`ShortCode::generate_with_nameplate`].
///
/// Locally curated lowercase ASCII words. With 256 entries, two random
/// picks yield ~16 bits of word entropy.
const WORDLIST: &[&str] = &[
    "absent",
    "acid",
    "acorn",
    "active",
    "actor",
    "adapt",
    "admit",
    "adobe",
    "adopt",
    "agent",
    "album",
    "alert",
    "alibi",
    "alive",
    "alley",
    "alpha",
    "amber",
    "amend",
    "amigo",
    "ample",
    "amuse",
    "anchor",
    "angel",
    "ankle",
    "apple",
    "april",
    "apron",
    "arbor",
    "arcade",
    "arena",
    "argue",
    "arise",
    "armor",
    "arrow",
    "ascot",
    "aspen",
    "aspect",
    "assist",
    "atlas",
    "atom",
    "audio",
    "aunt",
    "autumn",
    "avert",
    "awake",
    "axis",
    "bacon",
    "badge",
    "baker",
    "balsa",
    "bamboo",
    "banjo",
    "barn",
    "basil",
    "basin",
    "batch",
    "beach",
    "beacon",
    "beam",
    "bean",
    "bear",
    "beaver",
    "bench",
    "berry",
    "beta",
    "bicep",
    "binder",
    "bingo",
    "birch",
    "bishop",
    "bison",
    "bitmap",
    "blade",
    "blaze",
    "blend",
    "blink",
    "block",
    "bloom",
    "blueprint",
    "blush",
    "boat",
    "bobcat",
    "bonus",
    "boost",
    "border",
    "bottle",
    "bounce",
    "boxer",
    "brain",
    "brave",
    "bread",
    "breeze",
    "bridge",
    "brisk",
    "broker",
    "bronze",
    "brown",
    "bubble",
    "budget",
    "buffer",
    "bugle",
    "bulb",
    "bunker",
    "burst",
    "butter",
    "cabin",
    "cable",
    "cactus",
    "camel",
    "camera",
    "candle",
    "canvas",
    "canyon",
    "carbon",
    "career",
    "cargo",
    "carrot",
    "castle",
    "catch",
    "cedar",
    "celery",
    "cement",
    "census",
    "ceramic",
    "cereal",
    "chalk",
    "chant",
    "chapel",
    "charm",
    "chart",
    "cheese",
    "cherry",
    "chess",
    "chief",
    "chime",
    "chisel",
    "chord",
    "cider",
    "cinema",
    "cipher",
    "circle",
    "citrus",
    "civic",
    "clamp",
    "clarity",
    "clasp",
    "classic",
    "clean",
    "clever",
    "client",
    "cliff",
    "climb",
    "clinic",
    "clock",
    "clover",
    "cluster",
    "coast",
    "cobalt",
    "cobra",
    "cocoa",
    "comet",
    "common",
    "compass",
    "copper",
    "coral",
    "cosmic",
    "cotton",
    "couple",
    "courier",
    "coyote",
    "crab",
    "crane",
    "crater",
    "crayon",
    "credit",
    "crisp",
    "crochet",
    "crown",
    "crystal",
    "cube",
    "cumin",
    "cupcake",
    "current",
    "cygnet",
    "daisy",
    "dapper",
    "darling",
    "dashing",
    "dawn",
    "decade",
    "decoy",
    "delta",
    "denim",
    "depot",
    "desert",
    "design",
    "device",
    "dialog",
    "diamond",
    "diary",
    "dimple",
    "dingo",
    "dipper",
    "doctor",
    "dolphin",
    "domain",
    "donor",
    "donut",
    "dossier",
    "dragon",
    "dream",
    "driver",
    "drizzle",
    "drum",
    "dryad",
    "duet",
    "dynamo",
    "eagle",
    "earth",
    "easel",
    "eclair",
    "edible",
    "editor",
    "eject",
    "elastic",
    "elbow",
    "elder",
    "ember",
    "emblem",
    "emerald",
    "empire",
    "emu",
    "energy",
    "engine",
    "envelope",
    "epoch",
    "equal",
    "erode",
    "escape",
    "ethics",
    "evolve",
    "exhale",
    "expert",
    "extra",
    "fable",
    "fabric",
    "facet",
    "faint",
    "falcon",
    "famous",
    "fancy",
    "farm",
    "fawn",
    "feather",
    "fennel",
    "fern",
    "ferry",
    "fiber",
    "fiction",
    "field",
    "figure",
    "filter",
    "finch",
    "finish",
];

/// Parsed short code identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShortCode {
    nameplate: String,
    words: Vec<String>,
}

impl ShortCode {
    /// Parse a `PORTL-S-<nameplate>-<word>-<word>[-...]` string.
    pub fn parse(input: &str) -> Result<Self, ShortCodeParseError> {
        let rest = input
            .strip_prefix(PREFIX)
            .ok_or(ShortCodeParseError::WrongPrefix)?;
        let mut parts = rest.split('-');
        let nameplate = parts
            .next()
            .filter(|s| !s.is_empty())
            .ok_or(ShortCodeParseError::MissingComponents)?
            .to_string();
        if !nameplate.chars().all(|c| c.is_ascii_digit()) {
            return Err(ShortCodeParseError::InvalidNameplate);
        }
        let words: Vec<String> = parts.map(str::to_string).collect();
        if words.len() < 2 {
            return Err(ShortCodeParseError::MissingComponents);
        }
        for w in &words {
            if w.is_empty() || !w.chars().all(|c| c.is_ascii_lowercase()) {
                return Err(ShortCodeParseError::InvalidWord(w.clone()));
            }
        }
        Ok(Self { nameplate, words })
    }

    /// Generate a short code with the given nameplate and two random words
    /// drawn uniformly from the canonical internal [`WORDLIST`].
    ///
    /// The returned error type is shared with [`ShortCode::parse`]; only
    /// the [`ShortCodeParseError::InvalidNameplate`] variant is reachable
    /// from this constructor.
    pub fn generate_with_nameplate(
        nameplate: impl Into<String>,
    ) -> Result<Self, ShortCodeParseError> {
        let nameplate = nameplate.into();
        if nameplate.is_empty() || !nameplate.chars().all(|c| c.is_ascii_digit()) {
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
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
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

    #[test]
    fn rejects_empty_input() {
        assert_eq!(
            ShortCode::parse("").unwrap_err(),
            ShortCodeParseError::WrongPrefix
        );
    }

    #[test]
    fn rejects_prefix_only() {
        assert_eq!(
            ShortCode::parse("PORTL-S-").unwrap_err(),
            ShortCodeParseError::MissingComponents,
        );
    }

    #[test]
    fn rejects_empty_nameplate() {
        assert_eq!(
            ShortCode::parse("PORTL-S--nebula-involve").unwrap_err(),
            ShortCodeParseError::MissingComponents,
        );
    }

    #[test]
    fn rejects_non_digit_nameplate() {
        assert_eq!(
            ShortCode::parse("PORTL-S-2a-nebula-involve").unwrap_err(),
            ShortCodeParseError::InvalidNameplate,
        );
    }

    #[test]
    fn rejects_one_word_only() {
        assert_eq!(
            ShortCode::parse("PORTL-S-2-nebula").unwrap_err(),
            ShortCodeParseError::MissingComponents,
        );
    }

    #[test]
    fn rejects_double_hyphen_empty_word() {
        let err = ShortCode::parse("PORTL-S-2-nebula--involve").unwrap_err();
        assert_eq!(err, ShortCodeParseError::InvalidWord(String::new()));
    }

    #[test]
    fn rejects_trailing_hyphen_empty_word() {
        let err = ShortCode::parse("PORTL-S-2-nebula-involve-").unwrap_err();
        assert_eq!(err, ShortCodeParseError::InvalidWord(String::new()));
    }

    #[test]
    fn rejects_uppercase_in_word() {
        let err = ShortCode::parse("PORTL-S-2-Nebula-involve").unwrap_err();
        assert_eq!(err, ShortCodeParseError::InvalidWord("Nebula".into()));
    }

    #[test]
    fn rejects_digit_in_word() {
        let err = ShortCode::parse("PORTL-S-2-nebula1-involve").unwrap_err();
        assert_eq!(err, ShortCodeParseError::InvalidWord("nebula1".into()));
    }

    #[test]
    fn rejects_punctuation_in_word() {
        let err = ShortCode::parse("PORTL-S-2-nebula!-involve").unwrap_err();
        assert_eq!(err, ShortCodeParseError::InvalidWord("nebula!".into()));
    }

    #[test]
    fn rejects_unicode_in_word() {
        let err = ShortCode::parse("PORTL-S-2-nebulä-involve").unwrap_err();
        assert_eq!(err, ShortCodeParseError::InvalidWord("nebulä".into()));
    }

    #[test]
    fn accepts_extra_words() {
        let code = ShortCode::parse("PORTL-S-2-nebula-involve-harbor").unwrap();
        assert_eq!(code.password(), "2-nebula-involve-harbor");
        assert_eq!(code.display_code(), "PORTL-S-2-nebula-involve-harbor");
    }

    #[test]
    fn accepts_arbitrary_lowercase_passphrase() {
        // Manual passphrases need not appear in WORDLIST.
        let code = ShortCode::parse("PORTL-S-9-zzz-qqq").unwrap();
        assert_eq!(code.nameplate(), "9");
    }

    #[test]
    fn generate_rejects_empty_nameplate() {
        assert_eq!(
            ShortCode::generate_with_nameplate("").unwrap_err(),
            ShortCodeParseError::InvalidNameplate,
        );
    }

    #[test]
    fn generate_rejects_non_digit_nameplate() {
        assert_eq!(
            ShortCode::generate_with_nameplate("12a").unwrap_err(),
            ShortCodeParseError::InvalidNameplate,
        );
    }

    #[test]
    fn generated_words_are_from_wordlist() {
        let code = ShortCode::generate_with_nameplate("3").unwrap();
        for w in code.password().split('-').skip(1) {
            assert!(
                WORDLIST.contains(&w),
                "generated word {w:?} not in canonical WORDLIST",
            );
        }
    }

    #[test]
    fn wordlist_meets_minimum_size() {
        assert!(
            WORDLIST.len() >= 256,
            "wordlist too small: {}",
            WORDLIST.len()
        );
    }
}
