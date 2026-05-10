/// Portl's DA1 response parameter list: VT220-level conformance with 132-column,
/// selective-erase, and ANSI-color feature bits.
pub(crate) const PORTL_CANONICAL_DA1_PARAMETER_LIST: &[u8] = b"62;1;6;22";

/// Portl's DA2 response parameter list: VT220 device type, Portl-owned firmware
/// version 1, and no ROM cartridge.
pub(crate) const PORTL_CANONICAL_DA2_PARAMETER_LIST: &[u8] = b"1;1;0";

// These values are mission-canonical and environment-independent: do not derive
// them from TERM, TERM_PROGRAM, the host terminal, or any runtime probe. That
// no-host-coupling invariant is what prevents guest capability queries from
// re-exposing the host's terminal behavior through Portl.
pub(crate) const PORTL_CANONICAL_KITTY_KEYBOARD_FLAGS: u8 = 0;

#[cfg(test)]
mod tests {
    use super::{
        PORTL_CANONICAL_DA1_PARAMETER_LIST, PORTL_CANONICAL_DA2_PARAMETER_LIST,
        PORTL_CANONICAL_KITTY_KEYBOARD_FLAGS,
    };

    #[test]
    fn canonical_da1_parameter_list_matches_portl_vt220_profile() {
        assert_eq!(PORTL_CANONICAL_DA1_PARAMETER_LIST, b"62;1;6;22");
    }

    #[test]
    fn canonical_da2_parameter_list_matches_portl_vt220_profile() {
        assert_eq!(PORTL_CANONICAL_DA2_PARAMETER_LIST, b"1;1;0");
    }

    #[test]
    fn canonical_kitty_flags_are_host_independent_disabled_value() {
        assert_eq!(PORTL_CANONICAL_KITTY_KEYBOARD_FLAGS, 0);
    }
}
