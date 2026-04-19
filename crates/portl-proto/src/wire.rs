pub use portl_core::wire::StreamPreamble;

#[cfg(test)]
mod tests {
    use super::StreamPreamble;

    #[test]
    fn preamble_roundtrips_via_postcard() {
        let value = StreamPreamble {
            peer_token: [7; 16],
            alpn: "portl/meta/v1".to_owned(),
        };

        let encoded = postcard::to_stdvec(&value).expect("encode preamble");
        let decoded: StreamPreamble = postcard::from_bytes(&encoded).expect("decode preamble");
        assert_eq!(decoded, value);
    }
}
