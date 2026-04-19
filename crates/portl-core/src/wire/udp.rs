use serde::{Deserialize, Serialize};

use crate::wire::StreamPreamble;

pub const ALPN_UDP_V1: &[u8] = b"portl/udp/v1";
pub const MAX_UDP_DATAGRAM_BYTES: usize = 1200;
pub const UDP_ERROR_PREFIX: &str = "portl udp error: ";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdpCtlReq {
    pub preamble: StreamPreamble,
    pub session_id: [u8; 8],
    pub binds: Vec<UdpBind>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdpBind {
    pub local_port_range: (u16, u16),
    pub target_host: String,
    pub target_port_range: (u16, u16),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdpCtlResp {
    pub ok: bool,
    pub error: Option<String>,
    pub session_id: [u8; 8],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdpDatagram {
    pub session_id: [u8; 8],
    pub target_port: u16,
    pub src_tag: u32,
    pub payload: Vec<u8>,
}

#[must_use]
pub fn udp_error_payload(message: &str) -> Vec<u8> {
    format!("{UDP_ERROR_PREFIX}{message}").into_bytes()
}

pub fn encode_datagram(datagram: &UdpDatagram) -> Result<Vec<u8>, postcard::Error> {
    postcard::to_stdvec(datagram)
}

#[must_use]
pub fn datagram_fits(datagram: &UdpDatagram) -> bool {
    encode_datagram(datagram)
        .map(|bytes| bytes.len() <= MAX_UDP_DATAGRAM_BYTES)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::{
        ALPN_UDP_V1, UdpBind, UdpCtlReq, UdpCtlResp, UdpDatagram, datagram_fits, udp_error_payload,
    };
    use crate::wire::StreamPreamble;

    #[test]
    fn udp_ctl_req_roundtrips_via_postcard() {
        let value = UdpCtlReq {
            preamble: StreamPreamble {
                peer_token: [9; 16],
                alpn: String::from_utf8_lossy(ALPN_UDP_V1).into_owned(),
            },
            session_id: [7; 8],
            binds: vec![UdpBind {
                local_port_range: (6000, 6000),
                target_host: "127.0.0.1".to_owned(),
                target_port_range: (6001, 6001),
            }],
        };

        let encoded = postcard::to_stdvec(&value).expect("encode udp ctl req");
        let decoded: UdpCtlReq = postcard::from_bytes(&encoded).expect("decode udp ctl req");
        assert_eq!(decoded, value);
    }

    #[test]
    fn udp_ctl_resp_roundtrips_via_postcard() {
        let value = UdpCtlResp {
            ok: true,
            error: None,
            session_id: [3; 8],
        };

        let encoded = postcard::to_stdvec(&value).expect("encode udp ctl resp");
        let decoded: UdpCtlResp = postcard::from_bytes(&encoded).expect("decode udp ctl resp");
        assert_eq!(decoded, value);
    }

    #[test]
    fn udp_datagram_roundtrips_via_postcard() {
        let value = UdpDatagram {
            session_id: [1; 8],
            target_port: 6000,
            src_tag: 42,
            payload: b"hello".to_vec(),
        };

        let encoded = postcard::to_stdvec(&value).expect("encode udp datagram");
        let decoded: UdpDatagram = postcard::from_bytes(&encoded).expect("decode udp datagram");
        assert_eq!(decoded, value);
    }

    #[test]
    fn udp_error_payload_is_human_readable() {
        let payload = String::from_utf8(udp_error_payload("payload too large"))
            .expect("error payload should be utf-8");
        assert_eq!(payload, "portl udp error: payload too large");
    }

    #[test]
    fn udp_datagram_fit_helper_rejects_large_payloads() {
        let ok = UdpDatagram {
            session_id: [0; 8],
            target_port: 7,
            src_tag: 1,
            payload: vec![0; 64],
        };
        let too_large = UdpDatagram {
            session_id: [0; 8],
            target_port: 7,
            src_tag: 1,
            payload: vec![0; 2000],
        };

        assert!(datagram_fits(&ok));
        assert!(!datagram_fits(&too_large));
    }
}
