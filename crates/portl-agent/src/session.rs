use portl_core::ticket::schema::Capabilities;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub peer_token: [u8; 16],
    pub caps: Capabilities,
    pub ticket_id: [u8; 16],
    pub caller_endpoint_id: [u8; 32],
}
