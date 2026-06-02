use iroh::endpoint::{Connection, PathInfo};

pub(crate) fn spawn_connection_observer(
    connection: Connection,
    peer_eid: [u8; 32],
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let connection_id = connection.stable_id() as u64;
        let peer = hex::encode(peer_eid);
        tracing::info!(
            event = "transport.connection.opened",
            peer_eid = %crate::short_eid_for_log(&peer),
            connection_id,
            side = ?connection.side(),
        );
        log_current_paths(connection_id, &connection);
        let reason = connection.closed().await;
        tracing::info!(
            event = "transport.connection.closed",
            peer_eid = %crate::short_eid_for_log(&peer),
            connection_id,
            reason = %format!("{reason}"),
        );
    })
}

fn log_current_paths(connection_id: u64, connection: &Connection) {
    for (idx, path) in connection
        .paths()
        .into_iter()
        .filter(|path| !path.is_closed())
        .enumerate()
    {
        tracing::info!(
            event = if path.is_selected() {
                "transport.path.selected"
            } else {
                "transport.path.opened"
            },
            connection_id,
            path_index = idx,
            path = transport_path_kind(&path),
            rtt_micros = path
                .rtt()
                .map(|rtt| u64::try_from(rtt.as_micros()).unwrap_or(u64::MAX)),
        );
    }
}

fn transport_path_kind(path: &PathInfo) -> &'static str {
    if path.is_relay() {
        "relay"
    } else if path.is_ip() {
        "direct_udp"
    } else {
        "unknown"
    }
}

#[cfg(test)]
pub(crate) fn transport_addr_kind_for_test(kind: &str) -> &'static str {
    match kind {
        "relay" => "relay",
        "ip" => "direct_udp",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn path_kind_labels_are_stable() {
        assert_eq!(super::transport_addr_kind_for_test("relay"), "relay");
        assert_eq!(super::transport_addr_kind_for_test("ip"), "direct_udp");
        assert_eq!(super::transport_addr_kind_for_test("other"), "unknown");
    }
}
