use std::time::Duration;

use iroh::endpoint::Connection;

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
    let paths = connection.paths();
    for (idx, path) in paths.iter().enumerate() {
        let path_kind = if path.is_relay() {
            "relay"
        } else if path.is_ip() {
            "direct_udp"
        } else {
            "unknown"
        };
        tracing::info!(
            event = if path.is_selected() {
                "transport.path.selected"
            } else {
                "transport.path.opened"
            },
            connection_id,
            path_index = idx,
            path = path_kind,
            rtt_micros = rtt_micros_if_sampled(path.rtt()),
        );
    }
}

fn rtt_micros_if_sampled(rtt: Duration) -> Option<u64> {
    (!rtt.is_zero()).then(|| u64::try_from(rtt.as_micros()).unwrap_or(u64::MAX))
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
    use std::time::Duration;

    #[test]
    fn path_kind_labels_are_stable() {
        assert_eq!(super::transport_addr_kind_for_test("relay"), "relay");
        assert_eq!(super::transport_addr_kind_for_test("ip"), "direct_udp");
        assert_eq!(super::transport_addr_kind_for_test("other"), "unknown");
    }

    #[test]
    fn zero_rtt_is_treated_as_missing_sample() {
        assert_eq!(super::rtt_micros_if_sampled(Duration::ZERO), None);
        assert_eq!(
            super::rtt_micros_if_sampled(Duration::from_micros(42)),
            Some(42)
        );
    }
}
