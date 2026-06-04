use iroh::endpoint::Connection;
use portl_core::transport_telemetry::{ObserverConfig, TransportTelemetryContext};

use crate::session::Session;

pub(crate) fn spawn_connection_observer(
    connection: Connection,
    session: &Session,
    server_endpoint_id: [u8; 32],
    client_nonce_hash: Option<[u8; 16]>,
) -> tokio::task::JoinHandle<()> {
    let mut context = TransportTelemetryContext::agent_default();
    context.caller_endpoint_id = Some(session.caller_endpoint_id);
    context.server_endpoint_id = Some(server_endpoint_id);
    context.remote_endpoint_id = Some(*connection.remote_id().as_bytes());
    context.ticket_id = Some(session.ticket_id);
    context.ticket_issuer_id = Some(session.ticket_issuer_id);
    context.ticket_holder_id = session.ticket_holder_id;
    context.client_nonce_hash = client_nonce_hash;
    portl_core::transport_telemetry::spawn_connection_observer(
        connection,
        context,
        ObserverConfig::from_env(),
    )
}

#[cfg(test)]
mod tests {
    use portl_core::transport_telemetry::TelemetryRole;

    #[test]
    fn agent_default_context_uses_agent_role() {
        assert_eq!(
            portl_core::transport_telemetry::TransportTelemetryContext::agent_default().role,
            TelemetryRole::Agent
        );
    }
}
