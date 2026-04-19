use std::sync::Arc;

use anyhow::Result;
use iroh::endpoint::Connection;
use tracing::instrument;

use crate::AgentState;

#[instrument(skip_all, fields(remote = %connection.remote_id().fmt_short()))]
pub(crate) async fn serve_connection(
    connection: Connection,
    _state: Arc<AgentState>,
) -> Result<()> {
    connection.close(0x1000u32.into(), b"ticket handshake not ready");
    Ok(())
}
