use std::sync::Arc;

use anyhow::Result;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use tracing::instrument;

use crate::AgentState;
use crate::session::Session;

#[allow(dead_code)]
#[instrument(skip_all)]
pub(crate) async fn serve_stream(
    _connection: &Connection,
    _session: &Session,
    _state: Arc<AgentState>,
    _send: SendStream,
    _recv: RecvStream,
) -> Result<()> {
    Ok(())
}
