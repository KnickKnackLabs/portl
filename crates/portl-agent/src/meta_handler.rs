use std::sync::Arc;

use anyhow::Result;
use iroh::endpoint::Connection;
use tracing::instrument;

use crate::AgentState;

#[allow(dead_code)]
#[instrument(skip_all)]
pub(crate) async fn serve_stream(_connection: &Connection, _state: Arc<AgentState>) -> Result<()> {
    Ok(())
}
