//! WebSocket rendezvous backend.
//!
//! Connects to a Magic Wormhole–compatible mailbox server over
//! `ws://` or `wss://` using `tokio-websockets`. Each
//! [`crate::rendezvous::mailbox::ClientMessage`] is serialized as a
//! single websocket text frame; binary frames are rejected.
//!
//! The current [`WsRendezvousBackend`] implements
//! [`RendezvousBackend::accept`] end-to-end. The offer side requires
//! allocating a nameplate before a [`ShortCode`] can be displayed and
//! then keeping the connection alive until the recipient finishes the
//! exchange; the existing [`RendezvousBackend`] trait cannot express
//! that without a background task whose completion the caller cannot
//! observe. Rather than fake success, [`RendezvousBackend::offer`]
//! returns a documented [`RendezvousError::Backend`] error and Task 11
//! is expected to drive the websocket offer flow directly through
//! [`WsRendezvousBackend::connect_transport`] +
//! [`crate::rendezvous::backend::offer_over_mailbox`].

use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_websockets::{ClientBuilder, Limits, MaybeTlsStream, Message, WebSocketStream};

use super::backend::{
    AcceptOutcome, ExchangeOffer, OfferHandle, RecipientHelloV1, RendezvousBackend,
    RendezvousError, accept_over_mailbox,
};
use super::mailbox::{ClientMessage, MailboxError, MailboxTransport, ServerMessage};
use super::short_code::ShortCode;

/// Default exchange timeout (~2 minutes) applied to the encrypted
/// rendezvous flow when no override is supplied via
/// [`WsRendezvousBackend::with_timeout`].
pub const DEFAULT_WS_TIMEOUT: Duration = Duration::from_secs(120);

/// Maximum websocket payload length accepted from the mailbox server.
/// One mebibyte is well above any plausible control-plane frame size
/// while still bounding adversary-controlled allocation.
const MAX_WS_PAYLOAD_LEN: usize = 1024 * 1024;

/// WebSocket-backed [`RendezvousBackend`] for `ws://` and `wss://`
/// mailbox URLs.
#[derive(Debug, Clone)]
pub struct WsRendezvousBackend {
    url: url::Url,
    timeout: Duration,
}

impl WsRendezvousBackend {
    /// Construct a backend bound to the given mailbox URL.
    ///
    /// Only `ws://` and `wss://` URLs are accepted; any other scheme is
    /// rejected with a [`RendezvousError::Backend`] whose message
    /// contains the literal text `ws:// or wss://` so callers can
    /// surface a recognisable hint.
    pub fn new(url: &str) -> Result<Self, RendezvousError> {
        let parsed = url::Url::parse(url)
            .map_err(|e| RendezvousError::Backend(format!("invalid mailbox url: {e}")))?;
        match parsed.scheme() {
            "ws" | "wss" => {}
            other => {
                return Err(RendezvousError::Backend(format!(
                    "mailbox url must use ws:// or wss://, got {other}://"
                )));
            }
        }
        Ok(Self {
            url: parsed,
            timeout: DEFAULT_WS_TIMEOUT,
        })
    }

    /// Override the per-exchange timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The mailbox URL this backend was configured with.
    #[must_use]
    pub fn url(&self) -> &url::Url {
        &self.url
    }

    /// Open a fresh websocket transport against the configured URL.
    ///
    /// Exposed as a building block for higher layers (e.g. the CLI
    /// offer flow) that need to drive the mailbox protocol directly
    /// rather than via [`RendezvousBackend`].
    pub async fn connect_transport(&self) -> Result<WsMailboxTransport, RendezvousError> {
        WsMailboxTransport::connect(self.url.as_str()).await
    }
}

/// `tokio-websockets`-backed [`MailboxTransport`].
pub struct WsMailboxTransport {
    inner: WebSocketStream<MaybeTlsStream<TcpStream>>,
    next_id: u64,
}

impl WsMailboxTransport {
    /// Connect to the given `ws://` or `wss://` URL.
    pub async fn connect(url: &str) -> Result<Self, RendezvousError> {
        let uri = http::Uri::from_str(url)
            .map_err(|e| RendezvousError::Backend(format!("invalid mailbox uri: {e}")))?;
        let limits = Limits::default().max_payload_len(Some(MAX_WS_PAYLOAD_LEN));
        let (stream, _resp) = ClientBuilder::from_uri(uri)
            .limits(limits)
            .connect()
            .await
            .map_err(|e| RendezvousError::Backend(format!("websocket connect failed: {e}")))?;
        Ok(Self {
            inner: stream,
            next_id: 0,
        })
    }

    fn next_command_id(&mut self) -> String {
        self.next_id += 1;
        format!("portl-{}", self.next_id)
    }
}

fn serialize_client_message_with_id(msg: ClientMessage, id: &str) -> Result<String, MailboxError> {
    let mut value = serde_json::to_value(msg)
        .map_err(|e| MailboxError::Transport(format!("serialize client frame: {e}")))?;
    let object = value.as_object_mut().ok_or_else(|| {
        MailboxError::Transport("client frame did not serialize to a JSON object".into())
    })?;
    object.insert("id".to_owned(), serde_json::Value::String(id.to_owned()));
    serde_json::to_string(&value)
        .map_err(|e| MailboxError::Transport(format!("serialize client frame: {e}")))
}

#[async_trait]
impl MailboxTransport for WsMailboxTransport {
    async fn send(&mut self, msg: ClientMessage) -> Result<(), MailboxError> {
        let id = self.next_command_id();
        let body = serialize_client_message_with_id(msg, &id)?;
        self.inner
            .send(Message::text(body))
            .await
            .map_err(|e| MailboxError::Transport(format!("websocket send: {e}")))
    }

    async fn recv(&mut self) -> Result<ServerMessage, MailboxError> {
        loop {
            let next = self
                .inner
                .next()
                .await
                .ok_or_else(|| MailboxError::Transport("websocket stream closed".into()))?;
            let frame =
                next.map_err(|e| MailboxError::Transport(format!("websocket recv: {e}")))?;
            if frame.is_ping() || frame.is_pong() {
                continue;
            }
            if frame.is_close() {
                return Err(MailboxError::Transport(
                    "websocket peer sent close frame".into(),
                ));
            }
            if frame.is_binary() {
                return Err(MailboxError::Transport(
                    "unexpected binary websocket frame".into(),
                ));
            }
            let text = frame.as_text().ok_or_else(|| {
                MailboxError::Transport("websocket frame missing utf-8 text".into())
            })?;
            return serde_json::from_str::<ServerMessage>(text)
                .map_err(|e| MailboxError::Transport(format!("deserialize server frame: {e}")));
        }
    }
}

#[async_trait]
impl RendezvousBackend for WsRendezvousBackend {
    async fn offer(&self, _offer: ExchangeOffer) -> Result<OfferHandle, RendezvousError> {
        // See module docs: the trait cannot express an offer that
        // allocates a code, returns it to the user, and only then
        // awaits the recipient. Task 11 drives the websocket offer
        // through `connect_transport()` + `offer_over_mailbox` instead.
        Err(RendezvousError::Backend(
            "websocket offer requires CLI-hosted flow; use WsRendezvousBackend::connect_transport"
                .to_owned(),
        ))
    }

    async fn accept(&self, code: &ShortCode) -> Result<AcceptOutcome, RendezvousError> {
        match timeout(self.timeout, async {
            let mut transport = self.connect_transport().await?;
            accept_over_mailbox(&mut transport, code.clone(), RecipientHelloV1::anonymous()).await
        })
        .await
        {
            Ok(res) => res,
            Err(_) => Err(RendezvousError::Backend("rendezvous timed out".into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio_websockets::ServerBuilder;

    async fn spawn_ws_server<F, Fut>(handler: F) -> String
    where
        F: FnOnce(WebSocketStream<TcpStream>) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (conn, _) = listener.accept().await.unwrap();
            let (_request, server) = ServerBuilder::new().accept(conn).await.unwrap();
            handler(server).await;
        });
        format!("ws://{addr}")
    }

    fn text_json(message: &Message) -> serde_json::Value {
        let text = message.as_text().expect("websocket text frame");
        serde_json::from_str(text).expect("json frame")
    }

    #[test]
    fn serializes_client_message_with_wire_id() {
        let encoded =
            serialize_client_message_with_id(ClientMessage::add("pake", b"abc"), "cmd-1").unwrap();
        let value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "type": "add",
                "phase": "pake",
                "body": "616263",
                "id": "cmd-1",
            })
        );
    }

    #[tokio::test]
    async fn websocket_send_injects_monotonic_ids() {
        let (seen_tx, seen_rx) = oneshot::channel();
        let url = spawn_ws_server(move |mut server| async move {
            let first = server.next().await.unwrap().unwrap();
            let second = server.next().await.unwrap().unwrap();
            seen_tx
                .send((text_json(&first), text_json(&second)))
                .expect("send observed frames");
        })
        .await;

        let mut transport = WsMailboxTransport::connect(&url).await.unwrap();
        transport
            .send(ClientMessage::bind("portl.exchange.v1", "side-a"))
            .await
            .unwrap();
        transport
            .send(ClientMessage::add("pake", b"abc"))
            .await
            .unwrap();

        let (first, second) = seen_rx.await.unwrap();
        assert_eq!(first["type"], "bind");
        assert_eq!(first["id"], "portl-1");
        assert_eq!(second["type"], "add");
        assert_eq!(second["body"], "616263");
        assert_eq!(second["id"], "portl-2");
    }

    #[test]
    fn accepts_ws_and_wss_mailbox_urls() {
        assert!(WsRendezvousBackend::new("ws://relay.magic-wormhole.io:4000/v1").is_ok());
        assert!(WsRendezvousBackend::new("wss://example.invalid/v1").is_ok());
    }

    #[test]
    fn rejects_non_websocket_mailbox_urls() {
        let err = WsRendezvousBackend::new("https://example.invalid/v1").unwrap_err();
        assert!(err.to_string().contains("ws:// or wss://"));
    }

    #[test]
    fn default_timeout_is_used() {
        let b = WsRendezvousBackend::new("ws://example.invalid/v1").unwrap();
        assert_eq!(b.timeout, DEFAULT_WS_TIMEOUT);
        let b = b.with_timeout(Duration::from_secs(5));
        assert_eq!(b.timeout, Duration::from_secs(5));
    }

    #[tokio::test]
    async fn websocket_recv_parses_text_json() {
        let url = spawn_ws_server(|mut server| async move {
            server
                .send(Message::text(
                    r#"{"type":"allocated","nameplate":"7","id":"cmd-1"}"#,
                ))
                .await
                .unwrap();
        })
        .await;

        let mut transport = WsMailboxTransport::connect(&url).await.unwrap();
        let frame = transport.recv().await.unwrap();
        match frame {
            ServerMessage::Allocated { nameplate } => assert_eq!(nameplate, "7"),
            other => panic!("unexpected frame: {other:?}"),
        }
    }

    #[tokio::test]
    async fn websocket_recv_rejects_binary_frames() {
        let url = spawn_ws_server(|mut server| async move {
            server.send(Message::binary(vec![1, 2, 3])).await.unwrap();
        })
        .await;

        let mut transport = WsMailboxTransport::connect(&url).await.unwrap();
        let err = transport.recv().await.unwrap_err();
        assert!(err.to_string().contains("binary"));
    }

    #[tokio::test]
    async fn websocket_recv_reports_close_frames() {
        let url = spawn_ws_server(|mut server| async move {
            server.send(Message::close(None, "bye")).await.unwrap();
        })
        .await;

        let mut transport = WsMailboxTransport::connect(&url).await.unwrap();
        let err = transport.recv().await.unwrap_err();
        assert!(err.to_string().contains("close frame"));
    }

    #[tokio::test]
    #[ignore = "requires public Magic Wormhole relay availability"]
    async fn public_relay_offer_accept_smoke() {
        // The offer path is intentionally not implemented through the
        // RendezvousBackend trait; this smoke test exists so an
        // operator can manually exercise the websocket transport
        // against the public relay once Task 11 lands. For now we just
        // verify that a connection to the relay can be opened.
        let backend = WsRendezvousBackend::new("ws://relay.magic-wormhole.io:4000/v1").unwrap();
        let _transport = backend
            .connect_transport()
            .await
            .expect("connect to public relay");
    }
}
