//! Generic `portl accept` router introduced in Task 10 of the
//! shortcode-rendezvous plan.
//!
//! Routes the user-supplied `<THING>` argument to the right
//! consumer based on its prefix:
//!
//! 1. `PORTLINV-*`     → existing peer invite accept implementation.
//! 2. `PORTL-S-*`      → short online exchange share.
//! 3. `PORTL-SHARE1-*` → offline share token (not in this slice).
//! 4. `portl...`       → ticket string; suggest `portl ticket save`.
//! 5. unknown          → list supported forms.

use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use iroh_tickets::Ticket;
use portl_core::peer_store::PeerStore;
use portl_core::rendezvous::backend::{RecipientHelloV1, accept_over_mailbox};
use portl_core::rendezvous::exchange::{ExchangePayload, PortlExchangeEnvelopeV1};
use portl_core::rendezvous::ws::WsRendezvousBackend;
use portl_core::rendezvous::{RendezvousError, ShortCode};
use portl_core::store_index::label_in_use;
use portl_core::ticket::canonical::{canonical_check_ticket, resolved_issuer};
use portl_core::ticket::schema::PortlTicket;
use portl_core::ticket::sign::verify_body;
use portl_core::ticket_store::{TicketEntry, TicketStore};

use crate::commands;
use crate::commands::session_share::{load_identity, resolve_rendezvous_url, share_caps};

/// Dispatch entry point for the top-level `portl accept` command.
pub fn run(
    thing: &str,
    yes: bool,
    label: Option<&str>,
    rendezvous_url: Option<&str>,
    timeout: Duration,
) -> Result<ExitCode> {
    let trimmed = thing.trim();

    if trimmed.starts_with("PORTLINV-") {
        reject_short_share_only_options(label, rendezvous_url)?;
        return commands::peer::pair::run(trimmed, yes);
    }

    if trimmed.starts_with("PORTL-S-") {
        return run_short_code(trimmed, label, rendezvous_url, timeout);
    }

    if trimmed.starts_with("PORTL-SHARE1-") {
        reject_short_share_only_options(label, rendezvous_url)?;
        bail!(
            "offline share tokens are not implemented yet.\n       \
             `PORTL-SHARE1-*` will be supported in a future release."
        );
    }

    if trimmed.starts_with("PORTLTKT-") || trimmed.starts_with("portl") {
        reject_short_share_only_options(label, rendezvous_url)?;
        bail!(
            "this looks like a ticket string, not an invite or share code.\n       \
             To save it for later use:\n         \
             portl ticket save <label> <ticket>"
        );
    }

    reject_short_share_only_options(label, rendezvous_url)?;
    bail!(
        "unrecognized accept input.\n       \
         Supported forms:\n         \
         PORTLINV-…    pairing invite from `portl invite`\n         \
         PORTL-S-…     short online session share\n         \
         PORTL-SHARE1-… offline share token (not yet implemented)\n         \
         portl…        ticket string — use `portl ticket save <label> <ticket>`"
    );
}

fn reject_short_share_only_options(
    label: Option<&str>,
    rendezvous_url: Option<&str>,
) -> Result<()> {
    if label.is_some() || rendezvous_url.is_some() {
        bail!("--label and --rendezvous-url only apply to PORTL-S session shares");
    }
    Ok(())
}

fn run_short_code(
    thing: &str,
    label: Option<&str>,
    rendezvous_url: Option<&str>,
    timeout: Duration,
) -> Result<ExitCode> {
    // Validate shape now so we surface clear `PORTL-S-` guidance for
    // malformed inputs even before the network path lands.
    let code = ShortCode::parse(thing).map_err(|err| {
        anyhow::anyhow!(
            "invalid `PORTL-S-` short code: {err}.\n       \
             Expected `PORTL-S-<nameplate>-<word>-<word>[-…]`."
        )
    })?;

    let url = resolve_rendezvous_url(rendezvous_url);
    let identity = load_identity(None)?;
    let recipient_endpoint_id_hex = hex::encode(identity.endpoint_id().as_bytes());
    let hello = RecipientHelloV1 {
        schema: portl_core::rendezvous::backend::PORTL_RECIPIENT_HELLO_SCHEMA_V1.to_owned(),
        endpoint_id_hex: Some(recipient_endpoint_id_hex.clone()),
        label_hint: None,
    };

    let runtime = tokio::runtime::Runtime::new()?;
    let outcome = runtime.block_on(async move {
        match tokio::time::timeout(timeout, async {
            let mut transport = WsRendezvousBackend::new(&url)
                .map_err(|e| anyhow!("rendezvous backend: {e}"))?
                .with_timeout(timeout)
                .connect_transport()
                .await
                .map_err(|e| anyhow!("connect to rendezvous server: {e}"))?;
            accept_over_mailbox(&mut transport, code, hello)
                .await
                .map_err(short_code_accept_error)
        })
        .await
        {
            Ok(result) => result,
            Err(_) => Err(anyhow!(
                "accept timed out after {}; the sender must keep `portl session share` running",
                humantime::format_duration(timeout)
            )),
        }
    });
    runtime.shutdown_background();
    let outcome = outcome?;

    import_exchange_envelope(
        &outcome.envelope,
        ImportOptions {
            label,
            recipient_endpoint_id_hex: Some(&recipient_endpoint_id_hex),
        },
        &PeerStore::default_path(),
        &TicketStore::default_path(),
    )?;
    Ok(ExitCode::SUCCESS)
}

fn short_code_accept_error(err: RendezvousError) -> anyhow::Error {
    match err {
        RendezvousError::AlreadyClaimed => anyhow!("short code was already claimed"),
        RendezvousError::Expired => anyhow!("short code expired"),
        RendezvousError::NotFound => anyhow!("short code was not found"),
        RendezvousError::Backend(msg) => anyhow!("rendezvous backend failed: {msg}"),
        RendezvousError::Mailbox(err) => anyhow!("mailbox transport error: {err}"),
        RendezvousError::Crypto(_) => {
            anyhow!("short-code exchange failed; check the code and try again")
        }
        RendezvousError::InvalidPayload(msg) => anyhow!("invalid exchange payload: {msg}"),
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ImportOptions<'a> {
    pub(crate) label: Option<&'a str>,
    pub(crate) recipient_endpoint_id_hex: Option<&'a str>,
}

#[allow(clippy::too_many_lines)]
pub(crate) fn import_exchange_envelope(
    envelope: &PortlExchangeEnvelopeV1,
    options: ImportOptions<'_>,
    peers_path: &Path,
    tickets_path: &Path,
) -> Result<String> {
    envelope
        .validate()
        .map_err(|err| anyhow!("invalid exchange envelope: {err}"))?;
    let now = unix_now()?;
    if let Some(not_after) = envelope.not_after_unix
        && not_after <= now
    {
        bail!("session share expired; ask the sender to run `portl session share` again");
    }
    let ExchangePayload::SessionShare(share) = &envelope.payload;
    if share.access_not_after_unix <= now {
        bail!("session share access expired; ask the sender to mint a fresh share");
    }

    let ticket = <PortlTicket as Ticket>::deserialize(&share.ticket)
        .map_err(|err| anyhow!("parse embedded session ticket: {err}"))?;
    canonical_check_ticket(&ticket)
        .map_err(|err| anyhow!("invalid embedded session ticket: {err}"))?;
    verify_body(&resolved_issuer(&ticket), &ticket.body, &ticket.sig)
        .map_err(|err| anyhow!("embedded session ticket signature failed: {err}"))?;
    if ticket.v != 1
        || ticket.body.parent.is_some()
        || ticket.body.bearer.is_some()
        || ticket.body.caps != share_caps()
    {
        bail!("embedded session ticket is not a session-share ticket");
    }

    let endpoint_id_hex = hex::encode(ticket.addr.id.as_bytes());
    if !endpoint_id_hex.eq_ignore_ascii_case(&share.target_endpoint_id_hex) {
        bail!("embedded session ticket target did not match share envelope");
    }
    if ticket.body.not_after > share.access_not_after_unix {
        bail!("embedded session ticket outlives share access window");
    }
    if ticket.body.not_after <= now {
        bail!("embedded session ticket has already expired");
    }
    if let Some(expected) = options.recipient_endpoint_id_hex {
        let Some(holder) = ticket.body.to else {
            bail!("embedded session ticket is not bound to this recipient");
        };
        let holder = hex::encode(holder);
        if !holder.eq_ignore_ascii_case(expected) {
            bail!("embedded session ticket is bound to a different recipient");
        }
    }

    let label = options.label.map_or_else(
        || share.import_label(),
        |label| {
            let trimmed = label.trim();
            if trimmed.is_empty() {
                String::new()
            } else {
                trimmed.to_owned()
            }
        },
    );
    if label.trim().is_empty() {
        bail!("session share label is empty; pass --label <name>");
    }

    let peers = PeerStore::load(peers_path)?;
    let mut tickets = TicketStore::load(tickets_path)?;
    if peers.get_by_label(&label).is_some() {
        bail!(
            "label '{label}' is already in use by a peer; pass --label <name> or choose another label"
        );
    }

    if let Some(existing) = tickets.get(&label).cloned() {
        if !existing
            .endpoint_id_hex
            .eq_ignore_ascii_case(&endpoint_id_hex)
        {
            bail!(
                "label '{label}' is already in use by a ticket for a different endpoint; pass --label <name> or remove the existing label first"
            );
        }
        if existing.expires_at >= ticket.body.not_after {
            bail!(
                "ticket '{label}' already exists for this endpoint and expires later or at the same time; keeping the existing ticket"
            );
        }
        tickets.remove(&label);
    } else if let Some(store) = label_in_use(&label, &peers, &tickets) {
        bail!(
            "label '{label}' is already in use by a {store}; pass --label <name> or remove the existing label first"
        );
    }

    tickets.insert(
        label.clone(),
        TicketEntry {
            endpoint_id_hex,
            ticket_string: share.ticket.clone(),
            expires_at: ticket.body.not_after,
            saved_at: now,
        },
    )?;
    tickets.save(tickets_path)?;

    let expires_in_secs = ticket.body.not_after - now;
    if let Some(origin) = &share.origin_label_hint {
        println!(
            "Accepted session share \"{}\" from {}.",
            share.friendly_name, origin
        );
    } else {
        println!("Accepted session share \"{}\".", share.friendly_name);
    }
    println!("Saved access as ticket \"{label}\" (expires in {expires_in_secs}s).\n");
    println!(
        "Attach with:\n  portl session attach {label} {}",
        share.provider_session
    );

    Ok(label)
}

fn unix_now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::session_share::run_offer_against_transport;
    use async_trait::async_trait;
    use ed25519_dalek::SigningKey;
    use iroh::EndpointAddr;
    use portl_core::id::Identity;
    use portl_core::rendezvous::exchange::SessionShareEnvelopeV1;
    use portl_core::rendezvous::mailbox::{
        ClientMessage, MailboxError, MailboxTransport, ServerMessage,
    };
    use portl_core::ticket::mint::mint_root;
    use portl_core::ticket::schema::MetaCaps;
    use tempfile::TempDir;
    use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

    fn fixture_identity(byte: u8) -> Identity {
        Identity::from_signing_key(SigningKey::from_bytes(&[byte; 32]))
    }

    fn fixture_addr() -> EndpointAddr {
        EndpointAddr::new(fixture_identity(7).endpoint_id())
    }

    fn broader_caps() -> portl_core::ticket::schema::Capabilities {
        let mut caps = share_caps();
        caps.presence |= 0b0010_0000;
        caps.meta = Some(MetaCaps {
            ping: true,
            info: true,
        });
        caps
    }

    fn fixture_session_share(friendly_name: &str, origin: Option<&str>) -> PortlExchangeEnvelopeV1 {
        fixture_session_share_with_ttl(friendly_name, origin, 3_600)
    }

    fn fixture_session_share_with_ttl(
        friendly_name: &str,
        origin: Option<&str>,
        ttl_secs: u64,
    ) -> PortlExchangeEnvelopeV1 {
        fixture_session_share_with_options(
            friendly_name,
            origin,
            Some(fixture_identity(9).verifying_key()),
            false,
            ttl_secs,
        )
    }

    fn fixture_session_share_with_options(
        friendly_name: &str,
        origin: Option<&str>,
        recipient: Option<[u8; 32]>,
        broader: bool,
        ttl_secs: u64,
    ) -> PortlExchangeEnvelopeV1 {
        let now = unix_now().unwrap();
        let issuer = fixture_identity(3);
        let addr = fixture_addr();
        let ticket = mint_root(
            issuer.signing_key(),
            addr.clone(),
            if broader {
                broader_caps()
            } else {
                share_caps()
            },
            now,
            now + ttl_secs,
            recipient,
        )
        .unwrap();
        let share = SessionShareEnvelopeV1 {
            workspace_id: "ws_test".to_owned(),
            friendly_name: friendly_name.to_owned(),
            conflict_handle: "abcd1234".to_owned(),
            origin_label_hint: origin.map(ToOwned::to_owned),
            target_label_hint: Some("max-b265".to_owned()),
            target_endpoint_id_hex: hex::encode(addr.id.as_bytes()),
            provider: Some("zmx".to_owned()),
            provider_session: friendly_name.to_owned(),
            ticket: ticket.serialize(),
            access_not_after_unix: now + ttl_secs,
        };
        PortlExchangeEnvelopeV1::session_share(share, now, Some(now + 300))
    }

    struct PairedMailboxTransport {
        own_side: Option<String>,
        incoming_rx: UnboundedReceiver<ServerMessage>,
        incoming_tx: UnboundedSender<ServerMessage>,
        peer_tx: UnboundedSender<ServerMessage>,
    }

    impl PairedMailboxTransport {
        fn pair() -> (Self, Self) {
            let (a_tx, a_rx) = mpsc::unbounded_channel();
            let (b_tx, b_rx) = mpsc::unbounded_channel();
            (
                Self {
                    own_side: None,
                    incoming_rx: a_rx,
                    incoming_tx: a_tx.clone(),
                    peer_tx: b_tx.clone(),
                },
                Self {
                    own_side: None,
                    incoming_rx: b_rx,
                    incoming_tx: b_tx,
                    peer_tx: a_tx,
                },
            )
        }
    }

    #[async_trait]
    impl MailboxTransport for PairedMailboxTransport {
        async fn send(&mut self, msg: ClientMessage) -> Result<(), MailboxError> {
            match msg {
                ClientMessage::Bind { side, .. } => {
                    self.own_side = Some(side);
                    let _ = self.incoming_tx.send(ServerMessage::Welcome {
                        welcome: serde_json::json!({}),
                    });
                }
                ClientMessage::Allocate => {
                    let _ = self.incoming_tx.send(ServerMessage::Allocated {
                        nameplate: "7".to_owned(),
                    });
                }
                ClientMessage::Claim { nameplate } => {
                    let _ = self.incoming_tx.send(ServerMessage::Claimed {
                        mailbox: format!("mailbox-{nameplate}"),
                    });
                }
                ClientMessage::Release { .. } => {
                    let _ = self.incoming_tx.send(ServerMessage::Released);
                }
                ClientMessage::Open { .. } => {
                    let _ = self
                        .incoming_tx
                        .send(ServerMessage::Ack { id: "open".into() });
                }
                ClientMessage::Add { phase, body, .. } => {
                    let side = self.own_side.clone().unwrap_or_else(|| "side".to_owned());
                    let _ = self
                        .incoming_tx
                        .send(ServerMessage::Ack { id: phase.clone() });
                    let _ = self.peer_tx.send(ServerMessage::Message {
                        id: format!("msg-{phase}"),
                        side,
                        phase,
                        body,
                    });
                }
                ClientMessage::Close { mood, .. } => {
                    let _ = self
                        .incoming_tx
                        .send(ServerMessage::Closed { mood: mood.clone() });
                    let _ = self.peer_tx.send(ServerMessage::Closed { mood });
                }
            }
            Ok(())
        }

        async fn recv(&mut self) -> Result<ServerMessage, MailboxError> {
            self.incoming_rx
                .recv()
                .await
                .ok_or(MailboxError::Closed { mood: None })
        }
    }

    fn temp_paths(temp: &TempDir) -> (std::path::PathBuf, std::path::PathBuf) {
        (
            temp.path().join("peers.json"),
            temp.path().join("tickets.json"),
        )
    }

    #[test]
    fn accepted_session_share_saves_ticket_under_import_label() {
        let temp = TempDir::new().unwrap();
        let (peers_path, tickets_path) = temp_paths(&temp);
        let envelope = fixture_session_share("dev", Some("alice"));
        let label = import_exchange_envelope(
            &envelope,
            ImportOptions {
                label: None,
                recipient_endpoint_id_hex: Some(&hex::encode(fixture_identity(9).verifying_key())),
            },
            &peers_path,
            &tickets_path,
        )
        .unwrap();

        assert_eq!(label, "max-b265-dev");
        let tickets = TicketStore::load(&tickets_path).unwrap();
        assert!(tickets.get("max-b265-dev").is_some());
    }

    #[test]
    fn accepted_session_share_replaces_same_endpoint_when_expiry_extends() {
        let temp = TempDir::new().unwrap();
        let (peers_path, tickets_path) = temp_paths(&temp);
        let short = fixture_session_share_with_ttl("dev", Some("alice"), 60);
        let long = fixture_session_share_with_ttl("dev", Some("alice"), 3_600);
        let recipient = Some(hex::encode(fixture_identity(9).verifying_key()));
        import_exchange_envelope(
            &short,
            ImportOptions {
                label: None,
                recipient_endpoint_id_hex: recipient.as_deref(),
            },
            &peers_path,
            &tickets_path,
        )
        .unwrap();
        let label = import_exchange_envelope(
            &long,
            ImportOptions {
                label: None,
                recipient_endpoint_id_hex: recipient.as_deref(),
            },
            &peers_path,
            &tickets_path,
        )
        .unwrap();

        assert_eq!(label, "max-b265-dev");
        let tickets = TicketStore::load(&tickets_path).unwrap();
        let saved = tickets.get("max-b265-dev").unwrap();
        let ExchangePayload::SessionShare(long_share) = &long.payload;
        assert_eq!(saved.expires_at, long_share.access_not_after_unix);
    }

    #[test]
    fn accepted_session_share_keeps_same_endpoint_when_not_newer() {
        let temp = TempDir::new().unwrap();
        let (peers_path, tickets_path) = temp_paths(&temp);
        let envelope = fixture_session_share("dev", Some("alice"));
        import_exchange_envelope(
            &envelope,
            ImportOptions {
                label: None,
                recipient_endpoint_id_hex: Some(&hex::encode(fixture_identity(9).verifying_key())),
            },
            &peers_path,
            &tickets_path,
        )
        .unwrap();

        let err = import_exchange_envelope(
            &envelope,
            ImportOptions {
                label: None,
                recipient_endpoint_id_hex: Some(&hex::encode(fixture_identity(9).verifying_key())),
            },
            &peers_path,
            &tickets_path,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("keeping the existing ticket"),
            "{err}"
        );
    }

    #[test]
    fn accepted_session_share_honors_explicit_label() {
        let temp = TempDir::new().unwrap();
        let (peers_path, tickets_path) = temp_paths(&temp);
        let envelope = fixture_session_share("dev", Some("alice"));
        let label = import_exchange_envelope(
            &envelope,
            ImportOptions {
                label: Some("daily-dev"),
                recipient_endpoint_id_hex: Some(&hex::encode(fixture_identity(9).verifying_key())),
            },
            &peers_path,
            &tickets_path,
        )
        .unwrap();
        assert_eq!(label, "daily-dev");
    }

    #[test]
    fn shortcode_offer_accept_and_import_e2e_without_network() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let outcome = runtime.block_on(async {
            let (mut sender_t, mut receiver_t) = PairedMailboxTransport::pair();
            let (code_tx, code_rx) = tokio::sync::oneshot::channel();
            let sender = async move {
                run_offer_against_transport(
                    &mut sender_t,
                    None,
                    |code| {
                        let _ = code_tx.send(code.clone());
                    },
                    |_hello| Ok(fixture_session_share("dev", Some("alice"))),
                )
                .await
            };
            let receiver = async move {
                let code = code_rx.await.unwrap();
                let hello = RecipientHelloV1 {
                    schema: portl_core::rendezvous::backend::PORTL_RECIPIENT_HELLO_SCHEMA_V1
                        .to_owned(),
                    endpoint_id_hex: Some(hex::encode(fixture_identity(9).verifying_key())),
                    label_hint: Some("recipient".to_owned()),
                };
                accept_over_mailbox(&mut receiver_t, code, hello).await
            };
            let (sender_result, receiver_result) = tokio::join!(sender, receiver);
            sender_result.unwrap();
            receiver_result.unwrap()
        });

        let temp = TempDir::new().unwrap();
        let (peers_path, tickets_path) = temp_paths(&temp);
        let label = import_exchange_envelope(
            &outcome.envelope,
            ImportOptions {
                label: None,
                recipient_endpoint_id_hex: Some(&hex::encode(fixture_identity(9).verifying_key())),
            },
            &peers_path,
            &tickets_path,
        )
        .unwrap();
        assert_eq!(label, "max-b265-dev");
        assert!(
            TicketStore::load(&tickets_path)
                .unwrap()
                .get("max-b265-dev")
                .is_some()
        );
    }

    #[test]
    fn accepted_session_share_rejects_mismatched_recipient_binding() {
        let temp = TempDir::new().unwrap();
        let (peers_path, tickets_path) = temp_paths(&temp);
        let envelope = fixture_session_share("dev", Some("alice"));
        let err = import_exchange_envelope(
            &envelope,
            ImportOptions {
                label: None,
                recipient_endpoint_id_hex: Some(&hex::encode(fixture_identity(8).verifying_key())),
            },
            &peers_path,
            &tickets_path,
        )
        .unwrap_err();
        assert!(err.to_string().contains("different recipient"), "{err}");
    }

    #[test]
    fn accepted_session_share_rejects_unbound_bearer_ticket_when_recipient_known() {
        let temp = TempDir::new().unwrap();
        let (peers_path, tickets_path) = temp_paths(&temp);
        let envelope = fixture_session_share_with_options("dev", Some("alice"), None, false, 3_600);
        let err = import_exchange_envelope(
            &envelope,
            ImportOptions {
                label: None,
                recipient_endpoint_id_hex: Some(&hex::encode(fixture_identity(9).verifying_key())),
            },
            &peers_path,
            &tickets_path,
        )
        .unwrap_err();
        assert!(err.to_string().contains("not bound"), "{err}");
    }

    #[test]
    fn accepted_session_share_rejects_non_session_share_caps() {
        let temp = TempDir::new().unwrap();
        let (peers_path, tickets_path) = temp_paths(&temp);
        let envelope = fixture_session_share_with_options(
            "dev",
            Some("alice"),
            Some(fixture_identity(9).verifying_key()),
            true,
            3_600,
        );
        let err = import_exchange_envelope(
            &envelope,
            ImportOptions {
                label: None,
                recipient_endpoint_id_hex: Some(&hex::encode(fixture_identity(9).verifying_key())),
            },
            &peers_path,
            &tickets_path,
        )
        .unwrap_err();
        assert!(err.to_string().contains("session-share ticket"), "{err}");
    }
}
