//! `portl session share` — CLI-hosted PORTL-S session share flow.
//!
//! Implementation notes
//! ====================
//!
//! This command must keep the Portl invariants intact:
//!
//! 1. It only attempts the rendezvous flow for target forms where we
//!    can mint a *fresh* root ticket from the local identity to a
//!    resolved endpoint address. Inline ticket strings, saved-ticket
//!    labels, and alias-stored ticket files would require unsafe
//!    delegation (or echoing a ticket credential) and are rejected
//!    *before* any network activity, with errors that never echo the
//!    raw `<TARGET>` (which may itself be a ticket string).
//!
//! 2. The default code path mints a *recipient-bound* ticket (`to =
//!    recipient endpoint id`) using the hello the recipient sends
//!    over the wormhole. If the recipient hello does not carry an
//!    endpoint id we refuse to send a bearer ticket unless the user
//!    explicitly opts in with `--allow-bearer-fallback`. Bearer
//!    fallback caps the ticket TTL at `min(access_ttl, 10m)`.
//!
//! 3. The TCP/websocket I/O lives behind helpers in `portl-core`
//!    (`offer_pake_and_recv_hello` / `offer_send_envelope`) so the
//!    share-time minting can happen *between* PAKE and envelope
//!    transmission. Unit tests in this module use the in-process
//!    paired mailbox transport from `portl-core` to exercise the full
//!    sender pipeline without a public relay.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use iroh_base::{EndpointAddr, EndpointId};
use iroh_tickets::Ticket;
use portl_core::id::Identity;
use portl_core::peer_store::PeerStore;
use portl_core::rendezvous::mailbox::{MailboxClient, MailboxTransport};
use portl_core::rendezvous::{
    PORTL_EXCHANGE_APPID_V1, PortlExchangeEnvelopeV1, RecipientHelloV1, RendezvousError,
    SessionShareEnvelopeV1, ShortCode, fresh_side, offer_pake_and_recv_hello, offer_send_envelope,
};
use portl_core::ticket::mint::mint_root;
use portl_core::ticket::schema::{Capabilities, EnvPolicy, PortlTicket, ShellCaps};
use portl_core::ticket_store::TicketStore;

use crate::alias_store::AliasStore;

/// Default mailbox URL when neither flag nor environment variable is set.
pub(crate) const DEFAULT_RENDEZVOUS_URL: &str = "ws://relay.magic-wormhole.io:4000/v1";

/// Hard cap on bearer-fallback ticket TTL. Bearer tickets are
/// uncountersigned by recipient identity, so they remain useful only
/// long enough to bridge the immediate rendezvous.
pub(crate) const BEARER_FALLBACK_MAX_TTL: Duration = Duration::from_secs(600);

/// Resolved-target form supported by `portl session share`.
///
/// All variants ultimately resolve to a `(EndpointAddr, label_hint)`
/// pair the offerer can mint a fresh root ticket against. Forms that
/// would require delegating a saved ticket or echoing a raw credential
/// are intentionally not represented.
#[derive(Debug, Clone)]
pub(crate) enum ShareTargetForm {
    /// Peer-store entry where `they_accept_from_me=true`.
    PeerStore {
        label: String,
        endpoint_id: EndpointId,
    },
    /// Alias entry pointing to a bare endpoint id (no stored ticket).
    AliasEid {
        label: String,
        endpoint_id: EndpointId,
    },
    /// Raw 64-char endpoint id token (or middle-elided form).
    RawEid { endpoint_id: EndpointId },
}

impl ShareTargetForm {
    pub(crate) fn endpoint_id(&self) -> EndpointId {
        match self {
            Self::PeerStore { endpoint_id, .. }
            | Self::AliasEid { endpoint_id, .. }
            | Self::RawEid { endpoint_id } => *endpoint_id,
        }
    }

    /// Display tag used in `using …` and progress lines. Never echoes
    /// raw target input that could be a ticket credential.
    pub(crate) fn target_label_hint(&self) -> String {
        match self {
            Self::PeerStore { label, .. } | Self::AliasEid { label, .. } => label.clone(),
            Self::RawEid { endpoint_id } => {
                let hex = hex::encode(endpoint_id.as_bytes());
                portl_core::labels::machine_label(None, &hex)
            }
        }
    }

    pub(crate) fn safe_display(&self) -> String {
        match self {
            Self::PeerStore { label, .. } => format!("peer \"{label}\""),
            Self::AliasEid { label, .. } => format!("alias \"{label}\""),
            Self::RawEid { endpoint_id } => {
                let hex = hex::encode(endpoint_id.as_bytes());
                format!("endpoint {}", crate::eid::format_short(&hex))
            }
        }
    }
}

/// Errors classified by what the user can do about them. Notably
/// every variant is constructed from non-secret data — `<TARGET>`
/// itself is never embedded.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ResolveTargetError {
    /// The argument parsed as a `portl…` ticket. We refuse to delegate
    /// it (and do not echo the input).
    #[error(
        "session share cannot safely delegate a ticket credential passed as <TARGET>. \
         Use a peer-store label, alias, or `endpoint_id` instead."
    )]
    TicketCredential,
    /// The argument matched a saved-ticket label.
    #[error(
        "session share cannot delegate the saved ticket for label '{0}'. \
         Use a peer-store label, alias, or `endpoint_id` instead."
    )]
    SavedTicketLabel(String),
    /// The argument matched an alias whose backing is a stored ticket file.
    #[error(
        "session share cannot delegate the stored alias ticket for label '{0}'. \
         Use a peer-store label, alias backed by `endpoint_id`, or raw endpoint id."
    )]
    AliasStoredTicket(String),
    /// The argument matched a peer-store row with no outbound authority.
    #[error(
        "peer '{0}' is inbound-only — we don't have outbound authority to mint into them. \
         Have them run `portl session share` instead."
    )]
    InboundOnlyPeer(String),
    /// The argument matched a peer that is currently held.
    #[error("peer '{0}' is currently held; resume it before sharing")]
    HeldPeer(String),
    /// The argument did not match any supported form.
    #[error(
        "unsupported share target. Supported forms:\n  \
         - peer label from `portl peer ls` (outbound-capable)\n  \
         - alias label backed by an `endpoint_id`\n  \
         - 64-char hex endpoint id (or `PPPP…SSSS` elided form)"
    )]
    Unsupported,
}

/// Resolve `target` to a [`ShareTargetForm`] without echoing the raw
/// argument. Mutates no state and performs no network I/O.
pub(crate) fn classify_share_target(
    target: &str,
    peers: &PeerStore,
    tickets: &TicketStore,
    aliases: &AliasStore,
) -> Result<ShareTargetForm, ResolveTargetError> {
    let trimmed = target.trim();

    // 1) Inline `portl…` ticket pasted as the arg. Refuse — never echo.
    if <PortlTicket as Ticket>::deserialize(trimmed).is_ok() {
        return Err(ResolveTargetError::TicketCredential);
    }

    // 2) Peer-store label.
    if let Some(entry) = peers.get_by_label(trimmed) {
        if entry.last_hold_at.is_some() {
            return Err(ResolveTargetError::HeldPeer(trimmed.to_owned()));
        }
        if !entry.they_accept_from_me {
            return Err(ResolveTargetError::InboundOnlyPeer(trimmed.to_owned()));
        }
        let eid_bytes = entry
            .endpoint_id_bytes()
            .map_err(|_| ResolveTargetError::Unsupported)?;
        let endpoint_id =
            EndpointId::from_bytes(&eid_bytes).map_err(|_| ResolveTargetError::Unsupported)?;
        return Ok(ShareTargetForm::PeerStore {
            label: trimmed.to_owned(),
            endpoint_id,
        });
    }

    // 3) Saved-ticket label. Refuse — never echo (label is fine but
    //    delegation is not supported here).
    if tickets.get(trimmed).is_some() {
        return Err(ResolveTargetError::SavedTicketLabel(trimmed.to_owned()));
    }

    // 4) Alias label.
    if let Ok(Some(alias)) = aliases.get(trimmed) {
        if let Ok(Some(spec)) = aliases.get_spec(trimmed)
            && spec.ticket_file_path.is_some()
        {
            return Err(ResolveTargetError::AliasStoredTicket(trimmed.to_owned()));
        }
        if let Ok(endpoint_id) = crate::eid::resolve(&alias.endpoint_id, None, None) {
            return Ok(ShareTargetForm::AliasEid {
                label: trimmed.to_owned(),
                endpoint_id,
            });
        }
        return Err(ResolveTargetError::Unsupported);
    }

    // 5) Raw endpoint id (full hex or middle-elided form).
    if let Ok(endpoint_id) = crate::eid::resolve(trimmed, Some(peers), Some(tickets)) {
        return Ok(ShareTargetForm::RawEid { endpoint_id });
    }

    Err(ResolveTargetError::Unsupported)
}

/// Inputs to [`build_session_share_envelope`].
pub(crate) struct EnvelopeInputs<'a> {
    pub(crate) identity: &'a Identity,
    pub(crate) target_addr: EndpointAddr,
    pub(crate) hello: &'a RecipientHelloV1,
    pub(crate) session_name: &'a str,
    pub(crate) provider: Option<&'a str>,
    pub(crate) origin_label_hint: Option<String>,
    pub(crate) target_label_hint: Option<String>,
    pub(crate) workspace_id: String,
    pub(crate) conflict_handle: String,
    pub(crate) now_unix: u64,
    pub(crate) access_ttl: Duration,
    pub(crate) allow_bearer_fallback: bool,
}

/// Outcome of envelope construction. Surfaces the recipient binding
/// chosen so the CLI can emit a clear progress line and tests can
/// assert without parsing the envelope.
#[derive(Debug)]
pub(crate) struct BuiltEnvelope {
    pub(crate) envelope: PortlExchangeEnvelopeV1,
    pub(crate) bound_to_recipient: bool,
    pub(crate) effective_access_ttl: Duration,
}

/// Build the share envelope, minting a recipient-bound or capped
/// bearer ticket as appropriate.
pub(crate) fn build_session_share_envelope(inputs: EnvelopeInputs<'_>) -> Result<BuiltEnvelope> {
    let target_eid_hex = hex::encode(inputs.target_addr.id.as_bytes());

    // Decide recipient binding from the validated hello.
    let recipient_eid: Option<[u8; 32]> = inputs
        .hello
        .endpoint_id_hex
        .as_deref()
        .map(|hexed| {
            let mut buf = [0u8; 32];
            let decoded = hex::decode(hexed).context("recipient hello endpoint id hex")?;
            if decoded.len() != 32 {
                bail!("recipient hello endpoint id has wrong length");
            }
            buf.copy_from_slice(&decoded);
            Ok::<[u8; 32], anyhow::Error>(buf)
        })
        .transpose()?;

    let (to, effective_access_ttl, bound_to_recipient) = if let Some(eid) = recipient_eid {
        (Some(eid), inputs.access_ttl, true)
    } else if inputs.allow_bearer_fallback {
        let capped = inputs.access_ttl.min(BEARER_FALLBACK_MAX_TTL);
        (None, capped, false)
    } else {
        bail!(
            "recipient did not advertise an endpoint id and --allow-bearer-fallback was not set; \
             refusing to mint an unrestricted bearer ticket"
        );
    };

    let not_after = inputs
        .now_unix
        .checked_add(effective_access_ttl.as_secs())
        .ok_or_else(|| anyhow!("access ttl overflow"))?;
    let ticket = mint_root(
        inputs.identity.signing_key(),
        inputs.target_addr.clone(),
        share_caps(),
        inputs.now_unix,
        not_after,
        to,
    )
    .context("mint share ticket")?;

    let share = SessionShareEnvelopeV1 {
        workspace_id: inputs.workspace_id,
        friendly_name: inputs.session_name.to_owned(),
        conflict_handle: inputs.conflict_handle,
        origin_label_hint: inputs.origin_label_hint,
        target_label_hint: inputs.target_label_hint,
        target_endpoint_id_hex: target_eid_hex,
        provider: inputs.provider.map(ToOwned::to_owned),
        provider_session: inputs.session_name.to_owned(),
        ticket: ticket.serialize(),
        access_not_after_unix: not_after,
    };
    let envelope = PortlExchangeEnvelopeV1::session_share(share, inputs.now_unix, Some(not_after));
    Ok(BuiltEnvelope {
        envelope,
        bound_to_recipient,
        effective_access_ttl,
    })
}

/// Capabilities baked into the share-time root ticket. Mirrors the
/// caps `portl session attach` requests on the recipient side so the
/// recipient can reuse the share for the same subset of operations.
pub(crate) fn share_caps() -> Capabilities {
    Capabilities {
        presence: 0b0000_0001,
        shell: Some(ShellCaps {
            user_allowlist: None,
            pty_allowed: true,
            exec_allowed: true,
            command_allowlist: None,
            env_policy: EnvPolicy::Merge { allow: None },
        }),
        tcp: None,
        udp: None,
        fs: None,
        vpn: None,
        meta: None,
    }
}

/// Drive the offer side of the encrypted exchange end-to-end against
/// any `MailboxTransport`. Allocates a nameplate, derives the short
/// code, prints it via `on_code`, runs PAKE, awaits the recipient
/// hello, builds the envelope using the supplied `mint_envelope`
/// closure (which sees the validated hello and can mint a
/// recipient-bound ticket), and finally sends + closes.
///
/// The closure is fallible so the caller can refuse a hello that does
/// not satisfy local policy (e.g. missing endpoint id without bearer
/// fallback).
pub(crate) async fn run_offer_against_transport<T, F>(
    transport: &mut T,
    nameplate_seed: Option<String>,
    on_code: impl FnOnce(&ShortCode),
    mint_envelope: F,
) -> Result<()>
where
    T: MailboxTransport + Send,
    F: FnOnce(&RecipientHelloV1) -> Result<PortlExchangeEnvelopeV1>,
{
    let side = fresh_side();
    let mut client = MailboxClient::new(PORTL_EXCHANGE_APPID_V1, &side, transport);
    let setup = if let Some(np) = nameplate_seed {
        client
            .claim_and_open(np)
            .await
            .map_err(RendezvousError::from)?
    } else {
        client
            .allocate_and_open()
            .await
            .map_err(RendezvousError::from)?
    };
    let code = ShortCode::generate_with_nameplate(setup.nameplate.clone())
        .map_err(|e| anyhow!("generate short code: {e}"))?;
    on_code(&code);
    let (key, hello) = offer_pake_and_recv_hello(&mut client, &code).await?;
    let envelope = match mint_envelope(&hello) {
        Ok(envelope) => envelope,
        Err(err) => {
            let _ = client.close_scary("offer refused").await;
            return Err(err);
        }
    };
    offer_send_envelope(&mut client, &key, &envelope).await?;
    Ok(())
}

pub(crate) fn unix_now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs())
}

/// Resolve `--rendezvous-url` / `PORTL_RENDEZVOUS_URL` / default.
pub(crate) fn resolve_rendezvous_url(flag: Option<&str>) -> String {
    resolve_rendezvous_url_from(flag, std::env::var("PORTL_RENDEZVOUS_URL").ok())
}

pub(crate) fn resolve_rendezvous_url_from(flag: Option<&str>, env_url: Option<String>) -> String {
    if let Some(url) = flag {
        return url.to_owned();
    }
    if let Some(url) = env_url
        && !url.is_empty()
    {
        return url;
    }
    DEFAULT_RENDEZVOUS_URL.to_owned()
}

/// Generate a fresh per-share `workspace_id` / `conflict_handle` pair.
pub(crate) fn fresh_workspace_handles() -> (String, String) {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut ws = [0u8; 16];
    rng.fill_bytes(&mut ws);
    let mut ch = [0u8; 4];
    rng.fill_bytes(&mut ch);
    (format!("ws_{}", hex::encode(ws)), hex::encode(ch))
}

/// Identity-resolution shim for tests vs. real runs.
pub(crate) fn load_identity(explicit: Option<&Path>) -> Result<Identity> {
    let path = crate::commands::peer_resolve::resolve_identity_path(explicit);
    portl_core::id::store::load(&path).context("load local identity")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use portl_core::id::Identity;
    use portl_core::peer_store::{PeerEntry, PeerOrigin};
    use portl_core::rendezvous::backend::PORTL_RECIPIENT_HELLO_SCHEMA_V1;
    use portl_core::ticket_store::TicketEntry;
    // (No additional rendezvous helpers needed in tests beyond what
    // is already imported via the module body.)

    fn fixture_identity() -> Identity {
        let bytes = [3u8; 32];
        let sk = SigningKey::from_bytes(&bytes);
        Identity::from_signing_key(sk)
    }

    fn fixture_addr() -> EndpointAddr {
        // Derive a valid ed25519 verifying key for the target endpoint.
        let target_sk = SigningKey::from_bytes(&[7u8; 32]);
        let bytes = target_sk.verifying_key().to_bytes();
        let eid = EndpointId::from_bytes(&bytes).unwrap();
        EndpointAddr::new(eid)
    }

    #[test]
    fn rejects_inline_ticket_without_echoing_target() {
        // Build a valid root ticket and pass its serialized form as
        // <TARGET>. The error message must not echo the credential.
        let id = fixture_identity();
        let ticket = mint_root(
            id.signing_key(),
            fixture_addr(),
            share_caps(),
            1_000,
            2_000,
            None,
        )
        .unwrap();
        let target = ticket.serialize();
        let peers = PeerStore::default();
        let tickets = TicketStore::default();
        let aliases = AliasStore::default();
        let err = classify_share_target(&target, &peers, &tickets, &aliases).unwrap_err();
        let msg = err.to_string();
        assert!(
            !msg.contains(&target),
            "error must not echo ticket credential: {msg}"
        );
        assert!(matches!(err, ResolveTargetError::TicketCredential));
    }

    #[test]
    fn raw_eid_classifies_as_share_form() {
        let hexed = hex::encode([9u8; 32]);
        let peers = PeerStore::default();
        let tickets = TicketStore::default();
        let aliases = AliasStore::default();
        let form = classify_share_target(&hexed, &peers, &tickets, &aliases).unwrap();
        assert!(matches!(form, ShareTargetForm::RawEid { .. }));
    }

    fn peer_entry(label: &str, they_accept_from_me: bool, held: bool) -> PeerEntry {
        let endpoint_id_hex = hex::encode(fixture_addr().id.as_bytes());
        PeerEntry {
            label: label.to_owned(),
            endpoint_id_hex,
            accepts_from_them: true,
            they_accept_from_me,
            since: 1_000,
            origin: PeerOrigin::Raw,
            last_hold_at: held.then_some(1_001),
            is_self: false,
            relay_hint: None,
            schema_version: PeerEntry::default_schema_version(),
        }
    }

    #[test]
    fn outbound_peer_label_classifies_as_share_form() {
        let mut peers = PeerStore::default();
        peers
            .insert_or_update(peer_entry("devbox", true, false))
            .unwrap();
        let tickets = TicketStore::default();
        let aliases = AliasStore::default();
        let form = classify_share_target("devbox", &peers, &tickets, &aliases).unwrap();
        assert!(matches!(form, ShareTargetForm::PeerStore { label, .. } if label == "devbox"));
    }

    #[test]
    fn inbound_only_peer_is_rejected() {
        let mut peers = PeerStore::default();
        peers
            .insert_or_update(peer_entry("inbound", false, false))
            .unwrap();
        let tickets = TicketStore::default();
        let aliases = AliasStore::default();
        let err = classify_share_target("inbound", &peers, &tickets, &aliases).unwrap_err();
        assert!(matches!(err, ResolveTargetError::InboundOnlyPeer(label) if label == "inbound"));
    }

    #[test]
    fn held_peer_is_rejected() {
        let mut peers = PeerStore::default();
        peers
            .insert_or_update(peer_entry("held", true, true))
            .unwrap();
        let tickets = TicketStore::default();
        let aliases = AliasStore::default();
        let err = classify_share_target("held", &peers, &tickets, &aliases).unwrap_err();
        assert!(matches!(err, ResolveTargetError::HeldPeer(label) if label == "held"));
    }

    #[test]
    fn saved_ticket_label_is_rejected() {
        let peers = PeerStore::default();
        let mut tickets = TicketStore::default();
        tickets
            .insert(
                "saved".to_owned(),
                TicketEntry {
                    endpoint_id_hex: hex::encode(fixture_addr().id.as_bytes()),
                    ticket_string: "portl-redacted".to_owned(),
                    expires_at: 2_000,
                    saved_at: 1_000,
                    session_share: None,
                },
            )
            .unwrap();
        let aliases = AliasStore::default();
        let err = classify_share_target("saved", &peers, &tickets, &aliases).unwrap_err();
        assert!(matches!(err, ResolveTargetError::SavedTicketLabel(label) if label == "saved"));
    }

    #[test]
    fn unsupported_target_does_not_echo_input() {
        let peers = PeerStore::default();
        let tickets = TicketStore::default();
        let aliases = AliasStore::default();
        let err = classify_share_target("totally-unknown", &peers, &tickets, &aliases).unwrap_err();
        let msg = err.to_string();
        assert!(!msg.contains("totally-unknown"), "must not echo: {msg}");
    }

    #[test]
    fn build_envelope_uses_recipient_endpoint_id_when_present() {
        let id = fixture_identity();
        let addr = fixture_addr();
        let hello = RecipientHelloV1 {
            schema: PORTL_RECIPIENT_HELLO_SCHEMA_V1.to_owned(),
            endpoint_id_hex: Some(hex::encode([0xAAu8; 32])),
            label_hint: Some("bob".into()),
        };
        let inputs = EnvelopeInputs {
            identity: &id,
            target_addr: addr,
            hello: &hello,
            session_name: "dev",
            provider: Some("zmx"),
            origin_label_hint: Some("alice-laptop".into()),
            target_label_hint: Some("max-b265".into()),
            workspace_id: "ws_abc".into(),
            conflict_handle: "1111".into(),
            now_unix: 1_000,
            access_ttl: Duration::from_secs(7_200),
            allow_bearer_fallback: false,
        };
        let built = build_session_share_envelope(inputs).unwrap();
        assert!(built.bound_to_recipient);
        assert_eq!(built.effective_access_ttl, Duration::from_secs(7_200));
        // Parse the embedded ticket and confirm the `to` field matches
        // the recipient hello.
        let portl_core::rendezvous::exchange::ExchangePayload::SessionShare(payload) =
            &built.envelope.payload;
        let ticket = <PortlTicket as Ticket>::deserialize(&payload.ticket).unwrap();
        assert_eq!(ticket.body.to, Some([0xAAu8; 32]));
    }

    #[test]
    fn build_envelope_refuses_anonymous_hello_without_fallback() {
        let id = fixture_identity();
        let hello = RecipientHelloV1::anonymous();
        let inputs = EnvelopeInputs {
            identity: &id,
            target_addr: fixture_addr(),
            hello: &hello,
            session_name: "dev",
            provider: None,
            origin_label_hint: None,
            target_label_hint: None,
            workspace_id: "ws_abc".into(),
            conflict_handle: "1111".into(),
            now_unix: 1_000,
            access_ttl: Duration::from_secs(7_200),
            allow_bearer_fallback: false,
        };
        let err = build_session_share_envelope(inputs).unwrap_err();
        assert!(err.to_string().contains("bearer"), "{err}");
    }

    #[test]
    fn build_envelope_caps_bearer_fallback_ttl() {
        let id = fixture_identity();
        let hello = RecipientHelloV1::anonymous();
        let inputs = EnvelopeInputs {
            identity: &id,
            target_addr: fixture_addr(),
            hello: &hello,
            session_name: "dev",
            provider: None,
            origin_label_hint: None,
            target_label_hint: None,
            workspace_id: "ws_abc".into(),
            conflict_handle: "1111".into(),
            now_unix: 1_000,
            access_ttl: Duration::from_secs(7_200),
            allow_bearer_fallback: true,
        };
        let built = build_session_share_envelope(inputs).unwrap();
        assert!(!built.bound_to_recipient);
        assert_eq!(built.effective_access_ttl, BEARER_FALLBACK_MAX_TTL);
        let portl_core::rendezvous::exchange::ExchangePayload::SessionShare(payload) =
            &built.envelope.payload;
        let ticket = <PortlTicket as Ticket>::deserialize(&payload.ticket).unwrap();
        assert_eq!(
            ticket.body.to, None,
            "bearer fallback must not bind a recipient"
        );
        assert_eq!(
            ticket.body.not_after - ticket.body.not_before,
            BEARER_FALLBACK_MAX_TTL.as_secs()
        );
    }

    #[test]
    fn build_envelope_bearer_fallback_respects_short_access_ttl() {
        let id = fixture_identity();
        let hello = RecipientHelloV1::anonymous();
        let inputs = EnvelopeInputs {
            identity: &id,
            target_addr: fixture_addr(),
            hello: &hello,
            session_name: "dev",
            provider: None,
            origin_label_hint: None,
            target_label_hint: None,
            workspace_id: "ws_abc".into(),
            conflict_handle: "1111".into(),
            now_unix: 1_000,
            access_ttl: Duration::from_secs(60),
            allow_bearer_fallback: true,
        };
        let built = build_session_share_envelope(inputs).unwrap();
        assert_eq!(built.effective_access_ttl, Duration::from_secs(60));
    }

    #[test]
    fn resolve_rendezvous_url_prefers_flag() {
        let url = resolve_rendezvous_url_from(
            Some("ws://flag-url/v1"),
            Some("ws://env-url/v1".to_owned()),
        );
        assert_eq!(url, "ws://flag-url/v1");
    }

    #[test]
    fn resolve_rendezvous_url_uses_env_when_flag_absent() {
        assert_eq!(
            resolve_rendezvous_url_from(None, Some("ws://env-url/v1".to_owned())),
            "ws://env-url/v1"
        );
    }

    #[test]
    fn resolve_rendezvous_url_ignores_empty_env() {
        assert_eq!(
            resolve_rendezvous_url_from(None, Some(String::new())),
            DEFAULT_RENDEZVOUS_URL
        );
    }

    #[test]
    fn resolve_rendezvous_url_uses_default_without_flag_or_env() {
        assert_eq!(
            resolve_rendezvous_url_from(None, None),
            DEFAULT_RENDEZVOUS_URL
        );
    }

    #[test]
    fn fresh_workspace_handles_have_expected_shape() {
        let (ws, ch) = fresh_workspace_handles();
        assert!(ws.starts_with("ws_"));
        assert_eq!(ws.len(), 3 + 32, "16 bytes hex-encoded");
        assert_eq!(ch.len(), 8, "4 bytes hex-encoded");
    }
}
