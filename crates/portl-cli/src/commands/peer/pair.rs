//! `portl peer pair <code>` / `portl peer accept <code>` — consume
//! an invite code and establish a mutual/one-way peer relationship.

use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use iroh::EndpointAddr;
use iroh_base::{EndpointId, SecretKey};
use portl_core::id::{Identity, store};
use portl_core::pair_code::InviteCode;
use portl_core::peer_store::{PeerEntry, PeerOrigin, PeerStore};
use portl_proto::pair_v1::{ALPN_PAIR_V1, PairMode, PairRequest, PairResponse, PairResult};
const PAIR_RESPONSE_MAX_BYTES: usize = 8 * 1024;

pub fn run(code: &str, mode: PairMode) -> Result<ExitCode> {
    let invite = InviteCode::decode(code).context("decode invite code")?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if invite.not_after_unix <= now {
        bail!(
            "invite code expired {} seconds ago",
            now - invite.not_after_unix
        );
    }

    let runtime = tokio::runtime::Runtime::new().context("spawn tokio runtime")?;
    runtime.block_on(run_async(&invite, mode))
}

async fn run_async(invite: &InviteCode, mode: PairMode) -> Result<ExitCode> {
    let identity = store::load(&store::default_path()).context("load local identity")?;
    let our_eid_hex = hex::encode(identity.verifying_key());
    let endpoint = bind_client_endpoint(&identity).await?;

    // Dial the inviter's endpoint_id directly. Relay hint from the
    // invite code (if any) gives us a fallback when direct + DNS fail.
    let inviter_eid = EndpointId::from_bytes(&invite.inviter_eid)
        .context("decode inviter endpoint_id from invite code")?;
    let mut dial_target = EndpointAddr::new(inviter_eid);
    if let Some(relay_hint) = &invite.relay_hint {
        match relay_hint.parse() {
            Ok(url) => dial_target = dial_target.with_relay_url(url),
            Err(err) => {
                eprintln!(
                    "warning: invite's relay_hint {relay_hint:?} is invalid ({err}); continuing without"
                );
            }
        }
    }

    println!("dialing inviter...");
    let connection = endpoint
        .connect(dial_target, ALPN_PAIR_V1)
        .await
        .context("dial pair endpoint")?;

    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .context("open bi-stream for pair")?;

    let request = PairRequest {
        version: 1,
        nonce: invite.nonce,
        mode,
        caller_relay_hint: None, // TODO(v0.3.4.1): read from local relay config
        caller_label: None,
    };
    let body = postcard::to_stdvec(&request).context("encode PairRequest")?;
    let len_prefix: u32 = body
        .len()
        .try_into()
        .context("PairRequest length overflow u32")?;
    let mut framed = Vec::with_capacity(4 + body.len());
    framed.extend_from_slice(&len_prefix.to_le_bytes());
    framed.extend_from_slice(&body);
    send.write_all(&framed).await.context("write PairRequest")?;
    send.finish().ok();

    // Read the 4-byte length-prefixed PairResponse.
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .context("read PairResponse length prefix")?;
    let resp_len = u32::from_le_bytes(len_buf) as usize;
    if resp_len > PAIR_RESPONSE_MAX_BYTES {
        bail!("PairResponse size {resp_len} exceeds cap {PAIR_RESPONSE_MAX_BYTES}");
    }
    let mut body = vec![0u8; resp_len];
    recv.read_exact(&mut body)
        .await
        .context("read PairResponse body")?;
    let response: PairResponse = postcard::from_bytes(&body).context("decode PairResponse")?;

    connection.close(0u32.into(), b"pair complete");
    endpoint.close().await;

    apply_response(&identity, invite, &our_eid_hex, mode, &response)
}

async fn bind_client_endpoint(identity: &Identity) -> Result<iroh::Endpoint> {
    use iroh::address_lookup::{DnsAddressLookup, PkarrResolver};
    use iroh::endpoint::presets;

    let mut builder = iroh::Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&identity.signing_key().to_bytes()))
        .alpns(vec![ALPN_PAIR_V1.to_vec()])
        .address_lookup(DnsAddressLookup::n0_dns())
        .address_lookup(PkarrResolver::n0_dns());
    // Ephemeral client bind; let the OS pick a port.
    let bind: std::net::SocketAddr = "[::]:0".parse().expect("valid bind addr literal");
    builder = builder.bind_addr(bind)?;
    builder.bind().await.map_err(Into::into)
}

fn apply_response(
    identity: &Identity,
    invite: &InviteCode,
    _our_eid_hex: &str,
    mode: PairMode,
    response: &PairResponse,
) -> Result<ExitCode> {
    let (their_accepts_from_me, they_accept_from_us) = match mode {
        PairMode::Pair => (true, true),
        PairMode::Accept => (false, true),
    };

    match &response.result {
        PairResult::Ok => {
            let inviter_eid_hex = hex::encode(invite.inviter_eid);
            let peers_path = PeerStore::default_path();
            let mut peers = PeerStore::load(&peers_path)?;
            let label = choose_local_label(
                &peers,
                response.responder_self_label.as_deref(),
                &inviter_eid_hex,
            );
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            peers
                .insert_or_update(PeerEntry {
                    label: label.clone(),
                    endpoint_id_hex: inviter_eid_hex,
                    accepts_from_them: their_accepts_from_me,
                    they_accept_from_me: they_accept_from_us,
                    since: now,
                    origin: match mode {
                        PairMode::Pair => PeerOrigin::Paired,
                        PairMode::Accept => PeerOrigin::Accepted,
                    },
                    last_hold_at: None,
                    is_self: false,
                    relay_hint: response.responder_relay_hint.clone(),
                    schema_version: 2,
                })
                .context("insert paired peer locally")?;
            peers.save(&peers_path).context("save peer store")?;
            let relay_note = response
                .responder_relay_hint
                .as_deref()
                .map(|r| format!("  (relay-hint: {r})"))
                .unwrap_or_default();
            let mode_label = match mode {
                PairMode::Pair => "mutual (paired)",
                PairMode::Accept => "outbound (accepted)",
            };
            println!(
                "handshake ok.\nadded peer '{label}' ({})  — {mode_label}{relay_note}",
                &hex::encode(invite.inviter_eid)[..12]
            );
            let _ = identity; // consumed for side-effect binding above
            Ok(ExitCode::SUCCESS)
        }
        PairResult::NonceExpired => {
            eprintln!("pair failed: the invite code has expired. Ask the issuer for a new one.");
            Ok(ExitCode::FAILURE)
        }
        PairResult::NonceUnknown => {
            eprintln!(
                "pair failed: the server doesn't recognize this invite code. It may have been\n\
                 consumed already or revoked. Ask the issuer to re-issue with `portl peer invite`."
            );
            Ok(ExitCode::FAILURE)
        }
        PairResult::AlreadyPaired { existing_label } => {
            eprintln!(
                "already paired as '{existing_label}'. No peer entry was added locally;\n\
                 run `portl peer ls` to see the existing record."
            );
            Ok(ExitCode::FAILURE)
        }
        PairResult::PolicyRejected(reason) => {
            eprintln!("pair rejected by the server: {reason}");
            Ok(ExitCode::FAILURE)
        }
    }
}

fn choose_local_label(
    peers: &PeerStore,
    responder_self_label: Option<&str>,
    inviter_eid_hex: &str,
) -> String {
    let candidate =
        responder_self_label.unwrap_or(&inviter_eid_hex[..8.min(inviter_eid_hex.len())]);
    if !peers.iter().any(|e| e.label == candidate) {
        return candidate.to_owned();
    }
    format!(
        "{candidate}-{suffix}",
        suffix = &inviter_eid_hex[..4.min(inviter_eid_hex.len())]
    )
}

#[allow(dead_code)]
fn _keep_imports_alive() {
    let _ = Duration::from_secs(1);
}
