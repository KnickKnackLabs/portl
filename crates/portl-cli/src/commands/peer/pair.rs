//! `portl accept <code>` — consume an invite code and establish
//! the inviter-chosen peer relationship.

use std::io::{self, IsTerminal, Write as _};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use iroh::EndpointAddr;
use iroh_base::EndpointId;
use portl_core::id::{Identity, store};
use portl_core::pair_code::InviteCode;
use portl_core::peer_store::{PeerEntry, PeerOrigin, PeerStore};
use portl_proto::pair_v1::{ALPN_PAIR_V1, PairRequest, PairResponse, PairResult};
const PAIR_RESPONSE_MAX_BYTES: usize = 8 * 1024;

pub fn run(code: &str, yes: bool) -> Result<ExitCode> {
    if code.trim().starts_with("PORTLTKT-") {
        bail!(
            "this looks like a ticket string, not an invite code.\n       To save it for later use:\n         portl ticket save {code}"
        );
    }
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

    if !yes && io::stdin().is_terminal() {
        let inviter_label = crate::eid::format_short_bytes(&invite.inviter_eid);
        println!(
            "{inviter_label} is inviting you to pair with {} access.\n",
            access_label(invite.initiator)
        );
        println!("  If you accept:");
        for line in acceptor_relationship_lines(&inviter_label, invite.initiator) {
            println!("    {line}");
        }
        if !confirm_default_yes("\nAccept? [Y/n] ")? {
            return Ok(ExitCode::FAILURE);
        }
    }

    let runtime = tokio::runtime::Runtime::new().context("spawn tokio runtime")?;
    runtime.block_on(run_async(&invite))
}

async fn run_async(invite: &InviteCode) -> Result<ExitCode> {
    let identity = store::load(&store::default_path()).context("load local identity")?;
    let our_eid_hex = hex::encode(identity.verifying_key());
    let client_cfg = crate::client_endpoint::load_client_config()?;
    let caller_relay_hint = crate::client_endpoint::preferred_relay_hint(&client_cfg);
    let endpoint =
        crate::client_endpoint::bind_client_endpoint_with_config(&identity, &client_cfg).await?;
    let result = run_async_with_endpoint(
        invite,
        &identity,
        &our_eid_hex,
        caller_relay_hint,
        &endpoint,
    )
    .await;
    crate::commands::peer_resolve::close_client_endpoint(endpoint, "pair command").await;
    result
}

async fn run_async_with_endpoint(
    invite: &InviteCode,
    identity: &Identity,
    our_eid_hex: &str,
    caller_relay_hint: Option<String>,
    endpoint: &iroh::Endpoint,
) -> Result<ExitCode> {
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

    tracing::info!(
        inviter = %crate::eid::format_short_bytes(&invite.inviter_eid),
        invite_relay_hint = invite.relay_hint.as_deref().unwrap_or(""),
        caller_relay_hint = caller_relay_hint.as_deref().unwrap_or(""),
        "dialing pair inviter"
    );
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
        initiator: invite.initiator,
        caller_relay_hint,
        caller_label: Some(crate::commands::local_machine_label(&our_eid_hex)),
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
    tracing::debug!(request_bytes = body.len(), initiator = ?invite.initiator, "sent pair request");

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
    tracing::debug!(result = ?response.result, "received pair response");

    connection.close(0u32.into(), b"pair complete");

    apply_response(identity, invite, our_eid_hex, &response)
}

fn apply_response(
    identity: &Identity,
    invite: &InviteCode,
    _our_eid_hex: &str,
    response: &PairResponse,
) -> Result<ExitCode> {
    let (their_accepts_from_me, they_accept_from_us) =
        invite.initiator.relationship().acceptor_peer_flags();

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
                    origin: PeerOrigin::Paired,
                    last_hold_at: None,
                    is_self: false,
                    relay_hint: response.responder_relay_hint.clone(),
                    schema_version: 2,
                })
                .context("insert paired peer locally")?;
            peers.save(&peers_path).context("save peer store")?;
            tracing::info!(
                label = %label,
                initiator = ?invite.initiator,
                peer_store = %peers_path.display(),
                "saved paired peer locally"
            );
            let relay_note = response
                .responder_relay_hint
                .as_deref()
                .map(|r| format!("  (relay-hint: {r})"))
                .unwrap_or_default();
            let relationship = acceptor_relationship_sentence(
                response.responder_self_label.as_deref().unwrap_or(&label),
                invite.initiator,
            );
            println!("paired with {label}. {relationship}{relay_note}");
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
                 consumed already or revoked. Ask the issuer to re-issue with `portl invite`."
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

fn confirm_default_yes(prompt: &str) -> Result<bool> {
    print!("{prompt}");
    io::stdout().flush().context("flush confirmation prompt")?;
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .context("read confirmation")?;
    let answer = answer.trim().to_ascii_lowercase();
    Ok(answer.is_empty() || matches!(answer.as_str(), "y" | "yes"))
}

fn access_label(initiator: portl_core::pair_code::InitiatorMode) -> &'static str {
    match initiator {
        portl_core::pair_code::InitiatorMode::Mutual => "mutual",
        portl_core::pair_code::InitiatorMode::Me | portl_core::pair_code::InitiatorMode::Them => {
            "one-way"
        }
    }
}

fn acceptor_relationship_lines(
    inviter_label: &str,
    initiator: portl_core::pair_code::InitiatorMode,
) -> Vec<String> {
    match initiator {
        portl_core::pair_code::InitiatorMode::Mutual => {
            vec![format!("{inviter_label} and you can reach each other")]
        }
        portl_core::pair_code::InitiatorMode::Me => vec![
            format!("{inviter_label} can reach you"),
            format!("you cannot reach {inviter_label}"),
        ],
        portl_core::pair_code::InitiatorMode::Them => vec![
            format!("you can reach {inviter_label}"),
            format!("{inviter_label} cannot reach you"),
        ],
    }
}

fn acceptor_relationship_sentence(
    inviter_label: &str,
    initiator: portl_core::pair_code::InitiatorMode,
) -> String {
    match initiator {
        portl_core::pair_code::InitiatorMode::Mutual => {
            format!("{inviter_label} and you can reach each other.")
        }
        portl_core::pair_code::InitiatorMode::Me => {
            format!("{inviter_label} can reach you; you cannot reach {inviter_label}.")
        }
        portl_core::pair_code::InitiatorMode::Them => {
            format!("you can reach {inviter_label}; {inviter_label} cannot reach you.")
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
