//! C ABI boundary for embedding Portl clients in Apple applications.

#![allow(unsafe_code)]

use std::cell::RefCell;
use std::ffi::{CStr, CString, c_char, c_void};
use std::path::PathBuf;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use ed25519_dalek::SigningKey;
use iroh::endpoint::presets;
use iroh::endpoint::{Connection, SendStream};
use iroh::{EndpointAddr, EndpointId, SecretKey};
use iroh_tickets::Ticket;
use portl_core::endpoint::Endpoint;
use portl_core::id::Identity;
use portl_core::io::BufferedRecv;
use portl_core::net::{
    SessionClient, ShellClient, open_session_attach_checked, open_shell, open_ticket_v1,
};
use portl_core::pair_accept::{SaveAcceptedPeerOptions, save_accepted_peer};
use portl_core::pair_code::InviteCode;
use portl_core::peer_store::PeerStore;
use portl_core::rendezvous::backend::{
    PORTL_RECIPIENT_HELLO_SCHEMA_V1, RecipientHelloV1, accept_over_mailbox,
};
use portl_core::rendezvous::ws::WsRendezvousBackend;
use portl_core::rendezvous::{RendezvousError, ShortCode};
use portl_core::session_share::{
    ImportSessionShareOptions, import_session_share_envelope, import_session_share_envelope_json,
};
use portl_core::target_resolve::{ResolveTargetOptions, interactive_shell_caps, resolve_target};
use portl_core::ticket::schema::PortlTicket;
use portl_core::ticket_save::save_ticket;
use portl_core::ticket_store::TicketStore;
use portl_core::wire::shell::{ExitFrame, PtyCfg};
use portl_proto::pair_v1::{ALPN_PAIR_V1, PairRequest, PairResponse, PairResult};
use tokio::io::AsyncReadExt;
use tokio::runtime::Runtime;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;

const ABI_VERSION: u32 = 1;
const VERSION: &[u8] = concat!(env!("CARGO_PKG_VERSION"), "\0").as_bytes();
const STATUS_OK: i32 = 0;
const STATUS_ERR: i32 = -1;
const SHELL_EVENT_STDOUT: u32 = 1;
const SHELL_EVENT_STDERR: u32 = 2;
const SHELL_EVENT_EXIT: u32 = 3;
const SHELL_EVENT_ERROR: u32 = 4;
pub const PORTL_SHELL_EVENT_CLOSED: u32 = 5;
const OUTPUT_CHUNK_BYTES: usize = 16 * 1024;
const ENDPOINT_CLOSE_GRACE: Duration = Duration::from_millis(200);
const DEFAULT_SESSION_SHARE_TIMEOUT: Duration = Duration::from_secs(60);
const DEFAULT_PEER_INVITE_TIMEOUT: Duration = Duration::from_secs(60);
const DEFAULT_RENDEZVOUS_URL: &str = "ws://relay.magic-wormhole.io:4000/v1";
const PAIR_RESPONSE_MAX_BYTES: usize = 8 * 1024;

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

pub type PortlShellEventCallback = Option<
    unsafe extern "C" fn(
        context: *mut c_void,
        event: u32,
        data: *const u8,
        data_len: usize,
        code: i32,
        message: *const c_char,
    ),
>;

pub struct PortlClient {
    runtime: Arc<Runtime>,
    identity: Identity,
    endpoint: iroh::Endpoint,
    peer_store_path: PathBuf,
    ticket_store_path: PathBuf,
}

pub struct PortlShell {
    runtime: Arc<Runtime>,
    connection: Connection,
    _control_send: SendStream,
    _control_recv: BufferedRecv,
    stdin: Arc<AsyncMutex<SendStream>>,
    resize: Arc<AsyncMutex<Option<SendStream>>>,
    closed: Arc<AtomicBool>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

#[unsafe(no_mangle)]
pub extern "C" fn portl_ffi_abi_version() -> u32 {
    ABI_VERSION
}

#[unsafe(no_mangle)]
pub extern "C" fn portl_ffi_version() -> *const c_char {
    VERSION.as_ptr().cast()
}

#[unsafe(no_mangle)]
pub extern "C" fn portl_ffi_iroh_quic_available() -> bool {
    let _ = std::mem::size_of::<iroh::endpoint::Endpoint>();
    let _ = std::mem::size_of::<portl_core::net::PeerSession>();
    true
}

#[unsafe(no_mangle)]
pub extern "C" fn portl_last_error() -> *const c_char {
    LAST_ERROR.with(|slot| {
        slot.borrow()
            .as_ref()
            .map_or(ptr::null(), |message| message.as_ptr())
    })
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `value` must be a pointer returned by this library from `CString::into_raw`.
/// Passing any other pointer, or freeing the same pointer twice, is undefined behavior.
pub unsafe extern "C" fn portl_string_free(value: *mut c_char) {
    if value.is_null() {
        return;
    }
    drop(unsafe { CString::from_raw(value) });
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `identity_seed32_out` must point to at least 32 writable bytes.
pub unsafe extern "C" fn portl_identity_generate(identity_seed32_out: *mut u8) -> i32 {
    ffi_status(|| {
        if identity_seed32_out.is_null() {
            bail!("identity_seed32_out is null");
        }

        let identity = Identity::new();
        let seed = identity.signing_key().to_bytes();
        unsafe {
            ptr::copy_nonoverlapping(seed.as_ptr(), identity_seed32_out, seed.len());
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
/// # Safety
///
/// When non-null, `identity_seed32` must point to exactly 32 readable seed bytes.
pub unsafe extern "C" fn portl_client_new(identity_seed32: *const u8) -> *mut PortlClient {
    clear_last_error();
    match create_client(
        identity_seed32,
        PeerStore::default_path(),
        TicketStore::default_path(),
    ) {
        Ok(client) => Box::into_raw(Box::new(client)),
        Err(err) => {
            set_last_error(err);
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
/// # Safety
///
/// When non-null, `identity_seed32` must point to exactly 32 readable seed bytes.
/// `peer_store_path` and `ticket_store_path` must be valid, null-terminated UTF-8 strings.
pub unsafe extern "C" fn portl_client_new_with_stores(
    identity_seed32: *const u8,
    peer_store_path: *const c_char,
    ticket_store_path: *const c_char,
) -> *mut PortlClient {
    clear_last_error();
    let result = (|| {
        let peer_store_path = PathBuf::from(required_cstr(peer_store_path, "peer_store_path")?);
        let ticket_store_path =
            PathBuf::from(required_cstr(ticket_store_path, "ticket_store_path")?);
        create_client(identity_seed32, peer_store_path, ticket_store_path)
    })();
    match result {
        Ok(client) => Box::into_raw(Box::new(client)),
        Err(err) => {
            set_last_error(err);
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `client` must be null or a pointer returned by this library. A non-null
/// pointer must be freed at most once.
pub unsafe extern "C" fn portl_client_free(client: *mut PortlClient) {
    if client.is_null() {
        return;
    }

    let client = unsafe { Box::from_raw(client) };
    let endpoint = client.endpoint.clone();
    let runtime = Arc::clone(&client.runtime);
    let _ = runtime.block_on(async move {
        tokio::time::timeout(ENDPOINT_CLOSE_GRACE, endpoint.close()).await
    });
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `client` must be a valid pointer returned by this library.
pub unsafe extern "C" fn portl_client_endpoint_id(client: *const PortlClient) -> *mut c_char {
    clear_last_error();
    match client_ref(client).and_then(|client| {
        let endpoint_id = hex::encode(client.identity.verifying_key());
        CString::new(endpoint_id).context("encode endpoint id")
    }) {
        Ok(value) => value.into_raw(),
        Err(err) => {
            set_last_error(err);
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `client` must be a valid pointer returned by this library. `ticket` must be
/// a valid, null-terminated UTF-8 string. `label` may be null or a valid string.
pub unsafe extern "C" fn portl_client_save_ticket(
    client: *const PortlClient,
    label: *const c_char,
    ticket: *const c_char,
) -> *mut c_char {
    clear_last_error();
    let result = (|| {
        let client = client_ref(client)?;
        let label = optional_cstr(label)?;
        let ticket = required_cstr(ticket, "ticket")?;
        let saved = save_ticket(
            label.as_deref(),
            ticket.trim(),
            &client.peer_store_path,
            &client.ticket_store_path,
        )?;
        CString::new(saved.label).context("encode saved ticket label")
    })();
    match result {
        Ok(value) => value.into_raw(),
        Err(err) => {
            set_last_error(err);
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `client` must be a valid pointer returned by this library. `envelope_json`
/// must be a valid, null-terminated UTF-8 string. `label` may be null or valid.
pub unsafe extern "C" fn portl_client_import_session_share_envelope_json(
    client: *const PortlClient,
    label: *const c_char,
    envelope_json: *const c_char,
) -> *mut c_char {
    clear_last_error();
    let result = (|| {
        let client = client_ref(client)?;
        let label = optional_cstr(label)?;
        let envelope_json = required_cstr(envelope_json, "envelope_json")?;
        let recipient_endpoint_id_hex = hex::encode(client.identity.verifying_key());
        let imported = import_session_share_envelope_json(
            envelope_json.trim(),
            ImportSessionShareOptions {
                label: label.as_deref(),
                recipient_endpoint_id_hex: Some(&recipient_endpoint_id_hex),
            },
            &client.peer_store_path,
            &client.ticket_store_path,
        )?;
        CString::new(imported.label).context("encode imported session share label")
    })();
    match result {
        Ok(value) => value.into_raw(),
        Err(err) => {
            set_last_error(err);
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `client` must be a valid pointer returned by this library. `code` must be a
/// valid, null-terminated UTF-8 string. `label` and `rendezvous_url` may be
/// null or valid strings.
pub unsafe extern "C" fn portl_client_accept_session_share_code(
    client: *const PortlClient,
    code: *const c_char,
    label: *const c_char,
    rendezvous_url: *const c_char,
    timeout_millis: u64,
) -> *mut c_char {
    clear_last_error();
    let result = (|| {
        let client = client_ref(client)?;
        let code = required_cstr(code, "code")?;
        let label = optional_cstr(label)?;
        let rendezvous_url = optional_cstr(rendezvous_url)?
            .map(|url| url.trim().to_owned())
            .filter(|url| !url.is_empty())
            .unwrap_or_else(|| DEFAULT_RENDEZVOUS_URL.to_owned());
        let timeout = if timeout_millis == 0 {
            DEFAULT_SESSION_SHARE_TIMEOUT
        } else {
            Duration::from_millis(timeout_millis)
        };
        let short_code = ShortCode::parse(code.trim()).map_err(|err| {
            anyhow::anyhow!(
                "invalid `PORTL-S-` short code: {err}. Expected `PORTL-S-<nameplate>-<word>-<word>[-…]`."
            )
        })?;
        let recipient_endpoint_id_hex = hex::encode(client.identity.verifying_key());
        let hello = RecipientHelloV1 {
            schema: PORTL_RECIPIENT_HELLO_SCHEMA_V1.to_owned(),
            endpoint_id_hex: Some(recipient_endpoint_id_hex.clone()),
            label_hint: None,
        };

        let outcome = client.runtime.block_on(async {
            match tokio::time::timeout(timeout, async {
                let mut transport = WsRendezvousBackend::new(&rendezvous_url)
                    .map_err(|err| anyhow::anyhow!("rendezvous backend: {err}"))?
                    .with_timeout(timeout)
                    .connect_transport()
                    .await
                    .map_err(|err| anyhow::anyhow!("connect to rendezvous server: {err}"))?;
                accept_over_mailbox(&mut transport, short_code, hello)
                    .await
                    .map_err(short_code_accept_error)
            })
            .await
            {
                Ok(result) => result,
                Err(_) => Err(anyhow::anyhow!(
                    "accept timed out after {}ms; the sender must keep `portl session share` running",
                    timeout.as_millis()
                )),
            }
        })?;

        let imported = import_session_share_envelope(
            &outcome.envelope,
            ImportSessionShareOptions {
                label: label.as_deref(),
                recipient_endpoint_id_hex: Some(&recipient_endpoint_id_hex),
            },
            &client.peer_store_path,
            &client.ticket_store_path,
        )?;
        CString::new(imported.label).context("encode accepted session share label")
    })();
    match result {
        Ok(value) => value.into_raw(),
        Err(err) => {
            set_last_error(err);
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `client` must be a valid pointer returned by this library. `code` must be a
/// valid, null-terminated UTF-8 string. `local_label` may be null or valid.
pub unsafe extern "C" fn portl_client_accept_peer_invite(
    client: *const PortlClient,
    code: *const c_char,
    local_label: *const c_char,
    timeout_millis: u64,
) -> *mut c_char {
    clear_last_error();
    let result = (|| {
        let client = client_ref(client)?;
        let code = required_cstr(code, "code")?;
        let local_label = optional_cstr(local_label)?;
        let timeout = if timeout_millis == 0 {
            DEFAULT_PEER_INVITE_TIMEOUT
        } else {
            Duration::from_millis(timeout_millis)
        };
        let invite = InviteCode::decode(code.trim())
            .map_err(|err| anyhow::anyhow!("invalid `PORTLINV-` invite code: {err}"))?;
        let now = unix_now()?;
        if invite.not_after_unix <= now {
            bail!(
                "invite code expired {} seconds ago",
                now - invite.not_after_unix
            );
        }

        let identity = client.identity.clone();
        let peer_store_path = client.peer_store_path.clone();
        let label = client.runtime.block_on(async move {
            match tokio::time::timeout(
                timeout,
                accept_peer_invite(identity, invite, local_label, peer_store_path),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => Err(anyhow::anyhow!(
                    "accept timed out after {}ms; the inviter must keep `portl invite` available",
                    timeout.as_millis()
                )),
            }
        })?;
        CString::new(label).context("encode accepted peer label")
    })();
    match result {
        Ok(value) => value.into_raw(),
        Err(err) => {
            set_last_error(err);
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// `client` must be a valid pointer returned by this library. `ticket` must be
/// a valid, null-terminated UTF-8 string. `term` may be null or valid.
/// `shell_out` must point to writable storage for one `PortlShell *`.
pub unsafe extern "C" fn portl_shell_open_ticket(
    client: *mut PortlClient,
    ticket: *const c_char,
    term: *const c_char,
    cols: u16,
    rows: u16,
    callback: PortlShellEventCallback,
    callback_context: *mut c_void,
    shell_out: *mut *mut PortlShell,
) -> i32 {
    ffi_status(|| {
        if shell_out.is_null() {
            bail!("shell_out is null");
        }
        unsafe {
            *shell_out = ptr::null_mut();
        }

        let client = client_mut(client)?;
        let ticket = required_cstr(ticket, "ticket")?;
        let term = optional_cstr(term)?.unwrap_or_else(|| "xterm-256color".to_owned());
        let shell = open_shell_handle(
            client,
            &ticket,
            term,
            cols,
            rows,
            callback,
            callback_context,
        )?;
        unsafe {
            *shell_out = Box::into_raw(Box::new(shell));
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// `client` must be a valid pointer returned by this library. `target` must be
/// a valid, null-terminated UTF-8 string. `term` may be null or valid.
/// `shell_out` must point to writable storage for one `PortlShell *`.
pub unsafe extern "C" fn portl_shell_open_target(
    client: *mut PortlClient,
    target: *const c_char,
    term: *const c_char,
    cols: u16,
    rows: u16,
    callback: PortlShellEventCallback,
    callback_context: *mut c_void,
    shell_out: *mut *mut PortlShell,
) -> i32 {
    ffi_status(|| {
        if shell_out.is_null() {
            bail!("shell_out is null");
        }
        unsafe {
            *shell_out = ptr::null_mut();
        }

        let client = client_mut(client)?;
        let target = required_cstr(target, "target")?;
        let term = optional_cstr(term)?.unwrap_or_else(|| "xterm-256color".to_owned());
        let ticket = resolve_target_ticket_string(client, &target)?;
        let shell = open_shell_handle(
            client,
            &ticket,
            term,
            cols,
            rows,
            callback,
            callback_context,
        )?;
        unsafe {
            *shell_out = Box::into_raw(Box::new(shell));
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// `client` must be a valid pointer returned by this library. `ticket` and
/// `session_name` must be valid, null-terminated UTF-8 strings. `provider` and
/// `term` may be null or valid. `shell_out` must point to writable storage for
/// one `PortlShell *`.
pub unsafe extern "C" fn portl_session_attach_ticket(
    client: *mut PortlClient,
    ticket: *const c_char,
    provider: *const c_char,
    session_name: *const c_char,
    term: *const c_char,
    cols: u16,
    rows: u16,
    callback: PortlShellEventCallback,
    callback_context: *mut c_void,
    shell_out: *mut *mut PortlShell,
) -> i32 {
    ffi_status(|| {
        if shell_out.is_null() {
            bail!("shell_out is null");
        }
        unsafe {
            *shell_out = ptr::null_mut();
        }

        let client = client_mut(client)?;
        let ticket = required_cstr(ticket, "ticket")?;
        let provider = optional_cstr(provider)?;
        let session_name = required_cstr(session_name, "session_name")?;
        let term = optional_cstr(term)?.unwrap_or_else(|| "xterm-256color".to_owned());
        let shell = open_session_attach_handle(
            client,
            &ticket,
            provider,
            session_name,
            term,
            cols,
            rows,
            callback,
            callback_context,
        )?;
        unsafe {
            *shell_out = Box::into_raw(Box::new(shell));
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// `client` must be a valid pointer returned by this library. `target` and
/// `session_name` must be valid, null-terminated UTF-8 strings. `provider` and
/// `term` may be null or valid. `shell_out` must point to writable storage for
/// one `PortlShell *`.
pub unsafe extern "C" fn portl_session_attach_target(
    client: *mut PortlClient,
    target: *const c_char,
    provider: *const c_char,
    session_name: *const c_char,
    term: *const c_char,
    cols: u16,
    rows: u16,
    callback: PortlShellEventCallback,
    callback_context: *mut c_void,
    shell_out: *mut *mut PortlShell,
) -> i32 {
    ffi_status(|| {
        if shell_out.is_null() {
            bail!("shell_out is null");
        }
        unsafe {
            *shell_out = ptr::null_mut();
        }

        let client = client_mut(client)?;
        let target = required_cstr(target, "target")?;
        let provider = optional_cstr(provider)?;
        let session_name = required_cstr(session_name, "session_name")?;
        let term = optional_cstr(term)?.unwrap_or_else(|| "xterm-256color".to_owned());
        let ticket = resolve_target_ticket_string(client, &target)?;
        let shell = open_session_attach_handle(
            client,
            &ticket,
            provider,
            session_name,
            term,
            cols,
            rows,
            callback,
            callback_context,
        )?;
        unsafe {
            *shell_out = Box::into_raw(Box::new(shell));
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `shell` must be a valid pointer returned by this library. `data` must point
/// to `data_len` readable bytes unless `data_len` is zero.
pub unsafe extern "C" fn portl_shell_write(
    shell: *mut PortlShell,
    data: *const u8,
    data_len: usize,
) -> i32 {
    ffi_status(|| {
        if data.is_null() && data_len > 0 {
            bail!("data is null");
        }
        let shell = shell_mut(shell)?;
        let bytes = if data_len == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(data, data_len) }.to_vec()
        };
        let stdin = Arc::clone(&shell.stdin);
        shell.runtime.block_on(async move {
            stdin
                .lock()
                .await
                .write_all(&bytes)
                .await
                .context("write shell stdin")
        })
    })
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `shell` must be a valid pointer returned by this library.
pub unsafe extern "C" fn portl_shell_resize(shell: *mut PortlShell, cols: u16, rows: u16) -> i32 {
    ffi_status(|| {
        let shell = shell_mut(shell)?;
        let resize = Arc::clone(&shell.resize);
        shell.runtime.block_on(async move {
            let mut resize = resize.lock().await;
            let Some(resize) = resize.as_mut() else {
                bail!("resize stream is unavailable");
            };
            let frame = portl_core::wire::shell::ResizeFrame { cols, rows };
            resize
                .write_all(&postcard::to_stdvec(&frame).context("encode resize frame")?)
                .await
                .context("write resize frame")
        })
    })
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `shell` must be null or a valid pointer returned by this library.
pub unsafe extern "C" fn portl_shell_is_closed(shell: *const PortlShell) -> bool {
    if shell.is_null() {
        return true;
    }

    let shell = unsafe { &*shell };
    shell.closed.load(Ordering::SeqCst) || shell.connection.close_reason().is_some()
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `shell` must be null or a pointer returned by this library. A non-null
/// pointer must be closed at most once.
pub unsafe extern "C" fn portl_shell_close(shell: *mut PortlShell) {
    if shell.is_null() {
        return;
    }

    let shell = unsafe { Box::from_raw(shell) };
    if let Ok(mut tasks) = shell.tasks.lock() {
        for task in tasks.drain(..) {
            task.abort();
        }
    }
    shell.closed.store(true, Ordering::SeqCst);
    shell.connection.close(0u32.into(), b"shell closed");
}

fn create_client(
    identity_seed32: *const u8,
    peer_store_path: PathBuf,
    ticket_store_path: PathBuf,
) -> Result<PortlClient> {
    let identity = if identity_seed32.is_null() {
        Identity::new()
    } else {
        let mut seed = [0; 32];
        unsafe {
            ptr::copy_nonoverlapping(identity_seed32, seed.as_mut_ptr(), seed.len());
        }
        Identity::from_signing_key(SigningKey::from_bytes(&seed))
    };
    let runtime = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("portl-ffi")
            .build()
            .context("build Portl runtime")?,
    );
    let endpoint = runtime
        .block_on(async { Endpoint::bind().await })
        .context("bind Portl endpoint")?
        .inner()
        .clone();

    Ok(PortlClient {
        runtime,
        identity,
        endpoint,
        peer_store_path,
        ticket_store_path,
    })
}

fn resolve_target_ticket_string(client: &PortlClient, target: &str) -> Result<String> {
    let resolved = resolve_target(
        target,
        ResolveTargetOptions {
            identity: &client.identity,
            caps: interactive_shell_caps(),
            peer_store_path: &client.peer_store_path,
            ticket_store_path: &client.ticket_store_path,
            now_unix: unix_now()?,
            ephemeral_ttl_secs: 300,
        },
    )?;
    Ok(resolved.ticket_string)
}

fn short_code_accept_error(err: RendezvousError) -> anyhow::Error {
    match err {
        RendezvousError::AlreadyClaimed => anyhow::anyhow!("short code was already claimed"),
        RendezvousError::Expired => anyhow::anyhow!("short code expired"),
        RendezvousError::NotFound => anyhow::anyhow!("short code was not found"),
        RendezvousError::Backend(msg) => anyhow::anyhow!("rendezvous backend failed: {msg}"),
        RendezvousError::Mailbox(err) => anyhow::anyhow!("mailbox transport error: {err}"),
        RendezvousError::Crypto(_) => {
            anyhow::anyhow!("short-code exchange failed; check the code and try again")
        }
        RendezvousError::InvalidPayload(msg) => anyhow::anyhow!("invalid exchange payload: {msg}"),
    }
}

async fn accept_peer_invite(
    identity: Identity,
    invite: InviteCode,
    local_label: Option<String>,
    peer_store_path: PathBuf,
) -> Result<String> {
    let endpoint = iroh::Endpoint::builder(presets::N0)
        .secret_key(SecretKey::from_bytes(&identity.signing_key().to_bytes()))
        .bind()
        .await
        .context("bind Portl pairing endpoint")?;

    let result =
        accept_peer_invite_with_endpoint(&endpoint, &invite, local_label, &peer_store_path).await;
    endpoint.close().await;
    result
}

async fn accept_peer_invite_with_endpoint(
    endpoint: &iroh::Endpoint,
    invite: &InviteCode,
    local_label: Option<String>,
    peer_store_path: &std::path::Path,
) -> Result<String> {
    let inviter_eid = EndpointId::from_bytes(&invite.inviter_eid)
        .context("decode inviter endpoint_id from invite code")?;
    let mut dial_target = EndpointAddr::new(inviter_eid);
    if let Some(relay_hint) = &invite.relay_hint
        && let Ok(url) = relay_hint.parse()
    {
        dial_target = dial_target.with_relay_url(url);
    }

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
        caller_relay_hint: None,
        caller_label: local_label,
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
    let _ = send.finish();

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

    match response.result {
        PairResult::Ok => {
            let accepted = save_accepted_peer(
                invite,
                SaveAcceptedPeerOptions {
                    responder_self_label: response.responder_self_label.as_deref(),
                    responder_relay_hint: response.responder_relay_hint,
                    now_unix: unix_now()?,
                },
                peer_store_path,
            )?;
            Ok(accepted.label)
        }
        PairResult::NonceExpired => {
            bail!("pair failed: the invite code has expired. Ask the issuer for a new one.")
        }
        PairResult::NonceUnknown => bail!(
            "pair failed: the server does not recognize this invite code. It may have been consumed already or revoked."
        ),
        PairResult::AlreadyPaired { existing_label } => {
            bail!("already paired as '{existing_label}'")
        }
        PairResult::PolicyRejected(reason) => bail!("pair rejected by the server: {reason}"),
    }
}

fn open_shell_handle(
    client: &mut PortlClient,
    ticket: &str,
    term: String,
    cols: u16,
    rows: u16,
    callback: PortlShellEventCallback,
    callback_context: *mut c_void,
) -> Result<PortlShell> {
    let runtime = Arc::clone(&client.runtime);
    let shell_runtime = Arc::clone(&runtime);
    let endpoint = client.endpoint.clone();
    let identity = client.identity.clone();
    let ticket = <PortlTicket as Ticket>::decode_string(ticket).context("decode Portl ticket")?;
    let callback_context = callback_context as usize;

    runtime.block_on(async move {
        let endpoint_wrapper = Endpoint::from(endpoint);
        let (connection, session) = open_ticket_v1(&endpoint_wrapper, &ticket, &[], &identity)
            .await
            .context("open Portl ticket")?;
        let shell = open_shell(
            &connection,
            &session,
            None,
            None,
            PtyCfg { term, cols, rows },
        )
        .await
        .context("open Portl shell")?;
        Ok(build_shell_handle(
            shell_runtime,
            connection,
            shell,
            callback,
            callback_context,
        ))
    })
}

#[allow(clippy::too_many_arguments)]
fn open_session_attach_handle(
    client: &mut PortlClient,
    ticket: &str,
    provider: Option<String>,
    session_name: String,
    term: String,
    cols: u16,
    rows: u16,
    callback: PortlShellEventCallback,
    callback_context: *mut c_void,
) -> Result<PortlShell> {
    let runtime = Arc::clone(&client.runtime);
    let shell_runtime = Arc::clone(&runtime);
    let endpoint = client.endpoint.clone();
    let identity = client.identity.clone();
    let ticket = <PortlTicket as Ticket>::decode_string(ticket).context("decode Portl ticket")?;
    let callback_context = callback_context as usize;

    runtime.block_on(async move {
        let endpoint_wrapper = Endpoint::from(endpoint);
        let (connection, session) = open_ticket_v1(&endpoint_wrapper, &ticket, &[], &identity)
            .await
            .context("open Portl ticket")?;
        let attach = open_session_attach_checked(
            &connection,
            &session,
            provider,
            session_name,
            None,
            None,
            None,
            PtyCfg { term, cols, rows },
        )
        .await
        .context("open Portl session attach")?;
        Ok(build_session_attach_handle(
            shell_runtime,
            connection,
            attach,
            callback,
            callback_context,
        ))
    })
}

fn build_shell_handle(
    runtime: Arc<Runtime>,
    connection: Connection,
    shell: ShellClient,
    callback: PortlShellEventCallback,
    callback_context: usize,
) -> PortlShell {
    let ShellClient {
        control_send,
        control_recv,
        stdin,
        stdout,
        stderr,
        exit,
        signal: _,
        resize,
    } = shell;

    let closed = Arc::new(AtomicBool::new(false));
    let tasks = vec![
        spawn_connection_closed_task(
            &runtime,
            connection.clone(),
            Arc::clone(&closed),
            callback,
            callback_context,
        ),
        spawn_output_task(
            &runtime,
            stdout,
            callback,
            callback_context,
            SHELL_EVENT_STDOUT,
        ),
        spawn_output_task(
            &runtime,
            stderr,
            callback,
            callback_context,
            SHELL_EVENT_STDERR,
        ),
        spawn_exit_task(&runtime, exit, callback, callback_context),
    ];

    PortlShell {
        runtime,
        connection,
        _control_send: control_send,
        _control_recv: control_recv,
        stdin: Arc::new(AsyncMutex::new(stdin)),
        resize: Arc::new(AsyncMutex::new(resize)),
        closed,
        tasks: Mutex::new(tasks),
    }
}

fn build_session_attach_handle(
    runtime: Arc<Runtime>,
    connection: Connection,
    session: SessionClient,
    callback: PortlShellEventCallback,
    callback_context: usize,
) -> PortlShell {
    let SessionClient {
        provider: _,
        control_send,
        control_recv,
        stdin,
        stdout,
        stderr,
        exit,
        signal: _,
        resize,
        control: _,
    } = session;

    let closed = Arc::new(AtomicBool::new(false));
    let tasks = vec![
        spawn_connection_closed_task(
            &runtime,
            connection.clone(),
            Arc::clone(&closed),
            callback,
            callback_context,
        ),
        spawn_output_task(
            &runtime,
            stdout,
            callback,
            callback_context,
            SHELL_EVENT_STDOUT,
        ),
        spawn_output_task(
            &runtime,
            stderr,
            callback,
            callback_context,
            SHELL_EVENT_STDERR,
        ),
        spawn_exit_task(&runtime, exit, callback, callback_context),
    ];

    PortlShell {
        runtime,
        connection,
        _control_send: control_send,
        _control_recv: control_recv,
        stdin: Arc::new(AsyncMutex::new(stdin)),
        resize: Arc::new(AsyncMutex::new(Some(resize))),
        closed,
        tasks: Mutex::new(tasks),
    }
}

fn spawn_connection_closed_task(
    runtime: &Runtime,
    connection: Connection,
    closed: Arc<AtomicBool>,
    callback: PortlShellEventCallback,
    callback_context: usize,
) -> JoinHandle<()> {
    runtime.spawn(async move {
        let reason = connection.closed().await;
        closed.store(true, Ordering::SeqCst);
        emit_shell_event(
            callback,
            callback_context,
            PORTL_SHELL_EVENT_CLOSED,
            &[],
            STATUS_OK,
            Some(&reason.to_string()),
        );
    })
}

fn spawn_output_task(
    runtime: &Runtime,
    mut recv: BufferedRecv,
    callback: PortlShellEventCallback,
    callback_context: usize,
    event: u32,
) -> JoinHandle<()> {
    runtime.spawn(async move {
        let mut buffer = vec![0; OUTPUT_CHUNK_BYTES];
        loop {
            match recv.read(&mut buffer).await {
                Ok(0) => break,
                Ok(n) => emit_shell_event(callback, callback_context, event, &buffer[..n], 0, None),
                Err(err) => {
                    emit_shell_event(
                        callback,
                        callback_context,
                        SHELL_EVENT_ERROR,
                        &[],
                        STATUS_ERR,
                        Some(&format!("read shell stream: {err}")),
                    );
                    break;
                }
            }
        }
    })
}

fn spawn_exit_task(
    runtime: &Runtime,
    mut exit: BufferedRecv,
    callback: PortlShellEventCallback,
    callback_context: usize,
) -> JoinHandle<()> {
    runtime.spawn(async move {
        match exit.read_frame::<ExitFrame>(1024).await {
            Ok(Some(frame)) => {
                emit_shell_event(
                    callback,
                    callback_context,
                    SHELL_EVENT_EXIT,
                    &[],
                    frame.code,
                    None,
                );
            }
            Ok(None) => {
                emit_shell_event(
                    callback,
                    callback_context,
                    SHELL_EVENT_ERROR,
                    &[],
                    STATUS_ERR,
                    Some("shell exit stream closed before exit frame"),
                );
            }
            Err(err) => {
                emit_shell_event(
                    callback,
                    callback_context,
                    SHELL_EVENT_ERROR,
                    &[],
                    STATUS_ERR,
                    Some(&format!("read shell exit frame: {err}")),
                );
            }
        }
    })
}

fn emit_shell_event(
    callback: PortlShellEventCallback,
    callback_context: usize,
    event: u32,
    data: &[u8],
    code: i32,
    message: Option<&str>,
) {
    let Some(callback) = callback else { return };
    let message = message.and_then(|message| CString::new(sanitize_c_string(message)).ok());
    let message_ptr = message
        .as_ref()
        .map_or(ptr::null(), |message| message.as_ptr());
    let data_ptr = if data.is_empty() {
        ptr::null()
    } else {
        data.as_ptr()
    };
    unsafe {
        callback(
            callback_context as *mut c_void,
            event,
            data_ptr,
            data.len(),
            code,
            message_ptr,
        );
    }
}

fn required_cstr(value: *const c_char, name: &str) -> Result<String> {
    if value.is_null() {
        bail!("{name} is null");
    }
    unsafe { CStr::from_ptr(value) }
        .to_str()
        .with_context(|| format!("{name} is not valid UTF-8"))
        .map(ToOwned::to_owned)
}

fn optional_cstr(value: *const c_char) -> Result<Option<String>> {
    if value.is_null() {
        return Ok(None);
    }
    let value = unsafe { CStr::from_ptr(value) }
        .to_str()
        .context("string is not valid UTF-8")?
        .trim()
        .to_owned();
    Ok((!value.is_empty()).then_some(value))
}

fn client_ref(client: *const PortlClient) -> Result<&'static PortlClient> {
    if client.is_null() {
        bail!("client is null");
    }
    Ok(unsafe { &*client })
}

fn client_mut(client: *mut PortlClient) -> Result<&'static mut PortlClient> {
    if client.is_null() {
        bail!("client is null");
    }
    Ok(unsafe { &mut *client })
}

fn shell_mut(shell: *mut PortlShell) -> Result<&'static mut PortlShell> {
    if shell.is_null() {
        bail!("shell is null");
    }
    Ok(unsafe { &mut *shell })
}

fn unix_now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs())
}

fn ffi_status(operation: impl FnOnce() -> Result<()>) -> i32 {
    clear_last_error();
    match operation() {
        Ok(()) => STATUS_OK,
        Err(err) => {
            set_last_error(err);
            STATUS_ERR
        }
    }
}

fn set_last_error(error: impl Into<anyhow::Error>) {
    let error = error.into();
    let message = sanitize_c_string(&format!("{error:#}"));
    let message = CString::new(message).expect("sanitized error has no nul bytes");
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = Some(message);
    });
}

fn clear_last_error() {
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = None;
    });
}

fn sanitize_c_string(value: &str) -> String {
    value.replace('\0', "\\0")
}
