use std::ffi::CStr;
use std::ffi::CString;
use std::path::PathBuf;
use std::ptr;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use iroh::EndpointAddr;
use iroh_tickets::Ticket;
use portl_core::id::Identity;
use portl_core::target_resolve::interactive_shell_caps;
use portl_core::ticket::mint::mint_root;
use portl_core::ticket::schema::{Capabilities, EnvPolicy, ShellCaps};
use portl_core::ticket_store::TicketStore;

#[test]
fn version_returns_workspace_package_version() {
    let raw = portl_ffi::portl_ffi_version();

    assert!(!raw.is_null());
    let version = unsafe { CStr::from_ptr(raw) };
    assert_eq!(version.to_str().unwrap(), env!("CARGO_PKG_VERSION"));
}

#[test]
fn abi_version_is_stable_for_initial_vvterm_integration() {
    assert_eq!(portl_ffi::portl_ffi_abi_version(), 1);
}

#[test]
fn quic_link_probe_reports_available() {
    assert!(portl_ffi::portl_ffi_iroh_quic_available());
}

#[test]
fn shell_closed_event_constant_is_part_of_abi() {
    assert_eq!(portl_ffi::PORTL_SHELL_EVENT_CLOSED, 5);
}

#[test]
fn null_shell_reports_closed() {
    assert!(unsafe { portl_ffi::portl_shell_is_closed(ptr::null_mut()) });
}

#[test]
fn generated_identity_can_create_client_and_endpoint_id() {
    let mut seed = [0; 32];
    let status = unsafe { portl_ffi::portl_identity_generate(seed.as_mut_ptr()) };

    assert_eq!(status, 0);
    assert_ne!(seed, [0; 32]);

    let client = unsafe { portl_ffi::portl_client_new(seed.as_ptr()) };
    assert!(!client.is_null());

    let endpoint_id = unsafe { portl_ffi::portl_client_endpoint_id(client) };
    assert!(!endpoint_id.is_null());
    let endpoint_id = unsafe { CStr::from_ptr(endpoint_id) };
    assert_eq!(endpoint_id.to_str().unwrap().len(), 64);

    unsafe {
        portl_ffi::portl_string_free(endpoint_id.as_ptr().cast_mut());
        portl_ffi::portl_client_free(client);
    }
}

#[test]
fn shell_open_bad_ticket_sets_last_error() {
    let client = unsafe { portl_ffi::portl_client_new(ptr::null()) };
    assert!(!client.is_null());

    let ticket = CString::new("not-a-portl-ticket").unwrap();
    let term = CString::new("xterm-256color").unwrap();
    let mut shell: *mut portl_ffi::PortlShell = ptr::null_mut();

    let status = unsafe {
        portl_ffi::portl_shell_open_ticket(
            client,
            ticket.as_ptr(),
            term.as_ptr(),
            80,
            24,
            None,
            ptr::null_mut(),
            &mut shell,
        )
    };

    assert_ne!(status, 0);
    assert!(shell.is_null());

    let error = portl_ffi::portl_last_error();
    assert!(!error.is_null());
    let error = unsafe { CStr::from_ptr(error) }.to_str().unwrap();
    assert!(
        error.contains("decode") || error.contains("ticket"),
        "{error}"
    );

    unsafe {
        portl_ffi::portl_client_free(client);
    }
}

#[test]
fn session_attach_requires_session_name() {
    let client = unsafe { portl_ffi::portl_client_new(ptr::null()) };
    assert!(!client.is_null());

    let ticket = CString::new("not-a-portl-ticket").unwrap();
    let term = CString::new("xterm-256color").unwrap();
    let mut shell: *mut portl_ffi::PortlShell = ptr::null_mut();

    let status = unsafe {
        portl_ffi::portl_session_attach_ticket(
            client,
            ticket.as_ptr(),
            ptr::null(),
            ptr::null(),
            term.as_ptr(),
            80,
            24,
            None,
            ptr::null_mut(),
            &mut shell,
        )
    };

    assert_ne!(status, 0);
    assert!(shell.is_null());

    let error = portl_ffi::portl_last_error();
    assert!(!error.is_null());
    let error = unsafe { CStr::from_ptr(error) }.to_str().unwrap();
    assert!(error.contains("session_name"), "{error}");

    unsafe {
        portl_ffi::portl_client_free(client);
    }
}

#[test]
fn client_new_with_stores_accepts_explicit_paths() {
    let (peer_path, ticket_path) = unique_store_paths("explicit-paths");
    let peer_path = CString::new(peer_path).unwrap();
    let ticket_path = CString::new(ticket_path).unwrap();

    let client = unsafe {
        portl_ffi::portl_client_new_with_stores(
            ptr::null(),
            peer_path.as_ptr(),
            ticket_path.as_ptr(),
        )
    };

    assert!(!client.is_null());

    unsafe {
        portl_ffi::portl_client_free(client);
    }
}

#[test]
fn shell_open_target_requires_target() {
    let (peer_path, ticket_path) = unique_store_paths("shell-target");
    let peer_path = CString::new(peer_path).unwrap();
    let ticket_path = CString::new(ticket_path).unwrap();
    let client = unsafe {
        portl_ffi::portl_client_new_with_stores(
            ptr::null(),
            peer_path.as_ptr(),
            ticket_path.as_ptr(),
        )
    };
    assert!(!client.is_null());

    let target = CString::new("").unwrap();
    let term = CString::new("xterm-256color").unwrap();
    let mut shell: *mut portl_ffi::PortlShell = ptr::null_mut();

    let status = unsafe {
        portl_ffi::portl_shell_open_target(
            client,
            target.as_ptr(),
            term.as_ptr(),
            80,
            24,
            None,
            ptr::null_mut(),
            &mut shell,
        )
    };

    assert_ne!(status, 0);
    assert!(shell.is_null());

    let error = portl_ffi::portl_last_error();
    assert!(!error.is_null());
    let error = unsafe { CStr::from_ptr(error) }.to_str().unwrap();
    assert!(error.contains("target"), "{error}");

    unsafe {
        portl_ffi::portl_client_free(client);
    }
}

#[test]
fn session_attach_target_requires_session_name() {
    let (peer_path, ticket_path) = unique_store_paths("session-target");
    let peer_path = CString::new(peer_path).unwrap();
    let ticket_path = CString::new(ticket_path).unwrap();
    let client = unsafe {
        portl_ffi::portl_client_new_with_stores(
            ptr::null(),
            peer_path.as_ptr(),
            ticket_path.as_ptr(),
        )
    };
    assert!(!client.is_null());

    let target = CString::new("devbox").unwrap();
    let term = CString::new("xterm-256color").unwrap();
    let mut shell: *mut portl_ffi::PortlShell = ptr::null_mut();

    let status = unsafe {
        portl_ffi::portl_session_attach_target(
            client,
            target.as_ptr(),
            ptr::null(),
            ptr::null(),
            term.as_ptr(),
            80,
            24,
            None,
            ptr::null_mut(),
            &mut shell,
        )
    };

    assert_ne!(status, 0);
    assert!(shell.is_null());

    let error = portl_ffi::portl_last_error();
    assert!(!error.is_null());
    let error = unsafe { CStr::from_ptr(error) }.to_str().unwrap();
    assert!(error.contains("session_name"), "{error}");

    unsafe {
        portl_ffi::portl_client_free(client);
    }
}

#[test]
fn client_save_ticket_persists_entry_and_returns_label() {
    let (peer_path, ticket_path) = unique_store_paths("save-ticket");
    let client = client_with_store_paths(&peer_path, &ticket_path);
    let (ticket_string, endpoint_id_hex) = fixture_ticket_string(3_600);
    let label = CString::new("devbox").unwrap();
    let ticket = CString::new(ticket_string.clone()).unwrap();

    let saved_label =
        unsafe { portl_ffi::portl_client_save_ticket(client, label.as_ptr(), ticket.as_ptr()) };

    assert!(!saved_label.is_null());
    let saved_label = unsafe { CStr::from_ptr(saved_label) };
    assert_eq!(saved_label.to_str().unwrap(), "devbox");

    let tickets = TicketStore::load(&PathBuf::from(&ticket_path)).unwrap();
    let entry = tickets.get("devbox").expect("saved ticket");
    assert_eq!(entry.endpoint_id_hex, endpoint_id_hex);
    assert_eq!(entry.ticket_string, ticket_string);
    assert!(entry.session_share.is_none());

    unsafe {
        portl_ffi::portl_string_free(saved_label.as_ptr().cast_mut());
        portl_ffi::portl_client_free(client);
    }
}

#[test]
fn client_save_ticket_rejects_expired_ticket() {
    let (peer_path, ticket_path) = unique_store_paths("save-expired-ticket");
    let client = client_with_store_paths(&peer_path, &ticket_path);
    let (ticket_string, _) = fixture_ticket_string(-1);
    let label = CString::new("expired").unwrap();
    let ticket = CString::new(ticket_string).unwrap();

    let saved_label =
        unsafe { portl_ffi::portl_client_save_ticket(client, label.as_ptr(), ticket.as_ptr()) };

    assert!(saved_label.is_null());
    let error = portl_ffi::portl_last_error();
    assert!(!error.is_null());
    let error = unsafe { CStr::from_ptr(error) }.to_str().unwrap();
    assert!(error.contains("ticket expired"), "{error}");

    unsafe {
        portl_ffi::portl_client_free(client);
    }
}

#[test]
fn client_import_session_share_envelope_json_persists_metadata() {
    let (peer_path, ticket_path) = unique_store_paths("import-session-share");
    let client = client_with_seed_store_paths([9u8; 32], &peer_path, &ticket_path);
    let envelope_json = fixture_session_share_envelope_json("dev", "alice");
    let envelope_json = CString::new(envelope_json).unwrap();

    let saved_label = unsafe {
        portl_ffi::portl_client_import_session_share_envelope_json(
            client,
            ptr::null(),
            envelope_json.as_ptr(),
        )
    };

    assert!(!saved_label.is_null());
    let saved_label = unsafe { CStr::from_ptr(saved_label) };
    assert_eq!(saved_label.to_str().unwrap(), "max-b265/dev");

    let tickets = TicketStore::load(&PathBuf::from(&ticket_path)).unwrap();
    let entry = tickets.get("max-b265/dev").expect("saved session share");
    let metadata = entry
        .session_share
        .as_ref()
        .expect("session share metadata");
    assert_eq!(metadata.friendly_name, "dev");
    assert_eq!(metadata.provider.as_deref(), Some("tmux"));
    assert_eq!(metadata.provider_session, "dev");
    assert_eq!(metadata.origin_label_hint.as_deref(), Some("alice"));
    assert_eq!(metadata.target_label_hint.as_deref(), Some("max-b265"));

    unsafe {
        portl_ffi::portl_string_free(saved_label.as_ptr().cast_mut());
        portl_ffi::portl_client_free(client);
    }
}

#[test]
fn client_accept_session_share_code_rejects_malformed_code() {
    let (peer_path, ticket_path) = unique_store_paths("accept-bad-session-share");
    let client = client_with_store_paths(&peer_path, &ticket_path);
    let code = CString::new("PORTL-S-not-a-valid-code").unwrap();

    let saved_label = unsafe {
        portl_ffi::portl_client_accept_session_share_code(
            client,
            code.as_ptr(),
            ptr::null(),
            ptr::null(),
            100,
        )
    };

    assert!(saved_label.is_null());
    let error = portl_ffi::portl_last_error();
    assert!(!error.is_null());
    let error = unsafe { CStr::from_ptr(error) }.to_str().unwrap();
    assert!(error.contains("invalid `PORTL-S-` short code"), "{error}");

    unsafe {
        portl_ffi::portl_client_free(client);
    }
}

#[test]
fn client_accept_peer_invite_rejects_malformed_code() {
    let (peer_path, ticket_path) = unique_store_paths("accept-bad-peer-invite");
    let client = client_with_store_paths(&peer_path, &ticket_path);
    let code = CString::new("PORTLINV-not-a-valid-code").unwrap();

    let label = unsafe {
        portl_ffi::portl_client_accept_peer_invite(client, code.as_ptr(), ptr::null(), 100)
    };

    assert!(label.is_null());
    let error = portl_ffi::portl_last_error();
    assert!(!error.is_null());
    let error = unsafe { CStr::from_ptr(error) }.to_str().unwrap();
    assert!(error.contains("invalid `PORTLINV-` invite code"), "{error}");

    unsafe {
        portl_ffi::portl_client_free(client);
    }
}

fn unique_store_paths(name: &str) -> (String, String) {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("portl-ffi-{name}-{}-{nanos}", std::process::id()));
    (
        dir.join("peers.json").to_string_lossy().into_owned(),
        dir.join("tickets.json").to_string_lossy().into_owned(),
    )
}

fn client_with_store_paths(peer_path: &str, ticket_path: &str) -> *mut portl_ffi::PortlClient {
    client_with_seed_store_paths([0u8; 32], peer_path, ticket_path)
}

fn client_with_seed_store_paths(
    seed: [u8; 32],
    peer_path: &str,
    ticket_path: &str,
) -> *mut portl_ffi::PortlClient {
    let peer_path = CString::new(peer_path).unwrap();
    let ticket_path = CString::new(ticket_path).unwrap();
    let seed_ptr = if seed == [0u8; 32] {
        ptr::null()
    } else {
        seed.as_ptr()
    };
    let client = unsafe {
        portl_ffi::portl_client_new_with_stores(seed_ptr, peer_path.as_ptr(), ticket_path.as_ptr())
    };
    assert!(!client.is_null());
    client
}

fn fixture_session_share_envelope_json(friendly_name: &str, origin_label: &str) -> String {
    let now = unix_now();
    let issuer = Identity::from_signing_key(SigningKey::from_bytes(&[3u8; 32]));
    let target = Identity::from_signing_key(SigningKey::from_bytes(&[7u8; 32]));
    let recipient = Identity::from_signing_key(SigningKey::from_bytes(&[9u8; 32]));
    let addr = EndpointAddr::new(target.endpoint_id());
    let ticket = mint_root(
        issuer.signing_key(),
        addr,
        interactive_shell_caps(),
        now.saturating_sub(60),
        now + 3_600,
        Some(recipient.verifying_key()),
    )
    .expect("mint fixture session-share ticket");
    let target_endpoint_id_hex = hex::encode(ticket.addr.id.as_bytes());
    let ticket = ticket.encode_string();

    format!(
        r#"{{
            "schema": "portl.exchange.v1",
            "kind": "session-share",
            "created_at_unix": {now},
            "not_after_unix": {},
            "sender": {{ "label": "{origin_label}" }},
            "payload": {{
                "kind": "session-share",
                "body": {{
                    "workspace_id": "ws_test",
                    "friendly_name": "{friendly_name}",
                    "conflict_handle": "abcd1234",
                    "origin_label_hint": "{origin_label}",
                    "target_label_hint": "max-b265",
                    "target_endpoint_id_hex": "{target_endpoint_id_hex}",
                    "provider": "tmux",
                    "provider_session": "{friendly_name}",
                    "ticket": "{ticket}",
                    "access_not_after_unix": {}
                }}
            }}
        }}"#,
        now + 300,
        now + 3_600,
    )
}

fn fixture_ticket_string(ttl_secs: i64) -> (String, String) {
    let now = unix_now();
    let identity = Identity::from_signing_key(SigningKey::from_bytes(&[81u8; 32]));
    let addr = EndpointAddr::new(identity.endpoint_id());
    let ticket = mint_root(
        identity.signing_key(),
        addr,
        shell_caps(),
        now.saturating_sub(60),
        now.saturating_add_signed(ttl_secs),
        None,
    )
    .expect("mint fixture ticket");
    let endpoint_id_hex = hex::encode(ticket.addr.id.as_bytes());
    (ticket.encode_string(), endpoint_id_hex)
}

fn shell_caps() -> Capabilities {
    Capabilities {
        presence: 0b0000_0001,
        shell: Some(ShellCaps {
            user_allowlist: None,
            pty_allowed: true,
            exec_allowed: true,
            command_allowlist: None,
            env_policy: EnvPolicy::Deny,
        }),
        tcp: None,
        udp: None,
        fs: None,
        vpn: None,
        meta: None,
        unix: None,
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
