use std::process::Command;

use assert_cmd::prelude::*;
use ed25519_dalek::SigningKey;
use iroh_tickets::Ticket;
use portl_core::id::store::{default_path_with_home, load};
use portl_core::ticket::schema::{
    Capabilities, EnvPolicy, MetaCaps, PortRule, PortlTicket, ShellCaps,
};
use tempfile::{TempDir, tempdir};

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
    }
}

fn init_identity(home: &TempDir) -> [u8; 32] {
    Command::cargo_bin("portl")
        .unwrap()
        .env("PORTL_HOME", home.path())
        .args(["id", "new"])
        .assert()
        .success();

    load(&default_path_with_home(Some(home.path())))
        .unwrap()
        .verifying_key()
}

fn endpoint_hex_from_seed(seed: u8) -> String {
    hex::encode(
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
    )
}

#[test]
fn id_new_creates_identity_file() {
    let home = tempdir().unwrap();
    let identity_path = default_path_with_home(Some(home.path()));

    Command::cargo_bin("portl")
        .unwrap()
        .env("PORTL_HOME", home.path())
        .args(["id", "new"])
        .assert()
        .success();

    assert!(identity_path.exists());
}

#[test]
fn id_new_refuses_overwrite_without_force() {
    let home = tempdir().unwrap();

    Command::cargo_bin("portl")
        .unwrap()
        .env("PORTL_HOME", home.path())
        .args(["id", "new"])
        .assert()
        .success();

    Command::cargo_bin("portl")
        .unwrap()
        .env("PORTL_HOME", home.path())
        .args(["id", "new"])
        .assert()
        .failure();
}

#[test]
fn id_new_with_force_overwrites() {
    let home = tempdir().unwrap();
    let identity_path = default_path_with_home(Some(home.path()));

    Command::cargo_bin("portl")
        .unwrap()
        .env("PORTL_HOME", home.path())
        .args(["id", "new"])
        .assert()
        .success();
    let before = load(&identity_path).unwrap().verifying_key();

    Command::cargo_bin("portl")
        .unwrap()
        .env("PORTL_HOME", home.path())
        .args(["id", "new", "--force"])
        .assert()
        .success();
    let after = load(&identity_path).unwrap().verifying_key();

    assert_ne!(before, after);
}

#[test]
fn id_show_prints_endpoint_id() {
    let home = tempdir().unwrap();

    Command::cargo_bin("portl")
        .unwrap()
        .env("PORTL_HOME", home.path())
        .args(["id", "new"])
        .assert()
        .success();

    let output = Command::cargo_bin("portl")
        .unwrap()
        .env("PORTL_HOME", home.path())
        .args(["id", "show"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8(output).unwrap();

    assert!(
        stdout.contains("endpoint_id:"),
        "unexpected stdout: {stdout}"
    );
}

#[test]
fn id_show_errors_when_no_identity() {
    let home = tempdir().unwrap();

    Command::cargo_bin("portl")
        .unwrap()
        .env("PORTL_HOME", home.path())
        .args(["id", "show"])
        .assert()
        .failure();
}

#[test]
fn id_import_uses_passphrase_cmd() {
    let home_a = tempdir().unwrap();
    let home_b = tempdir().unwrap();
    let export_path = home_a.path().join("identity.age");

    init_identity(&home_a);

    let original_show = Command::cargo_bin("portl")
        .unwrap()
        .env("PORTL_HOME", home_a.path())
        .args(["id", "show"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    Command::cargo_bin("portl")
        .unwrap()
        .env("PORTL_HOME", home_a.path())
        .args([
            "id",
            "export",
            "--out",
            export_path.to_str().unwrap(),
            "--passphrase-cmd",
            "echo hunter2",
        ])
        .assert()
        .success();

    Command::cargo_bin("portl")
        .unwrap()
        .env("PORTL_HOME", home_b.path())
        .args([
            "id",
            "import",
            "--from",
            export_path.to_str().unwrap(),
            "--passphrase-cmd",
            "echo hunter2",
        ])
        .assert()
        .success();

    let imported_show = Command::cargo_bin("portl")
        .unwrap()
        .env("PORTL_HOME", home_b.path())
        .args(["id", "show"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert_eq!(
        String::from_utf8(original_show).unwrap(),
        String::from_utf8(imported_show).unwrap()
    );
}

#[test]
fn id_import_refuses_overwrite_without_force() {
    let home_a = tempdir().unwrap();
    let home_b = tempdir().unwrap();
    let export_path = home_a.path().join("identity.age");
    let passphrase = "battery horse staple";

    init_identity(&home_a);
    init_identity(&home_b);

    Command::cargo_bin("portl")
        .unwrap()
        .env("PORTL_HOME", home_a.path())
        .env("PORTL_PASSPHRASE", passphrase)
        .args(["id", "export", "--out", export_path.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("portl")
        .unwrap()
        .env("PORTL_HOME", home_b.path())
        .env("PORTL_PASSPHRASE", passphrase)
        .args(["id", "import", "--from", export_path.to_str().unwrap()])
        .assert()
        .failure();
}

#[test]
fn id_export_then_import_roundtrip() {
    let home_a = tempdir().unwrap();
    let home_b = tempdir().unwrap();
    let export_path = home_a.path().join("identity.age");
    let passphrase = "battery horse staple";

    Command::cargo_bin("portl")
        .unwrap()
        .env("PORTL_HOME", home_a.path())
        .args(["id", "new"])
        .assert()
        .success();

    let original_show = Command::cargo_bin("portl")
        .unwrap()
        .env("PORTL_HOME", home_a.path())
        .args(["id", "show"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    Command::cargo_bin("portl")
        .unwrap()
        .env("PORTL_HOME", home_a.path())
        .env("PORTL_PASSPHRASE", passphrase)
        .args(["id", "export", "--out", export_path.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("portl")
        .unwrap()
        .env("PORTL_HOME", home_b.path())
        .env("PORTL_PASSPHRASE", passphrase)
        .args(["id", "import", "--from", export_path.to_str().unwrap()])
        .assert()
        .success();

    let imported_show = Command::cargo_bin("portl")
        .unwrap()
        .env("PORTL_HOME", home_b.path())
        .args(["id", "show"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert_eq!(
        String::from_utf8(original_show).unwrap(),
        String::from_utf8(imported_show).unwrap()
    );
}

#[test]
fn mint_root_requires_endpoint_arg() {
    let home = tempdir().unwrap();
    init_identity(&home);

    Command::cargo_bin("portl")
        .unwrap()
        .env("PORTL_HOME", home.path())
        .args(["mint-root", "--caps", "shell", "--ttl", "24h"])
        .assert()
        .failure();
}

#[test]
fn mint_root_emits_portl_prefix_ticket() {
    let home = tempdir().unwrap();
    let operator = init_identity(&home);
    let endpoint = hex::encode(operator);

    let stdout = Command::cargo_bin("portl")
        .unwrap()
        .env("PORTL_HOME", home.path())
        .args([
            "mint-root",
            "--endpoint",
            endpoint.as_str(),
            "--caps",
            "shell",
            "--ttl",
            "24h",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let ticket = String::from_utf8(stdout).unwrap();

    assert!(
        ticket.trim().starts_with("portl"),
        "unexpected ticket: {ticket}"
    );

    let parsed = PortlTicket::deserialize(ticket.trim()).unwrap();
    assert_eq!(parsed.body.caps, shell_caps());
    assert_eq!(parsed.body.issuer, None);
}

#[test]
fn mint_root_with_tcp_rule() {
    let home = tempdir().unwrap();
    let operator = init_identity(&home);
    let endpoint = hex::encode(operator);

    let stdout = Command::cargo_bin("portl")
        .unwrap()
        .env("PORTL_HOME", home.path())
        .args([
            "mint-root",
            "--endpoint",
            endpoint.as_str(),
            "--caps",
            "tcp:127.0.0.1:22-22",
            "--ttl",
            "1h",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let ticket = String::from_utf8(stdout).unwrap();
    let parsed = PortlTicket::deserialize(ticket.trim()).unwrap();

    assert_eq!(parsed.body.caps.presence, 0b0000_0010);
    assert_eq!(
        parsed.body.caps.tcp,
        Some(vec![PortRule {
            host_glob: "127.0.0.1".into(),
            port_min: 22,
            port_max: 22,
        }])
    );
}

#[test]
fn mint_root_accepts_all_caps_keyword() {
    let home = tempdir().unwrap();
    let operator = init_identity(&home);
    let endpoint = hex::encode(operator);

    let stdout = Command::cargo_bin("portl")
        .unwrap()
        .env("PORTL_HOME", home.path())
        .args([
            "mint-root",
            "--endpoint",
            endpoint.as_str(),
            "--caps",
            "all",
            "--ttl",
            "1h",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let ticket = String::from_utf8(stdout).unwrap();
    let parsed = PortlTicket::deserialize(ticket.trim()).unwrap();

    assert_eq!(parsed.body.caps.presence, 0b0010_0111);
    assert_eq!(
        parsed.body.caps.shell,
        Some(ShellCaps {
            user_allowlist: None,
            pty_allowed: true,
            exec_allowed: true,
            command_allowlist: None,
            env_policy: EnvPolicy::Deny,
        })
    );
    assert_eq!(
        parsed.body.caps.tcp,
        Some(vec![PortRule {
            host_glob: "*".into(),
            port_min: 1,
            port_max: u16::MAX,
        }])
    );
    assert_eq!(
        parsed.body.caps.udp,
        Some(vec![PortRule {
            host_glob: "*".into(),
            port_min: 1,
            port_max: u16::MAX,
        }])
    );
    assert_eq!(
        parsed.body.caps.meta,
        Some(MetaCaps {
            ping: true,
            info: true,
        })
    );
}

#[test]
fn mint_root_accepts_y_ttl_up_to_365d() {
    let home = tempdir().unwrap();
    let operator = init_identity(&home);
    let endpoint = hex::encode(operator);

    let stdout = Command::cargo_bin("portl")
        .unwrap()
        .env("PORTL_HOME", home.path())
        .args([
            "mint-root",
            "--endpoint",
            endpoint.as_str(),
            "--caps",
            "shell",
            "--ttl",
            "1y",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let ticket = String::from_utf8(stdout).unwrap();
    let parsed = PortlTicket::deserialize(ticket.trim()).unwrap();

    assert_eq!(
        parsed.body.not_after - parsed.body.not_before,
        365 * 24 * 60 * 60
    );
}

#[test]
fn mint_root_sets_to_field_from_flag() {
    let home = tempdir().unwrap();
    let operator = init_identity(&home);
    let endpoint = hex::encode(operator);
    let holder = endpoint_hex_from_seed(91);
    let holder_bytes: [u8; 32] = hex::decode(&holder).unwrap().try_into().unwrap();

    let stdout = Command::cargo_bin("portl")
        .unwrap()
        .env("PORTL_HOME", home.path())
        .args([
            "mint-root",
            "--endpoint",
            endpoint.as_str(),
            "--caps",
            "shell",
            "--ttl",
            "24h",
            "--to",
            holder.as_str(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let ticket = String::from_utf8(stdout).unwrap();
    let parsed = PortlTicket::deserialize(ticket.trim()).unwrap();

    assert_eq!(parsed.body.to, Some(holder_bytes));
}

#[test]
fn mint_root_targets_endpoint_when_different_from_operator() {
    let home = tempdir().unwrap();
    let operator = init_identity(&home);
    let endpoint = endpoint_hex_from_seed(92);
    let endpoint_bytes: [u8; 32] = hex::decode(&endpoint).unwrap().try_into().unwrap();

    let stdout = Command::cargo_bin("portl")
        .unwrap()
        .env("PORTL_HOME", home.path())
        .args([
            "mint-root",
            "--endpoint",
            endpoint.as_str(),
            "--caps",
            "shell",
            "--ttl",
            "24h",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let ticket = String::from_utf8(stdout).unwrap();
    let parsed = PortlTicket::deserialize(ticket.trim()).unwrap();

    assert_eq!(parsed.body.issuer, Some(operator));
    assert_eq!(*parsed.addr.id.as_bytes(), endpoint_bytes);
    assert_eq!(parsed.body.target, endpoint_bytes);
}
