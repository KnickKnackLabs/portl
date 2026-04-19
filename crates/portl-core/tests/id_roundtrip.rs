use std::path::PathBuf;

use iroh_base::EndpointId;
use portl_core::id::{
    keypair::Identity,
    store::{default_path_with_home, export, import, load, save},
};
use tempfile::tempdir;

#[test]
fn new_creates_different_keys() {
    let first = Identity::new();
    let second = Identity::new();

    assert_ne!(first.verifying_key(), second.verifying_key());
}

#[test]
fn save_load_roundtrip_preserves_key() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("identity.bin");
    let identity = Identity::new();

    save(&identity, &path).unwrap();
    let loaded = load(&path).unwrap();

    assert_eq!(loaded.verifying_key(), identity.verifying_key());
    assert_eq!(
        loaded.signing_key().to_bytes(),
        identity.signing_key().to_bytes()
    );
}

#[cfg(unix)]
#[test]
fn save_sets_0600_on_unix() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempdir().unwrap();
    let path = dir.path().join("identity.bin");

    save(&Identity::new(), &path).unwrap();

    let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn save_creates_parent_dir() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("nested").join("identity.bin");

    save(&Identity::new(), &path).unwrap();

    assert!(path.exists());
}

#[test]
fn export_then_import_roundtrip() {
    let identity = Identity::new();
    let passphrase = "correct horse battery staple";

    let bytes = export(&identity, passphrase).unwrap();
    let imported = import(&bytes, passphrase).unwrap();

    assert_eq!(imported.verifying_key(), identity.verifying_key());
    assert_eq!(
        imported.signing_key().to_bytes(),
        identity.signing_key().to_bytes()
    );
}

#[test]
fn import_rejects_wrong_passphrase() {
    let identity = Identity::new();
    let bytes = export(&identity, "right-passphrase").unwrap();

    let message = import(&bytes, "wrong-passphrase")
        .err()
        .expect("wrong passphrase must fail")
        .to_string();
    assert!(
        message.contains("passphrase") || message.contains("decrypt") || message.contains("age"),
        "unexpected error: {message}"
    );
}

#[test]
fn endpoint_id_matches_verifying_key_bytes() {
    let identity = Identity::new();
    let expected = EndpointId::from_bytes(&identity.verifying_key()).unwrap();

    assert_eq!(identity.endpoint_id(), expected);
}

#[test]
fn default_path_honours_portl_home_env() {
    let home = PathBuf::from("/tmp/portl-home");
    let path = default_path_with_home(Some(home.as_path()));

    assert_eq!(path, home.join("identity.bin"));
}
