//! On-disk storage and encrypted import/export for [`Identity`].

use std::fs::{self, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};

use age::armor::{ArmoredReader, ArmoredWriter, Format};
use age::scrypt;
use age::secrecy::SecretString;
use age::{Decryptor, Encryptor};
use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

use crate::error::{PortlError, Result};
use crate::id::keypair::Identity;

/// Resolve the default identity path.
#[must_use]
pub fn default_path() -> PathBuf {
    crate::paths::identity_path()
}

/// Resolve the default identity path with an optional home override.
#[must_use]
pub fn default_path_with_home(home_override: Option<&Path>) -> PathBuf {
    home_override.map_or_else(default_path, |home| {
        crate::paths::for_home(home).identity_path()
    })
}

/// Save an identity as raw 32-byte signing-key material.
pub fn save(id: &Identity, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let tmp_path = sibling_tmp_path(path);
    let mut file = open_private_file(&tmp_path)?;
    let secret = Zeroizing::new(id.signing_key().to_bytes().to_vec());
    file.write_all(secret.as_slice())?;
    file.sync_all()?;
    drop(file);

    #[cfg(unix)]
    set_mode_0600(&tmp_path)?;

    fs::rename(&tmp_path, path)?;

    #[cfg(unix)]
    set_mode_0600(path)?;

    Ok(())
}

/// Load an identity saved via [`save`].
pub fn load(path: &Path) -> Result<Identity> {
    let bytes = Zeroizing::new(fs::read(path)?);
    let secret = Zeroizing::new(bytes.as_slice().try_into().map_err(|_| {
        PortlError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "identity file must contain exactly 32 bytes",
        ))
    })?);
    Ok(Identity::from_signing_key(SigningKey::from_bytes(&secret)))
}

/// Export an identity as age-armored bytes encrypted with a passphrase.
pub fn export(id: &Identity, passphrase: &str) -> Result<Vec<u8>> {
    let encryptor = Encryptor::with_user_passphrase(SecretString::from(passphrase.to_owned()));
    let mut ciphertext = Vec::new();
    let armor =
        ArmoredWriter::wrap_output(&mut ciphertext, Format::AsciiArmor).map_err(age_error)?;
    let mut writer = encryptor.wrap_output(armor).map_err(age_error)?;
    let secret = Zeroizing::new(id.signing_key().to_bytes().to_vec());
    writer.write_all(secret.as_slice())?;
    let armor = writer.finish().map_err(age_error)?;
    armor.finish().map_err(age_error)?;
    Ok(ciphertext)
}

/// Import an age-armored identity encrypted with a passphrase.
pub fn import(bytes: &[u8], passphrase: &str) -> Result<Identity> {
    let decryptor =
        Decryptor::new_buffered(ArmoredReader::new(Cursor::new(bytes))).map_err(age_error)?;
    let mut plaintext = Zeroizing::new(Vec::new());

    if !decryptor.is_scrypt() {
        return Err(PortlError::Age(
            "identity export is not passphrase-encrypted".to_owned(),
        ));
    }

    let identity = scrypt::Identity::new(SecretString::from(passphrase.to_owned()));
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(age_error)?;
    reader.read_to_end(&mut plaintext).map_err(age_error)?;

    let secret = Zeroizing::new(plaintext.as_slice().try_into().map_err(|_| {
        PortlError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "decrypted identity must contain exactly 32 bytes",
        ))
    })?);
    Ok(Identity::from_signing_key(SigningKey::from_bytes(&secret)))
}

fn sibling_tmp_path(path: &Path) -> PathBuf {
    let file_name = path.file_name().map_or_else(
        || "identity.bin".into(),
        |name| name.to_string_lossy().into_owned(),
    );
    path.with_file_name(format!(".{file_name}.tmp"))
}

fn age_error(err: impl std::fmt::Display) -> PortlError {
    PortlError::Age(err.to_string())
}

fn open_private_file(path: &Path) -> std::io::Result<fs::File> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
    }

    options.open(path)
}

#[cfg(unix)]
fn set_mode_0600(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}
