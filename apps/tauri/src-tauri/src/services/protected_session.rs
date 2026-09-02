//! The live protected session and the password-management service.
//!
//! Treslay on: some data lies in `crypto` and the write paths in `db`/`write`.
//! `login/protected` decrypts the stored data key with the password-derived key
//! and parks it in a process-global mutex; every read of protected content then
//! decrypts against it (like the real `protectedSessionService`), and every
//! write of protected content encrypts with it.

use std::sync::{Mutex, OnceLock};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use rusqlite::Connection;

use crate::crypto;
use crate::crypto::{DecryptError, DecryptOutcome};
use crate::db;

/// The decrypted data key held while the protected session is active. `None`
/// between sessions (the locked state).
fn session_global() -> &'static Mutex<Option<Vec<u8>>> {
    static SESSION: OnceLock<Mutex<Option<Vec<u8>>>> = OnceLock::new();
    SESSION.get_or_init(|| Mutex::new(None))
}

/// Whether the protected session data key is currently set.
pub fn is_available() -> bool {
    session_global().lock().map_or(false, |guard| guard.is_some())
}

/// Establish the session: `setDataKey` in the real service.
pub fn set_data_key(key: Vec<u8>) {
    *session_global().lock().expect("protected session lock") = Some(key);
}

/// Close the session: `resetDataKey`.
pub fn reset() {
    *session_global().lock().expect("protected session lock") = None;
}

fn with_key<T>(f: impl FnOnce(&[u8]) -> T) -> Option<T> {
    let guard = session_global().lock().ok()?;
    Some(f(guard.as_ref()?))
}

/// Encrypt bytes with the current data key; `None` when the session is locked.
pub fn encrypt(plain: &[u8]) -> Option<String> {
    with_key(|key| crypto::encrypt_bytes(key, plain))
}

/// Encrypt a UTF-8 string with the current data key; `None` when locked.
pub fn encrypt_string(plain: &str) -> Option<String> {
    with_key(|key| crypto::encrypt_string(key, plain))
}

/// `processContent` twin for string blobs: decrypt when the session is active,
/// blank when locked, and run the legacy recovery (return the stored value
/// verbatim) for rows that never were real ciphertext.
pub fn process_content(is_protected: bool, content: String) -> String {
    if !is_protected {
        return content;
    }
    with_key(|key| match crypto::decrypt(key, &content) {
        DecryptOutcome::Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        DecryptOutcome::NotCiphertext => content,
        DecryptOutcome::BadDigest => String::new(),
    })
    .unwrap_or_default()
}

/// `getTitleOrProtected` twin: `[protected]` while locked, the decrypted title
/// while unlocked; a title that will not decrypt is kept as stored.
pub fn title_or_mask(is_protected: bool, raw_title: String) -> String {
    if !is_protected {
        return raw_title;
    }
    with_key(|key| match crypto::decrypt_string(key, &raw_title) {
        Ok(plain) => plain,
        Err(DecryptError::NotCiphertext) => raw_title,
        Err(DecryptError::BadDigest) => crypto::PROTECTED_MASK.to_string(),
    })
    .unwrap_or_else(|| crypto::PROTECTED_MASK.to_string())
}

/// Decrypt protected content bytes (attachment blobs, binary note content).
/// `None` when locked or when the payload does not carry a valid digest.
pub fn decrypt_bytes(cipher_text: &str) -> Option<Vec<u8>> {
    with_key(|key| {
        match crypto::decrypt(key, cipher_text) {
            DecryptOutcome::Ok(bytes) => Some(bytes),
            _ => None,
        }
    })
    .flatten()
}

/// `isPasswordSet`: a non-empty `passwordVerificationHash` option.
pub fn is_password_set(conn: &Connection) -> bool {
    db::get_option(conn, "passwordVerificationHash").is_some_and(|v| !v.is_empty())
}

/// `verifyPassword`: scrypt the given password and constant-time-compare the
/// base64 result with the stored verification hash.
pub fn verify_password(conn: &Connection, password: &str) -> bool {
    let (Some(db_hash), Some(salt)) = (
        db::get_option(conn, "passwordVerificationHash"),
        db::get_option(conn, "passwordVerificationSalt"),
    ) else {
        return false;
    };
    let Ok(computed) = crypto::scrypt_derive(password, &salt) else {
        return false;
    };
    let computed = BASE64.encode(computed);
    crypto::constant_time_eq(computed.as_bytes(), db_hash.as_bytes())
}

/// `getDataKey`: derive the password-derived key and unwrap the stored data key.
/// `None` for a wrong password or a missing/undecryptable option.
pub fn get_data_key(conn: &Connection, password: &str) -> Option<Vec<u8>> {
    let salt = db::get_option(conn, "passwordDerivedKeySalt")?;
    let encrypted = db::get_option(conn, "encryptedDataKey")?;
    let pd_key = crypto::scrypt_derive(password, &salt).ok()?;
    match crypto::decrypt(&pd_key, &encrypted) {
        DecryptOutcome::Ok(bytes) => Some(bytes),
        _ => None,
    }
}

/// The result of a password change: success, or the current password not matching.
#[derive(Debug, PartialEq, Eq)]
pub enum PasswordChange {
    Ok,
    WrongPassword,
}

/// Shared tail of `setPassword`/`changePassword`: generate fresh salts, a fresh
/// verification hash, and a freshly re-wrapped data key, then persist the four
/// password options (`password.ts` in the real service).
fn write_password_options(
    conn: &Connection,
    new_password: &str,
    maybe_data_key: Option<Vec<u8>>,
) -> Result<(), String> {
    let verification_salt = BASE64.encode(crypto::rand_bytes(32));
    let derived_salt = BASE64.encode(crypto::rand_bytes(32));
    let verification_hash = BASE64.encode(crypto::scrypt_derive(new_password, &verification_salt)?);
    let data_key = match maybe_data_key {
        Some(key) => key,
        None => crypto::rand_bytes(16),
    };
    let pd_key = crypto::scrypt_derive(new_password, &derived_salt)?;
    let encrypted_data_key = crypto::encrypt_bytes(&pd_key, &data_key);

    for (name, value) in [
        ("passwordVerificationSalt", verification_salt),
        ("passwordDerivedKeySalt", derived_salt),
        ("passwordVerificationHash", verification_hash),
        ("encryptedDataKey", encrypted_data_key),
    ] {
        db::set_option(conn, name, &value).map_err(|err| format!("failed to store option '{name}': {err}"))?;
    }
    Ok(())
}

/// `setPassword` (no password set yet): plus a fresh random 16-byte data key.
pub fn set_password(conn: &Connection, new_password: &str) -> Result<(), String> {
    if is_password_set(conn) {
        return Err("Password is set already. Either change it or perform 'reset password' first.".to_string());
    }
    write_password_options(conn, new_password, None)
}

/// `changePassword`: when no password is set yet this is the initial `setPassword`
/// (the real route dispatches the same way); otherwise re-wrap the existing data
/// key under the new password.
pub fn change_password(conn: &Connection, current_password: &str, new_password: &str) -> Result<PasswordChange, String> {
    if !is_password_set(conn) {
        set_password(conn, new_password)?;
        return Ok(PasswordChange::Ok);
    }
    if !verify_password(conn, current_password) {
        return Ok(PasswordChange::WrongPassword);
    }
    let data_key = get_data_key(conn, current_password).ok_or_else(|| "Unable to obtain data key.".to_string())?;
    write_password_options(conn, new_password, Some(data_key))?;
    Ok(PasswordChange::Ok)
}

/// `resetPassword`: clear the password options, making the protected notes
/// permanently inaccessible.
pub fn reset_password(conn: &Connection) -> Result<(), String> {
    for name in ["passwordVerificationSalt", "passwordDerivedKeySalt", "encryptedDataKey", "passwordVerificationHash"] {
        db::set_option(conn, name, "").map_err(|err| format!("failed to reset option '{name}': {err}"))?;
    }
    Ok(())
}