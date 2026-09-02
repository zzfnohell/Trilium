//! Protected-note cryptography — the faithful mirror of Trilium's three
//! encryption services, in one module:
//!
//! - `data_encryption.ts`: AES-128-CBC with a 4-byte SHA-1 digest prefix and a
//!   random 16-byte IV; the payload is `sha1(plain)[..4] ++ plain`, the output
//!   is `base64(iv ++ ciphertext)`. Keys/IVs are truncated or zero-padded to
//!   16 bytes (`pad()`). The 13-byte IV for legacy rows is accepted on decrypt.
//! - `scrypt.ts`: scrypt(N=16384, r=8, p=1) of `password` over the *string*
//!   salt stored in the options, yielding the 32-byte password-derived key.
//! - `password_encryption.ts`: the password-derived key wraps a random 16-byte
//!   *data key* stored as `options.encryptedDataKey`; `passwordVerificationHash`
//!   is the base64 scrypt of the password for constant-time verification.
//!
//! Everything here is pure (no DB or session state) so it can be unit-tested
//! against the real protocol. The live session (the decrypted data key) lives
//! in `services/protected_session.rs`.

use aes::Aes128;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cbc::{Decryptor, Encryptor};
use rand::Rng;
use sha1::{Digest as _, Sha1};

/// Prepended to the *unencrypted* content before hashing, so the blobId of an
/// encrypted entity is distinct from the one its plaintext would have produced.
/// Matches `getUnencryptedContentForHashCalculation` in the real becca entity.
pub const ENCRYPTED_PREFIX: &str = "t$[nvQg7q)&_ENCRYPTED_?M:Bf&j3jr_";

/// The title placeholder served for protected notes while the protected
/// session is not active (`getTitleOrProtected`).
pub const PROTECTED_MASK: &str = "[protected]";

type Aes128CbcEnc = Encryptor<Aes128>;
type Aes128CbcDec = Decryptor<Aes128>;

/// The outcome of a decryption: verified plaintext, a digest mismatch (garbage
/// key or corrupted payload), or bytes that are not AES-CBC ciphertext at all
/// (the legacy "wrong final block length" case the real server recovers from by
/// handing the input back verbatim).
#[derive(Debug, PartialEq, Eq)]
pub enum DecryptOutcome {
    Ok(Vec<u8>),
    BadDigest,
    NotCiphertext,
}

/// `pad()` in `data_encryption.ts`: truncate to 16 bytes, or zero-pad up to it.
fn pad16(data: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let n = data.len().min(16);
    out[..n].copy_from_slice(&data[..n]);
    out
}

fn sha1(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
}

/// Fresh random bytes, e.g. the per-message IV or the password salts.
pub fn rand_bytes(n: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..n).map(|_| rng.gen::<u8>()).collect()
}

/// `scrypt`: password-derived key over the *string* salt stored in the options.
/// The real server passes the option value (a base64 string) straight into
/// `crypto.scrypt`, so it is used as UTF-8 bytes, not base64-decoded.
pub fn scrypt_derive(password: &str, salt: &str) -> Result<Vec<u8>, String> {
    // N = 2^14 = 16384, matching the real `SCRYPT_OPTIONS`.
    let params = scrypt::ScryptParams::new(14, 8, 1).map_err(|e| format!("invalid scrypt params: {e}"))?;
    let mut out = vec![0u8; 32];
    scrypt::scrypt(password.as_bytes(), salt.as_bytes(), &params, &mut out)
        .map_err(|e| format!("scrypt failed: {e}"))?;
    Ok(out)
}

/// Name-neutral byte comparison — the sessions' `constantTimeCompare` twin.
/// Length is compared first (hashes always match in length); a mismatch of
/// equal-length inputs is detected with a XOR fold.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// `encrypt()` in `data_encryption.ts`: `base64(iv || AES-CBC(sha1(p)[..4] || p))`.
/// Non-deterministic — a fresh IV is drawn for every message, which is why the
/// blob hash is always computed from the *unencrypted* content instead.
pub fn encrypt_bytes(key: &[u8], plain: &[u8]) -> String {
    let key16 = pad16(key);
    let iv = rand_bytes(16);
    let mut payload = Vec::with_capacity(4 + plain.len());
    let digest = sha1(plain);
    payload.extend_from_slice(&digest[..4]);
    payload.extend_from_slice(plain);

    let cipher = Aes128CbcEnc::new_from_slices(&key16, &iv).expect("16-byte key and IV");
    let mut out = iv;
    out.extend_from_slice(&cipher.encrypt_padded_vec_mut::<Pkcs7>(&payload));
    BASE64.encode(out)
}

/// Convenience: encrypt a UTF-8 string (protected note titles, text content).
pub fn encrypt_string(key: &[u8], plain: &str) -> String {
    encrypt_bytes(key, plain.as_bytes())
}

/// `decrypt()` in `data_encryption.ts`: unwrap the IV (16 bytes for data this
/// server wrote, 13 for legacy rows), CBC-decrypt, strip the 4-byte digest and
/// verify it, distinguishing digest failure from "never was ciphertext".
pub fn decrypt(key: &[u8], cipher_text: &str) -> DecryptOutcome {
    let Ok(bytes) = BASE64.decode(cipher_text.trim()) else {
        return DecryptOutcome::NotCiphertext;
    };
    // Old encrypted data can have an IV of length 13; data we write always uses 16.
    let iv_len = if bytes.len() % 16 == 0 { 16 } else { 13 };
    if iv_len >= bytes.len() {
        return DecryptOutcome::NotCiphertext;
    }
    let (iv, ct) = bytes.split_at(iv_len);
    let Ok(cipher) = Aes128CbcDec::new_from_slices(&pad16(key), &pad16(iv)) else {
        return DecryptOutcome::NotCiphertext;
    };
    // A length/padding failure is the WRONG_FINAL_BLOCK_LENGTH case: the value
    // was never real ciphertext, and the real server hands it back as itself.
    let Ok(decrypted) = cipher.decrypt_padded_vec_mut::<Pkcs7>(ct) else {
        return DecryptOutcome::NotCiphertext;
    };
    if decrypted.len() < 4 {
        return DecryptOutcome::BadDigest;
    }
    let (digest, payload) = decrypted.split_at(4);
    if digest == &sha1(payload)[..4] {
        DecryptOutcome::Ok(payload.to_vec())
    } else {
        DecryptOutcome::BadDigest
    }
}

/// Decrypt with the digest check; `false` corresponds to the `false` the real
/// `decrypt` returns for a mismatch, `null` for an absent/empty key.
pub fn decrypt_string(key: &[u8], cipher_text: &str) -> Result<String, DecryptError> {
    match decrypt(key, cipher_text) {
        DecryptOutcome::Ok(bytes) => Ok(String::from_utf8_lossy(&bytes).into_owned()),
        DecryptOutcome::BadDigest => Err(DecryptError::BadDigest),
        DecryptOutcome::NotCiphertext => Err(DecryptError::NotCiphertext),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum DecryptError {
    BadDigest,
    NotCiphertext,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_then_decrypt_round_trips() {
        let key = b"0123456789abcdef";
        for plain in [Vec::new(), b"a".to_vec(), b"hello world!".to_vec(), b"x".repeat(16), b"x".repeat(50)] {
            let cipher = encrypt_bytes(key, &plain);
            assert_eq!(
                decrypt(key, &cipher),
                DecryptOutcome::Ok(plain.clone()),
                "round trip for {} bytes",
                plain.len()
            );
        }
    }

    #[test]
    fn aes_key_is_truncated_padded_to_16() {
        // The real server generates a 16-byte data key, but the password-derived
        // key is 32 bytes and is truncated by pad(). Both must work.
        let short = encrypt_bytes(b"k", b"payload");
        assert_eq!(decrypt(b"k", &short), DecryptOutcome::Ok(b"payload".to_vec()));

        let long = encrypt_bytes(b"0123456789abcdef0123456789abcdef", b"payload");
        assert_eq!(decrypt(b"0123456789abcdef0123456789abcdef", &long), DecryptOutcome::Ok(b"payload".to_vec()));
    }

    #[test]
    fn legacy_13_byte_iv_is_decrypted() {
        // Simulate the old format: plain AES-CBC, still the 4-byte digest prefix,
        // but with a 13-byte IV (encoded compactly, so the total length is not a
        // multiple of the block size).
        let key = b"0123456789abcdef";
        let iv = b"1234567890123"; // 13 bytes
        let payload = {
            let mut v = sha1(b"legacy").into_iter().take(4).collect::<Vec<_>>();
            v.extend_from_slice(b"legacy");
            v
        };
        let cipher = Aes128CbcEnc::new_from_slices(&pad16(key), &pad16(iv)).unwrap();
        let mut raw = iv.to_vec();
        raw.extend_from_slice(&cipher.encrypt_padded_vec_mut::<Pkcs7>(&payload));
        let encoded = BASE64.encode(raw);
        assert_eq!(decrypt(key, &encoded), DecryptOutcome::Ok(b"legacy".to_vec()));
    }

    #[test]
    fn digest_mismatch_is_reported() {
        // A payload whose padding is valid but whose 4-byte SHA-1 digest is wrong
        // fails exactly on the digest check (wrong keys usually fail earlier, on
        // AES-CBC unpadding, so this is the deterministic path to BadDigest).
        let key = b"0123456789abcdef";
        let plain = b"secret";
        let mut digest = sha1(plain);
        digest[0] ^= 0x01;
        let mut payload = digest[..4].to_vec();
        payload.extend_from_slice(plain);
        let nonce = rand_bytes(16);
        let cipher = Aes128CbcEnc::new_from_slices(&pad16(key), &nonce).unwrap();
        let mut raw = nonce;
        raw.extend_from_slice(&cipher.encrypt_padded_vec_mut::<Pkcs7>(&payload));
        assert_eq!(decrypt(key, &BASE64.encode(raw)), DecryptOutcome::BadDigest);
    }

    #[test]
    fn wrong_key_never_yields_plaintext() {
        let key = b"0123456789abcdef";
        let cipher = encrypt_bytes(key, b"secret");
        match decrypt(b"fedcba9876543210", &cipher) {
            DecryptOutcome::Ok(bytes) => panic!(
                "wrong key must not decrypt, got {:?}",
                String::from_utf8_lossy(&bytes)
            ),
            _ => {}
        }
    }

    #[test]
    fn non_ciphertext_is_detected() {
        let key = b"0123456789abcdef";
        assert_eq!(decrypt(key, "this is not base64 at all!!!"), DecryptOutcome::NotCiphertext);
        // A base64 blob that is not a multiple of the block size: ciphertext
        // cannot be produced from it, so it is the recovery case.
        assert_eq!(decrypt(key, &BASE64.encode(b"short")), DecryptOutcome::NotCiphertext);
    }

    #[test]
    fn scrypt_derives_consistently_and_const_time_compares() {
        let a = scrypt_derive("hunter2", "salt").unwrap();
        let b = scrypt_derive("hunter2", "salt").unwrap();
        assert_eq!(a, b);
        assert_ne!(scrypt_derive("hunter2", "other-salt").unwrap(), a);
        assert!(constant_time_eq(&a, &b));
        let mut c = a.clone();
        c[0] ^= 1;
        assert!(!constant_time_eq(&a, &c));
    }

    #[test]
    fn encrypted_prefix_keeps_blobids_distinct() {
        // Two notes with identical clear content but different protection must
        // hash to different blob ids — the point of the _ENCRYPTED_ prefix.
        let unencrypted = b"same content";
        let mut prefixed = Vec::new();
        prefixed.extend_from_slice(ENCRYPTED_PREFIX.as_bytes());
        prefixed.extend_from_slice(unencrypted);
        let hasher = |b: &[u8]| -> String { BASE64.encode(sha512(b))[..20].replace('+', "X").replace('/', "Y").to_string() };
        assert_ne!(hasher(unencrypted), hasher(&prefixed));
    }

    fn sha512(bytes: &[u8]) -> Vec<u8> {
        use sha2::{Digest as _, Sha512};
        let mut hasher = Sha512::new();
        hasher.update(bytes);
        hasher.finalize().to_vec()
    }
}