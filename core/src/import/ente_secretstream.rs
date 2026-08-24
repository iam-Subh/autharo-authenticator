//! Reader for Ente Authenticator's one-message secret-stream payload.
//!
//! Ente uses libsodium's `crypto_secretstream_xchacha20poly1305` format. That
//! format is not the same as the usual XChaCha20-Poly1305 AEAD wire format.
//! This module implements the one-message `pull` operation that Ente exports.

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::{ChaCha20, Key, R20, hchacha};
use poly1305::{Poly1305, universal_hash::KeyInit};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::encrypted::DecryptError;

const HEADER_BYTES: usize = 24;
const AUTH_BYTES: usize = 17;
const TAG_MESSAGE: u8 = 0;
const TAG_FINAL: u8 = 3;

/// Opens the single secret-stream message stored in an Ente export.
pub(super) fn open(
    data: &[u8],
    key: &[u8; 32],
    header: &[u8],
) -> Result<Zeroizing<Vec<u8>>, DecryptError> {
    if header.len() != HEADER_BYTES {
        return Err(DecryptError::Malformed {
            detail: format!(
                "the Ente encryption nonce is {} bytes, not 24",
                header.len()
            ),
        });
    }
    if data.len() < AUTH_BYTES {
        return Err(DecryptError::Malformed {
            detail: "the Ente encrypted data is too short".to_string(),
        });
    }

    let header_prefix: [u8; 16] = header[..16]
        .try_into()
        .map_err(|_| DecryptError::Malformed {
            detail: "the Ente encryption nonce is invalid".to_string(),
        })?;
    let chacha_key = Key::from(*key);
    let subkey = hchacha::<R20>(&chacha_key, &header_prefix.into());

    // libsodium starts the four-byte message counter at one. The final eight
    // nonce bytes come from the secret-stream header.
    let mut nonce = [0u8; 12];
    nonce[0] = 1;
    nonce[4..].copy_from_slice(&header[16..]);
    let mut cipher = ChaCha20::new(&subkey, &nonce.into());

    // ChaCha block zero supplies the one-time Poly1305 key.
    let mut first_block = Zeroizing::new([0u8; 64]);
    cipher.apply_keystream(first_block.as_mut());
    let mut poly_key = Zeroizing::new([0u8; 32]);
    poly_key.copy_from_slice(&first_block[..32]);

    let message_len = data.len() - AUTH_BYTES;
    let ciphertext = &data[1..1 + message_len];
    let stored_mac = &data[1 + message_len..];

    // The encrypted tag occupies a full 64-byte authenticated block.
    let mut tag_block = Zeroizing::new([0u8; 64]);
    tag_block[0] = data[0];
    cipher.apply_keystream(tag_block.as_mut());
    let tag = tag_block[0];
    tag_block[0] = data[0];

    // This is libsodium secret-stream's padding calculation. It differs from
    // the padding used by the stand-alone ChaCha20-Poly1305 AEAD construction.
    let padding_len = message_len & 0x0f;
    let mut authenticated = Zeroizing::new(Vec::with_capacity(64 + message_len + padding_len + 16));
    authenticated.extend_from_slice(tag_block.as_ref());
    authenticated.extend_from_slice(ciphertext);
    let padded_len = authenticated.len() + padding_len;
    authenticated.resize(padded_len, 0);
    authenticated.extend_from_slice(&0u64.to_le_bytes());
    authenticated.extend_from_slice(&(64u64 + message_len as u64).to_le_bytes());

    let poly = Poly1305::new((&*poly_key).into());
    let computed_mac = poly.compute_unpadded(&authenticated);
    if !bool::from(computed_mac.as_slice().ct_eq(stored_mac)) {
        return Err(DecryptError::WrongPasswordOrDamaged);
    }
    if tag != TAG_FINAL && tag != TAG_MESSAGE {
        return Err(DecryptError::Malformed {
            detail: format!("the Ente secret-stream tag ({tag}) is not supported"),
        });
    }

    let mut plaintext = Zeroizing::new(ciphertext.to_vec());
    cipher.apply_keystream(plaintext.as_mut());
    Ok(plaintext)
}
