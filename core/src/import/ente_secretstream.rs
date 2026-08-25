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

#[cfg(test)]
mod libsodium_vectors {
    use super::*;

    /// Real libsodium output, one message per length, covering every residue
    /// modulo sixteen.
    ///
    /// # Why these exist
    ///
    /// The padding this module applies to the Poly1305 input is the one detail
    /// of `crypto_secretstream_xchacha20poly1305` that cannot be checked by a
    /// round trip: an encoder and a decoder that pad the same wrong way agree
    /// perfectly and fail on every real file. The single Ente export in
    /// `fixtures/` happens to be one length, so it can only ever exercise one
    /// residue.
    ///
    /// These vectors were produced by libsodium itself, through PyNaCl, and
    /// committed. They are the independent side of the check — nothing in this
    /// repository generated the ciphertext.
    #[test]
    fn every_message_length_matches_libsodium() {
        let raw = include_str!("fixtures/libsodium-secretstream-vectors.json");
        let root: serde_json::Value = serde_json::from_str(raw).unwrap();

        let key_bytes = b64(root["key"].as_str().unwrap());
        let key: [u8; 32] = key_bytes.as_slice().try_into().unwrap();

        let vectors = root["vectors"].as_array().unwrap();
        assert_eq!(vectors.len(), 40, "the vector file is incomplete");

        let mut residues = std::collections::HashSet::new();
        for vector in vectors {
            let mlen = vector["mlen"].as_u64().unwrap() as usize;
            residues.insert(mlen % 16);

            let header = b64(vector["header"].as_str().unwrap());
            let data = b64(vector["data"].as_str().unwrap());
            let expected = b64(vector["plain"].as_str().unwrap());

            let opened = open(&data, &key, &header)
                .unwrap_or_else(|error| panic!("length {mlen} failed: {error}"));
            assert_eq!(
                opened.to_vec(),
                expected,
                "length {mlen} decrypted to the wrong bytes"
            );
        }

        assert_eq!(residues.len(), 16, "not every length modulo 16 was covered");
    }

    /// A tampered byte must fail, or the test above would pass on a reader that
    /// ignored the tag entirely.
    #[test]
    fn a_modified_byte_is_refused() {
        let raw = include_str!("fixtures/libsodium-secretstream-vectors.json");
        let root: serde_json::Value = serde_json::from_str(raw).unwrap();
        let key: [u8; 32] = b64(root["key"].as_str().unwrap()).as_slice().try_into().unwrap();

        let vector = &root["vectors"][20];
        let header = b64(vector["header"].as_str().unwrap());
        let mut data = b64(vector["data"].as_str().unwrap());

        let last = data.len() - 1;
        data[last] ^= 0x01;
        assert!(matches!(
            open(&data, &key, &header),
            Err(DecryptError::WrongPasswordOrDamaged)
        ));
    }

    fn b64(text: &str) -> Vec<u8> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.decode(text).unwrap()
    }
}
