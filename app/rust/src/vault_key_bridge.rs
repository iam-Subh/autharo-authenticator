//! Android-only transfer of vault-key material between Rust and Kotlin.
//!
//! Dart receives only a random, one-time handle. Rust and Kotlin exchange the
//! protected bytes through JNI. A handle expires after five minutes, can be
//! consumed once, and contains no key material.

#![cfg(any(target_os = "android", feature = "jni-host-check"))]

use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use jni::objects::{JByteArray, JClass};
use jni::sys::jbyteArray;
use jni::JNIEnv;
use zeroize::Zeroizing;

const HANDLE_LENGTH: usize = 32;
const MAX_SECRET_LENGTH: usize = 4_096;
const MAX_PENDING_SECRETS: usize = 8;
const HANDLE_LIFETIME: Duration = Duration::from_secs(5 * 60);

struct PendingSecret {
    value: Zeroizing<Vec<u8>>,
    expires_at: Instant,
}

#[derive(Default)]
struct SecretRegistry {
    values: HashMap<[u8; HANDLE_LENGTH], PendingSecret>,
}

impl SecretRegistry {
    fn insert(&mut self, secret: Vec<u8>) -> Result<Vec<u8>> {
        self.remove_expired();
        if secret.is_empty() || secret.len() > MAX_SECRET_LENGTH {
            return Err(anyhow!("The pending vault secret has an invalid length."));
        }
        if self.values.len() >= MAX_PENDING_SECRETS {
            return Err(anyhow!("Too many vault-key operations are pending."));
        }

        let mut handle = [0_u8; HANDLE_LENGTH];
        loop {
            getrandom::fill(&mut handle).context("A vault-key handle could not be generated")?;
            if !self.values.contains_key(&handle) {
                break;
            }
        }

        self.values.insert(
            handle,
            PendingSecret {
                value: Zeroizing::new(secret),
                expires_at: Instant::now() + HANDLE_LIFETIME,
            },
        );
        Ok(handle.to_vec())
    }

    fn take(&mut self, handle: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        self.remove_expired();
        let handle: [u8; HANDLE_LENGTH] = handle
            .try_into()
            .map_err(|_| anyhow!("The vault-key handle has an invalid length."))?;
        self.values
            .remove(&handle)
            .map(|pending| pending.value)
            .ok_or_else(|| anyhow!("The vault-key handle is invalid, expired, or already used."))
    }

    fn remove(&mut self, handle: &[u8]) {
        if let Ok(handle) = <[u8; HANDLE_LENGTH]>::try_from(handle) {
            self.values.remove(&handle);
        }
    }

    fn clear(&mut self) {
        self.values.clear();
    }

    fn remove_expired(&mut self) {
        let now = Instant::now();
        self.values.retain(|_, pending| pending.expires_at > now);
    }
}

static REGISTRY: OnceLock<Mutex<SecretRegistry>> = OnceLock::new();

fn registry() -> &'static Mutex<SecretRegistry> {
    REGISTRY.get_or_init(|| Mutex::new(SecretRegistry::default()))
}

/// Stores bytes in Rust and returns a non-secret handle for Dart.
pub(crate) fn store_secret(secret: Vec<u8>) -> Result<Vec<u8>> {
    registry()
        .lock()
        .map_err(|_| anyhow!("The vault-key handle store is unavailable."))?
        .insert(secret)
}

/// Consumes a Dart-provided handle and returns the secret inside Rust.
pub(crate) fn take_secret(handle: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    registry()
        .lock()
        .map_err(|_| anyhow!("The vault-key handle store is unavailable."))?
        .take(handle)
}

pub(crate) fn clear_pending_secrets() {
    if let Ok(mut registry) = registry().lock() {
        registry.clear();
    }
}

fn read_and_wipe(env: &mut JNIEnv<'_>, array: &JByteArray<'_>) -> Result<Vec<u8>> {
    let bytes = env
        .convert_byte_array(array)
        .context("The Android vault-key bridge received unreadable bytes")?;
    let zeros = vec![0_i8; bytes.len()];
    env.set_byte_array_region(array, 0, &zeros)
        .context("The Android vault-key bridge could not clear its input buffer")?;
    Ok(bytes)
}

fn return_bytes(env: &mut JNIEnv<'_>, bytes: &[u8]) -> Result<jbyteArray> {
    Ok(env
        .byte_array_from_slice(bytes)
        .context("The Android vault-key bridge could not return bytes")?
        .into_raw())
}

fn throw_bridge_error(env: &mut JNIEnv<'_>, message: &str) -> jbyteArray {
    let _ = env.throw_new("java/lang/IllegalStateException", message);
    std::ptr::null_mut()
}

/// Kotlin gives an unwrapped secret directly to Rust and receives a handle.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_autharo_authenticator_NativeVaultBridge_storeSecret(
    mut env: JNIEnv,
    _class: JClass,
    secret: JByteArray,
) -> jbyteArray {
    let outcome = catch_unwind(AssertUnwindSafe(|| -> Result<jbyteArray> {
        let secret = read_and_wipe(&mut env, &secret)?;
        let handle = store_secret(secret)?;
        return_bytes(&mut env, &handle)
    }));

    match outcome {
        Ok(Ok(array)) => array,
        Ok(Err(error)) => throw_bridge_error(&mut env, &error.to_string()),
        Err(_) => throw_bridge_error(&mut env, "The Android vault-key bridge failed."),
    }
}

/// Kotlin consumes a setup handle and receives the secret directly from Rust.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_autharo_authenticator_NativeVaultBridge_takeSecret(
    mut env: JNIEnv,
    _class: JClass,
    handle: JByteArray,
) -> jbyteArray {
    let outcome = catch_unwind(AssertUnwindSafe(|| -> Result<jbyteArray> {
        let handle = read_and_wipe(&mut env, &handle)?;
        let secret = take_secret(&handle)?;
        return_bytes(&mut env, secret.as_slice())
    }));

    match outcome {
        Ok(Ok(array)) => array,
        Ok(Err(error)) => throw_bridge_error(&mut env, &error.to_string()),
        Err(_) => throw_bridge_error(&mut env, "The Android vault-key bridge failed."),
    }
}

/// Removes one unused handle after a cancelled wrapping operation.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_autharo_authenticator_NativeVaultBridge_discardSecret(
    mut env: JNIEnv,
    _class: JClass,
    handle: JByteArray,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if let Ok(handle) = read_and_wipe(&mut env, &handle) {
            if let Ok(mut registry) = registry().lock() {
                registry.remove(&handle);
            }
        }
    }));
}

/// Clears handles and pending device-slot requests on cancellation or lock.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_autharo_authenticator_NativeVaultBridge_cancelPendingOperation(
    _env: JNIEnv,
    _class: JClass,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        clear_pending_secrets();
        crate::api::vault::cancel_pending_keystore_operations();
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_are_random_single_use_and_non_secret() {
        let mut registry = SecretRegistry::default();
        let secret = vec![0x5a; 32];
        let first = registry.insert(secret.clone()).unwrap();
        let second = registry.insert(secret.clone()).unwrap();

        assert_eq!(first.len(), HANDLE_LENGTH);
        assert_ne!(first, secret);
        assert_ne!(first, second);
        assert_eq!(registry.take(&first).unwrap().as_slice(), secret);
        assert!(registry.take(&first).is_err());
        assert_eq!(registry.take(&second).unwrap().as_slice(), secret);
    }

    #[test]
    fn invalid_handles_and_excess_secrets_are_rejected() {
        let mut registry = SecretRegistry::default();
        assert!(registry.insert(Vec::new()).is_err());
        assert!(registry.insert(vec![0; MAX_SECRET_LENGTH + 1]).is_err());
        assert!(registry.take(&[0; HANDLE_LENGTH - 1]).is_err());

        for _ in 0..MAX_PENDING_SECRETS {
            registry.insert(vec![1]).unwrap();
        }
        assert!(registry.insert(vec![1]).is_err());
        registry.clear();
        assert!(registry.values.is_empty());
    }
}
