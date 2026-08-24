//! Persistent synchronization credentials.
//!
//! Android stores the complete access/refresh pair behind one Android
//! Keystore key. The pair is one atomic value because the server rotates both
//! tokens in one refresh operation. Dart is not part of this path.

#![cfg_attr(
    all(feature = "jni-host-check", not(target_os = "android")),
    allow(dead_code)
)]

use authcore::secret::SecretString;

#[cfg(any(target_os = "android", feature = "jni-host-check", test))]
use anyhow::{anyhow, Context, Result};

#[cfg(any(target_os = "android", feature = "jni-host-check", test))]
const PAYLOAD_MAGIC: &[u8; 4] = b"ASTS";
#[cfg(any(target_os = "android", feature = "jni-host-check", test))]
const PAYLOAD_VERSION: u8 = 1;
#[cfg(any(target_os = "android", feature = "jni-host-check", test))]
const HEADER_LEN: usize = PAYLOAD_MAGIC.len() + 1 + 2 + 2;
#[cfg(any(target_os = "android", feature = "jni-host-check", test))]
const MAX_TOKEN_LEN: usize = 4_096;

/// The session pair returned by the server.
pub(crate) struct SessionTokens {
    pub access: SecretString,
    pub refresh: SecretString,
}

#[cfg(any(target_os = "android", feature = "jni-host-check", test))]
fn encode(tokens: &SessionTokens) -> Result<Vec<u8>> {
    let access = tokens.access.expose().as_bytes();
    let refresh = tokens.refresh.expose().as_bytes();
    validate_length("access", access.len())?;
    validate_length("refresh", refresh.len())?;

    let mut encoded = Vec::with_capacity(HEADER_LEN + access.len() + refresh.len());
    encoded.extend_from_slice(PAYLOAD_MAGIC);
    encoded.push(PAYLOAD_VERSION);
    encoded.extend_from_slice(&(access.len() as u16).to_be_bytes());
    encoded.extend_from_slice(&(refresh.len() as u16).to_be_bytes());
    encoded.extend_from_slice(access);
    encoded.extend_from_slice(refresh);
    Ok(encoded)
}

#[cfg(any(target_os = "android", feature = "jni-host-check", test))]
fn decode(mut encoded: Vec<u8>) -> Result<SessionTokens> {
    let result = decode_inner(&encoded);
    encoded.fill(0);
    result
}

#[cfg(any(target_os = "android", feature = "jni-host-check", test))]
fn decode_inner(encoded: &[u8]) -> Result<SessionTokens> {
    if encoded.len() < HEADER_LEN || &encoded[..PAYLOAD_MAGIC.len()] != PAYLOAD_MAGIC {
        return Err(anyhow!(
            "The stored synchronization session has an invalid header."
        ));
    }
    if encoded[PAYLOAD_MAGIC.len()] != PAYLOAD_VERSION {
        return Err(anyhow!(
            "The stored synchronization session uses an unsupported version."
        ));
    }

    let access_len = u16::from_be_bytes([encoded[5], encoded[6]]) as usize;
    let refresh_len = u16::from_be_bytes([encoded[7], encoded[8]]) as usize;
    validate_length("access", access_len)?;
    validate_length("refresh", refresh_len)?;

    let expected = HEADER_LEN
        .checked_add(access_len)
        .and_then(|length| length.checked_add(refresh_len))
        .ok_or_else(|| anyhow!("The stored synchronization session is too large."))?;
    if encoded.len() != expected {
        return Err(anyhow!(
            "The stored synchronization session has an invalid length."
        ));
    }

    let access_end = HEADER_LEN + access_len;
    let access = core::str::from_utf8(&encoded[HEADER_LEN..access_end])
        .context("The stored access token is not valid UTF-8")?;
    let refresh = core::str::from_utf8(&encoded[access_end..])
        .context("The stored refresh token is not valid UTF-8")?;
    Ok(SessionTokens {
        access: SecretString::new(access),
        refresh: SecretString::new(refresh),
    })
}

#[cfg(any(target_os = "android", feature = "jni-host-check", test))]
fn validate_length(name: &str, length: usize) -> Result<()> {
    if length == 0 || length > MAX_TOKEN_LEN || length > u16::MAX as usize {
        return Err(anyhow!("The {name} token has an invalid length."));
    }
    Ok(())
}

#[cfg(any(target_os = "android", feature = "jni-host-check"))]
mod android {
    use std::sync::OnceLock;

    use super::{decode, encode, SessionTokens};
    use anyhow::{anyhow, Context, Result};
    use jni::objects::{GlobalRef, JByteArray, JClass, JObject, JValue};
    use jni::JNIEnv;
    use jni::JavaVM;

    static JVM: OnceLock<JavaVM> = OnceLock::new();
    static STORE: OnceLock<GlobalRef> = OnceLock::new();

    /// Installs the Kotlin token store. MainActivity calls this before Flutter
    /// starts Dart code. The global reference holds an application context,
    /// not an Activity, so an Activity recreation does not invalidate it.
    #[unsafe(no_mangle)]
    pub extern "system" fn Java_dev_authcore_authenticator_NativeSessionBridge_installTokenStore(
        mut env: JNIEnv,
        _class: JClass,
        store: JObject,
    ) {
        let installed = (|| -> jni::errors::Result<()> {
            let vm = env.get_java_vm()?;
            let store = env.new_global_ref(store)?;
            // Reinstallation after an Activity recreation is harmless. Keep
            // the first store because it contains only application context.
            let _ = JVM.set(vm);
            let _ = STORE.set(store);
            Ok(())
        })();

        if installed.is_err() {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                "The native synchronization token store could not be initialized.",
            );
        }
    }

    pub(crate) fn has_session() -> Result<bool> {
        with_store(|env, store| {
            env.call_method(store, "hasSession", "()Z", &[])
                .context("The Android token store could not check the session")?
                .z()
                .context("The Android token store returned an invalid session state")
        })
    }

    pub(crate) fn read_session() -> Result<Option<SessionTokens>> {
        let encoded = with_store(|env, store| {
            let value = env
                .call_method(store, "readSession", "()[B", &[])
                .context("The Android token store could not read the session")?
                .l()
                .context("The Android token store returned an invalid session")?;
            if value.is_null() {
                return Ok(None);
            }

            let array = JByteArray::from(value);
            let bytes = env
                .convert_byte_array(&array)
                .context("The Android token store returned unreadable bytes")?;

            // Wipe the temporary Java byte array after Rust owns its copy.
            // Kotlin cannot wipe this value before returning it.
            let zeros = vec![0_i8; bytes.len()];
            env.set_byte_array_region(&array, 0, &zeros)
                .context("The Android token-store buffer could not be cleared")?;
            Ok(Some(bytes))
        })?;
        encoded.map(decode).transpose()
    }

    pub(crate) fn write_session(tokens: &SessionTokens) -> Result<()> {
        let mut encoded = encode(tokens)?;
        let result = with_store(|env, store| {
            let array = env
                .byte_array_from_slice(&encoded)
                .context("The synchronization session could not enter the Android token store")?;
            let object = JObject::from(array);
            env.call_method(store, "writeSession", "([B)V", &[JValue::Object(&object)])
                .context("The Android token store could not save the session")?;
            Ok(())
        });
        encoded.fill(0);
        result
    }

    pub(crate) fn clear_session() -> Result<()> {
        with_store(|env, store| {
            env.call_method(store, "clearSession", "()V", &[])
                .context("The Android token store could not clear the session")?;
            Ok(())
        })
    }

    fn with_store<T>(
        operation: impl FnOnce(&mut JNIEnv<'_>, &JObject<'_>) -> Result<T>,
    ) -> Result<T> {
        let vm = JVM.get().ok_or_else(|| {
            anyhow!("The Android synchronization token store is not initialized.")
        })?;
        let store = STORE.get().ok_or_else(|| {
            anyhow!("The Android synchronization token store is not initialized.")
        })?;
        let mut env = vm
            .attach_current_thread()
            .context("The sync worker could not attach to the Android runtime")?;
        operation(&mut env, store.as_obj())
    }
}

#[cfg(any(target_os = "android", feature = "jni-host-check"))]
pub(crate) use android::{clear_session, has_session, read_session, write_session};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_payload_round_trips() {
        let original = SessionTokens {
            access: SecretString::new("access-value"),
            refresh: SecretString::new("refresh-value"),
        };
        let decoded = decode(encode(&original).unwrap()).unwrap();
        assert_eq!(decoded.access.expose(), "access-value");
        assert_eq!(decoded.refresh.expose(), "refresh-value");
    }

    #[test]
    fn session_payload_rejects_truncation_and_trailing_data() {
        let tokens = SessionTokens {
            access: SecretString::new("a"),
            refresh: SecretString::new("r"),
        };
        let mut encoded = encode(&tokens).unwrap();
        encoded.pop();
        assert!(decode(encoded).is_err());

        let mut encoded = encode(&tokens).unwrap();
        encoded.push(0);
        assert!(decode(encoded).is_err());
    }

    #[test]
    fn session_payload_rejects_empty_tokens() {
        let tokens = SessionTokens {
            access: SecretString::new(""),
            refresh: SecretString::new("refresh"),
        };
        assert!(encode(&tokens).is_err());
    }
}
