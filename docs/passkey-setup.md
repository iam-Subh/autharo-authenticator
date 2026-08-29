# Passkey deployment requirements

The passkey infrastructure is implemented. The Android package, release
certificate, and web relying-party identity now exist. The Digital Asset
Links file and the Render Android-origin allowlist are active.

The server provides these endpoints:

- `POST /v1/passkeys/register/start`
- `POST /v1/passkeys/register/finish`
- `POST /v1/passkeys/authenticate/start`
- `POST /v1/passkeys/authenticate/finish`

Registration requires a five-minute `security:read` capability. The server
stores the credential public key, credential counter, transports, user handle,
PRF salt, and encrypted vault-key slot. The server consumes ceremony state
once and rejects expired or replayed responses.

The Rust client derives a passkey key-encryption key from the 32-byte WebAuthn
PRF result. It uses HKDF-SHA-256 with the `authcore/v1/passkey-kek` label. It
then seals the vault key with XChaCha20-Poly1305. The raw vault key does not
enter Dart. The Android service extracts the PRF result and removes it from the
credential JSON before the application sends the assertion to the server. The
server rejects an assertion that still contains a PRF result.

The Settings interface exposes passkey registration. The synchronization
sign-in screen exposes passkey authentication. A successful assertion returns
only encrypted account slots. Rust unwraps the selected slot and sends a
one-time handle to Android Keystore. Dart does not receive the raw vault key.

New-device approval remains active for passkey sign-in. If the credential
provider omits the PRF result, use password sign-in or enter the recovery
phrase. The recovery phrase does not leave the device. The client sends only
its derived recovery authorization key.

See [Production security configuration](production-security.md) for the
server variables, Digital Asset Links steps, and fallback requirements.

The Android manifest includes the production Firebase Hosting association:

```text
https://autharo-auth-prod.web.app/.well-known/assetlinks.json
```

Firebase Hosting returns this file with HTTP status 200 and the
`application/json` content type.
