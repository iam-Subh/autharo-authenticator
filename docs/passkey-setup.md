# Passkey deployment requirements

The passkey infrastructure is implemented. Production activation is blocked
until the final Android and web identities exist.

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

See [Production security configuration](production-security.md) for the
server variables, Digital Asset Links steps, and fallback requirements.
