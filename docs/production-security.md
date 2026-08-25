# Production security configuration

## Certificate pins

The Android release build requires one production hostname and two SPKI pins.
SPKI means Subject Public Key Information. The pin is the SHA-256 digest of a
certificate public key.

1. Configure the production server with HTTPS.
2. Create the current TLS private key and certificate.
3. Create a separate backup TLS private key.
4. Create or obtain a certificate for the backup key.
5. Generate one pin from each certificate.
6. Set `AUTHCORE_PINNED_HOST` to the hostname only.
7. Set `AUTHCORE_SPKI_PINS` to the two comma-separated Base64 pins.
8. Build the Android release package.

Use this OpenSSL command for each certificate:

```sh
openssl x509 -in certificate.pem -pubkey -noout \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 -binary \
  | openssl base64 -A
```

Use these values for the build environment:

```text
AUTHCORE_PINNED_HOST=sync.example.com
AUTHCORE_SPKI_PINS=BASE64_CURRENT_PIN,BASE64_BACKUP_PIN
```

Do not include a scheme, port, path, or wildcard in the hostname. The Rust
client first verifies the certificate chain, hostname, and expiry. It then
checks the leaf certificate SPKI against both pins. A matching pin does not
override a failed standard certificate check.

### Pin rotation

1. Release the application with pins for current key A and backup key B.
2. Change the server certificate from key A to key B.
3. Create backup key C.
4. Release the application with pins for key B and key C.
5. Remove key A only after the supported application population has the new
   pin set.

Never publish a release with one pin duplicated twice. Do not remove the old
pin before the application update reaches users.

## Passkeys

Set all server values together:

```text
WEBAUTHN_RP_ID=auth.example.com
WEBAUTHN_RP_ORIGIN=https://auth.example.com
WEBAUTHN_RP_NAME=AuthCore
```

The server refuses a partial configuration. The origin must use HTTPS.

Complete these deployment steps before you enable the passkey UI:

1. Select the final Android package ID.
2. Create the final release signing key.
3. Get the SHA-256 fingerprint of the release signing certificate.
4. Replace all placeholders in `deploy/assetlinks.json.example`.
5. Publish the result at
   `https://AUTH_DOMAIN/.well-known/assetlinks.json`.
6. Return HTTP status 200 without a redirect.
7. Return the `application/json` content type.
8. Add the matching Android `asset_statements` resource.
9. Set the three WebAuthn server values.
10. Test registration, authentication, PRF output, password fallback, and
    recovery fallback on a release-signed physical device.

The server consumes each ceremony state before it verifies the response. A
ceremony expires after five minutes. The server verifies the challenge,
origin, relying-party ID, signature, user verification, credential counter,
and credential identity.

The Android credential provider can omit the WebAuthn pseudorandom function
(PRF) result. In that case, require the account password or recovery phrase.
Do not enable passkey-only recovery.

## Android integrity checks

Keep Warn as the default policy. Local checks do not prove that a device is
safe. They can miss a modified device. They can also report a clean test device
as modified. Play Integrity stays disabled until the final Google Play
application identity and a server-side verdict verifier exist.
