# Production security configuration

## Certificate pins

The Android release build requires one production hostname and at least two
SPKI pins. SPKI means Subject Public Key Information. A pin is the SHA-256
digest of a certificate public key.

The pins name **root certificate authorities**, not the server's own key. The
API runs on Render, which issues and renews the certificate for
`api.authfactor.app` itself, from Let's Encrypt or Google Trust Services. The
project never holds that key, so a leaf pin would break at the first renewal
and could not have a backup.

For the production host, the client verifies the chain against the pinned
roots only. A certificate that any other authority issued fails ordinary path
validation, even when the device would otherwise trust that authority. The
hostname, expiry, and every other standard check still apply.

`scripts/build_release.ps1` sets both values and builds the release:

| Root | Authority | Pin |
|---|---|---|
| ISRG Root X1 | Let's Encrypt | `C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=` |
| ISRG Root X2 | Let's Encrypt | `diGVwiVYbubAI3RW4hB9xU8e/CH2GnkuvVFZE8zmgzI=` |
| GTS Root R1 | Google Trust Services | `hxqRlPTu1bMS/0DITB1SSu0vd4u/8l8TjPgfaAp63Gc=` |
| GTS Root R3 | Google Trust Services | `QXnt2YHvdHR3tJYmQIr0Paosp6t/nggsEGD4QJZ3Q0g=` |
| GTS Root R4 | Google Trust Services | `mEflZT5enoR1FuXLgYYGqnVEoZvmf9c2bVBpiOjYQ0c=` |

Each pin must name a root in the bundled `webpki-roots` store. The client
refuses to start with a pin that names none, and the
`the_production_pins_name_bundled_roots` test fails on it.

Compute a pin from a root certificate with this OpenSSL command:

```sh
openssl x509 -in root.pem -pubkey -noout   | openssl pkey -pubin -outform DER   | openssl dgst -sha256 -binary   | openssl base64 -A
```

Do not include a scheme, port, path, or wildcard in the hostname.

Check a build environment against the live server:

```sh
cargo test --lib -- --ignored live
```

### Changing the pins

Pin changes need an application update, so make them before the server needs
them.

- **Render adds an authority.** Add its root pins, release, and wait for the
  update to reach users before Render serves a certificate from it.
- **The API moves to another host.** Pin the new host's authorities. Keep the
  old pins until the move is complete.
- **A pinned root is retired.** Remove its pin only after no certificate the
  server could receive chains to it.

Never publish a release with a repeated pin.

## Passkeys

Set all server values together:

```text
WEBAUTHN_RP_ID=auth.example.com
WEBAUTHN_RP_ORIGIN=https://auth.example.com
WEBAUTHN_RP_NAME=AuthCore
WEBAUTHN_ANDROID_ORIGINS=android:apk-key-hash:BASE64URL_RELEASE_SHA256
```

The current Autharo Firebase Hosting identity uses:

```text
WEBAUTHN_RP_ID=autharo-auth-prod.web.app
WEBAUTHN_RP_ORIGIN=https://autharo-auth-prod.web.app
WEBAUTHN_RP_NAME=Autharo Authenticator
WEBAUTHN_ANDROID_ORIGINS=android:apk-key-hash:cLWpxJnUHnzH5oiVwvyeZGudE1s9Cx4jHIHPdX8vSUg
```

The server refuses a partial configuration. The origin must use HTTPS.

Complete these deployment steps before you enable the passkey UI:

1. Select the final Android package ID.
2. Create the final release signing key.
3. Get the SHA-256 fingerprint of the release signing certificate.
4. Confirm that `deploy/assetlinks.json.example` contains the certificate
   fingerprint used to sign the installed application. Add the Google Play
   app-signing fingerprint before a Play release.
5. Publish the result at
   `https://AUTH_DOMAIN/.well-known/assetlinks.json`.
6. Return HTTP status 200 without a redirect.
7. Return the `application/json` content type.
8. Add the matching Android `asset_statements` resource.
9. Set the four WebAuthn server values. The Android origin is the unpadded
   base64url form of the release certificate SHA-256 fingerprint, prefixed
   with `android:apk-key-hash:`. Add the Google Play signing origin as a
   comma-separated second value before a Play release.
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
