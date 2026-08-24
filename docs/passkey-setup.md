# Passkey deployment requirements

Passkeys cannot use a placeholder domain. Complete these items before you
enable passkey registration in the application.

1. Select the final Android application ID.
2. Select one HTTPS sign-in domain.
3. Use that domain as the WebAuthn relying-party ID and origin.
4. Create the final Android release signing key.
5. Get the SHA-256 fingerprint of the release signing certificate.
6. Replace the placeholders in `deploy/assetlinks.json.example`.
7. Publish the file as `https://DOMAIN/.well-known/assetlinks.json`.
8. Return HTTP 200 without a redirect.
9. Return `Content-Type: application/json`.
10. Add an Android `asset_statements` resource that includes the same URL.
11. Configure the server with the same relying-party ID and origin.
12. Implement server endpoints that create and verify WebAuthn ceremonies.
13. Keep each ceremony state on the server and delete it after one use.
14. Verify support for the WebAuthn PRF extension on each supported credential
    provider before you use its output to wrap the vault key.

The Android bridge accepts standard WebAuthn JSON from the server. It returns
Credential Manager response JSON to the caller. It does not accept or verify
that response. The server must verify the challenge, origin, relying-party ID,
signature, and signature counter.

Do not enable passkey-only vault recovery until the PRF flow has a tested
fallback. WebAuthn extensions are optional. A credential provider can create a
valid passkey and omit the PRF result that the vault-key wrapping design needs.
