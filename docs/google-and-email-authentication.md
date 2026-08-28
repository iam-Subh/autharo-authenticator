# Google and verified-email authentication

The client and server implementation is complete. Production activation still
requires the Firebase project files and the final Android signing identity.

## Security boundary

Google or Firebase verifies account ownership. It does not encrypt the vault.
The application must still wrap the vault key with one of these secrets:

- an account password that only the client uses for key derivation;
- a passkey pseudorandom function (PRF) result;
- the 24-word recovery phrase.

Do not derive a vault key from a Google or Firebase ID token. The issuer and
the application server can read that token. The token also expires and changes.

## Selected provider

Use Firebase Authentication for these identity methods:

- Google Sign-In;
- email address and a separate identity password;
- verification email delivery.

Use the Firebase Local Emulator Suite during development. Keep production
identity disabled when `google-services.json` or server verification values are
absent.

## Registration sequence

1. Create the Firebase user with Google Sign-In or an email identity password.
2. For email registration, send the Firebase verification email.
3. Block sync-account registration until `emailVerified` is true.
4. Obtain a fresh Firebase ID token.
5. Use a separate vault password to create password and recovery slots on the
   Android device. Firebase never receives this password.
6. Send the Firebase ID token, the encrypted slots, and the authentication-key
   proof to the synchronization server.
7. Verify the Firebase token signature, issuer, audience, expiry, and subject
   on the server.
8. Store the Firebase user identifier as the external identity. Do not use the
   email address as the external identity key.
9. Require the token email to match the normalized account email.
10. Create the account and first device in one database transaction.

## Google sign-in sequence

1. Open the native Google provider through the supported Flutter plugin.
2. Exchange the Google ID token for a Firebase credential.
3. Send a fresh Firebase ID token to the synchronization server.
4. Verify the Firebase token on the server.
5. Require a vault password until the end-to-end passkey PRF flow is
   active.
6. Never send the encryption password to Firebase or Google.

## Existing email accounts

Existing accounts use a one-time identity-link operation. It requires all of
these items:

- an authenticated base session;
- a five-minute `security:read` capability;
- the current account password;
- a verified Firebase identity with the same normalized email address.

Record `identity_linked` in the security activity log. Do not link accounts by
email alone.

## Required configuration

Android:

- final application ID;
- debug and release SHA-1 and SHA-256 signing fingerprints;
- Firebase `google-services.json`;
- Google provider enabled in Firebase Authentication;
- email/password provider enabled in Firebase Authentication.

Server:

- `FIREBASE_AUTH_PROJECT_ID` with the Firebase project ID;
- production HTTPS origin;
- a release policy that rejects unverified registrations.

The server derives the accepted audience and issuer from the project ID. It
caches Google public keys according to the response cache policy.

## Tests

- Reject an invalid signature, issuer, audience, and expiry.
- Reject an unverified email registration.
- Reject a token whose email does not match the requested account.
- Reject identity reuse across two vault accounts.
- Verify Google and email registration create the same account structure.
- Verify a Google token never appears in logs or database dumps.
- Verify Firebase failure does not change local vault slots.
- Verify account linking requires the current password.
