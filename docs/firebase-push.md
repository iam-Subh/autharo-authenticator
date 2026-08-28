# Firebase push setup

The code is complete for Android Firebase Cloud Messaging (FCM) change
signals. The feature stays disabled until you supply the Firebase project
configuration.

FCM has no usage charge. The Firebase Spark plan is sufficient for this
feature. See [Firebase pricing](https://firebase.google.com/pricing) and the
[FCM product page](https://firebase.google.com/products/cloud-messaging).

## Data sent through Firebase

The server sends this fixed data only:

```json
{
  "type": "vault_changed",
  "schema": "1"
}
```

Do not add an issuer, account name, one-time code, secret, vault record, or
ciphertext to the FCM payload.

The message is a signal. The client uses the authenticated sync API to get the
encrypted changes. Entry payloads remain locked until the user authenticates.

## Values you must provide

Provide these two items when the Firebase project is ready:

1. The Android `google-services.json` file.
2. A server service-account JSON file that can send FCM messages.

Do not send a legacy FCM server key. The server uses the FCM HTTP v1 API and
Google Application Default Credentials. See the
[HTTP v1 authorization guide](https://firebase.google.com/docs/cloud-messaging/auth-server).

Treat the service-account JSON as a secret. Do not add it to Git. Store it in
the hosting provider's secret storage.

## Firebase console steps

1. Open the [Firebase console](https://console.firebase.google.com/).
2. Create a project on the Spark plan.
3. Add an Android application.
4. Use `app.autharo.authenticator` as the Android package name.
5. Confirm this package name before release. Firebase binds the file to it.
6. Download `google-services.json`.
7. Put the file at `app/android/app/google-services.json`.
8. Open Project settings, and then open Service accounts.
9. Create a service-account private key for the sync server.
10. Store that JSON file outside this repository.

The Android setup follows the official
[Firebase Android setup guide](https://firebase.google.com/docs/android/setup).

## Server variables

Set these variables on the sync server:

```text
FCM_PROJECT_ID=your-firebase-project-id
GOOGLE_APPLICATION_CREDENTIALS=/absolute/private/path/service-account.json
```

On Google Cloud, assign the required service identity and use Application
Default Credentials instead of a downloaded key when possible.

Restart the server after you set the variables. If `FCM_PROJECT_ID` is absent,
the server disables push. If the project ID exists but credentials are absent,
the server stops at startup and reports the configuration error.

## Verification

Use two physical Android devices with different sync device sessions.

1. Install the Firebase-configured application on both devices.
2. Open and unlock the application on both devices.
3. Sign in to the same sync account on both devices. Notification permission is not required.
4. Add or change an entry on device A.
5. Leave device B locked and move the application to the background.
6. Confirm that the background handler obtains the encrypted change.
7. Open and unlock device B. Confirm that the new entry is present.
8. Sign out device B.
9. Change an entry on device A again.
10. Confirm that device B no longer receives account update signals.

Also test device revocation. Revocation must remove the stored FCM route.

## Background execution

The server sends a data-only message with Android high priority. The handler
runs one bounded cycle. It does not display a notification. The cycle opens
the page-encrypted database with a separate Android Keystore key. Every entry
payload remains encrypted with the unavailable vault key.

Android can delay or stop background work. A force-stop from Android settings
prevents FCM delivery until the user opens the application again. Foreground
startup and the 15-minute foreground timer remain fallback triggers.

The implementation does not add Firebase credentials to the repository. It
does not run on iOS, Windows, macOS, or Linux.
