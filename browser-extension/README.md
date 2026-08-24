# Authenticator Companion browser extension

This directory contains an unpacked Manifest V3 extension for Chromium and
Firefox. It does not read web pages and it does not request content-script
permissions.

## Pair the extension

1. Open an account menu in the Android application.
2. Select **Share encrypted link**.
3. Keep **Delete after first download** enabled.
4. Copy the link.
5. Open the extension.
6. Paste the complete link, including the text after `#`.
7. Set a separate browser master password.

The mobile action is the approval step. The extension cannot read the mobile
vault or request another account by itself.

## Local storage

The extension encrypts its local account list with AES-256-GCM. It derives the
key from the browser master password with PBKDF2-HMAC-SHA-256 and 600,000
iterations. The password and derived key stay in popup memory. Closing the
popup locks the extension.

## Load for development

In Chromium, open `chrome://extensions`, enable Developer mode, select **Load
unpacked**, and select this directory. In Firefox, open `about:debugging`,
select **This Firefox**, select **Load Temporary Add-on**, and select
`manifest.json`.

Do not publish this development package without store review, icons, release
signing, and an independent security review.
