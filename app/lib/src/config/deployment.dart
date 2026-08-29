/// Public deployment values for the official Autharo service.
///
/// This value is not a secret. Keeping it in one file prevents account,
/// recovery, and synchronization screens from selecting different servers.
const autharoSyncServerUrl = 'https://autharo-api.onrender.com';

/// Enable only after Digital Asset Links is live and Render has WebAuthn set.
const autharoPasskeysEnabled = false;
