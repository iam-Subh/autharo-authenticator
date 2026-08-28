//! Registering and signing in (PRD sections 9.2.1, 9.5, 14.2).
//!
//! The same split as [`crate::transport`]: what to say lives here, opening the
//! socket does not. Both go through [`HttpClient`].
//!
//! # What crosses the wire, and what never does
//!
//! Section 9.2.1: the password is stretched with Argon2id against a
//! client-generated salt, and the result is split by HKDF into two halves. The
//! **authentication key** is sent. The **key-encryption key** is not, ever, and
//! nothing in this module can reach it — [`crate::account::derive_auth_key`]
//! returns only the half that travels.
//!
//! The wrapped vault key goes up as ciphertext the server cannot open. The
//! server stores an Argon2id hash of the authentication key under its own salt
//! (step 5), so a stolen database yields neither the vault key nor anything
//! that can be replayed as a login.
//!
//! # The salt comes from the client
//!
//! Section 9.2.1 step 2, and it is not incidental. A salt derived from the
//! email address would let anyone compute it, which turns the KDF into a
//! precomputable target for every account at once. The salt is generated on the
//! device that creates the account, stored in the password slot, and handed
//! back by `prelogin` so a second device can reproduce the derivation.
//!
//! # Sign-in tells you nothing about who exists
//!
//! Section 9.5 is the server's job, but the client has to cooperate with it:
//! `prelogin` returns parameters for an unknown address as readily as for a
//! known one, so this module must treat that response as ordinary rather than
//! as evidence. It does — it just derives a key and tries to log in, and the
//! failure it gets back is the same either way.

use core::fmt;

use zeroize::Zeroizing;

use crate::account::{Account, PasswordSlot, RecoverySlot};
use crate::pin::KdfParams;
use crate::secret::SecretString;
use crate::transport::{HttpClient, HttpRequest, HttpResponse, Method, b64_decode, b64_encode};

/// Why a request to the account endpoints failed.
#[derive(Debug)]
pub enum SessionError {
    /// The address or the password is wrong. Deliberately one variant for both:
    /// section 9.5 forbids telling them apart, and a client that split them
    /// would leak through its own error message what the server refused to say.
    InvalidCredentials,
    /// This address already has an account.
    AlreadyRegistered,
    /// The network, or the server.
    Transport { detail: String },
    /// A response this client could not read.
    Malformed { detail: String },
    /// The session has expired or been revoked — including by another device
    /// signing this one out (section 9.5).
    Unauthorized,
    /// The password was correct, but an existing device must authorize this
    /// new device with a single-use approval token.
    DeviceApprovalRequired,
    /// The server refused an action because this stored session has no matching
    /// permission.
    InsufficientScope,
    /// The persistent session is valid, but the action needs a short-lived
    /// password-authorized capability.
    ElevationRequired,
    /// The client requested a permission that the server does not issue.
    InvalidScope,
    /// A password-authorized capability is no longer valid.
    CapabilityExpired,
    /// A stable server error that does not need client control flow.
    Remote { code: String, detail: String },
    /// A device that is not on this account, or no longer exists.
    NotFound { detail: String },
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCredentials => f.write_str(
                "[invalid_credentials] The email address or password is not correct.",
            ),
            Self::AlreadyRegistered => {
                f.write_str("[conflict] An account already exists for this email address.")
            }
            Self::Transport { detail } => {
                write!(f, "[transport] The sync server could not be reached: {detail}")
            }
            Self::Malformed { detail } => write!(
                f,
                "[invalid_response] The sync server sent a response this app cannot read: {detail}"
            ),
            Self::Unauthorized => f.write_str(
                "[unauthorized] This device has been signed out. Sign in again to keep syncing.",
            ),
            Self::DeviceApprovalRequired => f.write_str(
                "[device_approval_required] An existing device must approve this sign-in. Create an approval code on that device, then enter it here.",
            ),
            Self::InsufficientScope => {
                f.write_str("[insufficient_scope] This session does not permit that action. Sign in again.")
            }
            Self::ElevationRequired => {
                f.write_str("[elevation_required] Enter the account password to authorize this action.")
            }
            Self::InvalidScope => f.write_str("[invalid_scope] This permission is not available."),
            Self::CapabilityExpired => {
                f.write_str("[capability_expired] The temporary authorization expired. Enter the password again.")
            }
            Self::NotFound { detail } => write!(f, "[not_found] {detail}"),
            Self::Remote { code, detail } => write!(f, "[{code}] {detail}"),
        }
    }
}

impl std::error::Error for SessionError {}

type Result<T> = core::result::Result<T, SessionError>;

/// A signed-in session, and the slots the server was holding.
#[derive(Debug)]
pub struct Session {
    pub access_token: SecretString,
    pub refresh_token: SecretString,
    /// The wrapped vault key for the password slot. Still ciphertext: the
    /// server has never seen the key that opens it.
    pub password_slot: WrappedSlot,
    pub recovery_slot: WrappedSlot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityStatus {
    pub linked: bool,
    pub provider: Option<String>,
    pub verified_email: Option<String>,
}

/// One wrapped copy of the vault key as the server stores it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedSlot {
    pub wrapped_key: Vec<u8>,
    pub nonce: Vec<u8>,
}

/// A renewed session. Both halves are new: the server rotates them together.
#[derive(Debug)]
pub struct Renewal {
    pub access_token: SecretString,
    pub refresh_token: SecretString,
}

/// What `prelogin` gives a device that does not hold the account's slot yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prelogin {
    pub client_salt: Vec<u8>,
    pub params: KdfParams,
}

#[derive(Debug)]
pub struct RecoveryStart {
    pub reset_token: SecretString,
    pub recovery_slot: WrappedSlot,
    pub expires_at: String,
}

/// The account endpoints, over an injected client.
/// One device on the account, for the "your devices" screen (section 9.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceSummary {
    pub id: String,
    pub name: String,
    /// `android`, `windows`, `linux`, and so on. Whatever the device said at
    /// sign-in; not trusted for anything, only shown.
    pub platform: String,
    /// RFC 3339, as the server wrote it. Left as text rather than parsed: this
    /// is displayed, and a parse here would be a second date implementation to
    /// keep correct for no gain.
    pub last_seen: Option<String>,
    /// True for the device making the request.
    pub current: bool,
    pub revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceApproval {
    pub token: SecretString,
    pub expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub access_token: SecretString,
    pub scopes: Vec<String>,
    pub expires_at: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SecurityEventSummary {
    pub id: i64,
    pub event_type: String,
    pub created_at: String,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
    pub detail: serde_json::Value,
}

impl DeviceSummary {
    fn from_json(value: &serde_json::Value) -> Result<Self> {
        let text = |key: &str| {
            value
                .get(key)
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        };

        Ok(Self {
            // The identifier is the only field worth failing over: without it
            // the row cannot be revoked, which is the one thing the screen is
            // for. A missing name is cosmetic and gets a placeholder.
            id: text("id").ok_or_else(|| SessionError::Malformed {
                detail: "a device has no identifier".to_string(),
            })?,
            name: text("name").unwrap_or_else(|| "Unnamed device".to_string()),
            platform: text("platform").unwrap_or_else(|| "unknown".to_string()),
            last_seen: text("last_seen"),
            current: value
                .get("current")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            revoked: value
                .get("revoked")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
        })
    }
}

pub struct SessionClient<C: HttpClient> {
    client: C,
    base: String,
}

impl<C: HttpClient> SessionClient<C> {
    pub fn new(client: C, base_url: &str) -> Self {
        Self {
            client,
            base: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Creates the account on the server around slots this device already has.
    ///
    /// The slots are built locally first by [`crate::account::create_account`],
    /// which wraps the **existing** vault key. Generating a fresh one here
    /// would orphan every entry already stored.
    pub fn register(
        &self,
        account: &Account,
        auth_key: &Zeroizing<[u8; 32]>,
        recovery_auth_key: &Zeroizing<[u8; 32]>,
        identity_token: Option<&str>,
    ) -> Result<()> {
        let slot = account
            .password_slot
            .as_ref()
            .ok_or_else(|| SessionError::Malformed {
                detail: "this account has no password slot to register".to_string(),
            })?;

        let mut body = serde_json::json!({
            "email": account.email,
            "auth_key": b64_encode(auth_key.as_slice()),
            "recovery_auth_key": b64_encode(recovery_auth_key.as_slice()),
            "kdf_params": params_json(slot.params),
            "client_salt": b64_encode(&slot.salt),
            "password_slot": wrapped_json(&slot.wrapped_key, &slot.nonce),
            "recovery_slot": wrapped_json(
                &account.recovery_slot.wrapped_key,
                &account.recovery_slot.nonce,
            ),
        });
        if let Some(token) = identity_token {
            body["identity_token"] = serde_json::Value::String(token.to_string());
        }

        let response = self.send(Method::Post, "/v1/auth/register", Some(body))?;
        match response.status {
            200..=299 => Ok(()),
            409 => Err(SessionError::AlreadyRegistered),
            status => Err(self.failure(status, &response.body)),
        }
    }

    /// The KDF parameters for an address, so a new device can derive the same
    /// key from the same password.
    ///
    /// Answers for an unknown address exactly as it does for a known one
    /// (section 9.5). Treating a successful response as proof the account
    /// exists would rebuild, on the client, the oracle the server refuses to
    /// be.
    pub fn prelogin(&self, email: &str) -> Result<Prelogin> {
        let body = serde_json::json!({ "email": email });
        let response = self.send(Method::Post, "/v1/auth/prelogin", Some(body))?;
        if !(200..300).contains(&response.status) {
            return Err(self.failure(response.status, &response.body));
        }

        let value: serde_json::Value = serde_json::from_slice(&response.body).map_err(malformed)?;
        Ok(Prelogin {
            client_salt: decode(&value, "client_salt")?,
            params: params_from(&value["kdf_params"])?,
        })
    }

    pub fn start_password_recovery(
        &self,
        email: &str,
        recovery_auth_key: &Zeroizing<[u8; 32]>,
    ) -> Result<RecoveryStart> {
        let body = serde_json::json!({
            "email": email,
            "recovery_auth_key": b64_encode(recovery_auth_key.as_slice()),
        });
        let response = self.send(Method::Post, "/v1/auth/recovery/start", Some(body))?;
        if response.status == 401 {
            return Err(SessionError::InvalidCredentials);
        }
        let value = self.read(response)?;
        Ok(RecoveryStart {
            reset_token: token(&value, "reset_token")?,
            recovery_slot: slot_from(&value["recovery_slot"])?,
            expires_at: value
                .get("expires_at")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_string(),
        })
    }

    pub fn finish_password_recovery(
        &self,
        reset_token: &SecretString,
        new_auth_key: &Zeroizing<[u8; 32]>,
        new_slot: &PasswordSlot,
        device_name: Option<&str>,
    ) -> Result<Session> {
        let body = serde_json::json!({
            "reset_token": reset_token.expose(),
            "new_auth_key": b64_encode(new_auth_key.as_slice()),
            "kdf_params": params_json(new_slot.params),
            "client_salt": b64_encode(&new_slot.salt),
            "password_slot": wrapped_json(&new_slot.wrapped_key, &new_slot.nonce),
            "device_name": device_name,
            "device_platform": std::env::consts::OS,
        });
        let response = self.send(Method::Post, "/v1/auth/recovery/finish", Some(body))?;
        if response.status == 401 {
            return Err(SessionError::InvalidCredentials);
        }
        let value = self.read(response)?;
        Ok(Session {
            access_token: token(&value, "access_token")?,
            refresh_token: token(&value, "refresh_token")?,
            password_slot: slot_from(&value["password_slot"])?,
            recovery_slot: slot_from(&value["recovery_slot"])?,
        })
    }

    /// Exchanges a refresh token for a new pair (section 13).
    ///
    /// Without this a device syncs for fifteen minutes after signing in and
    /// then never again — every cycle gets a 401 and the only way back is the
    /// account password. On a device syncing in the background the user never
    /// sees it stop; they find out when a code added on their phone is missing
    /// on their laptop a week later.
    ///
    /// The server rotates the pair and revokes the token that was spent, so the
    /// caller must store what comes back. A caller that kept the old refresh
    /// token would be signed out at the next attempt.
    pub fn refresh(&self, refresh_token: &SecretString) -> Result<Renewal> {
        let body = serde_json::json!({ "refresh_token": refresh_token.expose() });
        let response = self.send(Method::Post, "/v1/auth/refresh", Some(body))?;

        match response.status {
            200..=299 => {}
            // Expired, revoked, or never real. The server does not distinguish
            // them and neither does this: the action is the same, and the
            // difference would tell whoever holds a stolen token whether it
            // was ever valid.
            401 => return Err(SessionError::InvalidCredentials),
            status => return Err(self.failure(status, &response.body)),
        }

        let value: serde_json::Value = serde_json::from_slice(&response.body).map_err(malformed)?;
        Ok(Renewal {
            access_token: token(&value, "access_token")?,
            refresh_token: token(&value, "refresh_token")?,
        })
    }

    /// Exchanges the authentication key for a session.
    pub fn login(
        &self,
        email: &str,
        auth_key: &Zeroizing<[u8; 32]>,
        device_name: Option<&str>,
    ) -> Result<Session> {
        self.login_with_approval(email, auth_key, device_name, None, None)
    }

    pub fn login_with_approval(
        &self,
        email: &str,
        auth_key: &Zeroizing<[u8; 32]>,
        device_name: Option<&str>,
        device_approval_token: Option<&str>,
        recovery_auth_key: Option<&Zeroizing<[u8; 32]>>,
    ) -> Result<Session> {
        let body = serde_json::json!({
            "email": email,
            "auth_key": b64_encode(auth_key.as_slice()),
            "device_name": device_name,
            "device_platform": std::env::consts::OS,
            "device_approval_token": device_approval_token,
            "recovery_auth_key": recovery_auth_key.map(|value| b64_encode(value.as_slice())),
        });

        let response = self.send(Method::Post, "/v1/auth/login", Some(body))?;
        match response.status {
            200..=299 => {}
            401 => return Err(SessionError::InvalidCredentials),
            403 => return Err(self.failure(403, &response.body)),
            status => return Err(self.failure(status, &response.body)),
        }

        let value: serde_json::Value = serde_json::from_slice(&response.body).map_err(malformed)?;
        Ok(Session {
            access_token: token(&value, "access_token")?,
            refresh_token: token(&value, "refresh_token")?,
            password_slot: slot_from(&value["password_slot"])?,
            recovery_slot: slot_from(&value["recovery_slot"])?,
        })
    }

    // -----------------------------------------------------------------
    // Section 9.5: devices, sign-out, and deletion
    // -----------------------------------------------------------------

    /// Every device that has signed in to this account.
    ///
    /// Revoked ones are included. Someone checking whether the phone they lost
    /// is really cut off needs to see it listed as cut off — a list that has
    /// simply stopped mentioning it proves nothing.
    pub fn devices(&self, access_token: &SecretString) -> Result<Vec<DeviceSummary>> {
        let response = self.send_auth(Method::Get, "/v1/devices", access_token, None)?;
        let value = self.read(response)?;

        let list = value
            .get("devices")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| SessionError::Malformed {
                detail: "the device list is missing".to_string(),
            })?;

        list.iter().map(DeviceSummary::from_json).collect()
    }

    pub fn rename_device(
        &self,
        access_token: &SecretString,
        device_id: &str,
        name: &str,
    ) -> Result<()> {
        let response = self.send_auth(
            Method::Put,
            &format!("/v1/devices/{device_id}"),
            access_token,
            Some(serde_json::json!({ "name": name })),
        )?;
        match response.status {
            200..=299 => Ok(()),
            401 => Err(SessionError::Unauthorized),
            404 => Err(SessionError::NotFound {
                detail: "That active device is not on this account.".to_string(),
            }),
            status => Err(self.failure(status, &response.body)),
        }
    }

    /// Registers the current Firebase installation token for this device.
    /// The token routes a generic signal only. It is not an access token.
    pub fn set_push_token(&self, access_token: &SecretString, token: &str) -> Result<()> {
        let body = serde_json::json!({ "token": token });
        let response = self.send_auth(
            Method::Put,
            "/v1/devices/push-token",
            access_token,
            Some(body),
        )?;
        self.read(response).map(|_| ())
    }

    pub fn clear_push_token(&self, access_token: &SecretString) -> Result<()> {
        let response =
            self.send_auth(Method::Delete, "/v1/devices/push-token", access_token, None)?;
        self.read(response).map(|_| ())
    }

    pub fn identity_status(&self, access_token: &SecretString) -> Result<IdentityStatus> {
        let response = self.send_auth(Method::Get, "/v1/account/identity", access_token, None)?;
        let value = self.read(response)?;
        Ok(IdentityStatus {
            linked: value
                .get("linked")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            provider: value
                .get("provider")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            verified_email: value
                .get("verified_email")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
        })
    }

    pub fn link_identity(
        &self,
        access_token: &SecretString,
        auth_key: &Zeroizing<[u8; 32]>,
        identity_token: &str,
    ) -> Result<IdentityStatus> {
        let response = self.send_auth(
            Method::Put,
            "/v1/account/identity",
            access_token,
            Some(serde_json::json!({
                "auth_key": b64_encode(auth_key.as_slice()),
                "identity_token": identity_token,
            })),
        )?;
        let value = self.read(response)?;
        Ok(IdentityStatus {
            linked: value
                .get("linked")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            provider: value
                .get("provider")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            verified_email: value
                .get("verified_email")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
        })
    }

    /// Cuts one device off: its sessions end in the same request.
    pub fn revoke_device(
        &self,
        access_token: &SecretString,
        device_id: &str,
        auth_key: &Zeroizing<[u8; 32]>,
    ) -> Result<u64> {
        let response = self.send_auth(
            Method::Delete,
            &format!("/v1/devices/{device_id}"),
            access_token,
            Some(serde_json::json!({ "auth_key": b64_encode(auth_key.as_slice()) })),
        )?;
        let value = self.read(response)?;
        Ok(value
            .get("sessions_ended")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0))
    }

    /// Ends every session on the account, including this one.
    pub fn sign_out_everywhere(
        &self,
        access_token: &SecretString,
        auth_key: &Zeroizing<[u8; 32]>,
    ) -> Result<u64> {
        let body = serde_json::json!({ "auth_key": b64_encode(auth_key.as_slice()) });
        let response = self.send_auth(
            Method::Post,
            "/v1/auth/logout-all",
            access_token,
            Some(body),
        )?;
        let value = self.read(response)?;
        Ok(value
            .get("sessions_ended")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0))
    }

    /// Ends this session only.
    pub fn sign_out(&self, access_token: &SecretString) -> Result<()> {
        self.send_auth(Method::Post, "/v1/auth/logout", access_token, None)
            .map(|_| ())
    }

    /// Exchanges a password proof for a short-lived, non-refreshable token.
    pub fn elevate(
        &self,
        access_token: &SecretString,
        auth_key: &Zeroizing<[u8; 32]>,
        scopes: &[&str],
    ) -> Result<Capability> {
        let body = serde_json::json!({
            "auth_key": b64_encode(auth_key.as_slice()),
            "scopes": scopes,
        });
        let value = self.read(self.send_auth(
            Method::Post,
            "/v1/auth/elevate",
            access_token,
            Some(body),
        )?)?;
        let scopes = value
            .get("scopes")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| SessionError::Malformed {
                detail: "the elevated permission list is missing".to_string(),
            })?
            .iter()
            .map(|scope| {
                scope
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| SessionError::Malformed {
                        detail: "an elevated permission is not text".to_string(),
                    })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Capability {
            access_token: token(&value, "access_token")?,
            scopes,
            expires_at: value
                .get("expires_at")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| SessionError::Malformed {
                    detail: "the elevated permission expiry is missing".to_string(),
                })?
                .to_string(),
        })
    }

    pub fn create_device_approval(
        &self,
        access_token: &SecretString,
        auth_key: &Zeroizing<[u8; 32]>,
    ) -> Result<DeviceApproval> {
        let body = serde_json::json!({ "auth_key": b64_encode(auth_key.as_slice()) });
        let value = self.read(self.send_auth(
            Method::Post,
            "/v1/device-approvals",
            access_token,
            Some(body),
        )?)?;
        Ok(DeviceApproval {
            token: token(&value, "token")?,
            expires_at: value
                .get("expires_at")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| SessionError::Malformed {
                    detail: "the approval expiry is missing".to_string(),
                })?
                .to_string(),
        })
    }

    pub fn enroll_recovery_access(
        &self,
        access_token: &SecretString,
        auth_key: &Zeroizing<[u8; 32]>,
        recovery_auth_key: &Zeroizing<[u8; 32]>,
        recovery_slot: &RecoverySlot,
    ) -> Result<()> {
        let body = serde_json::json!({
            "auth_key": b64_encode(auth_key.as_slice()),
            "recovery_auth_key": b64_encode(recovery_auth_key.as_slice()),
            "recovery_slot": wrapped_json(
                &recovery_slot.wrapped_key,
                &recovery_slot.nonce,
            ),
        });
        let response = self.send_auth(
            Method::Post,
            "/v1/recovery/enroll",
            access_token,
            Some(body),
        )?;
        match response.status {
            200..=299 => Ok(()),
            401 => Err(SessionError::Unauthorized),
            status => Err(self.failure(status, &response.body)),
        }
    }

    /// Replaces the account password and returns a new base session.
    ///
    /// The replacement slot contains ciphertext only. The server revokes all
    /// older sessions and devices before it returns this token pair.
    pub fn change_password(
        &self,
        access_token: &SecretString,
        current_auth_key: &Zeroizing<[u8; 32]>,
        new_auth_key: &Zeroizing<[u8; 32]>,
        new_slot: &PasswordSlot,
    ) -> Result<Renewal> {
        let body = serde_json::json!({
            "current_auth_key": b64_encode(current_auth_key.as_slice()),
            "new_auth_key": b64_encode(new_auth_key.as_slice()),
            "kdf_params": params_json(new_slot.params),
            "client_salt": b64_encode(&new_slot.salt),
            "password_slot": wrapped_json(&new_slot.wrapped_key, &new_slot.nonce),
        });
        let value = self.read(self.send_auth(
            Method::Put,
            "/v1/account/password",
            access_token,
            Some(body),
        )?)?;
        Ok(Renewal {
            access_token: token(&value, "access_token")?,
            refresh_token: token(&value, "refresh_token")?,
        })
    }

    pub fn security_activity(
        &self,
        access_token: &SecretString,
    ) -> Result<Vec<SecurityEventSummary>> {
        let value =
            self.read(self.send_auth(Method::Get, "/v1/security/activity", access_token, None)?)?;
        let events = value
            .get("events")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| SessionError::Malformed {
                detail: "the security activity list is missing".to_string(),
            })?;
        events
            .iter()
            .map(|event| {
                Ok(SecurityEventSummary {
                    id: event
                        .get("id")
                        .and_then(serde_json::Value::as_i64)
                        .ok_or_else(|| SessionError::Malformed {
                            detail: "a security event has no identifier".to_string(),
                        })?,
                    event_type: event
                        .get("event_type")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("unknown")
                        .to_string(),
                    created_at: event
                        .get("created_at")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    device_id: event
                        .get("device_id")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string),
                    device_name: event
                        .get("device_name")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string),
                    detail: event.get("detail").cloned().unwrap_or_default(),
                })
            })
            .collect()
    }

    /// Deletes the account and everything stored under it. Irreversible.
    ///
    /// Takes the authentication key, not just the session. A stolen access
    /// token is exactly the situation the rest of this section exists for, and
    /// an attacker holding one must not be able to destroy the account its
    /// owner is trying to save.
    ///
    /// Returns how many encrypted records were destroyed, so a client can tell
    /// the user what went rather than reporting a bare success on the most
    /// irreversible action the product has.
    pub fn delete_account(
        &self,
        access_token: &SecretString,
        auth_key: &Zeroizing<[u8; 32]>,
    ) -> Result<i64> {
        let body = serde_json::json!({ "auth_key": b64_encode(auth_key.as_slice()) });
        let response = self.send_auth(Method::Delete, "/v1/account", access_token, Some(body))?;
        let value = self.read(response)?;
        Ok(value
            .get("records_deleted")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0))
    }

    /// Turns a response into JSON, mapping the statuses these endpoints use.
    fn read(&self, response: HttpResponse) -> Result<serde_json::Value> {
        match response.status {
            200..=299 => serde_json::from_slice(&response.body).map_err(malformed),
            // Distinct from `InvalidCredentials`. On these endpoints a 401
            // means the session went away — very often because another device
            // signed this one out, which is the feature working. Telling the
            // user their password is wrong would be both false and alarming.
            401 => Err(SessionError::Unauthorized),
            404 => Err(SessionError::NotFound {
                detail: "That device is not on this account.".to_string(),
            }),
            status => Err(self.failure(status, &response.body)),
        }
    }

    fn send_auth(
        &self,
        method: Method,
        path: &str,
        access_token: &SecretString,
        body: Option<serde_json::Value>,
    ) -> Result<HttpResponse> {
        let json = match body {
            Some(value) => Some(serde_json::to_vec(&value).map_err(malformed)?),
            None => None,
        };
        self.client
            .send(HttpRequest {
                method,
                url: format!("{}{path}", self.base),
                bearer: Some(access_token.expose().to_string()),
                json,
            })
            .map_err(|detail| SessionError::Transport { detail })
    }

    fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<HttpResponse> {
        let json = match body {
            Some(value) => Some(serde_json::to_vec(&value).map_err(malformed)?),
            None => None,
        };
        self.client
            .send(HttpRequest {
                method,
                url: format!("{}{path}", self.base),
                bearer: None,
                json,
            })
            .map_err(|detail| SessionError::Transport { detail })
    }

    fn failure(&self, status: u16, body: &[u8]) -> SessionError {
        let code = serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|value| value.get("error")?.as_str().map(str::to_string));
        match code.as_deref() {
            Some("invalid_credentials") => return SessionError::InvalidCredentials,
            Some("device_approval_required") => return SessionError::DeviceApprovalRequired,
            Some("insufficient_scope") => return SessionError::InsufficientScope,
            Some("elevation_required") => return SessionError::ElevationRequired,
            Some("invalid_scope") => return SessionError::InvalidScope,
            Some("capability_expired") => return SessionError::CapabilityExpired,
            _ => {}
        }
        let value = serde_json::from_slice::<serde_json::Value>(body).ok();
        let detail = value
            .as_ref()
            .and_then(|value| value.get("message"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("The server refused the request.")
            .to_string();
        if let Some(code) = code {
            return SessionError::Remote { code, detail };
        }
        if status == 401 {
            return SessionError::InvalidCredentials;
        }
        SessionError::Transport {
            detail: format!("the server returned status {status}"),
        }
    }
}

fn params_json(params: KdfParams) -> serde_json::Value {
    serde_json::json!({
        "m": params.memory_kib,
        "t": params.iterations,
        "p": params.lanes,
    })
}

fn params_from(value: &serde_json::Value) -> Result<KdfParams> {
    let field = |name: &str| -> Result<u32> {
        value[name]
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| SessionError::Malformed {
                detail: format!("the KDF parameters are missing {name}"),
            })
    };
    let params = KdfParams {
        memory_kib: field("m")?,
        iterations: field("t")?,
        lanes: field("p")?,
    };
    params.validate().map_err(|_| SessionError::Malformed {
        detail: "the KDF parameters are outside the supported range".to_string(),
    })?;
    Ok(params)
}

fn wrapped_json(wrapped_key: &[u8], nonce: &[u8]) -> serde_json::Value {
    serde_json::json!({
        "wrapped_key": b64_encode(wrapped_key),
        "nonce": b64_encode(nonce),
    })
}

fn slot_from(value: &serde_json::Value) -> Result<WrappedSlot> {
    Ok(WrappedSlot {
        wrapped_key: decode(value, "wrapped_key")?,
        nonce: decode(value, "nonce")?,
    })
}

fn decode(value: &serde_json::Value, field: &str) -> Result<Vec<u8>> {
    let text = value[field]
        .as_str()
        .ok_or_else(|| SessionError::Malformed {
            detail: format!("the response is missing {field}"),
        })?;
    b64_decode(text).map_err(|_| SessionError::Malformed {
        detail: format!("{field} is not valid base64url"),
    })
}

fn token(value: &serde_json::Value, field: &str) -> Result<SecretString> {
    value[field]
        .as_str()
        .map(SecretString::new)
        .ok_or_else(|| SessionError::Malformed {
            detail: format!("the response is missing {field}"),
        })
}

fn malformed(error: impl fmt::Display) -> SessionError {
    SessionError::Malformed {
        detail: error.to_string(),
    }
}

/// The wrapped slots the server holds, turned back into the local types.
///
/// A second device signs in, receives these, and unwraps the vault key with a
/// key-encryption key it derived itself. That is the whole point of the slot
/// model: the server hands over ciphertext and cannot participate.
pub fn slots_for_account(
    email: &str,
    prelogin: &Prelogin,
    session: &Session,
) -> core::result::Result<Account, SessionError> {
    let salt: [u8; 16] =
        prelogin
            .client_salt
            .as_slice()
            .try_into()
            .map_err(|_| SessionError::Malformed {
                detail: "the client salt is the wrong length".to_string(),
            })?;

    Ok(Account {
        email: email.to_string(),
        password_slot: Some(PasswordSlot {
            salt,
            params: prelogin.params,
            wrapped_key: session.password_slot.wrapped_key.clone(),
            nonce: session.password_slot.nonce.clone(),
        }),
        recovery_slot: RecoverySlot {
            wrapped_key: session.recovery_slot.wrapped_key.clone(),
            nonce: session.recovery_slot.nonce.clone(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct FakeClient {
        seen: RefCell<Vec<HttpRequest>>,
        status: u16,
        body: String,
    }

    impl FakeClient {
        fn answering(status: u16, body: &str) -> Self {
            Self {
                seen: RefCell::new(Vec::new()),
                status,
                body: body.to_string(),
            }
        }

        fn last(&self) -> serde_json::Value {
            let seen = self.seen.borrow();
            serde_json::from_slice(seen.last().unwrap().json.as_ref().unwrap()).unwrap()
        }
    }

    impl HttpClient for &FakeClient {
        fn send(&self, request: HttpRequest) -> core::result::Result<HttpResponse, String> {
            self.seen.borrow_mut().push(request);
            Ok(HttpResponse::new(
                self.status,
                self.body.as_bytes().to_vec(),
            ))
        }
    }

    fn account() -> Account {
        Account {
            email: "rupsa@example.invalid".to_string(),
            password_slot: Some(PasswordSlot {
                salt: [7; 16],
                params: KdfParams::default(),
                wrapped_key: vec![1, 2, 3],
                nonce: vec![4; 24],
            }),
            recovery_slot: RecoverySlot {
                wrapped_key: vec![5, 6],
                nonce: vec![8; 24],
            },
        }
    }

    /// The exit criterion for stage S4, restated on the client: whatever this
    /// module sends, the vault key is not in it.
    #[test]
    fn registration_never_sends_anything_that_opens_the_vault() {
        let client = FakeClient::answering(200, r#"{"account_id":"x"}"#);
        let session = SessionClient::new(&client, "https://example.invalid");

        let auth_key = Zeroizing::new([0xABu8; 32]);
        session
            .register(&account(), &auth_key, &Zeroizing::new([0xCDu8; 32]), None)
            .unwrap();

        let body = client.last();

        // What must be there.
        assert_eq!(body["auth_key"], b64_encode(&[0xABu8; 32]));
        assert_eq!(body["recovery_auth_key"], b64_encode(&[0xCDu8; 32]));
        assert_eq!(body["client_salt"], b64_encode(&[7u8; 16]));
        assert_eq!(body["password_slot"]["wrapped_key"], b64_encode(&[1, 2, 3]));
        assert_eq!(body["recovery_slot"]["wrapped_key"], b64_encode(&[5, 6]));

        // And nothing else. An allowlist rather than a list of forbidden
        // words: a denylist only catches what someone thought to name, and
        // says nothing about a field added later. This fails the moment the
        // body grows anything, which is when someone should look at it.
        //
        // The first version of this check *was* a denylist, and it flagged
        // `password_slot` — a field that carries ciphertext and belongs here.
        // A check that cries wolf on the correct behaviour gets deleted.
        let mut sent: Vec<&String> = body.as_object().unwrap().keys().collect();
        sent.sort();
        assert_eq!(
            sent,
            [
                "auth_key",
                "client_salt",
                "email",
                "kdf_params",
                "password_slot",
                "recovery_auth_key",
                "recovery_slot",
            ],
            "the registration body has changed shape; check what was added"
        );

        // The two slots carry ciphertext and a nonce, and no third thing.
        for slot in ["password_slot", "recovery_slot"] {
            let mut fields: Vec<&String> = body[slot].as_object().unwrap().keys().collect();
            fields.sort();
            assert_eq!(fields, ["nonce", "wrapped_key"], "{slot}");
        }
    }

    #[test]
    fn registration_sends_the_verified_identity_token_when_present() {
        let client = FakeClient::answering(200, r#"{"account_id":"x"}"#);
        let session = SessionClient::new(&client, "https://example.invalid");

        session
            .register(
                &account(),
                &Zeroizing::new([0xABu8; 32]),
                &Zeroizing::new([0xCDu8; 32]),
                Some("firebase-id-token"),
            )
            .unwrap();

        let body = client.last();
        assert_eq!(body["identity_token"], "firebase-id-token");
        assert!(body.get("vault_key").is_none());
        assert!(body.get("password").is_none());
        assert!(body.get("recovery_phrase").is_none());
    }

    #[test]
    fn the_kdf_parameters_travel_so_another_device_can_reproduce_the_key() {
        let client = FakeClient::answering(200, r#"{"account_id":"x"}"#);
        let session = SessionClient::new(&client, "https://example.invalid");
        session
            .register(
                &account(),
                &Zeroizing::new([0u8; 32]),
                &Zeroizing::new([1u8; 32]),
                None,
            )
            .unwrap();

        let params = KdfParams::default();
        let body = client.last();
        assert_eq!(body["kdf_params"]["m"], params.memory_kib);
        assert_eq!(body["kdf_params"]["t"], params.iterations);
        assert_eq!(body["kdf_params"]["p"], params.lanes);
    }

    #[test]
    fn a_second_registration_of_the_same_address_says_so() {
        let client = FakeClient::answering(409, r#"{"error":"conflict"}"#);
        let session = SessionClient::new(&client, "https://example.invalid");
        let error = session
            .register(
                &account(),
                &Zeroizing::new([0u8; 32]),
                &Zeroizing::new([1u8; 32]),
                None,
            )
            .unwrap_err();
        assert!(matches!(error, SessionError::AlreadyRegistered));
    }

    #[test]
    fn a_wrong_password_and_a_wrong_address_fail_identically() {
        let client = FakeClient::answering(401, r#"{"error":"invalid_credentials"}"#);
        let session = SessionClient::new(&client, "https://example.invalid");

        let error = session
            .login("nobody@example.invalid", &Zeroizing::new([0u8; 32]), None)
            .unwrap_err();

        assert!(
            matches!(error, SessionError::InvalidCredentials),
            "section 9.5: the client must not be able to tell them apart either"
        );
    }

    #[test]
    fn a_session_carries_the_slots_back_as_ciphertext() {
        let body = format!(
            r#"{{"access_token":"a","refresh_token":"r","password_slot":{{"wrapped_key":"{}","nonce":"{}"}},"recovery_slot":{{"wrapped_key":"{}","nonce":"{}"}}}}"#,
            b64_encode(&[1, 2, 3]),
            b64_encode(&[4; 24]),
            b64_encode(&[5, 6]),
            b64_encode(&[8; 24]),
        );
        let client = FakeClient::answering(200, &body);
        let session = SessionClient::new(&client, "https://example.invalid");

        let result = session
            .login(
                "rupsa@example.invalid",
                &Zeroizing::new([0u8; 32]),
                Some("phone"),
            )
            .unwrap();

        assert_eq!(result.password_slot.wrapped_key, vec![1, 2, 3]);
        assert_eq!(result.recovery_slot.nonce, vec![8; 24]);
        assert_eq!(result.access_token.expose(), "a");
    }

    #[test]
    fn a_refresh_returns_a_new_pair() {
        // Both halves. The server revokes the refresh token it was given, so a
        // caller that kept the old one is signed out at the next attempt — the
        // exact failure this endpoint exists to prevent, reintroduced.
        let client = FakeClient::answering(
            200,
            r#"{"access_token":"new-access","refresh_token":"new-refresh"}"#,
        );
        let session = SessionClient::new(&client, "https://example.invalid");

        let renewal = session.refresh(&SecretString::new("old-refresh")).unwrap();

        assert_eq!(renewal.access_token.expose(), "new-access");
        assert_eq!(
            renewal.refresh_token.expose(),
            "new-refresh",
            "the new refresh token must be kept, or the next renewal fails"
        );

        let sent = client.last();
        assert_eq!(sent["refresh_token"], "old-refresh");
    }

    #[test]
    fn a_spent_refresh_token_asks_for_a_sign_in() {
        let client = FakeClient::answering(401, r#"{"error":"unauthorized"}"#);
        let session = SessionClient::new(&client, "https://example.invalid");
        let error = session.refresh(&SecretString::new("spent")).unwrap_err();
        assert!(matches!(error, SessionError::InvalidCredentials));
    }

    #[test]
    fn a_push_route_is_bound_to_the_base_session() {
        let client = FakeClient::answering(200, r#"{"registered":true}"#);
        let session = SessionClient::new(&client, "https://example.invalid");

        session
            .set_push_token(&SecretString::new("base-access"), "fcm-route-token")
            .unwrap();

        let seen = client.seen.borrow();
        let request = seen.last().unwrap();
        assert_eq!(request.method, Method::Put);
        assert_eq!(request.url, "https://example.invalid/v1/devices/push-token");
        assert_eq!(request.bearer.as_deref(), Some("base-access"));
        drop(seen);
        assert_eq!(client.last()["token"], "fcm-route-token");
    }

    #[test]
    fn clearing_a_push_route_sends_no_body() {
        let client = FakeClient::answering(200, r#"{"registered":false}"#);
        let session = SessionClient::new(&client, "https://example.invalid");

        session
            .clear_push_token(&SecretString::new("base-access"))
            .unwrap();

        let seen = client.seen.borrow();
        let request = seen.last().unwrap();
        assert_eq!(request.method, Method::Delete);
        assert_eq!(request.url, "https://example.invalid/v1/devices/push-token");
        assert!(request.json.is_none());
    }

    #[test]
    fn the_tokens_are_not_printed() {
        let body = format!(
            r#"{{"access_token":"super-secret","refresh_token":"also-secret","password_slot":{{"wrapped_key":"{}","nonce":"{}"}},"recovery_slot":{{"wrapped_key":"{}","nonce":"{}"}}}}"#,
            b64_encode(&[1]),
            b64_encode(&[2]),
            b64_encode(&[3]),
            b64_encode(&[4]),
        );
        let client = FakeClient::answering(200, &body);
        let session = SessionClient::new(&client, "https://example.invalid");
        let result = session
            .login("x@example.invalid", &Zeroizing::new([0u8; 32]), None)
            .unwrap();

        let printed = format!("{result:?}");
        assert!(!printed.contains("super-secret"));
        assert!(!printed.contains("also-secret"));
    }

    #[test]
    fn prelogin_answers_for_an_unknown_address_and_the_client_believes_it() {
        // The server returns a deterministic fake salt for an address it does
        // not know (section 9.5). Nothing here may treat that as special.
        let body = format!(
            r#"{{"client_salt":"{}","kdf_params":{{"m":65536,"t":3,"p":4}}}}"#,
            b64_encode(&[9u8; 16])
        );
        let client = FakeClient::answering(200, &body);
        let session = SessionClient::new(&client, "https://example.invalid");

        let prelogin = session.prelogin("nobody@example.invalid").unwrap();
        assert_eq!(prelogin.client_salt, vec![9u8; 16]);
        assert_eq!(prelogin.params.iterations, 3);
    }

    #[test]
    fn signing_in_on_a_new_device_rebuilds_the_account_from_the_server() {
        let prelogin = Prelogin {
            client_salt: vec![7; 16],
            params: KdfParams::default(),
        };
        let session = Session {
            access_token: SecretString::new("a"),
            refresh_token: SecretString::new("r"),
            password_slot: WrappedSlot {
                wrapped_key: vec![1, 2, 3],
                nonce: vec![4; 24],
            },
            recovery_slot: WrappedSlot {
                wrapped_key: vec![5, 6],
                nonce: vec![8; 24],
            },
        };

        let rebuilt = slots_for_account("rupsa@example.invalid", &prelogin, &session).unwrap();

        assert_eq!(rebuilt, account());
    }

    #[test]
    fn a_salt_of_the_wrong_length_is_refused_rather_than_padded() {
        let prelogin = Prelogin {
            client_salt: vec![7; 15],
            params: KdfParams::default(),
        };
        let session = Session {
            access_token: SecretString::new("a"),
            refresh_token: SecretString::new("r"),
            password_slot: WrappedSlot {
                wrapped_key: vec![],
                nonce: vec![],
            },
            recovery_slot: WrappedSlot {
                wrapped_key: vec![],
                nonce: vec![],
            },
        };
        assert!(slots_for_account("x@example.invalid", &prelogin, &session).is_err());
    }

    #[test]
    fn changing_a_password_sends_only_proofs_and_wrapped_material() {
        let client = FakeClient::answering(
            200,
            r#"{"access_token":"new-access","refresh_token":"new-refresh"}"#,
        );
        let session = SessionClient::new(&client, "https://example.invalid");
        let slot = PasswordSlot {
            salt: [9; 16],
            params: KdfParams::default(),
            wrapped_key: vec![3; 48],
            nonce: vec![4; 24],
        };

        let result = session
            .change_password(
                &SecretString::new("capability"),
                &Zeroizing::new([1; 32]),
                &Zeroizing::new([2; 32]),
                &slot,
            )
            .unwrap();

        assert_eq!(result.access_token.expose(), "new-access");
        assert_eq!(result.refresh_token.expose(), "new-refresh");
        let seen = client.seen.borrow();
        let request = seen.last().unwrap();
        assert_eq!(request.method, Method::Put);
        assert_eq!(request.url, "https://example.invalid/v1/account/password");
        assert_eq!(request.bearer.as_deref(), Some("capability"));
        drop(seen);
        let body = client.last();
        assert_eq!(body["current_auth_key"], b64_encode(&[1; 32]));
        assert_eq!(body["new_auth_key"], b64_encode(&[2; 32]));
        assert_eq!(body["client_salt"], b64_encode(&[9; 16]));
        assert_eq!(body["password_slot"]["wrapped_key"], b64_encode(&[3; 48]));
        assert!(body.get("password").is_none());
        assert!(body.get("vault_key").is_none());
    }

    #[test]
    fn recovery_start_sends_a_derived_proof_not_the_phrase() {
        let body = format!(
            r#"{{"reset_token":"reset","expires_at":"soon","recovery_slot":{{"wrapped_key":"{}","nonce":"{}"}}}}"#,
            b64_encode(&[5; 48]),
            b64_encode(&[6; 24]),
        );
        let client = FakeClient::answering(200, &body);
        let session = SessionClient::new(&client, "https://example.invalid");

        let result = session
            .start_password_recovery("rupsa@example.invalid", &Zeroizing::new([7; 32]))
            .unwrap();

        assert_eq!(result.reset_token.expose(), "reset");
        assert_eq!(result.recovery_slot.wrapped_key, vec![5; 48]);
        let sent = client.last();
        assert_eq!(sent["recovery_auth_key"], b64_encode(&[7; 32]));
        assert!(sent.get("recovery_phrase").is_none());
    }

    #[test]
    fn renaming_a_device_uses_the_elevated_token() {
        let client = FakeClient::answering(204, "{}");
        let session = SessionClient::new(&client, "https://example.invalid");
        session
            .rename_device(&SecretString::new("capability"), "device-id", "Pixel 10")
            .unwrap();

        let seen = client.seen.borrow();
        let request = seen.last().unwrap();
        assert_eq!(request.method, Method::Put);
        assert_eq!(request.url, "https://example.invalid/v1/devices/device-id");
        assert_eq!(request.bearer.as_deref(), Some("capability"));
        drop(seen);
        assert_eq!(client.last()["name"], "Pixel 10");
    }
}
