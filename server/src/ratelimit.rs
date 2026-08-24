//! Sign-in rate limits (PRD sections 9.5 and 13).
//!
//! "Rate-limit sign-in to 10 attempts per account per hour and 100 per IP
//! address per hour."
//!
//! # The limit must not become an enumeration oracle
//!
//! This is the part that is easy to get wrong, and getting it wrong quietly
//! undoes section 9.5's other half.
//!
//! The obvious implementation counts attempts against an *account*, which means
//! looking the account up first, which means an address with no account cannot
//! be rate-limited — so eleven attempts against a real address return `429` and
//! eleven against an invented one return `401`. The status code then answers the
//! question that `prelogin`'s fake salt and timing floor exist to refuse. All
//! that careful work, undone by a counter.
//!
//! So the count is kept against the **submitted address**, normalised, whether
//! or not it names anything. An attacker learns that they have made ten attempts,
//! which they already knew.
//!
//! # Why the attempt is recorded before it is judged
//!
//! An attempt that is recorded only when it fails lets an attacker alternate a
//! wrong password with a right one and never accumulate a count. Recording
//! first, then checking, also means a request that dies part way through still
//! counts — which is the conservative direction.
//!
//! # What is not here
//!
//! No lockout. Ten attempts an hour is a rate, not a door that closes: a user
//! who mistypes their password ten times is inconvenienced for an hour, and a
//! user whose address is being attacked is not locked out of their own account
//! by the attacker's traffic. A lockout keyed on an address someone else chooses
//! is a denial-of-service anyone can trigger.

use std::net::{IpAddr, SocketAddr};

use axum::http::HeaderMap;

use crate::error::{ApiError, ApiResult};

/// The client's address, accounting for a reverse proxy.
///
/// # Why this is not simply the socket address
///
/// Behind a load balancer every request arrives from the balancer, so the
/// socket address is the same for everyone. The per-address limit would then be
/// a hundred sign-ins per hour *for the whole service*, and the first hour of a
/// busy morning would lock every user out. A rate limit that takes the service
/// down is worse than none.
///
/// # Why `X-Forwarded-For` is not trusted by default
///
/// Because a client can send it. Trusting it unconditionally turns the limit
/// into a formality — an attacker sends a different value each time and is
/// never counted. It is read only when `TRUST_FORWARDED_FOR` is set, which is
/// correct exactly when a proxy in front of this server overwrites the header,
/// and wrong the moment the server is reachable directly.
///
/// The leftmost entry is the original client. It is also the one a client can
/// forge, which is why the switch exists.
pub fn client_address(headers: &HeaderMap, socket: SocketAddr) -> IpAddr {
    if std::env::var("TRUST_FORWARDED_FOR").is_ok()
        && let Some(forwarded) = headers.get("x-forwarded-for")
        && let Ok(value) = forwarded.to_str()
        && let Some(first) = value.split(',').next()
        && let Ok(address) = first.trim().parse::<IpAddr>()
    {
        return address;
    }
    socket.ip()
}

/// Section 9.5's two limits.
pub const PER_ACCOUNT_PER_HOUR: i64 = 10;
pub const PER_ADDRESS_PER_HOUR: i64 = 100;
/// Registration performs an Argon2 hash. Keep this unauthenticated operation
/// below the sign-in address budget.
pub const REGISTRATIONS_PER_ADDRESS_PER_HOUR: i64 = 10;

/// The window both limits are measured over.
pub const WINDOW_SECONDS: i64 = 3600;

/// What is being counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// The submitted email address, normalised. Counted whether or not it names
    /// an account — see the note above on enumeration.
    Account,
    /// The client's network address.
    Address,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Account => "account",
            Self::Address => "address",
        }
    }

    fn limit(self) -> i64 {
        match self {
            Self::Account => PER_ACCOUNT_PER_HOUR,
            Self::Address => PER_ADDRESS_PER_HOUR,
        }
    }
}

/// Records one sign-in attempt and refuses it if either limit is now exceeded.
///
/// `address` is `None` when the client's address could not be determined. That
/// disables only the per-address limit; the per-account one still applies. It is
/// not treated as a reason to allow everything, and not silently: a deployment
/// that cannot see client addresses should know it is running with one of the
/// two limits off.
pub async fn record_and_check(
    db: &sqlx::PgPool,
    account_subject: &str,
    address: Option<IpAddr>,
) -> ApiResult<()> {
    // Discard what has fallen out of every window. Done here rather than on a
    // schedule: this table is written only on sign-in, so it grows slowly, and
    // a sweep that needs a cron job is a sweep that stops when the cron job is
    // forgotten. The delete is indexed and the table stays small.
    sweep(db).await?;

    // Recorded first. An attempt counted only when it fails lets an attacker
    // alternate a wrong password with a right one and never accumulate a count.
    insert(db, Kind::Account, account_subject).await?;
    if let Some(address) = address {
        insert(db, Kind::Address, &address.to_string()).await?;
    } else {
        tracing::warn!(
            "no client address on a sign-in attempt: the per-address limit in \
             section 9.5 is not being applied. Check the proxy configuration."
        );
    }

    check(db, Kind::Account, account_subject, Kind::Account.limit()).await?;
    if let Some(address) = address {
        check(
            db,
            Kind::Address,
            &address.to_string(),
            Kind::Address.limit(),
        )
        .await?;
    }
    Ok(())
}

/// Records an address-only attempt for an unauthenticated endpoint.
///
/// The endpoint name is part of the subject. This prevents prelogin traffic
/// from consuming the login budget and prevents one shared subject from
/// becoming a service-wide lockout.
pub async fn record_address_endpoint(
    db: &sqlx::PgPool,
    endpoint: &str,
    address: IpAddr,
    limit: i64,
) -> ApiResult<()> {
    sweep(db).await?;
    let subject = format!("{endpoint}:{address}");
    insert(db, Kind::Address, &subject).await?;
    check(db, Kind::Address, &subject, limit).await
}

async fn insert(db: &sqlx::PgPool, kind: Kind, subject: &str) -> ApiResult<()> {
    sqlx::query("INSERT INTO auth_attempt (subject, kind) VALUES ($1, $2)")
        .bind(subject)
        .bind(kind.as_str())
        .execute(db)
        .await?;
    Ok(())
}

async fn check(db: &sqlx::PgPool, kind: Kind, subject: &str, limit: i64) -> ApiResult<()> {
    let (count, oldest): (i64, Option<chrono::DateTime<chrono::Utc>>) = sqlx::query_as(
        "SELECT count(*), min(at) FROM auth_attempt
          WHERE kind = $1 AND subject = $2
            AND at > now() - make_interval(secs => $3)",
    )
    .bind(kind.as_str())
    .bind(subject)
    .bind(WINDOW_SECONDS as f64)
    .fetch_one(db)
    .await?;

    if count <= limit {
        return Ok(());
    }

    // Section 13: "Return 429 with a `Retry-After` header when a rate limit
    // applies." The value is when the oldest attempt in the window falls out of
    // it, which is the first moment another attempt could succeed — not a
    // constant, which would either tell the client to wait too long or send it
    // back to be refused again.
    let retry_after = oldest
        .map(|at| {
            let elapsed = (chrono::Utc::now() - at).num_seconds();
            (WINDOW_SECONDS - elapsed).clamp(1, WINDOW_SECONDS)
        })
        .unwrap_or(WINDOW_SECONDS);

    Err(ApiError::RateLimited { retry_after })
}

/// Discards rows that have fallen out of every window.
///
/// Called opportunistically rather than on a schedule: this table is only
/// written on sign-in, so it grows slowly, and a sweep that needs a cron job is
/// a sweep that stops running when the cron job is forgotten.
pub async fn sweep(db: &sqlx::PgPool) -> ApiResult<()> {
    sqlx::query("DELETE FROM auth_attempt WHERE at < now() - make_interval(secs => $1)")
        .bind((WINDOW_SECONDS * 2) as f64)
        .execute(db)
        .await?;
    Ok(())
}
