//! Record storage (PRD section 13).
//!
//! # This is not the sync engine
//!
//! Stage S4 ends at the dump test. The sync cycle, the conflict rules in
//! section 10.4, and the outbox drain are S5, with a 1000-operation
//! convergence test of their own. What is here stores rows and hands them
//! back: it does not merge, and it does not decide which of two writes wins.
//! It reports a disagreement and lets the client resolve it.
//!
//! Every `ciphertext` through here is opaque. The server has no vault key and
//! no way to obtain one.

use axum::Json;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::SharedState;
use crate::auth;
use crate::crypto;
use crate::error::{ApiError, ApiResult};
use crate::quota;

#[derive(Debug, Deserialize)]
pub struct IncomingRecord {
    pub entry_id: Uuid,
    /// Base64url. Absent for a tombstone.
    pub ciphertext: Option<String>,
    pub nonce: Option<String>,
    pub hlc: String,
    #[serde(default)]
    pub deleted: bool,
    /// The HLC this device last saw the server hold. `None` for an entry the
    /// server has never seen.
    pub base_hlc: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PushRequest {
    pub records: Vec<IncomingRecord>,
}

#[derive(Debug, Serialize)]
pub struct PushResponse {
    pub accepted: Vec<Uuid>,
    pub conflicts: Vec<Conflict>,
}

#[derive(Debug, Serialize)]
pub struct Conflict {
    pub entry_id: Uuid,
    /// What the server holds, so the client can resolve without a second call.
    pub hlc: String,
    pub ciphertext: Option<String>,
    pub nonce: Option<String>,
    pub deleted: bool,
}

pub async fn push_records(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(request): Json<PushRequest>,
) -> ApiResult<Json<PushResponse>> {
    let account_id = authenticate(&state, &headers).await?;
    quota::check_batch_size(request.records.len())?;

    let mut accepted = Vec::new();
    let mut conflicts = Vec::new();

    // Counted before anything is written, so a batch that would cross the
    // limit is refused whole rather than half-applied.
    let mut new_entries = 0i64;
    for incoming in &request.records {
        let (exists,): (bool,) = sqlx::query_as(
            "SELECT EXISTS(SELECT 1 FROM record WHERE account_id = $1 AND entry_id = $2)",
        )
        .bind(account_id)
        .bind(incoming.entry_id)
        .fetch_one(&state.db)
        .await?;
        if !exists && !incoming.deleted {
            new_entries += 1;
        }
    }
    quota::check_entry_limit(&state.db, account_id, new_entries).await?;

    for incoming in request.records {
        let ciphertext = match &incoming.ciphertext {
            Some(value) => Some(decode(value)?),
            None => None,
        };
        if let Some(bytes) = &ciphertext {
            quota::check_record_size(bytes.len())?;
        }
        let nonce = match &incoming.nonce {
            Some(value) => Some(decode(value)?),
            None => None,
        };

        let current = sqlx::query_as::<_, (String, Option<Vec<u8>>, Option<Vec<u8>>, bool)>(
            "SELECT hlc, ciphertext, nonce, deleted FROM record
              WHERE account_id = $1 AND entry_id = $2",
        )
        .bind(account_id)
        .bind(incoming.entry_id)
        .fetch_optional(&state.db)
        .await?;

        // The base revision check, and nothing more. Deciding which write wins
        // is section 10.4's job and belongs to S5.
        if let Some((held_hlc, held_ciphertext, held_nonce, held_deleted)) = &current
            && incoming.base_hlc.as_deref() != Some(held_hlc.as_str())
        {
            conflicts.push(Conflict {
                entry_id: incoming.entry_id,
                hlc: held_hlc.clone(),
                ciphertext: held_ciphertext.as_deref().map(crypto::b64_encode),
                nonce: held_nonce.as_deref().map(crypto::b64_encode),
                deleted: *held_deleted,
            });
            continue;
        }

        sqlx::query(
            "INSERT INTO record (account_id, entry_id, ciphertext, nonce, hlc, deleted)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (account_id, entry_id) DO UPDATE SET
               ciphertext = excluded.ciphertext,
               nonce      = excluded.nonce,
               hlc        = excluded.hlc,
               deleted    = excluded.deleted,
               seq        = nextval(pg_get_serial_sequence('record', 'seq'))",
        )
        .bind(account_id)
        .bind(incoming.entry_id)
        .bind(&ciphertext)
        .bind(&nonce)
        .bind(&incoming.hlc)
        .bind(incoming.deleted)
        .execute(&state.db)
        .await?;

        accepted.push(incoming.entry_id);
    }

    Ok(Json(PushResponse {
        accepted,
        conflicts,
    }))
}

#[derive(Debug, Deserialize)]
pub struct ChangesQuery {
    #[serde(default)]
    pub since: i64,
    #[serde(default = "default_limit")]
    pub limit: i64,
}

fn default_limit() -> i64 {
    500
}

#[derive(Debug, Serialize)]
pub struct ChangesResponse {
    pub records: Vec<OutgoingRecord>,
    pub cursor: i64,
    pub has_more: bool,
}

#[derive(Debug, Serialize)]
pub struct OutgoingRecord {
    pub entry_id: Uuid,
    pub ciphertext: Option<String>,
    pub nonce: Option<String>,
    pub hlc: String,
    pub deleted: bool,
    pub seq: i64,
}

pub async fn pull_changes(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(query): Query<ChangesQuery>,
) -> ApiResult<Json<ChangesResponse>> {
    let account_id = authenticate(&state, &headers).await?;
    let limit = query.limit.clamp(1, quota::MAX_BATCH as i64);

    // Section 10.4's prune watermark. A cursor at or below it means the client
    // may have missed a delete that has since been pruned, so a full re-sync
    // is the only correct answer.
    let (watermark,): (i64,) =
        sqlx::query_as("SELECT prune_watermark FROM sync_state WHERE account_id = $1")
            .bind(account_id)
            .fetch_optional(&state.db)
            .await?
            .unwrap_or((0,));

    if query.since > 0 && query.since <= watermark {
        return Err(ApiError::Conflict {
            message: "This device is too far behind and must re-sync in full.".to_string(),
        });
    }

    let rows = sqlx::query_as::<_, (Uuid, Option<Vec<u8>>, Option<Vec<u8>>, String, bool, i64)>(
        "SELECT entry_id, ciphertext, nonce, hlc, deleted, seq FROM record
          WHERE account_id = $1 AND seq > $2
          ORDER BY seq ASC LIMIT $3",
    )
    .bind(account_id)
    .bind(query.since)
    .bind(limit + 1)
    .fetch_all(&state.db)
    .await?;

    let has_more = rows.len() as i64 > limit;
    let records: Vec<OutgoingRecord> = rows
        .into_iter()
        .take(limit as usize)
        .map(
            |(entry_id, ciphertext, nonce, hlc, deleted, seq)| OutgoingRecord {
                entry_id,
                ciphertext: ciphertext.as_deref().map(crypto::b64_encode),
                nonce: nonce.as_deref().map(crypto::b64_encode),
                hlc,
                deleted,
                seq,
            },
        )
        .collect();

    let cursor = records.last().map(|r| r.seq).unwrap_or(query.since);

    Ok(Json(ChangesResponse {
        records,
        cursor,
        has_more,
    }))
}

async fn authenticate(state: &SharedState, headers: &HeaderMap) -> ApiResult<Uuid> {
    let token = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(ApiError::Unauthorized)?;

    auth::account_for_token(&state.db, token).await
}

fn decode(value: &str) -> ApiResult<Vec<u8>> {
    crypto::b64_decode(value).map_err(|_| ApiError::BadRequest {
        message: "a record field is not valid base64url".to_string(),
    })
}
