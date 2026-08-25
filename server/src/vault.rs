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
use std::collections::HashSet;
use uuid::Uuid;

use crate::SharedState;
use crate::auth;
use crate::crypto;
use crate::error::{ApiError, ApiResult};
use crate::push;
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
    let session = authenticate(&state, &headers).await?;
    let account_id = session.account_id;
    quota::check_batch_size(request.records.len())?;

    let mut identifiers = HashSet::with_capacity(request.records.len());
    let mut records = Vec::with_capacity(request.records.len());
    for incoming in request.records {
        if !identifiers.insert(incoming.entry_id) {
            return Err(ApiError::BadRequest {
                message: "A batch cannot contain the same entry twice.".to_string(),
            });
        }
        validate_hlc(&incoming.hlc)?;
        if let Some(base) = &incoming.base_hlc {
            validate_hlc(base)?;
        }
        let ciphertext = incoming.ciphertext.as_deref().map(decode).transpose()?;
        let nonce = incoming.nonce.as_deref().map(decode).transpose()?;
        if incoming.deleted {
            if ciphertext.is_some() || nonce.is_some() {
                return Err(ApiError::BadRequest {
                    message: "A deleted record cannot contain ciphertext or a nonce.".to_string(),
                });
            }
        } else {
            let Some(ciphertext_bytes) = ciphertext.as_ref() else {
                return Err(ApiError::BadRequest {
                    message: "A live record must contain ciphertext.".to_string(),
                });
            };
            quota::check_record_size(ciphertext_bytes.len())?;
            if nonce.as_ref().is_none_or(|bytes| bytes.len() != 24) {
                return Err(ApiError::BadRequest {
                    message: "A live record nonce must be 24 bytes.".to_string(),
                });
            }
        }
        records.push((incoming, ciphertext, nonce));
    }

    let mut transaction = state.db.begin().await?;
    // Serialize quota-changing operations for this account. This closes the
    // gap between a count and its following writes.
    sqlx::query("SELECT id FROM account WHERE id = $1 FOR UPDATE")
        .bind(account_id)
        .execute(&mut *transaction)
        .await?;

    let mut accepted = Vec::new();
    let mut conflicts = Vec::new();

    let (mut resulting_count,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM record WHERE account_id = $1 AND NOT deleted")
            .bind(account_id)
            .fetch_one(&mut *transaction)
            .await?;

    let mut writes = Vec::with_capacity(records.len());
    for (incoming, ciphertext, nonce) in records {
        let current = sqlx::query_as::<_, (String, Option<Vec<u8>>, Option<Vec<u8>>, bool)>(
            "SELECT hlc, ciphertext, nonce, deleted FROM record
              WHERE account_id = $1 AND entry_id = $2",
        )
        .bind(account_id)
        .bind(incoming.entry_id)
        .fetch_optional(&mut *transaction)
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

        if let Some((held_hlc, _, _, _)) = &current
            && incoming.hlc <= *held_hlc
        {
            return Err(ApiError::BadRequest {
                message: "An updated record must have a newer HLC.".to_string(),
            });
        }

        let was_live = current.as_ref().is_some_and(|row| !row.3);
        if was_live && incoming.deleted {
            resulting_count -= 1;
        } else if !was_live && !incoming.deleted {
            resulting_count += 1;
        }
        writes.push((incoming, ciphertext, nonce));
    }

    if resulting_count > quota::MAX_ENTRIES {
        return Err(ApiError::QuotaExceeded {
            message: format!(
                "An account can hold at most {} entries.",
                quota::MAX_ENTRIES
            ),
        });
    }

    for (incoming, ciphertext, nonce) in writes {
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
        .execute(&mut *transaction)
        .await?;

        accepted.push(incoming.entry_id);
    }

    transaction.commit().await?;

    if !accepted.is_empty() {
        push::notify_vault_changed(state.clone(), account_id, session.device_id).await;
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
    /// Set while the client is rebuilding its state from nothing (section
    /// 10.6), which suppresses the prune-watermark check below.
    #[serde(default)]
    pub full: bool,
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
    let account_id = authenticate(&state, &headers).await?.account_id;
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

    // Not during a full re-sync. The check is about a client resuming a cursor
    // it saved, which may have missed a delete that has since been pruned. A
    // re-sync walks up from zero, so every page after the first asks from a
    // sequence below the watermark by construction — refusing those refuses
    // page two of every re-sync on a vault larger than one page, and the
    // re-sync then can never complete, because it fails before it stores a
    // cursor and the next attempt starts from the same place.
    //
    // A missed delete cannot matter here in any case: the client is rebuilding
    // from nothing and drops whatever this server does not have.
    if !query.full && query.since > 0 && query.since <= watermark {
        return Err(ApiError::CursorTooOld {
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

async fn authenticate(state: &SharedState, headers: &HeaderMap) -> ApiResult<auth::Session> {
    let token = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(ApiError::Unauthorized)?;

    auth::session_for_token_with_scope(&state.db, token, auth::SCOPE_VAULT_SYNC).await
}

fn decode(value: &str) -> ApiResult<Vec<u8>> {
    crypto::b64_decode(value).map_err(|_| ApiError::BadRequest {
        message: "a record field is not valid base64url".to_string(),
    })
}

fn validate_hlc(value: &str) -> ApiResult<()> {
    let bytes = value.as_bytes();
    let valid = bytes.len() == 34
        && bytes[12] == b'-'
        && bytes[17] == b'-'
        && bytes.iter().enumerate().all(|(index, byte)| {
            index == 12 || index == 17 || byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)
        });
    if valid {
        Ok(())
    } else {
        Err(ApiError::BadRequest {
            message: "A record HLC must use 12-4-16 lowercase hexadecimal digits.".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::validate_hlc;

    #[test]
    fn accepts_the_wire_hlc_shape() {
        assert!(validate_hlc("01931f4a2c10-0003-a91b7f0e44d2c318").is_ok());
    }

    #[test]
    fn rejects_hlc_values_that_clients_cannot_parse() {
        for value in [
            "",
            "01931f4a2c10-0003",
            "01931f4a2c10-0003-a91b7f0e44d2c31z",
            "01931F4A2C10-0003-a91b7f0e44d2c318",
        ] {
            assert!(validate_hlc(value).is_err(), "{value} must be rejected");
        }
    }
}
