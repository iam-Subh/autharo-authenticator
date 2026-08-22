//! The hard quotas from NFR-11.
//!
//! Section 5.1: "A free service with no quota is an open storage service."
//! There is no payment step to bound abuse, so these limits are the only thing
//! that does.
//!
//! Each check runs before the write it guards, so a request that would exceed
//! a limit is refused rather than rolled back.

use uuid::Uuid;

use crate::error::{ApiError, ApiResult};

/// NFR-11, per account.
pub const MAX_ENTRIES: i64 = 2000;
pub const MAX_DEVICES: i64 = 10;
pub const MAX_RECORD_BYTES: usize = 4 * 1024;
/// Section 12.2 caps the payload at 3 KiB before encryption; NFR-11 caps the
/// encrypted record at 4 KiB. A client that respects the first never meets the
/// second, which is deliberate: the user should never see a server quota error.
pub const MAX_BATCH: usize = 500;

pub async fn check_device_limit(db: &sqlx::PgPool, account_id: Uuid) -> ApiResult<()> {
    let (count,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM device WHERE account_id = $1 AND NOT revoked")
            .bind(account_id)
            .fetch_one(db)
            .await?;

    if count >= MAX_DEVICES {
        return Err(ApiError::QuotaExceeded {
            message: format!(
                "This account already has {MAX_DEVICES} devices. Revoke one before adding another."
            ),
        });
    }
    Ok(())
}

/// Checks the entry count against NFR-11, counting only what a push would add.
///
/// `incoming_new` is the number of entry identifiers in the batch that the
/// account does not already hold. Updates to existing entries do not count: an
/// account at the limit must still be able to edit and delete, or the limit
/// would trap the user with no way down.
pub async fn check_entry_limit(
    db: &sqlx::PgPool,
    account_id: Uuid,
    incoming_new: i64,
) -> ApiResult<()> {
    if incoming_new == 0 {
        return Ok(());
    }

    let (count,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM record WHERE account_id = $1 AND NOT deleted")
            .bind(account_id)
            .fetch_one(db)
            .await?;

    if count + incoming_new > MAX_ENTRIES {
        return Err(ApiError::QuotaExceeded {
            message: format!("This account holds {count} entries and the limit is {MAX_ENTRIES}."),
        });
    }
    Ok(())
}

pub fn check_record_size(ciphertext_len: usize) -> ApiResult<()> {
    if ciphertext_len > MAX_RECORD_BYTES {
        return Err(ApiError::TooLarge);
    }
    Ok(())
}

pub fn check_batch_size(count: usize) -> ApiResult<()> {
    if count > MAX_BATCH {
        return Err(ApiError::BadRequest {
            message: format!("A batch holds at most {MAX_BATCH} records."),
        });
    }
    Ok(())
}
