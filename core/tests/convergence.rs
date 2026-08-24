//! The stage S5 exit criterion, driven against an in-memory server.
//!
//! The harness is in `harness/mod.rs` — the operations, the devices, the
//! oracle, the coverage floor and the invariants all live there, so that this
//! file and `convergence_http.rs` cannot drift into asserting different
//! things. What is here is the server itself, and the runs.
//!
//! ```text
//! cargo test --test convergence
//! CONVERGENCE_OPS=100000 cargo test --release --test convergence -- --ignored --nocapture
//! ```

mod harness;

use authcore::sync::{
    PullMode, PullResponse, PushRecord, PushResponse, SyncError, SyncTransport, WireRecord,
};

use harness::{Backend, Observed, go, operation_count};

// ---------------------------------------------------------------------------
// The server
// ---------------------------------------------------------------------------

/// What section 12.3 holds: ciphertext, a timestamp, and a sequence number.
#[derive(Default)]
struct Server {
    records: Vec<WireRecord>,
    next_seq: i64,
    prune_watermark: i64,
    /// Everything the server has accepted, kept so that a push whose response
    /// was lost can be replayed exactly as it was sent.
    accepted: Vec<PushRecord>,
}

impl Server {
    fn apply(&mut self, record: &PushRecord) {
        self.next_seq += 1;
        let wire = WireRecord {
            entry_id: record.entry_id.clone(),
            ciphertext: record.ciphertext.clone(),
            nonce: record.nonce.clone(),
            hlc: record.hlc,
            deleted: record.deleted,
            server_seq: self.next_seq,
        };
        match self
            .records
            .iter_mut()
            .find(|r| r.entry_id == wire.entry_id)
        {
            Some(existing) => *existing = wire,
            None => self.records.push(wire),
        }
        self.accepted.push(record.clone());
    }

    fn held(&self, entry_id: &str) -> Option<&WireRecord> {
        self.records.iter().find(|r| r.entry_id == entry_id)
    }
}

/// One device's connection to the server, with a partition switch.
struct Link<'a> {
    server: &'a mut Server,
    partitioned: bool,
    /// Entries the server reported as conflicts during this cycle.
    conflicted: Vec<String>,
    stale: bool,
}

impl<'a> Link<'a> {
    fn new(server: &'a mut Server, partitioned: bool) -> Self {
        Self {
            server,
            partitioned,
            conflicted: Vec::new(),
            stale: false,
        }
    }
}

impl SyncTransport for Link<'_> {
    fn pull(&mut self, since: i64, limit: i64, mode: PullMode) -> Result<PullResponse, SyncError> {
        if self.partitioned {
            return Err(SyncError::Transport {
                detail: "the device is partitioned".to_string(),
            });
        }
        // Exactly the server's rule, `full` flag and all. This model refusing
        // page two of a re-sync is what stranded three devices on their own
        // creations for sixty thousand operations.
        if mode == PullMode::Incremental && since > 0 && since <= self.server.prune_watermark {
            self.stale = true;
            return Err(SyncError::CursorTooOld);
        }

        let mut matching: Vec<WireRecord> = self
            .server
            .records
            .iter()
            .filter(|r| r.server_seq > since)
            .cloned()
            .collect();
        matching.sort_by_key(|r| r.server_seq);

        let has_more = matching.len() as i64 > limit;
        matching.truncate(limit as usize);
        let cursor = matching.last().map(|r| r.server_seq).unwrap_or(since);

        Ok(PullResponse {
            records: matching,
            cursor,
            has_more,
        })
    }

    fn push(&mut self, records: &[PushRecord]) -> Result<PushResponse, SyncError> {
        if self.partitioned {
            return Err(SyncError::Transport {
                detail: "the device is partitioned".to_string(),
            });
        }

        let mut accepted = Vec::new();
        let mut conflicts = Vec::new();

        for record in records {
            // The base-revision check, and nothing more — matching
            // `server/src/vault.rs`. Deciding which write wins is section
            // 10.4's job, on the client.
            //
            // The case that matters is a base the server cannot check because
            // it holds nothing for the entry. The real server falls through to
            // the insert and accepts it as a create. This model used to treat
            // it as neither accepted nor conflicted, and the record vanished:
            // not cleared from the outbox, and nothing to resolve, so the
            // client retried it forever with the same base. Three devices then
            // settled into holding their own creations and nothing else, which
            // is a state a real server would never have produced. A model that
            // is wrong about the thing it models is worse than no model.
            match self.server.held(&record.entry_id).cloned() {
                Some(current) if record.base_hlc != Some(current.hlc) => {
                    self.conflicted.push(record.entry_id.clone());
                    conflicts.push(current);
                }
                _ => {
                    self.server.apply(record);
                    accepted.push(record.entry_id.clone());
                }
            }
        }

        // Every record is answered for. A model that could drop one silently
        // is how the divergence above went unnoticed for a hundred thousand
        // operations.
        assert_eq!(
            accepted.len() + conflicts.len(),
            records.len(),
            "the server answered for {} of {} pushed records",
            accepted.len() + conflicts.len(),
            records.len(),
        );

        Ok(PushResponse {
            accepted,
            conflicts,
        })
    }
}
impl Backend for Server {
    fn open(&mut self, partitioned: bool) -> Box<dyn Observed + '_> {
        Box::new(Link::new(self, partitioned))
    }

    fn describe(&self, entry_id: &str) -> String {
        match self.held(entry_id) {
            Some(record) => format!(
                "holds {} at seq {}{}",
                record.hlc,
                record.server_seq,
                if record.deleted { ", deleted" } else { "" }
            ),
            None => "has never seen it".to_string(),
        }
    }

    fn summary(&self) -> String {
        format!(
            "server: {} records, next seq {}, prune watermark {}",
            self.records.len(),
            self.next_seq,
            self.prune_watermark
        )
    }

    fn prune(&mut self) -> bool {
        // The watermark trails the head by a retention window rather than
        // landing on it. A prune that reached the newest sequence would put
        // every device that is not exactly caught up into a full re-sync, and
        // that is not what a server does — it removes tombstones older than a
        // retention period. It also made the long run useless: nearly every
        // cycle became a full re-sync replaying the entire vault, so a hundred
        // thousand operations spent their time re-downloading rather than
        // interleaving.
        const RETENTION: i64 = 5;

        if self.next_seq <= RETENTION {
            return false;
        }
        let moved = self.next_seq - RETENTION;
        if moved <= self.prune_watermark {
            return false;
        }
        self.prune_watermark = moved;
        true
    }

    fn replay_push(&mut self, which: usize) -> bool {
        if self.accepted.is_empty() {
            return false;
        }
        // The most recent push the server would still accept, searched
        // backwards from the newest.
        //
        // A replay is only meaningful when the server still holds the version
        // the push was based on — otherwise it comes back as a conflict and
        // proves nothing about applying the same change twice. Picking an
        // index blindly mostly picked pushes whose base was long gone, and one
        // seed in six then went a whole thousand operations without a single
        // replay that landed. Which the floor caught, and which is also the
        // realistic case: what gets retried after a lost response is the push
        // that was just sent.
        let window = self.accepted.len().min(12);
        let start = self.accepted.len() - window;

        let applicable: Vec<PushRecord> = self.accepted[start..]
            .iter()
            .rev()
            .filter(|record| {
                let held = self.held(&record.entry_id).map(|r| r.hlc);
                match (held, record.base_hlc) {
                    (None, None) => true,
                    (Some(current), Some(base)) => current == base,
                    _ => false,
                }
            })
            .cloned()
            .collect();

        if applicable.is_empty() {
            return false;
        }
        self.apply(&applicable[which % applicable.len()]);
        true
    }
}

impl Observed for Link<'_> {
    fn conflicted(&self) -> &[String] {
        &self.conflicted
    }

    fn stale(&self) -> bool {
        self.stale
    }
}

#[test]
fn three_devices_converge() {
    go(0x5EED_0001, operation_count(), &Server::default);
}

/// Several seeds, so that one lucky arrangement cannot carry the suite. Each
/// is held to the same coverage floor.
#[test]
fn three_devices_converge_across_seeds() {
    for seed in [0xA11CE, 0xB0B, 0xC0FF_EE00, 0xDEFA_CED0, 0xFEED_FACE] {
        go(seed, operation_count().max(600), &Server::default);
    }
}

/// The long run: the same harness at a hundred times the operation count, for
/// the interleavings a thousand operations does not reach.
#[test]
#[ignore = "long; CONVERGENCE_OPS=100000 cargo test --test convergence -- --ignored --nocapture"]
fn three_devices_converge_over_a_long_run() {
    let count = std::env::var("CONVERGENCE_OPS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(100_000);
    go(0x1_0000_0001, count, &Server::default);
}
