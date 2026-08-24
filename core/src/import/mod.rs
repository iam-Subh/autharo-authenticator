//! Bringing entries in from other authenticators (PRD FR-11 to FR-15d).
//!
//! # Why this decides whether the product succeeds
//!
//! Nobody starts an authenticator empty. Every user already has one, with
//! between five and fifty accounts in it, and the cost of moving is the whole
//! decision. An app that syncs beautifully and cannot import is an app people
//! admire and do not install.
//!
//! # One entry never fails the whole import
//!
//! FR-15d: "Never fail a whole import because one entry is invalid. Import
//! every valid entry, then show a report that names each refused entry and the
//! reason."
//!
//! This is the rule that shapes the module. Every parser here returns a
//! [`Report`] holding what it understood *and* what it refused, and nothing in
//! the middle of a file can abort the rest. Someone moving forty accounts, one
//! of which is malformed, must end up with thirty-nine and a list — not with
//! nothing and an error, and not with thirty-nine and no idea which one is
//! missing until a service locks them out.
//!
//! The refusals carry a label as well as a reason, because "one entry was
//! invalid" is not something a user can act on. The common case is named in the
//! requirement: an HOTP entry with no counter, which the Key URI specification
//! marks as required and several exporters omit anyway. The user can supply the
//! missing value if they are told which account needs it.

pub mod aegis;
pub mod encrypted;
mod ente_secretstream;
pub mod file;
pub mod generic;
pub mod google;
pub mod twofas;

use crate::entry::Payload;

/// One entry that could not be imported, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    /// What it called itself, so the user can find it in the app they are
    /// leaving. Empty only when the entry carried no name at all — which is
    /// itself worth showing rather than hiding behind "one entry".
    pub label: String,
    /// In the user's terms. This reaches a screen.
    pub reason: String,
}

/// What one import produced.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Report {
    /// Ready to add. Still needs the duplicate check in FR-16 — that is the
    /// vault's job and needs the existing entries, which this module has no
    /// business seeing.
    pub entries: Vec<Payload>,
    pub refused: Vec<Refused>,
}

impl Report {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.refused.is_empty()
    }

    /// Everything the file offered, whether or not it could be read.
    pub fn total(&self) -> usize {
        self.entries.len() + self.refused.len()
    }

    pub(crate) fn refuse(&mut self, label: impl Into<String>, reason: impl Into<String>) {
        self.refused.push(Refused {
            label: label.into(),
            reason: reason.into(),
        });
    }
}
