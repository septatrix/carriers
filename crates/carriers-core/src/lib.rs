//! carriers-core — the message pipeline for a DMARC/ARC-compliant mailing list.
//!
//! The guiding principle is DKIM preservation: an inbound post is never modified in its body
//! or existing headers. We only *prepend* headers (`List-*`, our own `DKIM-Signature`, and an
//! `ARC-*` seal), so the author's original DKIM signature stays valid and DMARC passes at the
//! subscriber's server via DKIM alignment. The ARC seal is the backstop for hops that break
//! the original authentication.

pub mod config;
pub mod crypto;
pub mod error;
pub mod keygen;
pub mod list;
pub mod member;
pub mod pipeline;
pub mod sign;
pub mod store;
pub mod transform;

pub use error::{Error, Result};

// Re-export the authenticator so binaries don't need a direct mail-auth dependency.
pub use mail_auth::MessageAuthenticator;
