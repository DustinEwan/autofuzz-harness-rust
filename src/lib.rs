//! The Rust harness as a library: the parts every binary shares, exposed so the
//! harness can be scanned by itself.
//!
//! Discovery reaches only lib targets, because a target must be callable from
//! outside the crate that declares it. The plugin was a bin-only package, which
//! made it invisible to its own discovery; this library is the structural fix,
//! not a new design. `afz-rust` (the plugin), `afz-rust-emit`, and
//! `afz-rust-check` stay thin binaries over these modules.

pub mod coverage;
pub mod discover;
pub mod driver;
pub mod lower;
pub mod reproducer;
