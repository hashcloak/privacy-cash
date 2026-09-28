 //! Anchor-free core logic of the zkcash program.
//!
//! Everything in this crate is extracted to Lean with Charon/Aeneas and
//! formally verified, so it must stay free of Anchor, Solana syscalls and
//! features Aeneas does not support (interior mutability, raw pointers, `dyn`).
#![no_std]
extern crate alloc;

pub mod error;
pub mod field;
pub mod merkle_tree;
pub mod utils;
