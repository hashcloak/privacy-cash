//! Differential tests: each program function that now delegates to
//! `zkcash_core` must behave exactly like the upstream code it replaced,
//! including returning the same on-chain error code.
//!
//! Every `upstream` function is copied verbatim from privacy-cash `main`
//! and must never be edited: it is the frozen reference behavior.

mod validate_fee;

use anchor_lang::error::Error;

/// The observable outcome of an instruction-level `Result`: `Ok`, or the
/// numeric error code the transaction would fail with.
pub fn outcome<T>(r: anchor_lang::Result<T>) -> Result<T, u32> {
    r.map_err(|e| match e {
        Error::AnchorError(e) => e.error_code_number,
        Error::ProgramError(e) => u64::from(e.program_error) as u32,
    })
}
