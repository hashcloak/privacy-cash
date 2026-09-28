/// Mirrors the program's `ErrorCode` enum variant-for-variant, in the same
/// order, so every core error maps to the identical on-chain error code.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    Unauthorized,
    ExtDataHashMismatch,
    UnknownRoot,
    InvalidPublicAmountData,
    InsufficientFundsForWithdrawal,
    InsufficientFundsForFee,
    InvalidProof,
    InvalidFee,
    InvalidExtAmount,
    PublicAmountCalculationError,
    ArithmeticOverflow,
    DepositLimitExceeded,
    InvalidFeeRate,
    InvalidFeeRecipient,
    InvalidFeeAmount,
    RecipientMismatch,
    MerkleTreeFull,
    InvalidTokenAccount,
    InvalidMintAddress,
    InvalidTokenAccountMintAddress,
}

pub type Result<T> = core::result::Result<T, ErrorCode>;
