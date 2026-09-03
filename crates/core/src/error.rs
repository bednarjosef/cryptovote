//! Error types.

/// A byte string is not a canonical encoding (SPEC §2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("unexpected end of input")]
    Eof,
    #[error("trailing bytes after item")]
    Trailing,
    #[error("invalid UTF-8 in string")]
    Utf8,
    #[error("length {0} exceeds limit {1}")]
    TooLong(usize, usize),
    #[error("invalid enum discriminant {0}")]
    Discriminant(u8),
    #[error("non-canonical field element")]
    NonCanonicalField,
    #[error("unsupported item version {0}")]
    Version(u8),
    #[error("unknown item type {0}")]
    ItemType(u8),
    #[error("list not strictly ascending")]
    Unsorted,
    #[error("wrong element count: expected {expected}, got {got}")]
    Count { expected: usize, got: usize },
}
