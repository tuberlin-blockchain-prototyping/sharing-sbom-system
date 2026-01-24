use crate::error::{Error, Result};

pub use sbom_common::{DEFAULTS, bitmap_bit, count_bitmap_ones};

pub fn hex_to_bytes32(hex_str: &str) -> Result<[u8; 32]> {
    sbom_common::hex_to_bytes32(hex_str).map_err(|e| match e {
        sbom_common::HexError::TooShort => Error::Hex("Hex string too short".to_string()),
        sbom_common::HexError::InvalidCharacter => Error::Hex("Invalid hex character".to_string()),
    })
}
