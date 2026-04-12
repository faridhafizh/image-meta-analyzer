use md5::{Digest as _, Md5};
use sha2::Sha256; // Removed Digest

/// Returns (sha256_hex, md5_hex) for the given byte slice.
pub fn compute_hashes(data: &[u8]) -> (String, String) {
    let sha256 = hex::encode(Sha256::digest(data));
    let md5 = hex::encode(Md5::digest(data));
    (sha256, md5)
}
