//! Report data binding (spec D2): the 64 bytes the VM asks the TDX module to sign.
//!
//! report_data = SHA-512("ti-attest-v1" || nonce (32 bytes) || H)
//! H = SHA-256 over the sorted, concatenated SHA-256 hashes of each current leaf
//! certificate's SubjectPublicKeyInfo.

use sha2::{Digest, Sha256, Sha512};

pub const DOMAIN: &[u8] = b"ti-attest-v1";
pub const NONCE_LEN: usize = 32;

/// SHA-256 of a DER SubjectPublicKeyInfo.
pub fn spki_hash(spki_der: &[u8]) -> [u8; 32] {
    Sha256::digest(spki_der).into()
}

/// H over a set of key hashes. Order and duplicates do not change the result.
pub fn key_set_hash(key_hashes: &[[u8; 32]]) -> [u8; 32] {
    let mut sorted = key_hashes.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut h = Sha256::new();
    for k in &sorted {
        h.update(k);
    }
    h.finalize().into()
}

pub fn report_data(nonce: &[u8; NONCE_LEN], key_hashes: &[[u8; 32]]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(DOMAIN);
    h.update(nonce);
    h.update(key_set_hash(key_hashes));
    h.finalize().into()
}

/// Parse a 64-character lowercase or uppercase hex nonce. Anything else is refused.
pub fn parse_nonce(hex_str: &str) -> Option<[u8; NONCE_LEN]> {
    if hex_str.len() != NONCE_LEN * 2 {
        return None;
    }
    let mut out = [0u8; NONCE_LEN];
    hex::decode_to_slice(hex_str, &mut out).ok()?;
    Some(out)
}

pub fn parse_key_hash(hex_str: &str) -> Option<[u8; 32]> {
    if hex_str.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(hex_str, &mut out).ok()?;
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_and_duplicates_do_not_matter() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_eq!(key_set_hash(&[a, b]), key_set_hash(&[b, a, a]));
    }

    #[test]
    fn nonce_changes_report_data() {
        let k = [[7u8; 32]];
        assert_ne!(report_data(&[0; 32], &k), report_data(&[1; 32], &k));
    }

    #[test]
    fn key_changes_report_data() {
        let n = [9u8; 32];
        assert_ne!(report_data(&n, &[[1; 32]]), report_data(&n, &[[2; 32]]));
    }

    #[test]
    fn nonce_parsing_is_strict() {
        assert!(parse_nonce(&"ab".repeat(32)).is_some());
        assert!(parse_nonce(&"ab".repeat(31)).is_none());
        assert!(parse_nonce(&"ab".repeat(33)).is_none());
        assert!(parse_nonce(&"zz".repeat(32)).is_none());
        assert!(parse_nonce("").is_none());
    }
}
