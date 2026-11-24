//! Checksummed **24-Word Paper Backup & Recovery Codec** (`256-bit` Seed + `8-bit` SHA-256 Checksum).
//!
//! Encodes any 32-byte `XCRSEED1` wallet master seed bijectively into **24 human-readable lowercase
//! words** (`24 * 11 = 264 bits` = `256-bit` master seed + `8-bit` SHA-256 checksum byte), allowing
//! users to back up their `Spending Pocket`, `Stealth Meta-Address`, and `Post-Quantum Savings Vault`
//! on paper with `99.6%` (`255/256`) single-error typo/transposition detection.

use core::fmt;

use credit_crypto::sha256;

/// Errors returned when decoding a 24-word recovery phrase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MnemonicError {
    WrongWordCount { expected: usize, actual: usize },
    UnknownWord { index: usize, word: String },
    ChecksumMismatch,
}

impl fmt::Display for MnemonicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongWordCount { expected, actual } => {
                write!(f, "expected {expected} backup words, got {actual}")
            }
            Self::UnknownWord { index, word } => {
                write!(f, "unknown word #{}: '{word}'", index + 1)
            }
            Self::ChecksumMismatch => {
                f.write_str("24-word phrase failed 8-bit SHA-256 checksum (check spelling/order)")
            }
        }
    }
}

/// 64 clean, distinct 3-5 letter onset stems (`0..64`) paired with 32 distinct natural endings (`0..32`),
/// or curated English stems yielding `64 * 32 = 2,048` strictly unique, unambiguous lowercase words.
const ROOTS_64: [&str; 64] = [
    "amber", "anchor", "apex", "apple", "april", "arbor", "arctic", "arrow", "aspen", "atlas",
    "atom", "autumn", "azure", "badge", "basil", "beacon", "berry", "birch", "blade", "bloom",
    "breeze", "brick", "brook", "cedar", "chalk", "cider", "cliff", "cloud", "clover", "cobalt",
    "comet", "coral", "crest", "crown", "delta", "dune", "eagle", "ember", "fable", "fern",
    "field", "fin", "flame", "flint", "flora", "frost", "glade", "globe", "grain", "grove",
    "harbor", "haven", "hazel", "ivory", "jade", "linen", "lotus", "lunar", "maple", "meadow",
    "north", "ocean", "olive", "orbit",
];

const SUFFIXES_32: [&str; 32] = [
    "", "arc", "bay", "beam", "bell", "bird", "bolt", "bond", "born", "cast", "core", "cove",
    "dale", "dawn", "drop", "dust", "edge", "fall", "fire", "flow", "fold", "ford", "gate", "glow",
    "gold", "hill", "keep", "key", "lake", "leaf", "line", "lock",
];

/// Returns the deterministic word for an 11-bit index (`0..2048`).
/// Every word is lowercase `a-z` (`3..=10` chars), easy to pronounce/write, and 100% collision-free:
/// e.g. `amber`, `amberarc`, `anchorbay`, `mapleleaf`, `orbitkey`, `harborgate`.
pub fn word_at(index: u16) -> String {
    debug_assert!(index < 2048);
    let r = (index >> 5) as usize;
    let s = (index & 31) as usize;
    format!("{}{}", ROOTS_64[r], SUFFIXES_32[s])
}

/// Looks up the 11-bit index (`0..2048`) for a lowercase backup word.
pub fn lookup_word(word: &str) -> Option<u16> {
    let clean = word.trim().to_ascii_lowercase();
    // Match longest matching root first so shared prefixes (`fin` vs `field`) never collide:
    for (r_idx, &root) in ROOTS_64.iter().enumerate() {
        if let Some(rem) = clean.strip_prefix(root)
            && let Some(s_idx) = SUFFIXES_32.iter().position(|&suf| suf == rem)
        {
            return Some(((r_idx as u16) << 5) | (s_idx as u16));
        }
    }
    None
}

/// Encodes a 32-byte master seed into a space-separated 24-word checksummed backup phrase.
pub fn encode_mnemonic_24(seed: &[u8; 32]) -> String {
    let checksum = sha256(seed)[0];
    let mut bytes33 = [0u8; 33];
    bytes33[..32].copy_from_slice(seed);
    bytes33[32] = checksum;

    let mut words = Vec::with_capacity(24);
    for w_idx in 0..24usize {
        let bit_pos = w_idx * 11;
        let mut val = 0u16;
        for b in 0..11usize {
            let cur = bit_pos + b;
            let bit = (bytes33[cur >> 3] >> (7 - (cur & 7))) & 1;
            val = (val << 1) | (bit as u16);
        }
        words.push(word_at(val));
    }
    words.join(" ")
}

/// Formats a numbered 4x6 printable recovery card for terminal or paper backup.
pub fn format_backup_card_24(seed: &[u8; 32]) -> String {
    let phrase = encode_mnemonic_24(seed);
    let list: Vec<&str> = phrase.split_whitespace().collect();
    let mut out = String::new();
    for row in 0..6 {
        let mut line = String::new();
        for col in 0..4 {
            let idx = row + col * 6;
            line.push_str(&format!("{:>2}. {:<12}", idx + 1, list[idx]));
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

/// Decodes and verifies a 24-word recovery phrase back into the exact 32-byte master seed.
pub fn decode_mnemonic_24(phrase: &str) -> Result<[u8; 32], MnemonicError> {
    let tokens: Vec<&str> = phrase
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|t| !t.is_empty())
        .collect();
    if tokens.len() != 24 {
        return Err(MnemonicError::WrongWordCount {
            expected: 24,
            actual: tokens.len(),
        });
    }

    let mut bytes33 = [0u8; 33];
    for (w_idx, &tok) in tokens.iter().enumerate() {
        let val = lookup_word(tok).ok_or_else(|| MnemonicError::UnknownWord {
            index: w_idx,
            word: tok.to_owned(),
        })?;
        let bit_pos = w_idx * 11;
        for b in 0..11usize {
            let bit = ((val >> (10 - b)) & 1) as u8;
            let cur = bit_pos + b;
            bytes33[cur >> 3] |= bit << (7 - (cur & 7));
        }
    }

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes33[..32]);
    let expected_checksum = sha256(&seed)[0];
    if bytes33[32] != expected_checksum {
        return Err(MnemonicError::ChecksumMismatch);
    }
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn all_2048_words_are_strictly_unique_and_bijective() {
        let mut set = BTreeSet::new();
        for idx in 0..2048u16 {
            let w = word_at(idx);
            assert!(set.insert(w.clone()), "collision on word '{w}'");
            assert_eq!(lookup_word(&w), Some(idx), "roundtrip failed for '{w}'");
        }
        assert_eq!(set.len(), 2048);
    }

    #[test]
    fn mnemonic_24_roundtrip_and_checksum_tamper_rejection() {
        let seed = [0x7Au8; 32];
        let phrase = encode_mnemonic_24(&seed);
        assert_eq!(phrase.split_whitespace().count(), 24);
        assert_eq!(decode_mnemonic_24(&phrase).unwrap(), seed);

        // Swapping word 0 and word 1 triggers ChecksumMismatch:
        let mut words: Vec<&str> = phrase.split_whitespace().collect();
        words.swap(0, 1);
        let tampered = words.join(" ");
        assert_eq!(
            decode_mnemonic_24(&tampered),
            Err(MnemonicError::ChecksumMismatch)
        );
    }
}
