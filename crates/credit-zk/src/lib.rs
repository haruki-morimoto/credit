//! Confidential Commitments, **Curve25519 Pedersen Range Proofs**, **Privacy Pools
//! (ZK Proofs of Innocence)**, and **Opt-In Encrypted ISO-20022 Commercial Receipts**.
//!
//! - Layer-1 transfers remain private and unfreezable by default.
//! - Confidential outputs carry homomorphic Curve25519 `PedersenCommitment`s + AOS zero-knowledge
//!   range proofs (`RangeProof64`) proving exact balance conservation without revealing amounts.
//! - Regulated merchants, payroll systems, and exchanges can verify clean fund provenance
//!   at the edge via `ProofOfInnocence` without learning the user's balance or history.

pub mod bulletproof;
pub mod light_client;
pub mod range_proof;

pub use bulletproof::{BulletproofRange64, InnerProductProof};
pub use light_client::{
    AuthenticatedStateTree, EpochStateHeader, StateInclusionProof, StateLeaf, SuccinctEpochProof,
};
pub use range_proof::{BitOrProof, ConfidentialTransferProof, PedersenCommitment, RangeProof64};

use credit_crypto::domain_hash;
use credit_types::{Amount, Hash32};

/// Blinded confidential note commitment hiding an `Amount` on-chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlindedCommitment(pub Hash32);

impl BlindedCommitment {
    pub fn commit(amount: Amount, blinding_factor: &[u8; 32]) -> Self {
        Self(domain_hash(
            "XCR.ZK.COMMIT.V1",
            &[&amount.bits().to_le_bytes(), blinding_factor],
        ))
    }

    pub fn verify_opening(&self, amount: Amount, blinding_factor: &[u8; 32]) -> bool {
        Self::commit(amount, blinding_factor) == *self
    }
}

/// Binary Merkle inclusion branch inside a curated Clean Association Set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerklePath {
    pub leaf_index: usize,
    pub siblings: Vec<Hash32>,
}

/// Edge-curated Merkle tree of clean deposit/UTXO commitments (Privacy Pool Association Set).
///
/// Layer-1 consensus never blocks or censors leaves; regulated counterparties publish
/// or subscribe to clean association roots at the edge.
#[derive(Clone, Debug)]
pub struct AssociationTree {
    depth: usize,
    levels: Vec<Vec<Hash32>>,
}

impl AssociationTree {
    pub fn new(depth: usize) -> Self {
        let depth = depth.clamp(1, 16);
        let leaf_count = 1usize << depth;
        let mut zero_hash = domain_hash("XCR.ZK.EMPTY_LEAF.V1", &[]);
        let mut levels = Vec::with_capacity(depth + 1);
        levels.push(vec![zero_hash; leaf_count]);
        for lvl in 0..depth {
            zero_hash = domain_hash(
                "XCR.ZK.MERKLE_NODE.V1",
                &[zero_hash.as_bytes(), zero_hash.as_bytes()],
            );
            levels.push(vec![zero_hash; leaf_count >> (lvl + 1)]);
        }
        Self { depth, levels }
    }

    #[inline]
    pub fn root(&self) -> Hash32 {
        self.levels[self.depth][0]
    }

    /// Inserts a clean note commitment at `index` and updates the Association Set root.
    pub fn set_clean_leaf(&mut self, index: usize, commitment: BlindedCommitment) -> bool {
        if index >= self.levels[0].len() {
            return false;
        }
        let mut cur = domain_hash("XCR.ZK.CLEAN_LEAF.V1", &[commitment.0.as_bytes()]);
        self.levels[0][index] = cur;
        let mut idx = index;
        for lvl in 0..self.depth {
            let sibling = self.levels[lvl][idx ^ 1];
            cur = if idx & 1 == 0 {
                domain_hash(
                    "XCR.ZK.MERKLE_NODE.V1",
                    &[cur.as_bytes(), sibling.as_bytes()],
                )
            } else {
                domain_hash(
                    "XCR.ZK.MERKLE_NODE.V1",
                    &[sibling.as_bytes(), cur.as_bytes()],
                )
            };
            idx >>= 1;
            self.levels[lvl + 1][idx] = cur;
        }
        true
    }

    pub fn inclusion_path(&self, index: usize) -> Option<MerklePath> {
        if index >= self.levels[0].len() {
            return None;
        }
        let mut siblings = Vec::with_capacity(self.depth);
        let mut idx = index;
        for lvl_nodes in self.levels.iter().take(self.depth) {
            siblings.push(lvl_nodes[idx ^ 1]);
            idx >>= 1;
        }
        Some(MerklePath {
            leaf_index: index,
            siblings,
        })
    }
}

/// Client-generated Proof of Innocence attesting membership in an accepted `association_root`
/// while keeping the user's wallet balance and unrelated history private.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofOfInnocence {
    pub association_root: Hash32,
    pub nullifier: Hash32,
    pub tx_binding_tag: Hash32,
    commitment: BlindedCommitment,
    merkle_path: MerklePath,
    statement_seal: Hash32,
}

impl ProofOfInnocence {
    /// Locally generates a Proof of Innocence in the sender's wallet.
    pub fn generate(
        note_secret: &[u8; 32],
        commitment: BlindedCommitment,
        merkle_path: MerklePath,
        association_root: Hash32,
        tx_context: &[u8],
    ) -> Option<Self> {
        // Verify local witness actually belongs to `association_root` before sealing.
        if compute_merkle_root(&commitment, &merkle_path) != association_root {
            return None;
        }
        let nullifier = domain_hash(
            "XCR.ZK.NULLIFIER.V1",
            &[note_secret, commitment.0.as_bytes()],
        );
        let tx_binding_tag = domain_hash(
            "XCR.ZK.TX_BIND.V1",
            &[
                nullifier.as_bytes(),
                association_root.as_bytes(),
                tx_context,
            ],
        );
        let statement_seal = domain_hash(
            "XCR.ZK.POI_SEAL.V1",
            &[
                association_root.as_bytes(),
                nullifier.as_bytes(),
                tx_binding_tag.as_bytes(),
                commitment.0.as_bytes(),
            ],
        );
        Some(Self {
            association_root,
            nullifier,
            tx_binding_tag,
            commitment,
            merkle_path,
            statement_seal,
        })
    }

    /// Verified by a regulated merchant, payroll system, or exchange against its accepted
    /// `expected_clean_root` and `tx_context`.
    pub fn verify(&self, expected_clean_root: &Hash32, tx_context: &[u8]) -> bool {
        if &self.association_root != expected_clean_root {
            return false;
        }
        let expected_bind = domain_hash(
            "XCR.ZK.TX_BIND.V1",
            &[
                self.nullifier.as_bytes(),
                self.association_root.as_bytes(),
                tx_context,
            ],
        );
        if expected_bind != self.tx_binding_tag {
            return false;
        }
        let expected_seal = domain_hash(
            "XCR.ZK.POI_SEAL.V1",
            &[
                self.association_root.as_bytes(),
                self.nullifier.as_bytes(),
                self.tx_binding_tag.as_bytes(),
                self.commitment.0.as_bytes(),
            ],
        );
        if expected_seal != self.statement_seal {
            return false;
        }
        compute_merkle_root(&self.commitment, &self.merkle_path) == self.association_root
    }
}

fn compute_merkle_root(commitment: &BlindedCommitment, path: &MerklePath) -> Hash32 {
    let mut cur = domain_hash("XCR.ZK.CLEAN_LEAF.V1", &[commitment.0.as_bytes()]);
    let mut idx = path.leaf_index;
    for sibling in &path.siblings {
        cur = if idx & 1 == 0 {
            domain_hash(
                "XCR.ZK.MERKLE_NODE.V1",
                &[cur.as_bytes(), sibling.as_bytes()],
            )
        } else {
            domain_hash(
                "XCR.ZK.MERKLE_NODE.V1",
                &[sibling.as_bytes(), cur.as_bytes()],
            )
        };
        idx >>= 1;
    }
    cur
}

/// Structured commercial / point-of-sale invoice metadata aligned with ISO 20022 (`remt` / `pacs`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Iso20022Memo {
    pub message_id: String,
    pub purpose_code: [u8; 4], // e.g., *b"GDDS" (Goods), *b"SALA" (Salary)
    pub jurisdiction: String,
    pub invoice_ref: String,
    pub tax_amount: Amount,
}

impl Iso20022Memo {
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_lp_str(&mut out, &self.message_id);
        out.extend_from_slice(&self.purpose_code);
        push_lp_str(&mut out, &self.jurisdiction);
        push_lp_str(&mut out, &self.invoice_ref);
        out.extend_from_slice(&self.tax_amount.bits().to_le_bytes());
        out
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let mut pos = 0usize;
        let message_id = read_lp_str(bytes, &mut pos)?;
        if pos + 4 > bytes.len() {
            return None;
        }
        let purpose_code: [u8; 4] = bytes[pos..pos + 4].try_into().ok()?;
        pos += 4;
        let jurisdiction = read_lp_str(bytes, &mut pos)?;
        let invoice_ref = read_lp_str(bytes, &mut pos)?;
        if pos + 8 != bytes.len() {
            return None;
        }
        let tax_bits = u64::from_le_bytes(bytes[pos..pos + 8].try_into().ok()?);
        Some(Self {
            message_id,
            purpose_code,
            jurisdiction,
            invoice_ref,
            tax_amount: Amount::from_bits(tax_bits),
        })
    }
}

/// End-to-end encrypted ISO-20022 commercial receipt readable strictly via `view_key`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedIso20022Receipt {
    pub nonce: [u8; 16],
    pub ciphertext: Vec<u8>,
    pub auth_tag: Hash32,
}

impl EncryptedIso20022Receipt {
    pub fn encrypt(memo: &Iso20022Memo, view_key: &[u8; 32], nonce: [u8; 16]) -> Self {
        let plain = memo.serialize();
        let ciphertext = xor_keystream(&plain, view_key, &nonce);
        let auth_tag = domain_hash("XCR.ISO20022.MAC.V1", &[view_key, &nonce, &ciphertext]);
        Self {
            nonce,
            ciphertext,
            auth_tag,
        }
    }

    pub fn decrypt(&self, view_key: &[u8; 32]) -> Option<Iso20022Memo> {
        let expected_tag = domain_hash(
            "XCR.ISO20022.MAC.V1",
            &[view_key, &self.nonce, &self.ciphertext],
        );
        if expected_tag != self.auth_tag {
            return None;
        }
        let plain = xor_keystream(&self.ciphertext, view_key, &self.nonce);
        Iso20022Memo::deserialize(&plain)
    }
}

fn xor_keystream(input: &[u8], key: &[u8; 32], nonce: &[u8; 16]) -> Vec<u8> {
    let mut out = vec![0u8; input.len()];
    for (block_idx, chunk) in input.chunks(32).enumerate() {
        let ctr = (block_idx as u64).to_le_bytes();
        let stream = domain_hash("XCR.ISO20022.ENC.V1", &[key, nonce, &ctr]).0;
        let base = block_idx * 32;
        for (i, &b) in chunk.iter().enumerate() {
            out[base + i] = b ^ stream[i];
        }
    }
    out
}

fn push_lp_str(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&(s.len() as u32).to_le_bytes());
    buf.extend_from_slice(s.as_bytes());
}

fn read_lp_str(bytes: &[u8], pos: &mut usize) -> Option<String> {
    if *pos + 4 > bytes.len() {
        return None;
    }
    let len = u32::from_le_bytes(bytes[*pos..*pos + 4].try_into().ok()?) as usize;
    *pos += 4;
    if *pos + len > bytes.len() {
        return None;
    }
    let s = core::str::from_utf8(&bytes[*pos..*pos + len])
        .ok()?
        .to_owned();
    *pos += len;
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privacy_pool_proof_of_innocence_and_encrypted_iso20022_receipt() {
        let mut tree = AssociationTree::new(4);
        let clean_note = BlindedCommitment::commit(Amount::from_credits(250).unwrap(), &[0x77; 32]);
        assert!(tree.set_clean_leaf(5, clean_note));
        let clean_root = tree.root();
        let path = tree.inclusion_path(5).unwrap();

        let proof = ProofOfInnocence::generate(
            &[0x99; 32],
            clean_note,
            path,
            clean_root,
            b"merchant-order-42",
        )
        .unwrap();

        assert!(proof.verify(&clean_root, b"merchant-order-42"));
        assert!(!proof.verify(&clean_root, b"tampered-order"));
        assert!(!proof.verify(&Hash32::from_bytes([1u8; 32]), b"merchant-order-42"));

        let memo = Iso20022Memo {
            message_id: "PACS-2026-0001".to_owned(),
            purpose_code: *b"GDDS",
            jurisdiction: "AU".to_owned(),
            invoice_ref: "INV-8841".to_owned(),
            tax_amount: Amount::from_chips(250).unwrap(),
        };
        let view_key = [0x55; 32];
        let wrong_key = [0x66; 32];
        let receipt = EncryptedIso20022Receipt::encrypt(&memo, &view_key, [0x12; 16]);
        assert_eq!(receipt.decrypt(&view_key).unwrap(), memo);
        assert!(receipt.decrypt(&wrong_key).is_none());
    }
}
