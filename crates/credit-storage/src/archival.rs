//! **Sovereign Dormant Account Cold-Archival & `<1 KB` Stateless Revival** (`archival`).
//!
//! Keeps validator hot RAM flat on consumer laptops over decades without ever confiscating,
//! taxing, or freezing inactive user funds:
//! - Accounts untouched for `>= dormant_threshold_epochs` (default `1,051,200` = 2 years of
//!   1-minute epochs) are compacted out of hot `PersistentLedger.pockets` into an immutable
//!   32-byte `ArchiveRoot` (`DormantArchiveTree`).
//! - Whenever the owner returns—even 50 years later—presenting `(ArchivedPocketLeaf,
//!   ArchiveInclusionProof)` revives 100% of their `balance`, `nonce`, and `public_key` into hot
//!   state in 1 RTT while recording a one-time `revival_nullifier` so the snapshot cannot be
//!   replayed twice.

use std::collections::BTreeSet;
use std::io;

use credit_crypto::{PublicKey, SignatureScheme, domain_hash};
use credit_types::{Address, Amount, EpochId, Hash32, PocketState};

use crate::{PersistentLedger, StoredPocket, WalRecord};

/// Default inactivity horizon before cold-archiving (`2 years` = `1,051,200` 1-minute epochs).
pub const DEFAULT_DORMANT_THRESHOLD_EPOCHS: u64 = 1_051_200;

/// Full lossless snapshot of a cold-archived `Spending Pocket`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArchivedPocketLeaf {
    pub address: Address,
    pub public_key: PublicKey,
    pub balance: Amount,
    pub nonce: u64,
    pub daily_limit: Amount,
    pub archived_at_epoch: EpochId,
}

impl ArchivedPocketLeaf {
    pub fn hash(&self) -> Hash32 {
        domain_hash(
            "XCR.ARCHIVE.POCKET_LEAF.V1",
            &[
                self.address.as_bytes(),
                &[self.public_key.scheme as u8],
                self.public_key.merkle_root.as_bytes(),
                &self.balance.bits().to_le_bytes(),
                &self.nonce.to_le_bytes(),
                &self.daily_limit.bits().to_le_bytes(),
                &self.archived_at_epoch.0.to_le_bytes(),
            ],
        )
    }

    pub fn revival_nullifier(&self, archive_root: &Hash32) -> Hash32 {
        domain_hash(
            "XCR.ARCHIVE.REVIVE_NULLIFIER.V1",
            &[
                archive_root.as_bytes(),
                self.address.as_bytes(),
                &self.archived_at_epoch.0.to_le_bytes(),
            ],
        )
    }

    pub fn to_bytes(&self) -> [u8; 97] {
        let mut out = [0u8; 97];
        out[0..32].copy_from_slice(self.address.as_bytes());
        out[32] = self.public_key.scheme as u8;
        out[33..65].copy_from_slice(self.public_key.merkle_root.as_bytes());
        out[65..73].copy_from_slice(&self.balance.bits().to_le_bytes());
        out[73..81].copy_from_slice(&self.nonce.to_le_bytes());
        out[81..89].copy_from_slice(&self.daily_limit.bits().to_le_bytes());
        out[89..97].copy_from_slice(&self.archived_at_epoch.0.to_le_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 97 {
            return None;
        }
        let scheme = SignatureScheme::from_u8(bytes[32])?;
        Some(Self {
            address: Address::from_bytes(bytes[0..32].try_into().ok()?),
            public_key: PublicKey {
                scheme,
                merkle_root: Hash32::from_bytes(bytes[33..65].try_into().ok()?),
            },
            balance: Amount::from_bits(u64::from_le_bytes(bytes[65..73].try_into().ok()?)),
            nonce: u64::from_le_bytes(bytes[73..81].try_into().ok()?),
            daily_limit: Amount::from_bits(u64::from_le_bytes(bytes[81..89].try_into().ok()?)),
            archived_at_epoch: EpochId(u64::from_le_bytes(bytes[89..97].try_into().ok()?)),
        })
    }
}

/// Compact `O(log2 N)` Merkle inclusion proof inside a `DormantArchiveTree`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveInclusionProof {
    pub leaf_index: u32,
    pub siblings: Vec<Hash32>,
}

impl ArchiveInclusionProof {
    pub fn verify(&self, leaf: &ArchivedPocketLeaf, expected_archive_root: &Hash32) -> bool {
        let mut cur = leaf.hash();
        let mut idx = self.leaf_index as usize;
        for sibling in &self.siblings {
            cur = if idx & 1 == 0 {
                domain_hash(
                    "XCR.ARCHIVE.MERKLE_NODE.V1",
                    &[cur.as_bytes(), sibling.as_bytes()],
                )
            } else {
                domain_hash(
                    "XCR.ARCHIVE.MERKLE_NODE.V1",
                    &[sibling.as_bytes(), cur.as_bytes()],
                )
            };
            idx >>= 1;
        }
        &cur == expected_archive_root
    }

    pub fn byte_len(&self) -> usize {
        4 + self.siblings.len() * 32
    }
}

/// Immutable cold-archive Merkle tree built over a batch of dormant accounts.
#[derive(Clone, Debug)]
pub struct DormantArchiveTree {
    leaves: Vec<ArchivedPocketLeaf>,
    levels: Vec<Vec<Hash32>>,
}

impl DormantArchiveTree {
    pub fn build(mut leaves: Vec<ArchivedPocketLeaf>) -> Self {
        leaves.sort_by_key(|l| l.address);
        leaves.dedup_by(|a, b| a.address == b.address);

        let empty = domain_hash("XCR.ARCHIVE.EMPTY.V1", &[]);
        let padded = leaves.len().max(2).next_power_of_two();
        let mut lvl0 = Vec::with_capacity(padded);
        for l in &leaves {
            lvl0.push(l.hash());
        }
        while lvl0.len() < padded {
            lvl0.push(empty);
        }

        let mut levels = vec![lvl0];
        while levels.last().unwrap().len() > 1 {
            let prev = levels.last().unwrap();
            let mut next = Vec::with_capacity(prev.len() / 2);
            for pair in prev.as_chunks::<2>().0 {
                next.push(domain_hash(
                    "XCR.ARCHIVE.MERKLE_NODE.V1",
                    &[pair[0].as_bytes(), pair[1].as_bytes()],
                ));
            }
            levels.push(next);
        }
        Self { leaves, levels }
    }

    #[inline]
    pub fn root(&self) -> Hash32 {
        self.levels.last().unwrap()[0]
    }

    pub fn prove(&self, address: &Address) -> Option<(ArchivedPocketLeaf, ArchiveInclusionProof)> {
        let pos = self
            .leaves
            .binary_search_by(|l| l.address.cmp(address))
            .ok()?;
        let leaf = self.leaves[pos];
        let mut siblings = Vec::with_capacity(self.levels.len() - 1);
        let mut idx = pos;
        for lvl_nodes in self.levels.iter().take(self.levels.len() - 1) {
            siblings.push(lvl_nodes[idx ^ 1]);
            idx >>= 1;
        }
        Some((
            leaf,
            ArchiveInclusionProof {
                leaf_index: pos as u32,
                siblings,
            },
        ))
    }
}

/// Errors returned when attempting to wake a cold-archived account back into hot validator RAM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RevivalError {
    UnknownArchiveRoot(Hash32),
    InvalidMerkleProof,
    AlreadyRevived(Hash32),
    AlreadyActiveInHotState(Address),
    StorageIo(String),
}

/// Validator-side cold-archive manager storing ONLY 32-byte `archive_roots` and spent revival
/// nullifiers in RAM while letting owners wake accounts statelessly at any future date.
#[derive(Clone, Debug, Default)]
pub struct DormantArchiveRegistry {
    pub archive_roots: BTreeSet<Hash32>,
    pub used_revival_nullifiers: BTreeSet<Hash32>,
}

impl DormantArchiveRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Compacts `addresses_to_archive` out of `ledger.pockets` hot RAM into a single 32-byte
    /// `DormantArchiveTree` root—preserving 100% of user funds for future revival.
    pub fn archive_accounts(
        &mut self,
        ledger: &mut PersistentLedger,
        addresses_to_archive: &[Address],
        current_epoch: EpochId,
    ) -> Option<DormantArchiveTree> {
        let mut leaves = Vec::new();
        for addr in addresses_to_archive {
            if let Some(StoredPocket { public_key, state }) = ledger.remove_pocket_for_archive(addr)
            {
                leaves.push(ArchivedPocketLeaf {
                    address: *addr,
                    public_key,
                    balance: state.balance,
                    nonce: state.nonce,
                    daily_limit: state.daily_limit,
                    archived_at_epoch: current_epoch,
                });
            }
        }
        if leaves.is_empty() {
            return None;
        }
        let tree = DormantArchiveTree::build(leaves);
        self.archive_roots.insert(tree.root());
        Some(tree)
    }

    /// Wakes a cold-archived `Spending Pocket` back into hot `ledger.pockets` RAM and WAL storage
    /// after verifying its `<1 KB` Merkle inclusion proof and one-time revival nullifier.
    pub fn revive_account(
        &mut self,
        ledger: &mut PersistentLedger,
        archive_root: Hash32,
        leaf: &ArchivedPocketLeaf,
        proof: &ArchiveInclusionProof,
    ) -> Result<(), RevivalError> {
        if !self.archive_roots.contains(&archive_root) {
            return Err(RevivalError::UnknownArchiveRoot(archive_root));
        }
        if ledger.pockets.contains_key(&leaf.address) {
            return Err(RevivalError::AlreadyActiveInHotState(leaf.address));
        }
        if !proof.verify(leaf, &archive_root) {
            return Err(RevivalError::InvalidMerkleProof);
        }
        let nullifier = leaf.revival_nullifier(&archive_root);
        if self.used_revival_nullifiers.contains(&nullifier) {
            return Err(RevivalError::AlreadyRevived(nullifier));
        }

        let restored_state = PocketState {
            balance: leaf.balance,
            nonce: leaf.nonce,
            daily_spent: Amount::ZERO,
            daily_limit: leaf.daily_limit,
            current_day: 0,
        };
        ledger
            .append(WalRecord::UpsertPocket {
                address: leaf.address,
                public_key: leaf.public_key,
                state: restored_state,
            })
            .map_err(|e: io::Error| RevivalError::StorageIo(e.to_string()))?;

        self.used_revival_nullifiers.insert(nullifier);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use credit_crypto::Keypair;
    use std::env;
    use std::fs;

    #[test]
    fn dormant_accounts_compact_to_32b_root_and_revive_decades_later_with_zero_loss() {
        let mut dir = env::temp_dir();
        dir.push(format!("xcr_archive_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let mut ledger = PersistentLedger::open(dir.join("archive.wal")).unwrap();

        let kp_a = Keypair::from_seed(SignatureScheme::PasskeyP256, [0x31; 32]);
        let kp_b = Keypair::from_seed(SignatureScheme::PasskeyP256, [0x32; 32]);
        let addr_a = kp_a.address();
        let addr_b = kp_b.address();

        let mut st_a = PocketState::new(
            Amount::from_credits(142).unwrap(),
            Amount::from_credits(25).unwrap(),
        );
        st_a.nonce = 7;
        ledger
            .append(WalRecord::UpsertPocket {
                address: addr_a,
                public_key: kp_a.public_key(),
                state: st_a,
            })
            .unwrap();
        ledger
            .append(WalRecord::UpsertPocket {
                address: addr_b,
                public_key: kp_b.public_key(),
                state: PocketState::new(
                    Amount::from_bits(250), // 0.025 cents dust account
                    Amount::from_credits(10).unwrap(),
                ),
            })
            .unwrap();
        assert_eq!(ledger.pockets.len(), 2);

        // Cold-archive both inactive accounts out of validator hot RAM:
        let mut registry = DormantArchiveRegistry::new();
        let archive_tree = registry
            .archive_accounts(&mut ledger, &[addr_a, addr_b], EpochId(2_000_000))
            .unwrap();
        assert_eq!(ledger.pockets.len(), 0); // Hot RAM freed completely!

        // Owner A returns years later with `<1 KB` Merkle proof -> 100% balance & nonce=7 restored!
        let root = archive_tree.root();
        let (leaf_a, proof_a) = archive_tree.prove(&addr_a).unwrap();
        assert!(proof_a.byte_len() < 256);

        registry
            .revive_account(&mut ledger, root, &leaf_a, &proof_a)
            .unwrap();
        assert_eq!(
            ledger.pockets[&addr_a].state.balance,
            Amount::from_credits(142).unwrap()
        );
        assert_eq!(ledger.pockets[&addr_a].state.nonce, 7);

        // Replaying the same revival proof a second time after spending is blocked!
        ledger.pockets.remove(&addr_a);
        assert!(matches!(
            registry.revive_account(&mut ledger, root, &leaf_a, &proof_a),
            Err(RevivalError::AlreadyRevived(_))
        ));

        let _ = fs::remove_dir_all(&dir);
    }
}
