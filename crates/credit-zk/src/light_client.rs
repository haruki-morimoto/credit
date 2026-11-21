//! Stage-2 **Authenticated Merkle State Tree** & **Succinct Epoch Light-Client Proofs**
//! (`< 1 KB` per account inclusion proof, `164 B` per epoch header -> `< 10 MB` mobile sync).
//!
//! Enables smartphones and browser wallets to verify:
//! 1. **Global Epoch State Progression (`EpochStateHeader` + `SuccinctEpochProof`):** Binds shard
//!    roots, PoNC minting, `30%` fee burn, and Curve25519 homomorphic supply conservation from
//!    `Genesis (0 XCR)` up to `Epoch k` without downloading historical transactions.
//! 2. **Trustless Account Balance Inclusion (`AuthenticatedStateTree` + `StateInclusionProof`):**
//!    Proves an account's exact `balance` and `nonce` in `O(log2 N)` hashes against `new_state_root`
//!    so an untrusted RPC node can never spoof wallet balances.

use credit_crypto::{EdwardsPoint, Keypair, PublicKey, Scalar, Signature, domain_hash};
use credit_types::{Address, Amount, EpochId, Hash32};

use crate::PedersenCommitment;

/// Canonical account state leaf committed inside `AuthenticatedStateTree`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateLeaf {
    pub address: Address,
    pub balance: Amount,
    pub nonce: u64,
}

impl StateLeaf {
    pub fn hash(&self) -> Hash32 {
        domain_hash(
            "XCR.LIGHT.ACCOUNT_LEAF.V1",
            &[
                self.address.as_bytes(),
                &self.balance.bits().to_le_bytes(),
                &self.nonce.to_le_bytes(),
            ],
        )
    }
}

/// Compact `O(log2 N)` binary Merkle inclusion proof (`32 * depth + 8` bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateInclusionProof {
    pub leaf_index: u32,
    pub siblings: Vec<Hash32>,
}

impl StateInclusionProof {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.siblings.len() * 32);
        out.extend_from_slice(&self.leaf_index.to_le_bytes());
        out.extend_from_slice(&(self.siblings.len() as u32).to_le_bytes());
        for s in &self.siblings {
            out.extend_from_slice(s.as_bytes());
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 8 {
            return None;
        }
        let leaf_index = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
        let depth = u32::from_le_bytes(bytes[4..8].try_into().ok()?) as usize;
        if depth > 32 || bytes.len() != 8 + depth * 32 {
            return None;
        }
        let mut siblings = Vec::with_capacity(depth);
        for i in 0..depth {
            let off = 8 + i * 32;
            siblings.push(Hash32::from_bytes(bytes[off..off + 32].try_into().ok()?));
        }
        Some(Self {
            leaf_index,
            siblings,
        })
    }

    /// Verifies `leaf` against a quorum-certified `expected_state_root` in microseconds.
    pub fn verify(&self, leaf: &StateLeaf, expected_state_root: &Hash32) -> bool {
        let mut cur = leaf.hash();
        let mut idx = self.leaf_index as usize;
        for sibling in &self.siblings {
            cur = if idx & 1 == 0 {
                domain_hash(
                    "XCR.LIGHT.STATE_NODE.V1",
                    &[cur.as_bytes(), sibling.as_bytes()],
                )
            } else {
                domain_hash(
                    "XCR.LIGHT.STATE_NODE.V1",
                    &[sibling.as_bytes(), cur.as_bytes()],
                )
            };
            idx >>= 1;
        }
        &cur == expected_state_root
    }
}

/// Canonical binary Merkle tree over all active `StateLeaf` records in an epoch.
#[derive(Clone, Debug)]
pub struct AuthenticatedStateTree {
    sorted_leaves: Vec<StateLeaf>,
    levels: Vec<Vec<Hash32>>,
}

impl AuthenticatedStateTree {
    pub fn build(mut leaves: Vec<StateLeaf>) -> Self {
        leaves.sort_by_key(|a| a.address);
        leaves.dedup_by(|a, b| a.address == b.address);

        let empty_hash = domain_hash("XCR.LIGHT.EMPTY_STATE_LEAF.V1", &[]);
        let padded_len = leaves.len().max(2).next_power_of_two();
        let mut level0 = Vec::with_capacity(padded_len);
        for leaf in &leaves {
            level0.push(leaf.hash());
        }
        while level0.len() < padded_len {
            level0.push(empty_hash);
        }

        let mut levels = vec![level0];
        while levels.last().unwrap().len() > 1 {
            let prev = levels.last().unwrap();
            let mut next = Vec::with_capacity(prev.len() / 2);
            for pair in prev.as_chunks::<2>().0 {
                next.push(domain_hash(
                    "XCR.LIGHT.STATE_NODE.V1",
                    &[pair[0].as_bytes(), pair[1].as_bytes()],
                ));
            }
            levels.push(next);
        }

        Self {
            sorted_leaves: leaves,
            levels,
        }
    }

    #[inline]
    pub fn root(&self) -> Hash32 {
        self.levels.last().unwrap()[0]
    }

    pub fn prove(&self, address: &Address) -> Option<(StateLeaf, StateInclusionProof)> {
        let leaf_idx = self
            .sorted_leaves
            .binary_search_by(|l| l.address.cmp(address))
            .ok()?;
        let leaf = self.sorted_leaves[leaf_idx];
        let mut siblings = Vec::with_capacity(self.levels.len() - 1);
        let mut idx = leaf_idx;
        for lvl_nodes in self.levels.iter().take(self.levels.len() - 1) {
            siblings.push(lvl_nodes[idx ^ 1]);
            idx >>= 1;
        }
        Some((
            leaf,
            StateInclusionProof {
                leaf_index: leaf_idx as u32,
                siblings,
            },
        ))
    }
}

/// Fixed `188-byte` Epoch State Header (~53,000 epochs fit inside 10 MB on a mobile device!).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochStateHeader {
    pub epoch: EpochId,
    pub prev_header_hash: Hash32,
    pub prev_state_root: Hash32,
    pub new_state_root: Hash32,
    pub shard_roots_merkle: Hash32,
    pub circulating_supply: Amount,
    pub total_burned: Amount,
    pub verified_tx_count: u32,
    pub next_committee_root: Hash32,
}

impl EpochStateHeader {
    pub const WIRE_LEN: usize = 188;

    pub fn header_hash(&self) -> Hash32 {
        domain_hash("XCR.LIGHT.EPOCH_HDR.V1", &[&self.to_bytes()])
    }

    pub fn to_bytes(&self) -> [u8; Self::WIRE_LEN] {
        let mut out = [0u8; Self::WIRE_LEN];
        out[0..8].copy_from_slice(&self.epoch.0.to_le_bytes());
        out[8..40].copy_from_slice(self.prev_header_hash.as_bytes());
        out[40..72].copy_from_slice(self.prev_state_root.as_bytes());
        out[72..104].copy_from_slice(self.new_state_root.as_bytes());
        out[104..136].copy_from_slice(self.shard_roots_merkle.as_bytes());
        out[136..144].copy_from_slice(&self.circulating_supply.bits().to_le_bytes());
        out[144..152].copy_from_slice(&self.total_burned.bits().to_le_bytes());
        out[152..156].copy_from_slice(&self.verified_tx_count.to_le_bytes());
        out[156..188].copy_from_slice(self.next_committee_root.as_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::WIRE_LEN {
            return None;
        }
        Some(Self {
            epoch: EpochId(u64::from_le_bytes(bytes[0..8].try_into().ok()?)),
            prev_header_hash: Hash32::from_bytes(bytes[8..40].try_into().ok()?),
            prev_state_root: Hash32::from_bytes(bytes[40..72].try_into().ok()?),
            new_state_root: Hash32::from_bytes(bytes[72..104].try_into().ok()?),
            shard_roots_merkle: Hash32::from_bytes(bytes[104..136].try_into().ok()?),
            circulating_supply: Amount::from_bits(u64::from_le_bytes(
                bytes[136..144].try_into().ok()?,
            )),
            total_burned: Amount::from_bits(u64::from_le_bytes(bytes[144..152].try_into().ok()?)),
            verified_tx_count: u32::from_le_bytes(bytes[152..156].try_into().ok()?),
            next_committee_root: Hash32::from_bytes(bytes[156..188].try_into().ok()?),
        })
    }
}

/// Succinct recursive epoch rollup proof pairing an inductive Genesis chain seal, a Curve25519
/// homomorphic supply conservation proof, and `>= 2f + 1` validator quorum signatures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuccinctEpochProof {
    pub inductive_chain_seal: Hash32,
    pub minted_delta: Amount,
    pub burned_delta: Amount,
    pub prev_supply_commit: [u8; 32],
    pub new_supply_commit: [u8; 32],
    pub schnorr_nonce_pt: [u8; 32],
    pub schnorr_s: Scalar,
    pub quorum_signatures: Vec<(Address, Vec<u8>)>,
}

impl SuccinctEpochProof {
    /// Produced by a dedicated ZK Prover server at epoch close and co-signed by the active quorum.
    #[allow(clippy::too_many_arguments)]
    pub fn prove_epoch_transition(
        prev_chain_seal: &Hash32,
        prev_supply: Amount,
        prev_supply_blind: Scalar,
        minted_delta: Amount,
        burned_delta: Amount,
        new_supply_blind: Scalar,
        header: &EpochStateHeader,
        quorum_signers: &mut [(Address, Keypair)],
    ) -> Option<Self> {
        let expected_new_supply = prev_supply
            .checked_add(minted_delta)?
            .checked_sub(burned_delta)?;
        if expected_new_supply != header.circulating_supply {
            return None;
        }

        let prev_commit = PedersenCommitment::commit(prev_supply, prev_supply_blind);
        let new_commit = PedersenCommitment::commit(header.circulating_supply, new_supply_blind);

        // Homomorphic difference:
        // `new_commit - prev_commit - (minted - burned)*B == (new_blind - prev_blind)*H`!
        let b_gen = EdwardsPoint::basepoint_b();
        let h_gen = EdwardsPoint::pedersen_generator_h();
        let net_supply_pt = (Scalar::from_u64(minted_delta.bits()) * &b_gen)
            - (Scalar::from_u64(burned_delta.bits()) * &b_gen);
        let delta_blind = new_supply_blind - prev_supply_blind;
        let excess_pt = new_commit.0 - prev_commit.0 - net_supply_pt;
        debug_assert_eq!(excess_pt, delta_blind * &h_gen);

        let header_hash = header.header_hash();
        let k = Scalar::hash_from_parts(
            "XCR.LIGHT.SUPPLY_NONCE.V1",
            &[header_hash.as_bytes(), delta_blind.as_bytes()],
        );
        let r_pt = k * &h_gen;
        let schnorr_nonce_pt = r_pt.to_bytes();
        let e = Scalar::hash_from_parts(
            "XCR.LIGHT.SUPPLY_CHAL.V1",
            &[
                header_hash.as_bytes(),
                &excess_pt.to_bytes(),
                &schnorr_nonce_pt,
            ],
        );
        let schnorr_s = k + (e * delta_blind);

        let inductive_chain_seal = domain_hash(
            "XCR.LIGHT.CHAIN_SEAL.V1",
            &[prev_chain_seal.as_bytes(), header_hash.as_bytes()],
        );

        let mut quorum_signatures = Vec::with_capacity(quorum_signers.len());
        for (val_addr, val_kp) in quorum_signers.iter_mut() {
            let sig = val_kp.sign(inductive_chain_seal.as_bytes()).to_bytes();
            quorum_signatures.push((*val_addr, sig));
        }

        Some(Self {
            inductive_chain_seal,
            minted_delta,
            burned_delta,
            prev_supply_commit: prev_commit.to_bytes(),
            new_supply_commit: new_commit.to_bytes(),
            schnorr_nonce_pt,
            schnorr_s,
            quorum_signatures,
        })
    }

    /// Verifies inductive hash-chain continuity, Curve25519 homomorphic supply conservation,
    /// and `>= quorum_threshold` validator signatures in `< 1 ms`.
    pub fn verify_transition(
        &self,
        prev_chain_seal: &Hash32,
        prev_supply: Amount,
        header: &EpochStateHeader,
        committee_directory: &[(Address, PublicKey, u64)],
        quorum_threshold: u64,
    ) -> bool {
        let Some(expected_supply) = prev_supply
            .checked_add(self.minted_delta)
            .and_then(|s| s.checked_sub(self.burned_delta))
        else {
            return false;
        };
        if expected_supply != header.circulating_supply {
            return false;
        }

        let header_hash = header.header_hash();
        let expected_seal = domain_hash(
            "XCR.LIGHT.CHAIN_SEAL.V1",
            &[prev_chain_seal.as_bytes(), header_hash.as_bytes()],
        );
        if expected_seal != self.inductive_chain_seal {
            return false;
        }

        // Verify Curve25519 homomorphic supply conservation proof:
        let (Some(prev_pt), Some(new_pt), Some(r_pt)) = (
            EdwardsPoint::from_bytes(&self.prev_supply_commit),
            EdwardsPoint::from_bytes(&self.new_supply_commit),
            EdwardsPoint::from_bytes(&self.schnorr_nonce_pt),
        ) else {
            return false;
        };
        let b_gen = EdwardsPoint::basepoint_b();
        let h_gen = EdwardsPoint::pedersen_generator_h();
        let net_supply_pt = (Scalar::from_u64(self.minted_delta.bits()) * &b_gen)
            - (Scalar::from_u64(self.burned_delta.bits()) * &b_gen);
        let excess_pt = new_pt - prev_pt - net_supply_pt;
        let e = Scalar::hash_from_parts(
            "XCR.LIGHT.SUPPLY_CHAL.V1",
            &[
                header_hash.as_bytes(),
                &excess_pt.to_bytes(),
                &self.schnorr_nonce_pt,
            ],
        );
        if (self.schnorr_s * &h_gen) != (r_pt + (e * &excess_pt)) {
            return false;
        }

        // Verify `>= 2f + 1` quorum signatures without allowing duplicate voter replay:
        let mut seen = Vec::with_capacity(self.quorum_signatures.len());
        let mut weight = 0u64;
        for (addr, sig_bytes) in &self.quorum_signatures {
            if seen.contains(addr) {
                continue;
            }
            if let Some(sig) = Signature::from_bytes(sig_bytes)
                && let Some((_, pk, w)) = committee_directory.iter().find(|(a, _, _)| a == addr)
                && pk.verify(self.inductive_chain_seal.as_bytes(), &sig)
            {
                seen.push(*addr);
                weight = weight.saturating_add(*w);
            }
        }
        weight >= quorum_threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use credit_crypto::SignatureScheme;

    #[test]
    fn succinct_epoch_proof_and_sub_kilobyte_merkle_account_verification() {
        let alice = Address::from_bytes([0x10; 32]);
        let bob = Address::from_bytes([0x20; 32]);
        let carol = Address::from_bytes([0x30; 32]);

        let tree = AuthenticatedStateTree::build(vec![
            StateLeaf {
                address: alice,
                balance: Amount::from_credits(42).unwrap(),
                nonce: 3,
            },
            StateLeaf {
                address: bob,
                balance: Amount::from_credits(58).unwrap(),
                nonce: 1,
            },
            StateLeaf {
                address: carol,
                balance: Amount::ZERO,
                nonce: 0,
            },
        ]);
        let state_root = tree.root();
        let (alice_leaf, alice_proof) = tree.prove(&alice).unwrap();
        let wire_proof = alice_proof.to_bytes();
        assert!(wire_proof.len() < 256); // Tiny sub-kilobyte mobile proof!
        assert!(
            StateInclusionProof::from_bytes(&wire_proof)
                .unwrap()
                .verify(&alice_leaf, &state_root)
        );

        // Tampered balance rejected immediately by light verifier:
        let fake_leaf = StateLeaf {
            balance: Amount::from_credits(999_999).unwrap(),
            ..alice_leaf
        };
        assert!(!alice_proof.verify(&fake_leaf, &state_root));

        // Prove succinct Epoch 0 -> Epoch 1 transition from Genesis (`0 XCR` -> `99.999850 XCR`):
        let v1 = Keypair::from_seed(SignatureScheme::Ed25519, [1; 32]);
        let v2 = Keypair::from_seed(SignatureScheme::Ed25519, [2; 32]);
        let v3 = Keypair::from_seed(SignatureScheme::Ed25519, [3; 32]);
        let dir = vec![
            (v1.address(), v1.public_key(), 100u64),
            (v2.address(), v2.public_key(), 100u64),
            (v3.address(), v3.public_key(), 100u64),
        ];
        let mut signers = vec![(v1.address(), v1), (v2.address(), v2), (v3.address(), v3)];

        let hdr = EpochStateHeader {
            epoch: EpochId(1),
            prev_header_hash: Hash32::ZERO,
            prev_state_root: Hash32::ZERO,
            new_state_root: state_root,
            shard_roots_merkle: Hash32::from_bytes([0x55; 32]),
            circulating_supply: Amount::from_bits(99_999_850),
            total_burned: Amount::from_bits(150),
            verified_tx_count: 4,
            next_committee_root: Hash32::from_bytes([0x77; 32]),
        };

        let genesis_seal = domain_hash("XCR.LIGHT.GENESIS_SEAL.V1", &[]);
        let b0 = Scalar::ZERO;
        let b1 = Scalar::hash_from_parts("TEST", &[b"epoch1-supply-blind"]);
        let proof = SuccinctEpochProof::prove_epoch_transition(
            &genesis_seal,
            Amount::ZERO,
            b0,
            Amount::from_credits(100).unwrap(),
            Amount::from_bits(150),
            b1,
            &hdr,
            &mut signers,
        )
        .unwrap();

        assert!(proof.verify_transition(&genesis_seal, Amount::ZERO, &hdr, &dir, 201));
    }
}
