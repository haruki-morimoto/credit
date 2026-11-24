//! Stage-2 **`MobileLightClient`** (`< 200 bytes` RAM state, `< 10 MB` for 50,000+ epochs).
//!
//! Tracks quorum-certified `EpochStateHeader` transitions from `Genesis (0 XCR)` and verifies
//! compact `O(log2 N)` `StateInclusionProof`s so mobile and browser wallets never trust RPC nodes.

use credit_consensus::QuorumCommittee;
use credit_crypto::{PublicKey, domain_hash};
use credit_types::{Address, Amount, EpochId, Hash32};
use credit_zk::{EpochStateHeader, StateInclusionProof, StateLeaf, SuccinctEpochProof};

/// Verification failures raised by `MobileLightClient`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LightClientError {
    NonSequentialEpoch { expected: EpochId, actual: EpochId },
    BrokenParentHeaderLink,
    BrokenParentStateRoot,
    InvalidEpochTransitionProof,
}

/// Ultra-lightweight client verifier (~160 bytes in memory) suitable for phones, NFC cards, and WASM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MobileLightClient {
    pub latest_epoch: EpochId,
    pub latest_header_hash: Hash32,
    pub latest_state_root: Hash32,
    pub inductive_chain_seal: Hash32,
    pub circulating_supply: Amount,
    pub verified_headers_bytes: usize,
}

impl Default for MobileLightClient {
    fn default() -> Self {
        Self::from_genesis()
    }
}

impl MobileLightClient {
    /// Initializes at Constitutional Fair-Launch Genesis (`Epoch 0`, `Supply == 0.000000 XCR`).
    pub fn from_genesis() -> Self {
        Self {
            latest_epoch: EpochId(0),
            latest_header_hash: Hash32::ZERO,
            latest_state_root: Hash32::ZERO,
            inductive_chain_seal: domain_hash("XCR.LIGHT.GENESIS_SEAL.V1", &[]),
            circulating_supply: Amount::ZERO,
            verified_headers_bytes: 0,
        }
    }

    /// Verifies a `188-byte` `EpochStateHeader` + `SuccinctEpochProof` against `committee`
    /// and advances the mobile client's trusted state root without downloading epoch transactions.
    pub fn verify_and_advance(
        &mut self,
        header: &EpochStateHeader,
        proof: &SuccinctEpochProof,
        committee: &QuorumCommittee,
    ) -> Result<(), LightClientError> {
        let expected_epoch = EpochId(self.latest_epoch.0 + 1);
        if header.epoch != expected_epoch {
            return Err(LightClientError::NonSequentialEpoch {
                expected: expected_epoch,
                actual: header.epoch,
            });
        }
        if header.prev_header_hash != self.latest_header_hash {
            return Err(LightClientError::BrokenParentHeaderLink);
        }
        if header.prev_state_root != self.latest_state_root {
            return Err(LightClientError::BrokenParentStateRoot);
        }

        let dir: Vec<(Address, PublicKey, u64)> = committee
            .members()
            .iter()
            .map(|m| (m.address, m.public_key, m.weight))
            .collect();

        if !proof.verify_transition(
            &self.inductive_chain_seal,
            self.circulating_supply,
            header,
            &dir,
            committee.quorum_threshold(),
        ) {
            return Err(LightClientError::InvalidEpochTransitionProof);
        }

        self.latest_epoch = header.epoch;
        self.latest_header_hash = header.header_hash();
        self.latest_state_root = header.new_state_root;
        self.inductive_chain_seal = proof.inductive_chain_seal;
        self.circulating_supply = header.circulating_supply;
        self.verified_headers_bytes += EpochStateHeader::WIRE_LEN;
        Ok(())
    }

    /// Cryptographically verifies a wallet's `balance` and `nonce` against `self.latest_state_root`.
    pub fn verify_my_account(
        &self,
        leaf: &StateLeaf,
        inclusion_proof: &StateInclusionProof,
    ) -> bool {
        inclusion_proof.verify(leaf, &self.latest_state_root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use credit_consensus::QuorumMember;
    use credit_crypto::{Keypair, Scalar, SignatureScheme};
    use credit_zk::AuthenticatedStateTree;

    #[test]
    fn mobile_light_client_syncs_in_188_bytes_and_rejects_lying_rpc() {
        let mut mobile = MobileLightClient::from_genesis();

        let v1 = Keypair::from_seed(SignatureScheme::Ed25519, [1; 32]);
        let v2 = Keypair::from_seed(SignatureScheme::Ed25519, [2; 32]);
        let v3 = Keypair::from_seed(SignatureScheme::Ed25519, [3; 32]);
        let committee = QuorumCommittee::new(
            EpochId(1),
            vec![
                QuorumMember {
                    address: v1.address(),
                    public_key: v1.public_key(),
                    weight: 100,
                    wan_rtt_ms: 150,
                },
                QuorumMember {
                    address: v2.address(),
                    public_key: v2.public_key(),
                    weight: 100,
                    wan_rtt_ms: 170,
                },
                QuorumMember {
                    address: v3.address(),
                    public_key: v3.public_key(),
                    weight: 100,
                    wan_rtt_ms: 190,
                },
            ],
        );
        let mut signers = vec![(v1.address(), v1), (v2.address(), v2), (v3.address(), v3)];

        let alice = Address::from_bytes([0xaa; 32]);
        let tree = AuthenticatedStateTree::build(vec![StateLeaf {
            address: alice,
            balance: Amount::from_credits(100).unwrap(),
            nonce: 0,
        }]);

        let hdr = EpochStateHeader {
            epoch: EpochId(1),
            prev_header_hash: Hash32::ZERO,
            prev_state_root: Hash32::ZERO,
            new_state_root: tree.root(),
            shard_roots_merkle: Hash32::from_bytes([0x11; 32]),
            circulating_supply: Amount::from_credits(100).unwrap(),
            total_burned: Amount::ZERO,
            verified_tx_count: 1,
            next_committee_root: Hash32::ZERO,
        };
        let proof = SuccinctEpochProof::prove_epoch_transition(
            &mobile.inductive_chain_seal,
            Amount::ZERO,
            Scalar::ZERO,
            Amount::from_credits(100).unwrap(),
            Amount::ZERO,
            Scalar::from_u64(42),
            &hdr,
            &mut signers,
        )
        .unwrap();

        mobile.verify_and_advance(&hdr, &proof, &committee).unwrap();
        assert_eq!(mobile.verified_headers_bytes, 188);

        let (honest_leaf, branch) = tree.prove(&alice).unwrap();
        assert!(mobile.verify_my_account(&honest_leaf, &branch));

        // Untrusted RPC tries to lie that Alice has 0 XCR:
        let spoofed_leaf = StateLeaf {
            balance: Amount::ZERO,
            ..honest_leaf
        };
        assert!(!mobile.verify_my_account(&spoofed_leaf, &branch));
    }
}
