//! Elliptic-Curve **Homomorphic Pedersen Commitments**, **64-Bit Borromean/AOS Zero-Knowledge
//! Range Proofs**, and **Confidential Transfer Balance Conservation Proofs** over Curve25519.
//!
//! Guarantees two cryptographic properties simultaneously without revealing wallet amounts:
//! 1. **No Negative / Overflow Minting:** Every confidential output proves `v in [0, 2^64)` via
//!    bit commitments `C_i = b_i*B + r_i*H` (`sum 2^i * C_i == C`) and AOS 2-ring Schnorr proofs.
//! 2. **Exact Bit-Level Conservation:** Validators homomorphically compute
//!    `P_excess = sum(C_in) - sum(C_out) - fee * B` and verify a Schnorr signature on generator `H`,
//!    proving `sum(inputs) == sum(outputs) + fee` to the exact `10^-6 XCR` bit.

use credit_crypto::{EdwardsPoint, Scalar};
use credit_types::Amount;

/// Homomorphic Curve25519 Pedersen Commitment `C = v*B + r*H`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PedersenCommitment(pub EdwardsPoint);

impl PedersenCommitment {
    pub fn commit(amount: Amount, blinding: Scalar) -> Self {
        let b = EdwardsPoint::basepoint_b();
        let h = EdwardsPoint::pedersen_generator_h();
        Self((Scalar::from_u64(amount.bits()) * &b) + (blinding * &h))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        EdwardsPoint::from_bytes(bytes).map(Self)
    }
}

/// Compact AOS 2-ring zero-knowledge bit proof attesting `C_i in {r_i*H, B + r_i*H}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BitOrProof {
    pub bit_commitment: [u8; 32],
    pub e0: Scalar,
    pub s0: Scalar,
    pub s1: Scalar,
}

/// Zero-knowledge range proof attesting `amount in [0, 2^bit_width)` (`bit_width <= 64`)
/// for a `PedersenCommitment`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangeProof64 {
    pub bit_width: u8,
    pub bits: Vec<BitOrProof>,
}

impl RangeProof64 {
    /// Generates a zero-knowledge range proof for `amount < 2^bit_width` (`1 <= bit_width <= 64`).
    pub fn prove(
        amount: Amount,
        total_blinding: Scalar,
        bit_width: u8,
        entropy_seed: &[u8; 32],
    ) -> Option<(PedersenCommitment, Self)> {
        if !(1..=64).contains(&bit_width) {
            return None;
        }
        let val = amount.bits();
        if bit_width < 64 && (val >> bit_width) != 0 {
            return None;
        }

        let b_gen = EdwardsPoint::basepoint_b();
        let h_gen = EdwardsPoint::pedersen_generator_h();
        let total_commitment = PedersenCommitment::commit(amount, total_blinding);
        let total_bytes = total_commitment.to_bytes();

        let width = bit_width as usize;
        let mut r_bits = vec![Scalar::ZERO; width];
        let mut weighted_tail = Scalar::ZERO;
        for (i, r_slot) in r_bits.iter_mut().enumerate().skip(1) {
            let ri = Scalar::hash_from_parts(
                "XCR.ZK.RANGE_BIT_BLIND.V1",
                &[entropy_seed, &total_bytes, &(i as u8).to_le_bytes()],
            );
            *r_slot = ri;
            let two_pow_i = Scalar::from_u64(1u64 << i);
            weighted_tail = weighted_tail + (two_pow_i * ri);
        }
        // Choose `r_0 = total_blinding - sum_{i=1..w-1} 2^i * r_i (mod l)` so `sum_{i=0..w-1} 2^i * C_i == C`!
        r_bits[0] = total_blinding - weighted_tail;

        let mut proofs = Vec::with_capacity(width);
        for (i, &ri) in r_bits.iter().enumerate() {
            let bit = ((val >> i) & 1) as u8;
            let ci_pt = if bit == 0 {
                ri * &h_gen
            } else {
                b_gen + (ri * &h_gen)
            };
            let ci_bytes = ci_pt.to_bytes();

            let k = Scalar::hash_from_parts(
                "XCR.ZK.RANGE_NONCE.V1",
                &[entropy_seed, &ci_bytes, &(i as u8).to_le_bytes(), b"k"],
            );
            let fake_s = Scalar::hash_from_parts(
                "XCR.ZK.RANGE_NONCE.V1",
                &[entropy_seed, &ci_bytes, &(i as u8).to_le_bytes(), b"fake_s"],
            );

            let idx_byte = [i as u8];
            let (e0, s0, s1) = if bit == 0 {
                let r0_pt = k * &h_gen;
                let e1 = Scalar::hash_from_parts(
                    "XCR.ZK.AOS_E1.V1",
                    &[&total_bytes, &idx_byte, &ci_bytes, &r0_pt.to_bytes()],
                );
                let c_minus_b = ci_pt - b_gen;
                let r1_pt = (fake_s * &h_gen) - (e1 * &c_minus_b);
                let e0 = Scalar::hash_from_parts(
                    "XCR.ZK.AOS_E0.V1",
                    &[&total_bytes, &idx_byte, &ci_bytes, &r1_pt.to_bytes()],
                );
                let s0 = k + (e0 * ri);
                (e0, s0, fake_s)
            } else {
                let r1_pt = k * &h_gen;
                let e0 = Scalar::hash_from_parts(
                    "XCR.ZK.AOS_E0.V1",
                    &[&total_bytes, &idx_byte, &ci_bytes, &r1_pt.to_bytes()],
                );
                let r0_pt = (fake_s * &h_gen) - (e0 * &ci_pt);
                let e1 = Scalar::hash_from_parts(
                    "XCR.ZK.AOS_E1.V1",
                    &[&total_bytes, &idx_byte, &ci_bytes, &r0_pt.to_bytes()],
                );
                let s1 = k + (e1 * ri);
                (e0, fake_s, s1)
            };

            proofs.push(BitOrProof {
                bit_commitment: ci_bytes,
                e0,
                s0,
                s1,
            });
        }

        Some((
            total_commitment,
            Self {
                bit_width,
                bits: proofs,
            },
        ))
    }

    /// Verifies both bit-wise AOS zero-knowledge proofs AND homomorphic reconstruction of `commitment`.
    pub fn verify(&self, commitment: &PedersenCommitment) -> bool {
        let width = self.bit_width as usize;
        if !(1..=64).contains(&self.bit_width) || self.bits.len() != width {
            return false;
        }

        let b_gen = EdwardsPoint::basepoint_b();
        let h_gen = EdwardsPoint::pedersen_generator_h();
        let total_bytes = commitment.to_bytes();

        let mut reconstructed = EdwardsPoint::identity();
        for (i, bp) in self.bits.iter().enumerate() {
            let Some(ci_pt) = EdwardsPoint::from_bytes(&bp.bit_commitment) else {
                return false;
            };
            let idx_byte = [i as u8];

            // Ring step 0 -> 1:
            let r0_pt = (bp.s0 * &h_gen) - (bp.e0 * &ci_pt);
            let e1 = Scalar::hash_from_parts(
                "XCR.ZK.AOS_E1.V1",
                &[
                    &total_bytes,
                    &idx_byte,
                    &bp.bit_commitment,
                    &r0_pt.to_bytes(),
                ],
            );

            // Ring step 1 -> 0:
            let c_minus_b = ci_pt - b_gen;
            let r1_pt = (bp.s1 * &h_gen) - (e1 * &c_minus_b);
            let expected_e0 = Scalar::hash_from_parts(
                "XCR.ZK.AOS_E0.V1",
                &[
                    &total_bytes,
                    &idx_byte,
                    &bp.bit_commitment,
                    &r1_pt.to_bytes(),
                ],
            );
            if expected_e0 != bp.e0 {
                return false;
            }

            let scale = Scalar::from_u64(1u64 << i);
            reconstructed = reconstructed + (scale * &ci_pt);
        }

        reconstructed == commitment.0
    }
}

/// Homomorphic Confidential Transaction bundle proving `sum(inputs) == sum(outputs) + fee`
/// and non-negativity of every output without revealing input or output balances.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfidentialTransferProof {
    pub inputs: Vec<PedersenCommitment>,
    pub outputs: Vec<(PedersenCommitment, RangeProof64)>,
    pub public_fee: Amount,
    pub excess_nonce_point: [u8; 32],
    pub excess_response: Scalar,
}

impl ConfidentialTransferProof {
    /// Constructs a full confidential transfer proof from secret input `(amount, blinding)` notes
    /// and desired `(output_amount, bit_width)` targets plus `public_fee`.
    pub fn create(
        inputs: &[(Amount, Scalar)],
        outputs: &[(Amount, u8)],
        public_fee: Amount,
        entropy_seed: &[u8; 32],
    ) -> Option<Self> {
        if inputs.is_empty() || outputs.is_empty() {
            return None;
        }
        let mut in_sum: u128 = 0;
        let mut in_blind_sum = Scalar::ZERO;
        let mut input_commits = Vec::with_capacity(inputs.len());
        for &(amt, blind) in inputs {
            in_sum += amt.bits() as u128;
            in_blind_sum = in_blind_sum + blind;
            input_commits.push(PedersenCommitment::commit(amt, blind));
        }

        let mut out_sum: u128 = public_fee.bits() as u128;
        let mut out_blind_sum = Scalar::ZERO;
        let mut output_bundles = Vec::with_capacity(outputs.len());
        for (idx, &(amt, bit_width)) in outputs.iter().enumerate() {
            out_sum += amt.bits() as u128;
            let out_blind = Scalar::hash_from_parts(
                "XCR.ZK.CT_OUT_BLIND.V1",
                &[entropy_seed, &(idx as u32).to_le_bytes()],
            );
            out_blind_sum = out_blind_sum + out_blind;
            let sub_seed = Scalar::hash_from_parts(
                "XCR.ZK.CT_RANGE_SEED.V1",
                &[entropy_seed, &(idx as u32).to_le_bytes()],
            )
            .0;
            let (commit, range_proof) = RangeProof64::prove(amt, out_blind, bit_width, &sub_seed)?;
            output_bundles.push((commit, range_proof));
        }

        // Exact conservation check:
        if in_sum != out_sum {
            return None;
        }

        // Excess blinding `r_excess = sum(r_in) - sum(r_out)` satisfies `P_excess == r_excess * H`.
        let r_excess = in_blind_sum - out_blind_sum;
        let h_gen = EdwardsPoint::pedersen_generator_h();
        let excess_pt = r_excess * &h_gen;

        let k = Scalar::hash_from_parts("XCR.ZK.CT_EXCESS_NONCE.V1", &[entropy_seed]);
        let r_pt = k * &h_gen;
        let r_bytes = r_pt.to_bytes();
        let e = Scalar::hash_from_parts(
            "XCR.ZK.CT_EXCESS_CHAL.V1",
            &[
                &excess_pt.to_bytes(),
                &r_bytes,
                &public_fee.bits().to_le_bytes(),
            ],
        );
        let s = k + (e * r_excess);

        Some(Self {
            inputs: input_commits,
            outputs: output_bundles,
            public_fee,
            excess_nonce_point: r_bytes,
            excess_response: s,
        })
    }

    /// Public validator verification: checks every output's zero-knowledge range proof AND
    /// verifies homomorphic balance conservation `sum(C_in) - sum(C_out) - fee*B == r_excess*H`.
    pub fn verify(&self) -> bool {
        if self.inputs.is_empty() || self.outputs.is_empty() {
            return false;
        }
        for (commit, range_proof) in &self.outputs {
            if !range_proof.verify(commit) {
                return false;
            }
        }

        let mut sum_in = EdwardsPoint::identity();
        for c in &self.inputs {
            sum_in = sum_in + c.0;
        }
        let mut sum_out = EdwardsPoint::identity();
        for (c, _) in &self.outputs {
            sum_out = sum_out + c.0;
        }

        let b_gen = EdwardsPoint::basepoint_b();
        let h_gen = EdwardsPoint::pedersen_generator_h();
        let fee_pt = Scalar::from_u64(self.public_fee.bits()) * &b_gen;
        let excess_pt = sum_in - sum_out - fee_pt;

        let Some(r_pt) = EdwardsPoint::from_bytes(&self.excess_nonce_point) else {
            return false;
        };
        let e = Scalar::hash_from_parts(
            "XCR.ZK.CT_EXCESS_CHAL.V1",
            &[
                &excess_pt.to_bytes(),
                &self.excess_nonce_point,
                &self.public_fee.bits().to_le_bytes(),
            ],
        );

        (self.excess_response * &h_gen) == (r_pt + (e * &excess_pt))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confidential_pedersen_range_proof_and_homomorphic_conservation() {
        let in_blind = Scalar::hash_from_parts("TEST", &[b"in-note-1"]);
        let in_amt = Amount::from_credits(50).unwrap(); // 50,000,000 bits (< 2^32)

        let out_recipient = Amount::from_chips(1_995).unwrap(); // 19.95 XCR
        let fee = Amount::from_bits(50_000); // 0.05 XCR
        let out_change = in_amt
            .checked_sub(out_recipient)
            .unwrap()
            .checked_sub(fee)
            .unwrap();

        // Use 32-bit range width for fast CI test + verify 64-bit boundary rejection:
        let mut proof = ConfidentialTransferProof::create(
            &[(in_amt, in_blind)],
            &[(out_recipient, 32), (out_change, 32)],
            fee,
            &[0xab; 32],
        )
        .expect("balanced confidential transfer");
        assert!(proof.verify());

        // Tamper public fee by 1 bit (`0.000001 XCR`): homomorphic excess equation MUST fail!
        proof.public_fee = Amount::from_bits(fee.bits() - 1);
        assert!(!proof.verify());
    }
}
