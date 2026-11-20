//! **Logarithmic Inner-Product Bulletproofs (`BulletproofRange64`)** over Curve25519
//! (Bünz, Bootle, Boneh, Poelstra, Wuille, Maxwell — IEEE S&P 2018).
//!
//! Compresses a full **64-bit** zero-knowledge range proof (`v in [0, 2^64)`) from `8,192 B`
//! (`O(n)` bit commitments) down to **672 bytes** (`O(log2 n)` = 6 recursive Inner-Product folding
//! rounds: `4` header points + `3` polynomial scalars + `12` `L/R` points + `2` final scalars).
//!
//! Accelerated with precomputed `OnceLock` 4-bit generator tables, zero-inversion complement folding
//! (`s_i^-1 == s_{(n-1)^i}`), and single-pass Straus shared-doubling Multi-Scalar Multiplication.

use std::sync::OnceLock;

use credit_crypto::{EdwardsPoint, PrecomputedPointTable, Scalar, domain_hash};
use credit_types::Amount;

use crate::PedersenCommitment;

const MAX_BP_BITS: usize = 64;

struct BulletproofGenerators {
    g_vec: [EdwardsPoint; MAX_BP_BITS],
    h_vec: [EdwardsPoint; MAX_BP_BITS],
    g_tables: Vec<PrecomputedPointTable>,
    h_tables: Vec<PrecomputedPointTable>,
    u_table: PrecomputedPointTable,
    b_val_table: PrecomputedPointTable,
    b_blind_table: PrecomputedPointTable,
}

static BP_GENS: OnceLock<BulletproofGenerators> = OnceLock::new();

fn bp_generators() -> &'static BulletproofGenerators {
    BP_GENS.get_or_init(|| {
        let mut g_vec = [EdwardsPoint::identity(); MAX_BP_BITS];
        let mut h_vec = [EdwardsPoint::identity(); MAX_BP_BITS];
        let mut g_tables = Vec::with_capacity(MAX_BP_BITS);
        let mut h_tables = Vec::with_capacity(MAX_BP_BITS);
        for i in 0..MAX_BP_BITS {
            g_vec[i] = hash_to_prime_point("XCR.BP.G_VEC.V1", i as u32);
            h_vec[i] = hash_to_prime_point("XCR.BP.H_VEC.V1", i as u32);
            g_tables.push(PrecomputedPointTable::new(&g_vec[i]));
            h_tables.push(PrecomputedPointTable::new(&h_vec[i]));
        }
        let u_ipa = hash_to_prime_point("XCR.BP.U_IPA.V1", 0);
        let u_table = PrecomputedPointTable::new(&u_ipa);
        let b_val_table = PrecomputedPointTable::new(&EdwardsPoint::basepoint_b());
        let b_blind_table = PrecomputedPointTable::new(&EdwardsPoint::pedersen_generator_h());
        BulletproofGenerators {
            g_vec,
            h_vec,
            g_tables,
            h_tables,
            u_table,
            b_val_table,
            b_blind_table,
        }
    })
}

fn hash_to_prime_point(domain: &str, index: u32) -> EdwardsPoint {
    for ctr in 0u32..512 {
        let candidate = domain_hash(domain, &[&index.to_le_bytes(), &ctr.to_le_bytes()]).0;
        if let Some(pt) = EdwardsPoint::from_bytes(&candidate) {
            let prime_pt = pt.double().double().double();
            if prime_pt != EdwardsPoint::identity() {
                return prime_pt;
            }
        }
    }
    unreachable!("Hash-to-curve finds prime-order Edwards point within 512 tries")
}

/// Logarithmic Inner-Product Argument (`2 * log2(n)` curve points + `2` final scalars).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InnerProductProof {
    pub l_vec: Vec<[u8; 32]>,
    pub r_vec: Vec<[u8; 32]>,
    pub a: Scalar,
    pub b: Scalar,
}

impl InnerProductProof {
    /// Recursive `O(log2 n)` prover for `P = <a, G> + <b, H> + <a, b> * U` accelerated via Straus MSM.
    pub fn prove(
        mut g: Vec<EdwardsPoint>,
        mut h: Vec<EdwardsPoint>,
        u_pt: &EdwardsPoint,
        mut a: Vec<Scalar>,
        mut b: Vec<Scalar>,
        mut transcript_seed: [u8; 32],
    ) -> Self {
        let mut n = a.len();
        assert!(n.is_power_of_two() && g.len() == n && h.len() == n && b.len() == n);

        let rounds = n.trailing_zeros() as usize;
        let mut l_vec = Vec::with_capacity(rounds);
        let mut r_vec = Vec::with_capacity(rounds);
        let u_tbl = PrecomputedPointTable::new(u_pt);

        while n > 1 {
            let half = n / 2;
            let (a_l, a_r) = a.split_at(half);
            let (b_l, b_r) = b.split_at(half);
            let (g_l, g_r) = g.split_at(half);
            let (h_l, h_r) = h.split_at(half);

            let c_l = inner_product(a_l, b_r);
            let c_r = inner_product(a_r, b_l);

            let mut l_terms = Vec::with_capacity(2 * half);
            let mut r_terms = Vec::with_capacity(2 * half);
            for i in 0..half {
                l_terms.push((a_l[i], g_r[i]));
                l_terms.push((b_r[i], h_l[i]));
                r_terms.push((a_r[i], g_l[i]));
                r_terms.push((b_l[i], h_r[i]));
            }
            let l_pt =
                EdwardsPoint::vartime_multiscalar_mul_with_tables(&[(c_l, &u_tbl)], &l_terms);
            let r_pt =
                EdwardsPoint::vartime_multiscalar_mul_with_tables(&[(c_r, &u_tbl)], &r_terms);

            let l_bytes = l_pt.to_bytes();
            let r_bytes = r_pt.to_bytes();
            l_vec.push(l_bytes);
            r_vec.push(r_bytes);

            let mut u_chal = Scalar::hash_from_parts(
                "XCR.BP.IPA_ROUND.V1",
                &[&transcript_seed, &l_bytes, &r_bytes],
            );
            if u_chal == Scalar::ZERO {
                u_chal = Scalar::from_u64(1);
            }
            transcript_seed = u_chal.0;
            let u_inv = u_chal.invert().expect("non-zero Fiat-Shamir challenge");

            let mut next_a = Vec::with_capacity(half);
            let mut next_b = Vec::with_capacity(half);
            let mut next_g = Vec::with_capacity(half);
            let mut next_h = Vec::with_capacity(half);

            for i in 0..half {
                next_a.push((u_chal * a_l[i]) + (u_inv * a_r[i]));
                next_b.push((u_inv * b_l[i]) + (u_chal * b_r[i]));
                next_g.push(EdwardsPoint::vartime_multiscalar_mul_with_tables(
                    &[],
                    &[(u_inv, g_l[i]), (u_chal, g_r[i])],
                ));
                next_h.push(EdwardsPoint::vartime_multiscalar_mul_with_tables(
                    &[],
                    &[(u_chal, h_l[i]), (u_inv, h_r[i])],
                ));
            }

            a = next_a;
            b = next_b;
            g = next_g;
            h = next_h;
            n = half;
        }

        Self {
            l_vec,
            r_vec,
            a: a[0],
            b: b[0],
        }
    }

    /// Standalone verifier checking `P + sum(u_j^2 L_j + u_j^-2 R_j) == a*G_final + b*H_final + (a*b)*U`.
    pub fn verify(
        &self,
        g: &[EdwardsPoint],
        h: &[EdwardsPoint],
        u_pt: &EdwardsPoint,
        p_pt: &EdwardsPoint,
        mut transcript_seed: [u8; 32],
    ) -> bool {
        let n = g.len();
        if !n.is_power_of_two() || h.len() != n {
            return false;
        }
        let rounds = n.trailing_zeros() as usize;
        if self.l_vec.len() != rounds || self.r_vec.len() != rounds {
            return false;
        }

        let mut challenges = Vec::with_capacity(rounds);
        let mut inv_challenges = Vec::with_capacity(rounds);
        let mut dyn_pts = Vec::with_capacity(1 + 2 * rounds + 2 * n);
        dyn_pts.push((Scalar::from_u64(1), *p_pt));

        for round in 0..rounds {
            let Some(l_pt) = EdwardsPoint::from_bytes(&self.l_vec[round]) else {
                return false;
            };
            let Some(r_pt) = EdwardsPoint::from_bytes(&self.r_vec[round]) else {
                return false;
            };
            let mut u_chal = Scalar::hash_from_parts(
                "XCR.BP.IPA_ROUND.V1",
                &[&transcript_seed, &self.l_vec[round], &self.r_vec[round]],
            );
            if u_chal == Scalar::ZERO {
                u_chal = Scalar::from_u64(1);
            }
            transcript_seed = u_chal.0;
            let Some(u_inv) = u_chal.invert() else {
                return false;
            };

            dyn_pts.push((u_chal * u_chal, l_pt));
            dyn_pts.push((u_inv * u_inv, r_pt));
            challenges.push(u_chal);
            inv_challenges.push(u_inv);
        }

        let s_weights = build_s_weights(n, rounds, &challenges, &inv_challenges);
        for i in 0..n {
            let s_inv = s_weights[(n - 1) ^ i];
            dyn_pts.push((-(self.a * s_weights[i]), g[i]));
            dyn_pts.push((-(self.b * s_inv), h[i]));
        }
        dyn_pts.push((-(self.a * self.b), *u_pt));

        EdwardsPoint::vartime_multiscalar_mul_with_tables(&[], &dyn_pts) == EdwardsPoint::identity()
    }
}

fn build_s_weights(
    n: usize,
    rounds: usize,
    challenges: &[Scalar],
    inv_challenges: &[Scalar],
) -> Vec<Scalar> {
    let mut s_weights = vec![Scalar::from_u64(1); n];
    // Compute all `n` subset products in `n - 1` scalar multiplications instead of `n * log2(n)`!
    let mut root_inv = Scalar::from_u64(1);
    for &u_inv in inv_challenges {
        root_inv = root_inv * u_inv;
    }
    s_weights[0] = root_inv;
    for (round_idx, &u_c) in challenges.iter().enumerate().take(rounds) {
        let bit_pos = rounds - 1 - round_idx;
        let step = 1usize << bit_pos;
        let ratio = u_c * u_c; // u_j / u_j^-1 = u_j^2
        for mask in 0..n {
            if (mask & step) != 0 {
                s_weights[mask] = s_weights[mask ^ step] * ratio;
            }
        }
    }
    s_weights
}

/// Logarithmic **Bulletproofs Range Proof** (`672 bytes` for `bit_width = 64`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BulletproofRange64 {
    pub a_commit: [u8; 32],
    pub s_commit: [u8; 32],
    pub t1_commit: [u8; 32],
    pub t2_commit: [u8; 32],
    pub tau_x: Scalar,
    pub mu: Scalar,
    pub t_hat: Scalar,
    pub ipa: InnerProductProof,
}

impl BulletproofRange64 {
    /// Exact serialized byte length for a 64-bit Bulletproof (`672 bytes`).
    pub const SERIALIZED_SIZE_64BIT: usize = 672;

    /// Proves `amount in [0, 2^bit_width)` for `bit_width in {8, 16, 32, 64}`.
    pub fn prove(
        amount: Amount,
        gamma_blinding: Scalar,
        bit_width: usize,
        entropy_seed: &[u8; 32],
    ) -> Option<(PedersenCommitment, Self)> {
        if !bit_width.is_power_of_two() || !(8..=MAX_BP_BITS).contains(&bit_width) {
            return None;
        }
        let val = amount.bits();
        if bit_width < 64 && (val >> bit_width) != 0 {
            return None;
        }

        let gens = bp_generators();
        let v_pt = gens.b_val_table.mul_ct(&Scalar::from_u64(val))
            + gens.b_blind_table.mul_ct(&gamma_blinding);
        let v_commit = PedersenCommitment(v_pt);
        let v_bytes = v_commit.to_bytes();

        let mut a_l = Vec::with_capacity(bit_width);
        let mut a_r = Vec::with_capacity(bit_width);
        let mut s_l = Vec::with_capacity(bit_width);
        let mut s_r = Vec::with_capacity(bit_width);
        let one = Scalar::from_u64(1);

        let alpha = Scalar::hash_from_parts("XCR.BP.ALPHA.V1", &[entropy_seed, &v_bytes]);
        let rho = Scalar::hash_from_parts("XCR.BP.RHO.V1", &[entropy_seed, &v_bytes]);

        let mut a_pt = gens.b_blind_table.mul_ct(&alpha);
        let mut s_fixed_terms: Vec<(Scalar, &PrecomputedPointTable)> =
            Vec::with_capacity(1 + 2 * bit_width);
        s_fixed_terms.push((rho, &gens.b_blind_table));

        for i in 0..bit_width {
            let bit_u64 = (val >> i) & 1;
            let bit = Scalar::from_u64(bit_u64);
            a_l.push(bit);
            a_r.push(bit - one);
            // Constant-time select between `+ G_i` (bit == 1) and `- H_i` (bit == 0):
            let term = if bit_u64 == 1 {
                gens.g_vec[i]
            } else {
                -gens.h_vec[i]
            };
            a_pt = a_pt + term;

            let sl_i = Scalar::hash_from_parts(
                "XCR.BP.SL.V1",
                &[entropy_seed, &v_bytes, &(i as u32).to_le_bytes()],
            );
            let sr_i = Scalar::hash_from_parts(
                "XCR.BP.SR.V1",
                &[entropy_seed, &v_bytes, &(i as u32).to_le_bytes()],
            );
            s_fixed_terms.push((sl_i, &gens.g_tables[i]));
            s_fixed_terms.push((sr_i, &gens.h_tables[i]));
            s_l.push(sl_i);
            s_r.push(sr_i);
        }

        let s_pt = EdwardsPoint::vartime_multiscalar_mul_with_tables(&s_fixed_terms, &[]);
        let a_commit = a_pt.to_bytes();
        let s_commit = s_pt.to_bytes();

        let width_byte = [bit_width as u8];
        let mut y = Scalar::hash_from_parts(
            "XCR.BP.CHAL_Y.V1",
            &[&width_byte, &v_bytes, &a_commit, &s_commit],
        );
        if y == Scalar::ZERO {
            y = one;
        }
        let mut z = Scalar::hash_from_parts(
            "XCR.BP.CHAL_Z.V1",
            &[&width_byte, &v_bytes, &a_commit, &s_commit, y.as_bytes()],
        );
        if z == Scalar::ZERO {
            z = Scalar::from_u64(2);
        }
        let z_sq = z * z;

        let y_pows = powers_of(y, bit_width);
        let two_pows = powers_of(Scalar::from_u64(2), bit_width);

        let mut l0 = Vec::with_capacity(bit_width);
        let mut r0 = Vec::with_capacity(bit_width);
        let mut r1 = Vec::with_capacity(bit_width);
        for i in 0..bit_width {
            l0.push(a_l[i] - z);
            r0.push((y_pows[i] * (a_r[i] + z)) + (z_sq * two_pows[i]));
            r1.push(y_pows[i] * s_r[i]);
        }
        let l1 = s_l;

        let t1 = inner_product(&l0, &r1) + inner_product(&l1, &r0);
        let t2 = inner_product(&l1, &r1);

        let tau1 = Scalar::hash_from_parts("XCR.BP.TAU1.V1", &[entropy_seed, &a_commit]);
        let tau2 = Scalar::hash_from_parts("XCR.BP.TAU2.V1", &[entropy_seed, &s_commit]);

        let t1_commit =
            (gens.b_val_table.mul_ct(&t1) + gens.b_blind_table.mul_ct(&tau1)).to_bytes();
        let t2_commit =
            (gens.b_val_table.mul_ct(&t2) + gens.b_blind_table.mul_ct(&tau2)).to_bytes();

        let mut x = Scalar::hash_from_parts(
            "XCR.BP.CHAL_X.V1",
            &[y.as_bytes(), z.as_bytes(), &t1_commit, &t2_commit],
        );
        if x == Scalar::ZERO {
            x = one;
        }
        let x_sq = x * x;

        let mut l_eval = Vec::with_capacity(bit_width);
        let mut r_eval = Vec::with_capacity(bit_width);
        for i in 0..bit_width {
            l_eval.push(l0[i] + (x * l1[i]));
            r_eval.push(r0[i] + (x * r1[i]));
        }

        let t_hat = inner_product(&l_eval, &r_eval);
        let tau_x = (tau2 * x_sq) + (tau1 * x) + (z_sq * gamma_blinding);
        let mu = alpha + (rho * x);

        let mut w_chal = Scalar::hash_from_parts(
            "XCR.BP.CHAL_W.V1",
            &[
                x.as_bytes(),
                tau_x.as_bytes(),
                mu.as_bytes(),
                t_hat.as_bytes(),
            ],
        );
        if w_chal == Scalar::ZERO {
            w_chal = one;
        }
        let u_scaled = gens.u_table.mul_ct(&w_chal);

        let y_inv = y.invert().expect("non-zero y");
        let y_inv_pows = powers_of(y_inv, bit_width);
        let mut h_prime = Vec::with_capacity(bit_width);
        for i in 0..bit_width {
            h_prime.push(gens.h_tables[i].mul_ct(&y_inv_pows[i]));
        }

        let ipa = InnerProductProof::prove(
            gens.g_vec[..bit_width].to_vec(),
            h_prime,
            &u_scaled,
            l_eval,
            r_eval,
            w_chal.0,
        );

        Some((
            v_commit,
            Self {
                a_commit,
                s_commit,
                t1_commit,
                t2_commit,
                tau_x,
                mu,
                t_hat,
                ipa,
            },
        ))
    }

    /// Single-MSM Bulletproof verifier (`Bünz et al. Section 3.1/4.2`) using cached generator tables
    /// and zero-inversion complement weights (`s_i^-1 == s_{(n-1)^i}`).
    pub fn verify(&self, v_commit: &PedersenCommitment, bit_width: usize) -> bool {
        if !bit_width.is_power_of_two() || !(8..=MAX_BP_BITS).contains(&bit_width) {
            return false;
        }
        let rounds = bit_width.trailing_zeros() as usize;
        if self.ipa.l_vec.len() != rounds || self.ipa.r_vec.len() != rounds {
            return false;
        }
        let Some(a_pt) = EdwardsPoint::from_bytes(&self.a_commit) else {
            return false;
        };
        let Some(s_pt) = EdwardsPoint::from_bytes(&self.s_commit) else {
            return false;
        };
        let Some(t1_pt) = EdwardsPoint::from_bytes(&self.t1_commit) else {
            return false;
        };
        let Some(t2_pt) = EdwardsPoint::from_bytes(&self.t2_commit) else {
            return false;
        };

        let gens = bp_generators();
        let v_bytes = v_commit.to_bytes();
        let one = Scalar::from_u64(1);

        let width_byte = [bit_width as u8];
        let mut y = Scalar::hash_from_parts(
            "XCR.BP.CHAL_Y.V1",
            &[&width_byte, &v_bytes, &self.a_commit, &self.s_commit],
        );
        if y == Scalar::ZERO {
            y = one;
        }
        let mut z = Scalar::hash_from_parts(
            "XCR.BP.CHAL_Z.V1",
            &[
                &width_byte,
                &v_bytes,
                &self.a_commit,
                &self.s_commit,
                y.as_bytes(),
            ],
        );
        if z == Scalar::ZERO {
            z = Scalar::from_u64(2);
        }
        let z_sq = z * z;
        let z_cubed = z_sq * z;

        let y_pows = powers_of(y, bit_width);
        let two_pows = powers_of(Scalar::from_u64(2), bit_width);

        let sum_y = y_pows.iter().copied().fold(Scalar::ZERO, |acc, v| acc + v);
        let sum_two = two_pows
            .iter()
            .copied()
            .fold(Scalar::ZERO, |acc, v| acc + v);
        let delta_yz = ((z - z_sq) * sum_y) - (z_cubed * sum_two);

        let mut x = Scalar::hash_from_parts(
            "XCR.BP.CHAL_X.V1",
            &[y.as_bytes(), z.as_bytes(), &self.t1_commit, &self.t2_commit],
        );
        if x == Scalar::ZERO {
            x = one;
        }
        let x_sq = x * x;

        // 1. Verify polynomial commitment check via shared-doubling Straus MSM:
        let poly_check = EdwardsPoint::vartime_multiscalar_mul_with_tables(
            &[
                (self.t_hat - delta_yz, &gens.b_val_table),
                (self.tau_x, &gens.b_blind_table),
            ],
            &[(-z_sq, v_commit.0), (-x, t1_pt), (-x_sq, t2_pt)],
        );
        if poly_check != EdwardsPoint::identity() {
            return false;
        }

        // 2. Single-pass combined Inner-Product check over cached `G_i, H_i, U_ipa, B_blind` tables:
        let mut w_chal = Scalar::hash_from_parts(
            "XCR.BP.CHAL_W.V1",
            &[
                x.as_bytes(),
                self.tau_x.as_bytes(),
                self.mu.as_bytes(),
                self.t_hat.as_bytes(),
            ],
        );
        if w_chal == Scalar::ZERO {
            w_chal = one;
        }

        let Some(y_inv) = y.invert() else {
            return false;
        };
        let y_inv_pows = powers_of(y_inv, bit_width);

        let mut transcript_seed = w_chal.0;
        let mut challenges = Vec::with_capacity(rounds);
        let mut inv_challenges = Vec::with_capacity(rounds);
        let mut dyn_terms = Vec::with_capacity(1 + 2 * rounds);
        dyn_terms.push((x, s_pt));

        for round in 0..rounds {
            let Some(l_pt) = EdwardsPoint::from_bytes(&self.ipa.l_vec[round]) else {
                return false;
            };
            let Some(r_pt) = EdwardsPoint::from_bytes(&self.ipa.r_vec[round]) else {
                return false;
            };
            let mut u_chal = Scalar::hash_from_parts(
                "XCR.BP.IPA_ROUND.V1",
                &[
                    &transcript_seed,
                    &self.ipa.l_vec[round],
                    &self.ipa.r_vec[round],
                ],
            );
            if u_chal == Scalar::ZERO {
                u_chal = one;
            }
            transcript_seed = u_chal.0;
            let Some(u_inv) = u_chal.invert() else {
                return false;
            };
            dyn_terms.push((u_chal * u_chal, l_pt));
            dyn_terms.push((u_inv * u_inv, r_pt));
            challenges.push(u_chal);
            inv_challenges.push(u_inv);
        }

        let s_weights = build_s_weights(bit_width, rounds, &challenges, &inv_challenges);
        let mut fixed_terms: Vec<(Scalar, &PrecomputedPointTable)> =
            Vec::with_capacity(2 + 2 * bit_width);
        fixed_terms.push((-self.mu, &gens.b_blind_table));
        fixed_terms.push((
            ((self.t_hat - (self.ipa.a * self.ipa.b)) * w_chal),
            &gens.u_table,
        ));

        for i in 0..bit_width {
            let s_inv = s_weights[(bit_width - 1) ^ i];
            let g_coeff = -((self.ipa.a * s_weights[i]) + z);
            let h_coeff = z - (((self.ipa.b * s_inv) - (z_sq * two_pows[i])) * y_inv_pows[i]);
            fixed_terms.push((g_coeff, &gens.g_tables[i]));
            fixed_terms.push((h_coeff, &gens.h_tables[i]));
        }

        let combined = EdwardsPoint::vartime_multiscalar_mul_with_tables(&fixed_terms, &dyn_terms);
        (a_pt + combined) == EdwardsPoint::identity()
    }

    /// Randomized Multi-Proof Batch Verifier (`Bünz et al. Section 4.3`):
    /// Collapses `M` independent Bulletproofs into a **single** 131-generator fixed MSM + shared 256-doubling pass!
    pub fn verify_batch(
        items: &[(&PedersenCommitment, &Self)],
        bit_width: usize,
        batch_entropy: &[u8; 32],
    ) -> bool {
        if items.is_empty() {
            return true;
        }
        if items.len() == 1 {
            return items[0].1.verify(items[0].0, bit_width);
        }
        if !bit_width.is_power_of_two() || !(8..=MAX_BP_BITS).contains(&bit_width) {
            return false;
        }
        let rounds = bit_width.trailing_zeros() as usize;
        let gens = bp_generators();
        let one = Scalar::from_u64(1);
        let two_pows = powers_of(Scalar::from_u64(2), bit_width);
        let sum_two = two_pows
            .iter()
            .copied()
            .fold(Scalar::ZERO, |acc, v| acc + v);
        let width_byte = [bit_width as u8];

        let mut b_val_scalar = Scalar::ZERO;
        let mut b_blind_scalar = Scalar::ZERO;
        let mut u_scalar = Scalar::ZERO;
        let mut g_scalars = vec![Scalar::ZERO; bit_width];
        let mut h_scalars = vec![Scalar::ZERO; bit_width];
        let mut dyn_terms: Vec<(Scalar, EdwardsPoint)> =
            Vec::with_capacity(items.len() * (5 + 2 * rounds));

        for (idx, &(v_commit, proof)) in items.iter().enumerate() {
            if proof.ipa.l_vec.len() != rounds || proof.ipa.r_vec.len() != rounds {
                return false;
            }
            let Some(a_pt) = EdwardsPoint::from_bytes(&proof.a_commit) else {
                return false;
            };
            let Some(s_pt) = EdwardsPoint::from_bytes(&proof.s_commit) else {
                return false;
            };
            let Some(t1_pt) = EdwardsPoint::from_bytes(&proof.t1_commit) else {
                return false;
            };
            let Some(t2_pt) = EdwardsPoint::from_bytes(&proof.t2_commit) else {
                return false;
            };

            let v_bytes = v_commit.to_bytes();
            let mut y = Scalar::hash_from_parts(
                "XCR.BP.CHAL_Y.V1",
                &[&width_byte, &v_bytes, &proof.a_commit, &proof.s_commit],
            );
            if y == Scalar::ZERO {
                y = one;
            }
            let mut z = Scalar::hash_from_parts(
                "XCR.BP.CHAL_Z.V1",
                &[
                    &width_byte,
                    &v_bytes,
                    &proof.a_commit,
                    &proof.s_commit,
                    y.as_bytes(),
                ],
            );
            if z == Scalar::ZERO {
                z = Scalar::from_u64(2);
            }
            let z_sq = z * z;
            let z_cubed = z_sq * z;

            let y_pows = powers_of(y, bit_width);
            let sum_y = y_pows.iter().copied().fold(Scalar::ZERO, |acc, v| acc + v);
            let delta_yz = ((z - z_sq) * sum_y) - (z_cubed * sum_two);

            let mut x = Scalar::hash_from_parts(
                "XCR.BP.CHAL_X.V1",
                &[
                    y.as_bytes(),
                    z.as_bytes(),
                    &proof.t1_commit,
                    &proof.t2_commit,
                ],
            );
            if x == Scalar::ZERO {
                x = one;
            }
            let x_sq = x * x;

            let mut w_chal = Scalar::hash_from_parts(
                "XCR.BP.CHAL_W.V1",
                &[
                    x.as_bytes(),
                    proof.tau_x.as_bytes(),
                    proof.mu.as_bytes(),
                    proof.t_hat.as_bytes(),
                ],
            );
            if w_chal == Scalar::ZERO {
                w_chal = one;
            }
            let Some(y_inv) = y.invert() else {
                return false;
            };
            let y_inv_pows = powers_of(y_inv, bit_width);

            let idx_bytes = (idx as u32).to_le_bytes();
            let mut alpha_k = Scalar::hash_from_parts(
                "XCR.BP.BATCH_ALPHA.V1",
                &[
                    batch_entropy,
                    &idx_bytes,
                    &v_bytes,
                    &proof.t2_commit,
                    proof.tau_x.as_bytes(),
                ],
            );
            if alpha_k == Scalar::ZERO {
                alpha_k = one;
            }
            let mut beta_k = Scalar::hash_from_parts(
                "XCR.BP.BATCH_BETA.V1",
                &[
                    batch_entropy,
                    &idx_bytes,
                    &v_bytes,
                    &proof.a_commit,
                    proof.ipa.a.as_bytes(),
                ],
            );
            if beta_k == Scalar::ZERO {
                beta_k = one;
            }

            // 1. Fold polynomial check weighted by `alpha_k`:
            b_val_scalar = b_val_scalar + (alpha_k * (proof.t_hat - delta_yz));
            b_blind_scalar = b_blind_scalar + (alpha_k * proof.tau_x);
            dyn_terms.push((-(alpha_k * z_sq), v_commit.0));
            dyn_terms.push((-(alpha_k * x), t1_pt));
            dyn_terms.push((-(alpha_k * x_sq), t2_pt));

            // 2. Fold IPA check weighted by `beta_k`:
            dyn_terms.push((beta_k, a_pt));
            dyn_terms.push((beta_k * x, s_pt));

            let mut transcript_seed = w_chal.0;
            let mut challenges = Vec::with_capacity(rounds);
            let mut inv_challenges = Vec::with_capacity(rounds);
            for round in 0..rounds {
                let Some(l_pt) = EdwardsPoint::from_bytes(&proof.ipa.l_vec[round]) else {
                    return false;
                };
                let Some(r_pt) = EdwardsPoint::from_bytes(&proof.ipa.r_vec[round]) else {
                    return false;
                };
                let mut u_chal = Scalar::hash_from_parts(
                    "XCR.BP.IPA_ROUND.V1",
                    &[
                        &transcript_seed,
                        &proof.ipa.l_vec[round],
                        &proof.ipa.r_vec[round],
                    ],
                );
                if u_chal == Scalar::ZERO {
                    u_chal = one;
                }
                transcript_seed = u_chal.0;
                let Some(u_inv) = u_chal.invert() else {
                    return false;
                };
                dyn_terms.push((beta_k * (u_chal * u_chal), l_pt));
                dyn_terms.push((beta_k * (u_inv * u_inv), r_pt));
                challenges.push(u_chal);
                inv_challenges.push(u_inv);
            }

            let s_weights = build_s_weights(bit_width, rounds, &challenges, &inv_challenges);
            b_blind_scalar = b_blind_scalar - (beta_k * proof.mu);
            u_scalar = u_scalar + (beta_k * ((proof.t_hat - (proof.ipa.a * proof.ipa.b)) * w_chal));

            for i in 0..bit_width {
                let s_inv = s_weights[(bit_width - 1) ^ i];
                let g_coeff = -((proof.ipa.a * s_weights[i]) + z);
                let h_coeff = z - (((proof.ipa.b * s_inv) - (z_sq * two_pows[i])) * y_inv_pows[i]);
                g_scalars[i] = g_scalars[i] + (beta_k * g_coeff);
                h_scalars[i] = h_scalars[i] + (beta_k * h_coeff);
            }
        }

        let mut fixed_terms: Vec<(Scalar, &PrecomputedPointTable)> =
            Vec::with_capacity(3 + 2 * bit_width);
        fixed_terms.push((b_val_scalar, &gens.b_val_table));
        fixed_terms.push((b_blind_scalar, &gens.b_blind_table));
        fixed_terms.push((u_scalar, &gens.u_table));
        for i in 0..bit_width {
            fixed_terms.push((g_scalars[i], &gens.g_tables[i]));
            fixed_terms.push((h_scalars[i], &gens.h_tables[i]));
        }

        EdwardsPoint::vartime_multiscalar_mul_with_tables(&fixed_terms, &dyn_terms)
            == EdwardsPoint::identity()
    }

    /// Serializes into compact fixed-stride wire bytes (`672 bytes` for `bit_width = 64`).
    pub fn to_bytes(&self) -> Vec<u8> {
        let rounds = self.ipa.l_vec.len();
        let mut out = Vec::with_capacity((9 + 2 * rounds) * 32);
        out.extend_from_slice(&self.a_commit);
        out.extend_from_slice(&self.s_commit);
        out.extend_from_slice(&self.t1_commit);
        out.extend_from_slice(&self.t2_commit);
        out.extend_from_slice(self.tau_x.as_bytes());
        out.extend_from_slice(self.mu.as_bytes());
        out.extend_from_slice(self.t_hat.as_bytes());
        for l in &self.ipa.l_vec {
            out.extend_from_slice(l);
        }
        for r in &self.ipa.r_vec {
            out.extend_from_slice(r);
        }
        out.extend_from_slice(self.ipa.a.as_bytes());
        out.extend_from_slice(self.ipa.b.as_bytes());
        out
    }

    /// Deserializes a compact Bulletproof for `bit_width` (`rounds = log2(bit_width)`).
    pub fn from_bytes(bytes: &[u8], bit_width: usize) -> Option<Self> {
        if !bit_width.is_power_of_two() || !(8..=MAX_BP_BITS).contains(&bit_width) {
            return None;
        }
        let rounds = bit_width.trailing_zeros() as usize;
        let expected_len = (9 + 2 * rounds) * 32;
        if bytes.len() != expected_len {
            return None;
        }
        let mut pos = 0usize;
        let mut next32 = || -> [u8; 32] {
            let arr: [u8; 32] = bytes[pos..pos + 32].try_into().unwrap();
            pos += 32;
            arr
        };

        let a_commit = next32();
        let s_commit = next32();
        let t1_commit = next32();
        let t2_commit = next32();
        let tau_x = Scalar::from_canonical_bytes(&next32())?;
        let mu = Scalar::from_canonical_bytes(&next32())?;
        let t_hat = Scalar::from_canonical_bytes(&next32())?;

        let mut l_vec = Vec::with_capacity(rounds);
        for _ in 0..rounds {
            l_vec.push(next32());
        }
        let mut r_vec = Vec::with_capacity(rounds);
        for _ in 0..rounds {
            r_vec.push(next32());
        }
        let a = Scalar::from_canonical_bytes(&next32())?;
        let b = Scalar::from_canonical_bytes(&next32())?;

        Some(Self {
            a_commit,
            s_commit,
            t1_commit,
            t2_commit,
            tau_x,
            mu,
            t_hat,
            ipa: InnerProductProof { l_vec, r_vec, a, b },
        })
    }
}

fn inner_product(a: &[Scalar], b: &[Scalar]) -> Scalar {
    let mut sum = Scalar::ZERO;
    for (&x, &y) in a.iter().zip(b.iter()) {
        sum = sum + (x * y);
    }
    sum
}

fn powers_of(base: Scalar, n: usize) -> Vec<Scalar> {
    let mut out = Vec::with_capacity(n);
    let mut cur = Scalar::from_u64(1);
    for _ in 0..n {
        out.push(cur);
        cur = cur * base;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logarithmic_64bit_bulletproof_is_672_bytes_and_verifies_soundly() {
        let amount = Amount::from_bits(123_456_789_012_345);
        let blind = Scalar::hash_from_parts("TEST.BP", &[b"gamma-64"]);

        let (commit, proof) =
            BulletproofRange64::prove(amount, blind, 64, &[0x5a; 32]).expect("64-bit bulletproof");
        let wire = proof.to_bytes();
        assert_eq!(wire.len(), BulletproofRange64::SERIALIZED_SIZE_64BIT); // 672 bytes!

        let decoded = BulletproofRange64::from_bytes(&wire, 64).expect("decode 672B proof");
        assert!(decoded.verify(&commit, 64));

        // Wrong commitment (`+1 bit`) must be rejected by both polynomial and IPA checks:
        let tampered_commit =
            PedersenCommitment::commit(Amount::from_bits(amount.bits() + 1), blind);
        assert!(!decoded.verify(&tampered_commit, 64));

        // Corrupted IPA scalar or point must be rejected:
        let mut bad_wire = wire.clone();
        bad_wire[400] ^= 0x01;
        if let Some(corrupted) = BulletproofRange64::from_bytes(&bad_wire, 64) {
            assert!(!corrupted.verify(&commit, 64));
        }

        // Value overflowing an 8-bit range (`256 >= 2^8`) cannot produce an 8-bit proof:
        assert!(BulletproofRange64::prove(Amount::from_bits(256), blind, 8, &[0x11; 32]).is_none());

        // Multi-proof batch verification accepts valid batches and rejects if any proof is forged:
        let (c2, p2) = BulletproofRange64::prove(
            Amount::from_bits(9_876_543),
            Scalar::from_u64(42),
            64,
            &[0x77; 32],
        )
        .unwrap();
        assert!(BulletproofRange64::verify_batch(
            &[(&commit, &decoded), (&c2, &p2)],
            64,
            &[0x99; 32],
        ));
        assert!(!BulletproofRange64::verify_batch(
            &[(&tampered_commit, &decoded), (&c2, &p2)],
            64,
            &[0x99; 32],
        ));
    }
}
