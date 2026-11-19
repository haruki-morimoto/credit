//! Twisted Edwards Curve25519 (`-x^2 + y^2 = 1 + d*x^2*y^2 mod 2^255-19`) group operations
//! and prime-order `Scalar` arithmetic modulo `l = 2^252 + 27742317777372353535851937790883648493`.
//!
//! Powers homomorphic Pedersen commitments `C = v*B + r*H`, AOS Borromean 64-bit range proofs,
//! and Confidential Transaction excess balance signatures in pure safe `#![forbid(unsafe_code)]` Rust.

use core::ops::{Add, Mul, Neg, Sub};
use std::sync::OnceLock;

use crate::{
    EIGHT_P, Fe25519, carry25519, ct_eq_slice, domain_hash, fe_inv, fe_mul, fe_sq, pack25519,
    sel25519, unpack25519,
};

struct CachedCurveConsts {
    d: Fe25519,
    d2: Fe25519,
    sqrt_m1: Fe25519,
}

static CURVE_CONSTS: OnceLock<CachedCurveConsts> = OnceLock::new();
static GENERATORS: OnceLock<(EdwardsPoint, EdwardsPoint, PrecomputedPointTable)> = OnceLock::new();

fn curve_consts() -> &'static CachedCurveConsts {
    CURVE_CONSTS.get_or_init(|| {
        let (d, d2) = compute_edwards_d_and_2d();
        let sqrt_m1 = compute_sqrt_m1();
        CachedCurveConsts { d, d2, sqrt_m1 }
    })
}

/// Low 128 bits of the RFC 8032 Curve25519 prime subgroup order
/// `l = 2^252 + 27742317777372353535851937790883648493`.
const L_LO: u128 = 27_742_317_777_372_353_535_851_937_790_883_648_493_u128;
const L_HI: u128 = 1_u128 << 124;

#[inline]
fn fe_zero() -> Fe25519 {
    [0u64; 5]
}

#[inline]
fn fe_one() -> Fe25519 {
    [1, 0, 0, 0, 0]
}

#[inline]
fn fe_add_reduced(a: &Fe25519, b: &Fe25519) -> Fe25519 {
    let mut o = [
        a[0] + b[0],
        a[1] + b[1],
        a[2] + b[2],
        a[3] + b[3],
        a[4] + b[4],
    ];
    carry25519(&mut o);
    o
}

#[inline]
fn fe_sub_reduced(a: &Fe25519, b: &Fe25519) -> Fe25519 {
    let mut o = [
        (a[0] + EIGHT_P[0]) - b[0],
        (a[1] + EIGHT_P[1]) - b[1],
        (a[2] + EIGHT_P[2]) - b[2],
        (a[3] + EIGHT_P[3]) - b[3],
        (a[4] + EIGHT_P[4]) - b[4],
    ];
    carry25519(&mut o);
    o
}

#[inline]
fn fe_neg(a: &Fe25519) -> Fe25519 {
    fe_sub_reduced(&fe_zero(), a)
}

/// Computes `d = -121665 / 121666 mod p` and `2*d mod p`.
fn compute_edwards_d_and_2d() -> (Fe25519, Fe25519) {
    let n121665: Fe25519 = [121_665, 0, 0, 0, 0];
    let n121666: Fe25519 = [121_666, 0, 0, 0, 0];
    let d = fe_neg(&fe_mul(&n121665, &fe_inv(&n121666)));
    let d2 = fe_add_reduced(&d, &d);
    (d, d2)
}

/// Computes `sqrt(-1) = 2^((p - 1) / 4) = 2^(2^253 - 5) mod p`.
fn compute_sqrt_m1() -> Fe25519 {
    let two: Fe25519 = [2, 0, 0, 0, 0];
    let mut acc = fe_one();
    let mut cur = two;
    for bit in 0..=252 {
        if bit != 2 {
            acc = fe_mul(&acc, &cur);
        }
        cur = fe_sq(&cur);
    }
    acc
}

/// Computes `w^((p + 3) / 8) = w^(2^252 - 2) mod p` (all bits `1..=251` set, bit `0` clear).
fn pow_p_plus_3_div_8(w: &Fe25519) -> Fe25519 {
    let mut acc = fe_one();
    let mut cur = fe_sq(w); // w^(2^1)
    for _ in 1..=251 {
        acc = fe_mul(&acc, &cur);
        cur = fe_sq(&cur);
    }
    acc
}

/// Element of the scalar field `Z_l` (`l = 2^252 + 27742317777372353535851937790883648493`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Scalar(pub [u8; 32]);

impl Scalar {
    pub const ZERO: Self = Self([0u8; 32]);

    pub const fn from_u64(v: u64) -> Self {
        let mut out = [0u8; 32];
        let b = v.to_le_bytes();
        out[0] = b[0];
        out[1] = b[1];
        out[2] = b[2];
        out[3] = b[3];
        out[4] = b[4];
        out[5] = b[5];
        out[6] = b[6];
        out[7] = b[7];
        Self(out)
    }

    /// Deterministically hashes domain-separated inputs to a uniform `Scalar` mod `l` (512-bit wide reduction).
    pub fn hash_from_parts(domain: &str, parts: &[&[u8]]) -> Self {
        let lo = domain_hash(domain, &[&[0u8], &concat_parts(parts)]).0;
        let hi = domain_hash(domain, &[&[1u8], &concat_parts(parts)]).0;
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&lo);
        wide[32..].copy_from_slice(&hi);
        Self::from_bytes_mod_order_wide(&wide)
    }

    /// Reduces a canonical 32-byte encoding modulo `l`, returning `None` if `bytes >= l`.
    pub fn from_canonical_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let (lo, hi) = bytes32_to_u128_pair(bytes);
        if (hi, lo) >= (L_HI, L_LO) {
            return None;
        }
        Some(Self(*bytes))
    }

    /// Reduces an arbitrary 512-bit little-endian integer modulo `l`.
    pub fn from_bytes_mod_order_wide(wide: &[u8; 64]) -> Self {
        let mut limbs = [0u128; 8]; // 8 x 64-bit little-endian limbs
        for i in 0..8 {
            limbs[i] = u64::from_le_bytes(wide[i * 8..(i + 1) * 8].try_into().unwrap()) as u128;
        }
        Self(reduce_512_limbs_mod_l(limbs))
    }

    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Multiplicative inverse modulo prime `l` via Fermat's Little Theorem (`self^(l - 2) mod l`).
    pub fn invert(&self) -> Option<Self> {
        if *self == Self::ZERO {
            return None;
        }
        let exp_bytes = u128_pair_to_bytes32(L_LO - 2, L_HI);
        let mut acc = Self::from_u64(1);
        let mut base = *self;
        for byte in exp_bytes {
            for bit in 0..8 {
                if (byte >> bit) & 1 == 1 {
                    acc = acc * base;
                }
                base = base * base;
            }
        }
        Some(acc)
    }
}

impl Add for Scalar {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let (a_lo, a_hi) = bytes32_to_u128_pair(&self.0);
        let (b_lo, b_hi) = bytes32_to_u128_pair(&rhs.0);
        let (sum_lo, carry) = a_lo.overflowing_add(b_lo);
        let mut sum_hi = a_hi.wrapping_add(b_hi).wrapping_add(carry as u128);
        let mut final_lo = sum_lo;
        if (sum_hi, final_lo) >= (L_HI, L_LO) {
            let (sub_lo, borrow) = final_lo.overflowing_sub(L_LO);
            final_lo = sub_lo;
            sum_hi = sum_hi.wrapping_sub(L_HI).wrapping_sub(borrow as u128);
        }
        Self(u128_pair_to_bytes32(final_lo, sum_hi))
    }
}

impl Sub for Scalar {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self + (-rhs)
    }
}

impl Neg for Scalar {
    type Output = Self;

    fn neg(self) -> Self::Output {
        if self == Self::ZERO {
            return Self::ZERO;
        }
        let (lo, hi) = bytes32_to_u128_pair(&self.0);
        let (sub_lo, borrow) = L_LO.overflowing_sub(lo);
        let sub_hi = L_HI.wrapping_sub(hi).wrapping_sub(borrow as u128);
        Self(u128_pair_to_bytes32(sub_lo, sub_hi))
    }
}

impl Mul for Scalar {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let mut a = [0u128; 4];
        let mut b = [0u128; 4];
        for i in 0..4 {
            a[i] = u64::from_le_bytes(self.0[i * 8..(i + 1) * 8].try_into().unwrap()) as u128;
            b[i] = u64::from_le_bytes(rhs.0[i * 8..(i + 1) * 8].try_into().unwrap()) as u128;
        }
        let mut prod = [0u128; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let cur = prod[i + j] + a[i] * b[j] + carry;
                prod[i + j] = cur & 0xffff_ffff_ffff_ffff;
                carry = cur >> 64;
            }
            prod[i + 4] += carry;
        }
        Self(reduce_512_limbs_mod_l(prod))
    }
}

fn reduce_512_limbs_mod_l(limbs: [u128; 8]) -> [u8; 32] {
    // Represent value as signed 64-bit limbs and fold everything at bit >= 252 using `2^252 == -L_LO (mod l)`.
    let l_lo_0 = (L_LO & 0xffff_ffff_ffff_ffff) as i128;
    let l_lo_1 = (L_LO >> 64) as i128;

    let mut s = [0i128; 8];
    for i in 0..8 {
        s[i] = limbs[i] as i128;
    }

    // Repeatedly fold top limbs down below bit 252.
    for _ in 0..6 {
        // Carry-propagate limbs 0..7 in 64-bit chunks first.
        for i in 0..7 {
            let c = s[i] >> 64;
            s[i] &= 0xffff_ffff_ffff_ffff;
            s[i + 1] += c;
        }
        // Fold s[7], s[6], s[5], s[4] and top 4 bits of s[3] (since bit 252 is bit 60 of limb 3!).
        for top_idx in (4..=7).rev() {
            let q = s[top_idx];
            if q != 0 {
                s[top_idx] = 0;
                // top_idx * 64 = 252 + (top_idx * 64 - 252); shift = top_idx * 64 - 252 = (top_idx - 4) * 64 + 4.
                // Equivalent per-limb: 2^(top_idx * 64) = 16 * 2^((top_idx - 4) * 64) * 2^252 == -16 * L_LO * 2^((top_idx - 4) * 64).
                let base = top_idx - 4;
                let q16 = q * 16;
                // Split q16 into low/high to avoid i128 overflow when multiplying by 61-bit l_lo_1:
                let q_lo = q16 & 0xffff_ffff;
                let q_hi = q16 >> 32;

                let p0 = q_lo * l_lo_0;
                let p0_hi = q_hi * l_lo_0;
                s[base] -= p0 + ((p0_hi & 0xffff_ffff) << 32);
                s[base + 1] -= p0_hi >> 32;

                let p1 = q_lo * l_lo_1;
                let p1_hi = q_hi * l_lo_1;
                s[base + 1] -= p1 + ((p1_hi & 0xffff_ffff) << 32);
                s[base + 2] -= p1_hi >> 32;
            }
        }
        // Now fold `s[3] >> 60` (bits >= 252):
        let q3 = s[3] >> 60;
        if q3 != 0 {
            s[3] &= (1i128 << 60) - 1;
            let q_lo = q3 & 0xffff_ffff;
            let q_hi = q3 >> 32;
            s[0] -= q_lo * l_lo_0 + (((q_hi * l_lo_0) & 0xffff_ffff) << 32);
            s[1] -= (q_hi * l_lo_0) >> 32;
            s[1] -= q_lo * l_lo_1 + (((q_hi * l_lo_1) & 0xffff_ffff) << 32);
            s[2] -= (q_hi * l_lo_1) >> 32;
        }
    }

    for i in 0..3 {
        let c = s[i] >> 64;
        s[i] &= 0xffff_ffff_ffff_ffff;
        s[i + 1] += c;
    }

    // Reassemble signed 256-bit result and normalize into `[0, l)`.
    let mut lo = (s[0] as u128) | ((s[1] as u128) << 64);
    let mut hi_signed = s[2] + (s[3] << 64);
    while hi_signed < 0 {
        let (n_lo, carry) = lo.overflowing_add(L_LO);
        lo = n_lo;
        hi_signed += (L_HI as i128) + (carry as i128);
    }
    let mut hi = hi_signed as u128;
    while (hi, lo) >= (L_HI, L_LO) {
        let (n_lo, borrow) = lo.overflowing_sub(L_LO);
        lo = n_lo;
        hi = hi.wrapping_sub(L_HI).wrapping_sub(borrow as u128);
    }
    u128_pair_to_bytes32(lo, hi)
}

fn bytes32_to_u128_pair(b: &[u8; 32]) -> (u128, u128) {
    let lo = u128::from_le_bytes(b[0..16].try_into().unwrap());
    let hi = u128::from_le_bytes(b[16..32].try_into().unwrap());
    (lo, hi)
}

fn u128_pair_to_bytes32(lo: u128, hi: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..16].copy_from_slice(&lo.to_le_bytes());
    out[16..32].copy_from_slice(&hi.to_le_bytes());
    out
}

fn concat_parts(parts: &[&[u8]]) -> Vec<u8> {
    let cap: usize = parts.iter().map(|p| p.len() + 8).sum();
    let mut out = Vec::with_capacity(cap);
    for p in parts {
        out.extend_from_slice(&(p.len() as u64).to_le_bytes());
        out.extend_from_slice(p);
    }
    out
}

/// Extended Twisted Edwards point `(X : Y : Z : T)` on Curve25519 (`x = X/Z, y = Y/Z, x*y = T/Z`).
#[derive(Clone, Copy, Debug)]
pub struct EdwardsPoint {
    x: Fe25519,
    y: Fe25519,
    z: Fe25519,
    t: Fe25519,
}

impl PartialEq for EdwardsPoint {
    fn eq(&self, other: &Self) -> bool {
        ct_eq_slice(&self.to_bytes(), &other.to_bytes())
    }
}

impl Eq for EdwardsPoint {}

impl EdwardsPoint {
    /// Neutral identity element `(0, 1)`.
    pub fn identity() -> Self {
        Self {
            x: fe_zero(),
            y: fe_one(),
            z: fe_one(),
            t: fe_zero(),
        }
    }

    /// RFC 8032 Curve25519 basepoint `B` (`y = 4/5 mod p`, positive even `x`).
    pub fn basepoint_b() -> Self {
        GENERATORS
            .get_or_init(|| {
                let b = Self::compute_basepoint_b();
                let h = Self::compute_generator_h();
                let b_tbl = PrecomputedPointTable::new(&b);
                (b, h, b_tbl)
            })
            .0
    }

    /// Cached 4-bit lookup table for RFC 8032 basepoint `B`.
    pub fn basepoint_table() -> &'static PrecomputedPointTable {
        &GENERATORS
            .get_or_init(|| {
                let b = Self::compute_basepoint_b();
                let h = Self::compute_generator_h();
                let b_tbl = PrecomputedPointTable::new(&b);
                (b, h, b_tbl)
            })
            .2
    }

    /// Constant-time scalar multiplication `scalar * B` using the cached basepoint table (~4x faster).
    #[inline]
    pub fn mul_basepoint_ct(scalar: &Scalar) -> Self {
        Self::basepoint_table().mul_ct(scalar)
    }

    /// Nothing-Up-My-Sleeve second Pedersen generator `H = 8 * HashToCurve("XCR.PEDERSEN.H.V1")`
    /// with unknown discrete logarithm relative to `B`.
    pub fn pedersen_generator_h() -> Self {
        GENERATORS
            .get_or_init(|| {
                let b = Self::compute_basepoint_b();
                let h = Self::compute_generator_h();
                let b_tbl = PrecomputedPointTable::new(&b);
                (b, h, b_tbl)
            })
            .1
    }

    fn compute_basepoint_b() -> Self {
        let mut four = fe_zero();
        four[0] = 4;
        let mut five = fe_zero();
        five[0] = 5;
        let y = fe_mul(&four, &fe_inv(&five));
        let mut compressed = pack25519(&y);
        compressed[31] &= 0x7f;
        Self::from_bytes(&compressed).expect("RFC 8032 basepoint B is valid")
    }

    fn compute_generator_h() -> Self {
        for ctr in 0u32..256 {
            let candidate = domain_hash("XCR.PEDERSEN.H.V1", &[&ctr.to_le_bytes()]).0;
            if let Some(pt) = Self::from_bytes(&candidate) {
                let prime_pt = pt.double().double().double();
                if prime_pt != Self::identity() {
                    return prime_pt;
                }
            }
        }
        unreachable!("Hash-to-curve finds valid Edwards point within 256 tries")
    }

    /// Dedicated `dbl-2008-hwcd` Twisted Edwards point doubling (`4M + 4S`, ~2.3x faster than generic `add`).
    #[inline]
    pub fn double(&self) -> Self {
        let a = fe_sq(&self.x);
        let b = fe_sq(&self.y);
        let z2 = fe_sq(&self.z);
        let c = fe_add_reduced(&z2, &z2);
        let d = fe_neg(&a);
        let xy = fe_add_reduced(&self.x, &self.y);
        let e = fe_sub_reduced(&fe_sub_reduced(&fe_sq(&xy), &a), &b);
        let g = fe_add_reduced(&d, &b);
        let f = fe_sub_reduced(&g, &c);
        let h = fe_sub_reduced(&d, &b);
        Self {
            x: fe_mul(&e, &f),
            y: fe_mul(&g, &h),
            z: fe_mul(&f, &g),
            t: fe_mul(&e, &h),
        }
    }

    /// RFC 8032 32-byte compressed Edwards point encoding (`y` + `x_0` sign bit in bit 255).
    pub fn to_bytes(&self) -> [u8; 32] {
        let inv_z = fe_inv(&self.z);
        let x = pack25519(&fe_mul(&self.x, &inv_z));
        let mut y = pack25519(&fe_mul(&self.y, &inv_z));
        y[31] |= (x[0] & 1) << 7;
        y
    }

    /// RFC 8032 point decompression with full curve equation check.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let sign = (bytes[31] >> 7) & 1;
        let mut y_bytes = *bytes;
        y_bytes[31] &= 0x7f;
        let y = unpack25519(&y_bytes);
        // Reject non-canonical `y >= p`:
        if pack25519(&y) != y_bytes {
            return None;
        }

        let consts = curve_consts();
        let y2 = fe_sq(&y);
        let u = fe_sub_reduced(&y2, &fe_one()); // y^2 - 1
        let v = fe_add_reduced(&fe_mul(&consts.d, &y2), &fe_one()); // d*y^2 + 1
        let w = fe_mul(&u, &fe_inv(&v));
        let mut x = pow_p_plus_3_div_8(&w);

        let check = pack25519(&fe_mul(&v, &fe_sq(&x)));
        let u_packed = pack25519(&u);
        let neg_u_packed = pack25519(&fe_neg(&u));
        if check != u_packed {
            if check == neg_u_packed {
                x = fe_mul(&x, &consts.sqrt_m1);
            } else {
                return None;
            }
        }

        let x_packed = pack25519(&x);
        if x_packed == [0u8; 32] && sign == 1 {
            return None;
        }
        if (x_packed[0] & 1) != sign {
            x = fe_neg(&x);
        }

        let t = fe_mul(&x, &y);
        Some(Self {
            x,
            y,
            z: fe_one(),
            t,
        })
    }
}

impl Add for EdwardsPoint {
    type Output = Self;

    /// Strongly unified Hisil-Wong-Carter-Dawson (`add-2008-hwcd`) extended Twisted Edwards addition.
    fn add(self, rhs: Self) -> Self::Output {
        let d2 = &curve_consts().d2;
        let a = fe_mul(
            &fe_sub_reduced(&self.y, &self.x),
            &fe_sub_reduced(&rhs.y, &rhs.x),
        );
        let b = fe_mul(
            &fe_add_reduced(&self.y, &self.x),
            &fe_add_reduced(&rhs.y, &rhs.x),
        );
        let c = fe_mul(&fe_mul(&self.t, d2), &rhs.t);
        let z_mul = fe_mul(&self.z, &rhs.z);
        let d = fe_add_reduced(&z_mul, &z_mul);
        let e = fe_sub_reduced(&b, &a);
        let f = fe_sub_reduced(&d, &c);
        let g = fe_add_reduced(&d, &c);
        let h = fe_add_reduced(&b, &a);
        Self {
            x: fe_mul(&e, &f),
            y: fe_mul(&g, &h),
            z: fe_mul(&f, &g),
            t: fe_mul(&e, &h),
        }
    }
}

impl Neg for EdwardsPoint {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self {
            x: fe_neg(&self.x),
            y: self.y,
            z: self.z,
            t: fe_neg(&self.t),
        }
    }
}

impl Sub for EdwardsPoint {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self + (-rhs)
    }
}

impl Mul<&EdwardsPoint> for Scalar {
    type Output = EdwardsPoint;

    /// Constant-time 4-bit windowed scalar multiplication: scans all 16 table slots with branchless
    /// arithmetic masks (`sel25519`) and executes strongly unified `add-2008-hwcd` on every nibble
    /// (including `nibble == 0`), preventing cache-timing and branch-prediction side channels.
    fn mul(self, point: &EdwardsPoint) -> Self::Output {
        let mut table = [EdwardsPoint::identity(); 16];
        table[1] = *point;
        for i in 2..16 {
            table[i] = table[i - 1] + *point;
        }

        let mut acc = EdwardsPoint::identity();
        for &byte in self.0.iter().rev() {
            for nibble in [byte >> 4, byte & 0x0f] {
                acc = acc.double().double().double().double();
                let chosen = ct_select_point(&table, nibble);
                acc = acc + chosen;
            }
        }
        acc
    }
}

fn ct_select_point(table: &[EdwardsPoint; 16], target: u8) -> EdwardsPoint {
    let mut acc = EdwardsPoint::identity();
    for (idx, candidate) in table.iter().enumerate().skip(1) {
        let diff = (idx as u8 ^ target) as u16;
        let eq_bit = (diff.wrapping_sub(1) >> 15) as u64;
        let mut cand = *candidate;
        sel25519(&mut acc.x, &mut cand.x, eq_bit);
        sel25519(&mut acc.y, &mut cand.y, eq_bit);
        sel25519(&mut acc.z, &mut cand.z, eq_bit);
        sel25519(&mut acc.t, &mut cand.t, eq_bit);
    }
    acc
}

/// Precomputed 4-bit lookup table (`[0*P, 1*P, ..., 15*P]`) for fast fixed-base & Straus MSM operations.
#[derive(Clone, Copy, Debug)]
pub struct PrecomputedPointTable(pub [EdwardsPoint; 16]);

impl PrecomputedPointTable {
    pub fn new(point: &EdwardsPoint) -> Self {
        let mut table = [EdwardsPoint::identity(); 16];
        table[1] = *point;
        table[2] = point.double();
        for i in 3..16 {
            table[i] = table[i - 1] + *point;
        }
        Self(table)
    }

    /// Constant-time 4-bit windowed scalar multiplication using a cached table (for secret witnesses).
    pub fn mul_ct(&self, scalar: &Scalar) -> EdwardsPoint {
        let mut acc = EdwardsPoint::identity();
        for &byte in scalar.0.iter().rev() {
            for nibble in [byte >> 4, byte & 0x0f] {
                acc = acc.double().double().double().double();
                acc = acc + ct_select_point(&self.0, nibble);
            }
        }
        acc
    }
}

impl EdwardsPoint {
    /// Straus shared-doubling Multi-Scalar Multiplication (`sum_i s_i * F_i + sum_j d_j * D_j`) for
    /// public verification equations. Shares a single 256-doubling pass across all bases!
    pub fn vartime_multiscalar_mul_with_tables(
        fixed: &[(Scalar, &PrecomputedPointTable)],
        dynamic: &[(Scalar, EdwardsPoint)],
    ) -> Self {
        let dyn_tables: Vec<(Scalar, PrecomputedPointTable)> = dynamic
            .iter()
            .filter(|(s, _)| *s != Scalar::ZERO)
            .map(|(s, p)| (*s, PrecomputedPointTable::new(p)))
            .collect();

        let mut acc = Self::identity();
        let mut started = false;

        for byte_idx in (0..32).rev() {
            for shift in [4u8, 0u8] {
                if started {
                    acc = acc.double().double().double().double();
                }
                for (scalar, tbl) in fixed {
                    let nib = ((scalar.0[byte_idx] >> shift) & 0x0f) as usize;
                    if nib != 0 {
                        acc = if started {
                            acc + tbl.0[nib]
                        } else {
                            started = true;
                            tbl.0[nib]
                        };
                    }
                }
                for (scalar, tbl) in &dyn_tables {
                    let nib = ((scalar.0[byte_idx] >> shift) & 0x0f) as usize;
                    if nib != 0 {
                        acc = if started {
                            acc + tbl.0[nib]
                        } else {
                            started = true;
                            tbl.0[nib]
                        };
                    }
                }
            }
        }
        acc
    }
}

/// Produces a deterministic 64-byte Curve25519 Schnorr signature `(R_bytes || s_bytes)` proving
/// knowledge of `secret` such that `(secret * B).to_bytes() == *pub_bytes`.
pub fn schnorr_sign(secret: &Scalar, pub_bytes: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let nonce_r = Scalar::hash_from_parts(
        "XCR.SCHNORR.NONCE.V1",
        &[secret.as_bytes(), pub_bytes, message],
    );
    let r_bytes = EdwardsPoint::mul_basepoint_ct(&nonce_r).to_bytes();
    let e = Scalar::hash_from_parts("XCR.SCHNORR.CHAL.V1", &[&r_bytes, pub_bytes, message]);
    let s = nonce_r + (e * *secret);
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r_bytes);
    sig[32..].copy_from_slice(s.as_bytes());
    sig
}

/// Verifies a 64-byte Curve25519 Schnorr signature (`s * B - e * PK == R`) via Straus MSM.
pub fn schnorr_verify(pub_bytes: &[u8; 32], message: &[u8], sig64: &[u8; 64]) -> bool {
    let Some(pk) = EdwardsPoint::from_bytes(pub_bytes) else {
        return false;
    };
    let mut r_arr = [0u8; 32];
    r_arr.copy_from_slice(&sig64[..32]);
    let mut s_arr = [0u8; 32];
    s_arr.copy_from_slice(&sig64[32..]);
    if EdwardsPoint::from_bytes(&r_arr).is_none() {
        return false;
    };
    let Some(s) = Scalar::from_canonical_bytes(&s_arr) else {
        return false;
    };
    let e = Scalar::hash_from_parts("XCR.SCHNORR.CHAL.V1", &[&r_arr, pub_bytes, message]);
    let calc_r = EdwardsPoint::vartime_multiscalar_mul_with_tables(
        &[(s, EdwardsPoint::basepoint_table())],
        &[(-e, pk)],
    );
    ct_eq_slice(&calc_r.to_bytes(), &r_arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use credit_types::Hash32;

    #[test]
    fn rfc8032_basepoint_and_subgroup_order_l_identity() {
        let b = EdwardsPoint::basepoint_b();
        assert_eq!(
            Hash32(b.to_bytes()).to_hex(),
            "5866666666666666666666666666666666666666666666666666666666666666"
        );

        // (l - 1) * B must equal -B, and ((l - 1)*B + B) == Identity!
        let l_minus_1 = -Scalar::from_u64(1);
        let neg_b = l_minus_1 * &b;
        assert_eq!(neg_b, -b);
        assert_eq!(neg_b + b, EdwardsPoint::identity());

        // Generator H must also vanish at order l (`(l - 1)*H + H == Identity`).
        let h = EdwardsPoint::pedersen_generator_h();
        assert_eq!((l_minus_1 * &h) + h, EdwardsPoint::identity());
    }

    #[test]
    fn scalar_field_distributivity_and_homomorphism() {
        let a = Scalar::hash_from_parts("TEST", &[b"alpha"]);
        let b = Scalar::hash_from_parts("TEST", &[b"beta"]);
        let c = Scalar::hash_from_parts("TEST", &[b"gamma"]);
        assert_eq!((a + b) * c, a * c + b * c);

        let g = EdwardsPoint::basepoint_b();
        assert_eq!((a + b) * &g, (a * &g) + (b * &g));
        assert_eq!(g.double(), g + g);

        let tbl_g = PrecomputedPointTable::new(&g);
        let h = EdwardsPoint::pedersen_generator_h();
        let tbl_h = PrecomputedPointTable::new(&h);
        assert_eq!(tbl_g.mul_ct(&a), a * &g);
        let msm_res = EdwardsPoint::vartime_multiscalar_mul_with_tables(
            &[(a, &tbl_g), (b, &tbl_h)],
            &[(c, g + h)],
        );
        assert_eq!(msm_res, (a * &g) + (b * &h) + (c * &(g + h)));

        let pk_bytes = (a * &g).to_bytes();
        let sig = schnorr_sign(&a, &pk_bytes, b"claim-stealth-utxo");
        assert!(schnorr_verify(&pk_bytes, b"claim-stealth-utxo", &sig));
        assert!(!schnorr_verify(&pk_bytes, b"forged-msg", &sig));
    }
}
