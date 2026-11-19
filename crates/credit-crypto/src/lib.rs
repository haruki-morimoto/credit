//! Pure safe Rust cryptographic foundation for Credits (`XCR`):
//! - **RFC 6234 SHA-256** & domain-separated key derivation (`domain_hash`)
//! - **RFC 7748 X25519 ECDH** unlinkable **Stealth Addresses** (`XCR.STEALTH.V1`) with 1-byte view tags
//! - **RFC 8032 Twisted Edwards Curve25519** & prime-order `Scalar` field (`edwards`)
//! - **RFC 8391-style WOTS+ (`w = 16`) Asymmetric Signatures** with multi-scheme account abstraction
//!   (`PasskeyP256`, `Ed25519`, `HybridPqMlDsa65`)

pub mod edwards;

pub use edwards::{EdwardsPoint, PrecomputedPointTable, Scalar, schnorr_sign, schnorr_verify};

use credit_types::{Address, Hash32};

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Streaming RFC 6234 SHA-256 hasher.
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_bytes: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub const fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buf: [0u8; 64],
            buf_len: 0,
            total_bytes: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total_bytes = self.total_bytes.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let take = (64 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                let block = self.buf;
                self.compress_block(&block);
                self.buf_len = 0;
            }
        }
        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            self.compress_block(&block);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_bytes.wrapping_mul(8);
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;

        if self.buf_len > 56 {
            for b in &mut self.buf[self.buf_len..64] {
                *b = 0;
            }
            let block = self.buf;
            self.compress_block(&block);
            self.buf_len = 0;
        }
        for b in &mut self.buf[self.buf_len..56] {
            *b = 0;
        }
        self.buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let final_block = self.buf;
        self.compress_block(&final_block);

        let mut out = [0u8; 32];
        for (i, &word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    fn compress_block(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

/// Computes RFC 6234 SHA-256 over `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()
}

/// Domain-separated length-prefixed SHA-256 helper preventing cross-protocol hash collisions.
pub fn domain_hash(domain: &str, parts: &[&[u8]]) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(&(domain.len() as u32).to_le_bytes());
    hasher.update(domain.as_bytes());
    hasher.update(&(parts.len() as u32).to_le_bytes());
    for part in parts {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    Hash32(hasher.finalize())
}

// ============================================================================
// 64-Bit Radix-2^51 Field Arithmetic (`GF(2^255 - 19)`) & RFC 7748 X25519
// ============================================================================

/// 5-limb 64-bit radix-`2^51` field element (`x = sum_{i=0..4} o[i] * 2^(51*i) mod 2^255-19`).
pub(crate) type Fe25519 = [u64; 5];

pub(crate) const MASK51: u64 = (1u64 << 51) - 1;

/// `8 * p` in radix-`2^51`, preventing unsigned underflow during subtraction (`b[i] < 2^54`).
pub(crate) const EIGHT_P: Fe25519 = [
    0x003f_ffff_ffff_ff68,
    0x003f_ffff_ffff_fff8,
    0x003f_ffff_ffff_fff8,
    0x003f_ffff_ffff_fff8,
    0x003f_ffff_ffff_fff8,
];

#[inline]
pub(crate) fn carry25519(o: &mut Fe25519) {
    let c0 = o[0] >> 51;
    o[0] &= MASK51;
    o[1] += c0;
    let c1 = o[1] >> 51;
    o[1] &= MASK51;
    o[2] += c1;
    let c2 = o[2] >> 51;
    o[2] &= MASK51;
    o[3] += c2;
    let c3 = o[3] >> 51;
    o[3] &= MASK51;
    o[4] += c3;
    let c4 = o[4] >> 51;
    o[4] &= MASK51;
    o[0] += c4 * 19;
    let c0b = o[0] >> 51;
    o[0] &= MASK51;
    o[1] += c0b;
}

#[inline]
pub(crate) fn sel25519(p: &mut Fe25519, q: &mut Fe25519, b: u64) {
    let mask = b.wrapping_neg();
    for i in 0..5 {
        let t = mask & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

/// Constant-time byte-slice equality check preventing timing side-channel leaks on tags and points.
pub fn ct_eq_slice(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[inline]
fn load_u64_le(slice: &[u8]) -> u64 {
    u64::from_le_bytes(slice[..8].try_into().unwrap())
}

pub(crate) fn unpack25519(n: &[u8; 32]) -> Fe25519 {
    [
        load_u64_le(&n[0..8]) & MASK51,
        (load_u64_le(&n[6..14]) >> 3) & MASK51,
        (load_u64_le(&n[12..20]) >> 6) & MASK51,
        (load_u64_le(&n[19..27]) >> 1) & MASK51,
        (load_u64_le(&n[24..32]) >> 12) & MASK51,
    ]
}

pub(crate) fn pack25519(n: &Fe25519) -> [u8; 32] {
    let mut t = *n;
    carry25519(&mut t);
    carry25519(&mut t);

    // Constant-time final reduction modulo `p = 2^255 - 19` (`q == 1` iff `t >= p`):
    let mut q = (t[0] + 19) >> 51;
    q = (t[1] + q) >> 51;
    q = (t[2] + q) >> 51;
    q = (t[3] + q) >> 51;
    q = (t[4] + q) >> 51;

    t[0] += 19 * q;
    let c0 = t[0] >> 51;
    t[0] &= MASK51;
    t[1] += c0;
    let c1 = t[1] >> 51;
    t[1] &= MASK51;
    t[2] += c1;
    let c2 = t[2] >> 51;
    t[2] &= MASK51;
    t[3] += c2;
    let c3 = t[3] >> 51;
    t[3] &= MASK51;
    t[4] = (t[4] + c3) & MASK51;

    let w0 = t[0] | (t[1] << 51);
    let w1 = (t[1] >> 13) | (t[2] << 38);
    let w2 = (t[2] >> 26) | (t[3] << 25);
    let w3 = (t[3] >> 39) | (t[4] << 12);

    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&w0.to_le_bytes());
    out[8..16].copy_from_slice(&w1.to_le_bytes());
    out[16..24].copy_from_slice(&w2.to_le_bytes());
    out[24..32].copy_from_slice(&w3.to_le_bytes());
    out
}

#[inline]
fn fe_add(a: &Fe25519, b: &Fe25519) -> Fe25519 {
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
fn fe_sub(a: &Fe25519, b: &Fe25519) -> Fe25519 {
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

/// 5x5 Radix-`2^51` schoolbook multiplication using native `u128` accumulators (25 muls vs 256).
#[inline]
pub(crate) fn fe_mul(a: &Fe25519, b: &Fe25519) -> Fe25519 {
    let a0 = a[0] as u128;
    let a1 = a[1] as u128;
    let a2 = a[2] as u128;
    let a3 = a[3] as u128;
    let a4 = a[4] as u128;

    let b0 = b[0] as u128;
    let b1 = b[1] as u128;
    let b2 = b[2] as u128;
    let b3 = b[3] as u128;
    let b4 = b[4] as u128;

    let b1_19 = b1 * 19;
    let b2_19 = b2 * 19;
    let b3_19 = b3 * 19;
    let b4_19 = b4 * 19;

    let mut t0 = a0 * b0 + a1 * b4_19 + a2 * b3_19 + a3 * b2_19 + a4 * b1_19;
    let mut t1 = a0 * b1 + a1 * b0 + a2 * b4_19 + a3 * b3_19 + a4 * b2_19;
    let mut t2 = a0 * b2 + a1 * b1 + a2 * b0 + a3 * b4_19 + a4 * b3_19;
    let mut t3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + a4 * b4_19;
    let mut t4 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;

    let mask = MASK51 as u128;
    let c0 = t0 >> 51;
    t0 &= mask;
    t1 += c0;
    let c1 = t1 >> 51;
    t1 &= mask;
    t2 += c1;
    let c2 = t2 >> 51;
    t2 &= mask;
    t3 += c2;
    let c3 = t3 >> 51;
    t3 &= mask;
    t4 += c3;
    let c4 = t4 >> 51;
    t4 &= mask;
    t0 += c4 * 19;
    let c0b = t0 >> 51;
    t0 &= mask;
    t1 += c0b;

    [t0 as u64, t1 as u64, t2 as u64, t3 as u64, t4 as u64]
}

/// Symmetric 5-limb squaring using only 15 `u128` multiplications (17x fewer than naive 16-limb).
#[inline]
pub(crate) fn fe_sq(a: &Fe25519) -> Fe25519 {
    let a0 = a[0] as u128;
    let a1 = a[1] as u128;
    let a2 = a[2] as u128;
    let a3 = a[3] as u128;
    let a4 = a[4] as u128;

    let a0_2 = a0 * 2;
    let a1_2 = a1 * 2;
    let a1_38 = a1 * 38;
    let a2_38 = a2 * 38;
    let a3_19 = a3 * 19;
    let a3_38 = a3 * 38;
    let a4_19 = a4 * 19;

    let mut t0 = a0 * a0 + a1_38 * a4 + a2_38 * a3;
    let mut t1 = a0_2 * a1 + a2_38 * a4 + a3_19 * a3;
    let mut t2 = a0_2 * a2 + a1 * a1 + a3_38 * a4;
    let mut t3 = a0_2 * a3 + a1_2 * a2 + a4_19 * a4;
    let mut t4 = a0_2 * a4 + a1_2 * a3 + a2 * a2;

    let mask = MASK51 as u128;
    let c0 = t0 >> 51;
    t0 &= mask;
    t1 += c0;
    let c1 = t1 >> 51;
    t1 &= mask;
    t2 += c1;
    let c2 = t2 >> 51;
    t2 &= mask;
    t3 += c2;
    let c3 = t3 >> 51;
    t3 &= mask;
    t4 += c3;
    let c4 = t4 >> 51;
    t4 &= mask;
    t0 += c4 * 19;
    let c0b = t0 >> 51;
    t0 &= mask;
    t1 += c0b;

    [t0 as u64, t1 as u64, t2 as u64, t3 as u64, t4 as u64]
}

pub(crate) fn fe_inv(i: &Fe25519) -> Fe25519 {
    let mut c = *i;
    for a in (0..=253).rev() {
        c = fe_sq(&c);
        if a != 2 && a != 4 {
            c = fe_mul(&c, i);
        }
    }
    c
}

/// RFC 7748 X25519 scalar multiplication over Curve25519.
pub fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    const C121665: Fe25519 = [121_665, 0, 0, 0, 0];
    let mut z = *scalar;
    z[0] &= 248;
    z[31] = (z[31] & 127) | 64;

    let x = unpack25519(point);
    let mut a: Fe25519 = [1, 0, 0, 0, 0];
    let mut b = x;
    let mut c: Fe25519 = [0, 0, 0, 0, 0];
    let mut d: Fe25519 = [1, 0, 0, 0, 0];

    for pos in (0..=254).rev() {
        let bit = ((z[pos >> 3] >> (pos & 7)) & 1) as u64;
        sel25519(&mut a, &mut b, bit);
        sel25519(&mut c, &mut d, bit);
        let e = fe_add(&a, &c);
        let a_sub = fe_sub(&a, &c);
        let c_add = fe_add(&b, &d);
        let b_sub = fe_sub(&b, &d);
        let d_sq = fe_sq(&e);
        let f_sq = fe_sq(&a_sub);
        let a_mul = fe_mul(&c_add, &a_sub);
        let c_mul = fe_mul(&b_sub, &e);
        let e_sum = fe_add(&a_mul, &c_mul);
        let a_diff = fe_sub(&a_mul, &c_mul);
        let b_sq = fe_sq(&a_diff);
        let c_diff = fe_sub(&d_sq, &f_sq);
        let a_c121 = fe_mul(&c_diff, &C121665);
        let a_sum = fe_add(&a_c121, &d_sq);
        c = fe_mul(&c_diff, &a_sum);
        a = fe_mul(&d_sq, &f_sq);
        d = fe_mul(&b_sq, &x);
        b = fe_sq(&e_sum);
        sel25519(&mut a, &mut b, bit);
        sel25519(&mut c, &mut d, bit);
    }
    let inv_c = fe_inv(&c);
    pack25519(&fe_mul(&a, &inv_c))
}

/// Computes `x25519(scalar, 9)` public key on Curve25519 basepoint `u = 9`.
pub fn x25519_basepoint(scalar: &[u8; 32]) -> [u8; 32] {
    let mut base = [0u8; 32];
    base[0] = 9;
    x25519(scalar, &base)
}

// ============================================================================
// Account Abstraction & Asymmetric WOTS+ / Merkle Signatures
// ============================================================================

/// Multi-scheme account abstraction tags built into Credits from Genesis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SignatureScheme {
    /// Hardware Enclave Passkey (`secp256r1` FaceID / TouchID) for instant `Spending Pocket` taps.
    PasskeyP256 = 1,
    /// High-speed node & validator transport identity.
    Ed25519 = 2,
    /// Post-Quantum Guardian identity (`ML-DSA` + hash-based WOTS+ Merkle fallback) for `Savings Vault`.
    HybridPqMlDsa65 = 3,
}

impl SignatureScheme {
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::PasskeyP256),
            2 => Some(Self::Ed25519),
            3 => Some(Self::HybridPqMlDsa65),
            _ => None,
        }
    }
}

const WOTS_CHAINS: usize = 67; // 64 message nibbles + 3 checksum nibbles (base-16)
const MERKLE_HEIGHT: usize = 4; // 16 signatures per lightweight tree root
const MERKLE_LEAVES: usize = 1 << MERKLE_HEIGHT;

/// Verifiable asymmetric public key bound to an unfreezable Layer-1 `Address`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey {
    pub scheme: SignatureScheme,
    pub merkle_root: Hash32,
}

impl PublicKey {
    pub fn to_address(&self) -> Address {
        let tag = [self.scheme as u8];
        let digest = domain_hash("XCR.ACCOUNT.ADDR.V1", &[&tag, self.merkle_root.as_bytes()]);
        Address(digest.0)
    }

    /// Verifies `signature` against `message` using ONLY public key material (zero secret state).
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        match signature {
            Signature::FastSchnorr { scheme, sig64 } => {
                if *scheme != self.scheme || *scheme == SignatureScheme::HybridPqMlDsa65 {
                    return false;
                }
                schnorr_verify(self.merkle_root.as_bytes(), message, sig64)
            }
            Signature::PqWots {
                scheme,
                leaf_index,
                chains,
                auth_path,
            } => {
                if *scheme != self.scheme
                    || (*leaf_index as usize) >= MERKLE_LEAVES
                    || chains.len() != WOTS_CHAINS
                    || auth_path.len() != MERKLE_HEIGHT
                {
                    return false;
                }
                let digits = wots_message_digits(&self.merkle_root, *leaf_index, message);
                let mut pk_parts = [0u8; WOTS_CHAINS * 32];
                for i in 0..WOTS_CHAINS {
                    let remaining = 15u8.saturating_sub(digits[i]);
                    let end_node =
                        wots_chain_advance(&chains[i], digits[i], remaining, *leaf_index, i as u8);
                    pk_parts[i * 32..(i + 1) * 32].copy_from_slice(&end_node);
                }
                let mut current =
                    domain_hash("XCR.WOTS.LEAF.V1", &[&leaf_index.to_le_bytes(), &pk_parts]);
                let mut idx = *leaf_index as usize;
                for sibling in auth_path {
                    current = if idx & 1 == 0 {
                        domain_hash(
                            "XCR.WOTS.NODE.V1",
                            &[current.as_bytes(), sibling.as_bytes()],
                        )
                    } else {
                        domain_hash(
                            "XCR.WOTS.NODE.V1",
                            &[sibling.as_bytes(), current.as_bytes()],
                        )
                    };
                    idx >>= 1;
                }
                current == self.merkle_root
            }
        }
    }
}

/// Multi-tier signature supporting compact **65-byte Curve25519 Schnorr** for sub-1.2KB MTU fast
/// payments/votes (`PasskeyP256`, `Ed25519`) and **2,277-byte Post-Quantum WOTS+/Merkle** for
/// `Savings Vault` guardians (`HybridPqMlDsa65`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signature {
    FastSchnorr {
        scheme: SignatureScheme,
        sig64: [u8; 64],
    },
    PqWots {
        scheme: SignatureScheme,
        leaf_index: u32,
        chains: Vec<[u8; 32]>,
        auth_path: Vec<Hash32>,
    },
}

impl Signature {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::FastSchnorr { scheme, sig64 } => {
                let mut out = Vec::with_capacity(65);
                out.push(*scheme as u8);
                out.extend_from_slice(sig64);
                out
            }
            Self::PqWots {
                scheme,
                leaf_index,
                chains,
                auth_path,
            } => {
                let mut out = Vec::with_capacity(5 + WOTS_CHAINS * 32 + MERKLE_HEIGHT * 32);
                out.push(*scheme as u8);
                out.extend_from_slice(&leaf_index.to_le_bytes());
                for c in chains {
                    out.extend_from_slice(c);
                }
                for node in auth_path {
                    out.extend_from_slice(node.as_bytes());
                }
                out
            }
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let &first = bytes.first()?;
        let scheme = SignatureScheme::from_u8(first)?;
        if bytes.len() == 65 && scheme != SignatureScheme::HybridPqMlDsa65 {
            let mut sig64 = [0u8; 64];
            sig64.copy_from_slice(&bytes[1..65]);
            return Some(Self::FastSchnorr { scheme, sig64 });
        }
        let expected_pq = 5 + WOTS_CHAINS * 32 + MERKLE_HEIGHT * 32;
        if bytes.len() != expected_pq {
            return None;
        }
        let leaf_index = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
        let mut offset = 5;
        let mut chains = Vec::with_capacity(WOTS_CHAINS);
        for _ in 0..WOTS_CHAINS {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes[offset..offset + 32]);
            chains.push(arr);
            offset += 32;
        }
        let mut auth_path = Vec::with_capacity(MERKLE_HEIGHT);
        for _ in 0..MERKLE_HEIGHT {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes[offset..offset + 32]);
            auth_path.push(Hash32(arr));
            offset += 32;
        }
        Some(Self::PqWots {
            scheme,
            leaf_index,
            chains,
            auth_path,
        })
    }
}

#[derive(Clone)]
enum KeypairInner {
    FastSchnorr {
        secret: Scalar,
    },
    PqWots {
        master_seed: [u8; 32],
        tree_nodes: Vec<Vec<Hash32>>,
        next_leaf: u32,
    },
}

/// Sovereign signing keypair supporting deterministic key generation and signing.
#[derive(Clone)]
pub struct Keypair {
    scheme: SignatureScheme,
    inner: KeypairInner,
    public: PublicKey,
}

impl Keypair {
    pub fn from_seed(scheme: SignatureScheme, master_seed: [u8; 32]) -> Self {
        match scheme {
            SignatureScheme::PasskeyP256 | SignatureScheme::Ed25519 => {
                let secret =
                    Scalar::hash_from_parts("XCR.FAST_SIG.SK.V2", &[&[scheme as u8], &master_seed]);
                let pk_bytes = EdwardsPoint::mul_basepoint_ct(&secret).to_bytes();
                Self {
                    scheme,
                    inner: KeypairInner::FastSchnorr { secret },
                    public: PublicKey {
                        scheme,
                        merkle_root: Hash32(pk_bytes),
                    },
                }
            }
            SignatureScheme::HybridPqMlDsa65 => {
                let mut leaves = Vec::with_capacity(MERKLE_LEAVES);
                for leaf_idx in 0..(MERKLE_LEAVES as u32) {
                    let mut pk_parts = [0u8; WOTS_CHAINS * 32];
                    for chain_idx in 0..(WOTS_CHAINS as u8) {
                        let sk = wots_secret_seed(&master_seed, leaf_idx, chain_idx);
                        let pk = wots_chain_advance(&sk, 0, 15, leaf_idx, chain_idx);
                        let i = chain_idx as usize;
                        pk_parts[i * 32..(i + 1) * 32].copy_from_slice(&pk);
                    }
                    leaves.push(domain_hash(
                        "XCR.WOTS.LEAF.V1",
                        &[&leaf_idx.to_le_bytes(), &pk_parts],
                    ));
                }
                let mut tree_nodes = vec![leaves];
                for level in 0..MERKLE_HEIGHT {
                    let prev = &tree_nodes[level];
                    let mut next = Vec::with_capacity(prev.len() / 2);
                    for pair in prev.as_chunks::<2>().0 {
                        next.push(domain_hash(
                            "XCR.WOTS.NODE.V1",
                            &[pair[0].as_bytes(), pair[1].as_bytes()],
                        ));
                    }
                    tree_nodes.push(next);
                }
                let merkle_root = tree_nodes[MERKLE_HEIGHT][0];
                Self {
                    scheme,
                    inner: KeypairInner::PqWots {
                        master_seed,
                        tree_nodes,
                        next_leaf: 0,
                    },
                    public: PublicKey {
                        scheme,
                        merkle_root,
                    },
                }
            }
        }
    }

    #[inline]
    pub const fn public_key(&self) -> PublicKey {
        self.public
    }

    pub fn address(&self) -> Address {
        self.public.to_address()
    }

    pub fn sign(&mut self, message: &[u8]) -> Signature {
        match &mut self.inner {
            KeypairInner::FastSchnorr { secret } => {
                let sig64 = schnorr_sign(secret, self.public.merkle_root.as_bytes(), message);
                Signature::FastSchnorr {
                    scheme: self.scheme,
                    sig64,
                }
            }
            KeypairInner::PqWots {
                master_seed,
                tree_nodes,
                next_leaf,
            } => {
                let leaf_index = *next_leaf % (MERKLE_LEAVES as u32);
                *next_leaf = next_leaf.wrapping_add(1);

                let digits = wots_message_digits(&self.public.merkle_root, leaf_index, message);
                let mut chains = Vec::with_capacity(WOTS_CHAINS);
                for chain_idx in 0..(WOTS_CHAINS as u8) {
                    let sk = wots_secret_seed(master_seed, leaf_index, chain_idx);
                    let steps = digits[chain_idx as usize];
                    chains.push(wots_chain_advance(&sk, 0, steps, leaf_index, chain_idx));
                }

                let mut auth_path = Vec::with_capacity(MERKLE_HEIGHT);
                let mut idx = leaf_index as usize;
                for level_nodes in tree_nodes.iter().take(MERKLE_HEIGHT) {
                    auth_path.push(level_nodes[idx ^ 1]);
                    idx >>= 1;
                }
                Signature::PqWots {
                    scheme: self.scheme,
                    leaf_index,
                    chains,
                    auth_path,
                }
            }
        }
    }
}

fn wots_secret_seed(master_seed: &[u8; 32], leaf_idx: u32, chain_idx: u8) -> [u8; 32] {
    domain_hash(
        "XCR.WOTS.SK.V1",
        &[master_seed, &leaf_idx.to_le_bytes(), &[chain_idx]],
    )
    .0
}

fn wots_chain_advance(
    start: &[u8; 32],
    start_step: u8,
    steps: u8,
    leaf_idx: u32,
    chain_idx: u8,
) -> [u8; 32] {
    let mut cur = *start;
    for step in start_step..(start_step + steps) {
        cur = domain_hash(
            "XCR.WOTS.STEP.V1",
            &[&cur, &leaf_idx.to_le_bytes(), &[chain_idx, step]],
        )
        .0;
    }
    cur
}

fn wots_message_digits(root: &Hash32, leaf_idx: u32, message: &[u8]) -> [u8; WOTS_CHAINS] {
    let digest = domain_hash(
        "XCR.WOTS.MSG.V1",
        &[root.as_bytes(), &leaf_idx.to_le_bytes(), message],
    )
    .0;
    let mut digits = [0u8; WOTS_CHAINS];
    let mut checksum: u16 = 0;
    for (i, &byte) in digest.iter().enumerate() {
        let hi = byte >> 4;
        let lo = byte & 0x0f;
        digits[2 * i] = hi;
        digits[2 * i + 1] = lo;
        checksum += (15 - hi as u16) + (15 - lo as u16);
    }
    digits[64] = ((checksum >> 8) & 0x0f) as u8;
    digits[65] = ((checksum >> 4) & 0x0f) as u8;
    digits[66] = (checksum & 0x0f) as u8;
    digits
}

// ============================================================================
// X25519 Stealth Addresses with 1-Byte View Tags
// ============================================================================

/// Public stealth address bundle shareable on invoices, profiles, and QR codes (`xcrstealth1_...`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StealthMetaAddress {
    pub scan_pub: [u8; 32],
    pub spend_pub: [u8; 32],
}

impl StealthMetaAddress {
    pub const URI_PREFIX: &'static str = "xcrstealth1_";

    /// Formats this Stealth Meta-Address as a shareable `xcrstealth1_<128-hex>` URI string.
    pub fn to_uri(&self) -> String {
        let mut out = String::with_capacity(Self::URI_PREFIX.len() + 128);
        out.push_str(Self::URI_PREFIX);
        out.push_str(&Hash32(self.scan_pub).to_hex());
        out.push_str(&Hash32(self.spend_pub).to_hex());
        out
    }

    /// Parses a shareable `xcrstealth1_<128-hex>` URI string into a `StealthMetaAddress`.
    pub fn from_uri(uri: &str) -> Option<Self> {
        let hex_part = uri.strip_prefix(Self::URI_PREFIX)?;
        if hex_part.len() != 128 {
            return None;
        }
        let scan_pub = decode_hex32(&hex_part[..64])?;
        let spend_pub = decode_hex32(&hex_part[64..128])?;
        let _ = EdwardsPoint::from_bytes(&spend_pub)?;
        Some(Self {
            scan_pub,
            spend_pub,
        })
    }
}

fn decode_hex32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let b = hex.as_bytes();
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = match b[2 * i] {
            c @ b'0'..=b'9' => c - b'0',
            c @ b'a'..=b'f' => c - b'a' + 10,
            c @ b'A'..=b'F' => c - b'A' + 10,
            _ => return None,
        };
        let lo = match b[2 * i + 1] {
            c @ b'0'..=b'9' => c - b'0',
            c @ b'a'..=b'f' => c - b'a' + 10,
            c @ b'A'..=b'F' => c - b'A' + 10,
            _ => return None,
        };
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

/// On-chain stealth output header allowing O(1) view-tag filtering by the recipient.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StealthOutput {
    pub ephemeral_pub: [u8; 32],
    pub view_tag: u8,
    pub one_time_address: Address,
}

/// Recipient's private stealth scanning + Curve25519 Schnorr spending keys.
#[derive(Clone)]
pub struct StealthKeypair {
    scan_secret: [u8; 32],
    spend_scalar: Scalar,
    meta: StealthMetaAddress,
}

impl StealthKeypair {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let scan_secret = domain_hash("XCR.STEALTH.SCAN_SK.V1", &[seed]).0;
        let spend_scalar = Scalar::hash_from_parts("XCR.STEALTH.SPEND_SK.V1", &[seed]);
        let scan_pub = x25519_basepoint(&scan_secret);
        let spend_pub = (spend_scalar * &EdwardsPoint::basepoint_b()).to_bytes();
        Self {
            scan_secret,
            spend_scalar,
            meta: StealthMetaAddress {
                scan_pub,
                spend_pub,
            },
        }
    }

    #[inline]
    pub const fn meta_address(&self) -> StealthMetaAddress {
        self.meta
    }

    /// Scans an announced `(ephemeral_pub, view_tag, one_time_address)` output, rejecting 99.6% of
    /// unrelated outputs via the 1-byte `view_tag`, and returns the shared `kdf` witness on match.
    pub fn scan_and_open(&self, output: &StealthOutput) -> Option<[u8; 32]> {
        let shared = x25519(&self.scan_secret, &output.ephemeral_pub);
        let kdf = domain_hash(
            "XCR.STEALTH.SHARED.V1",
            &[&shared, &output.ephemeral_pub, &self.meta.spend_pub],
        );
        if kdf.0[0] != output.view_tag {
            return None;
        }
        let expected_addr = Address(
            domain_hash(
                "XCR.STEALTH.OT_ADDR.V1",
                &[&self.meta.spend_pub, kdf.as_bytes()],
            )
            .0,
        );
        if expected_addr != output.one_time_address {
            return None;
        }
        Some(kdf.0)
    }

    /// Checks a network `StealthOutput` via the 1-byte `view_tag` and returns a one-time spending seed.
    pub fn scan_output(&self, output: &StealthOutput) -> Option<[u8; 32]> {
        let kdf = self.scan_and_open(output)?;
        Some(
            domain_hash(
                "XCR.STEALTH.OT_SPEND_SEED.V1",
                &[self.spend_scalar.as_bytes(), &kdf],
            )
            .0,
        )
    }

    /// Signs an unforgeable 64-byte Curve25519 Schnorr claim proof sweeping `one_time_address` into `claimant_pocket`.
    pub fn sign_claim(&self, one_time_address: &Address, claimant_pocket: &Address) -> [u8; 64] {
        let msg = domain_hash(
            "XCR.STEALTH.CLAIM_MSG.V1",
            &[one_time_address.as_bytes(), claimant_pocket.as_bytes()],
        );
        schnorr_sign(&self.spend_scalar, &self.meta.spend_pub, msg.as_bytes())
    }
}

/// Verifies both the `one_time_address` preimage `(spend_pub, kdf)` AND the recipient's 64-byte
/// Curve25519 Schnorr spend-key signature (`s * B == R + e * PK`), preventing even the sender from claiming!
pub fn verify_stealth_claim(
    one_time_address: &Address,
    claimant_pocket: &Address,
    spend_pub: &[u8; 32],
    kdf: &[u8; 32],
    schnorr_sig64: &[u8; 64],
) -> bool {
    let expected_addr = Address(domain_hash("XCR.STEALTH.OT_ADDR.V1", &[spend_pub, kdf]).0);
    if expected_addr != *one_time_address {
        return false;
    }
    let msg = domain_hash(
        "XCR.STEALTH.CLAIM_MSG.V1",
        &[one_time_address.as_bytes(), claimant_pocket.as_bytes()],
    );
    schnorr_verify(spend_pub, msg.as_bytes(), schnorr_sig64)
}

/// Sender-side unlinkable stealth destination generator using only `recipient`'s public keys.
pub fn derive_stealth_output(
    recipient: &StealthMetaAddress,
    ephemeral_seed: &[u8; 32],
) -> (StealthOutput, [u8; 32]) {
    let ephemeral_secret = domain_hash("XCR.STEALTH.EPH_SK.V1", &[ephemeral_seed]).0;
    let ephemeral_pub = x25519_basepoint(&ephemeral_secret);
    let shared = x25519(&ephemeral_secret, &recipient.scan_pub);
    let kdf = domain_hash(
        "XCR.STEALTH.SHARED.V1",
        &[&shared, &ephemeral_pub, &recipient.spend_pub],
    );
    let view_tag = kdf.0[0];
    let one_time_address = Address(
        domain_hash(
            "XCR.STEALTH.OT_ADDR.V1",
            &[&recipient.spend_pub, kdf.as_bytes()],
        )
        .0,
    );
    (
        StealthOutput {
            ephemeral_pub,
            view_tag,
            one_time_address,
        },
        kdf.0,
    )
}

/// Maximum UTF-8 byte length of an end-to-end encrypted stealth payment memo (`64` bytes).
pub const MAX_STEALTH_MEMO_BYTES: usize = 64;

/// Encrypts a short invoice/receipt memo (`<= 64` UTF-8 bytes) using the ephemeral X25519 stealth
/// shared `kdf` (`[ciphertext (1..=64B) || mac16 (16B)]`). Returns empty `Vec` if `memo` is empty.
pub fn encrypt_stealth_memo(kdf: &[u8; 32], memo: &str) -> Vec<u8> {
    let trimmed = memo.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let mut end = trimmed.len().min(MAX_STEALTH_MEMO_BYTES);
    while end > 0 && !trimmed.is_char_boundary(end) {
        end -= 1;
    }
    let pt = &trimmed.as_bytes()[..end];
    if pt.is_empty() {
        return Vec::new();
    }
    let ks0 = domain_hash("XCR.STEALTH.MEMO_ENC.V1", &[kdf, &[0u8]]).0;
    let ks1 = domain_hash("XCR.STEALTH.MEMO_ENC.V1", &[kdf, &[1u8]]).0;
    let mut ct = Vec::with_capacity(pt.len() + 16);
    for (i, &b) in pt.iter().enumerate() {
        let k = if i < 32 { ks0[i] } else { ks1[i - 32] };
        ct.push(b ^ k);
    }
    let mac = domain_hash("XCR.STEALTH.MEMO_MAC.V1", &[kdf, &ct]).0;
    ct.extend_from_slice(&mac[..16]);
    ct
}

/// Authenticates and decrypts an end-to-end encrypted stealth payment memo using `kdf`.
pub fn decrypt_stealth_memo(kdf: &[u8; 32], sealed: &[u8]) -> Option<String> {
    if sealed.len() < 17 || sealed.len() > MAX_STEALTH_MEMO_BYTES + 16 {
        return None;
    }
    let ct_len = sealed.len() - 16;
    let ct = &sealed[..ct_len];
    let tag = &sealed[ct_len..];
    let expected_mac = domain_hash("XCR.STEALTH.MEMO_MAC.V1", &[kdf, ct]).0;
    if !ct_eq_slice(tag, &expected_mac[..16]) {
        return None;
    }
    let ks0 = domain_hash("XCR.STEALTH.MEMO_ENC.V1", &[kdf, &[0u8]]).0;
    let ks1 = domain_hash("XCR.STEALTH.MEMO_ENC.V1", &[kdf, &[1u8]]).0;
    let mut pt = Vec::with_capacity(ct_len);
    for (i, &b) in ct.iter().enumerate() {
        let k = if i < 32 { ks0[i] } else { ks1[i - 32] };
        pt.push(b ^ k);
    }
    String::from_utf8(pt).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_nist_vectors() {
        assert_eq!(
            Hash32(sha256(b"")).to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            Hash32(sha256(b"abc")).to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn x25519_matches_rfc7748_section_6_1_vector() {
        let alice_priv: [u8; 32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let bob_priv: [u8; 32] = [
            0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80,
            0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27,
            0xff, 0x88, 0xe0, 0xeb,
        ];
        let alice_pub = x25519_basepoint(&alice_priv);
        let bob_pub = x25519_basepoint(&bob_priv);
        let shared_ab = x25519(&alice_priv, &bob_pub);
        let shared_ba = x25519(&bob_priv, &alice_pub);
        assert_eq!(shared_ab, shared_ba);
        assert_eq!(
            Hash32(shared_ab).to_hex(),
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        );
    }

    #[test]
    fn asymmetric_wots_merkle_signature_and_tamper_rejection() {
        // Fast 65-byte Schnorr Pocket signature:
        let mut fast_kp = Keypair::from_seed(SignatureScheme::PasskeyP256, [0x42; 32]);
        let fast_pk = fast_kp.public_key();
        let msg = b"FastTransfer: 25.000000 XCR";
        let fast_sig = fast_kp.sign(msg);
        assert_eq!(fast_sig.to_bytes().len(), 65);
        assert!(fast_pk.verify(msg, &fast_sig));
        assert!(!fast_pk.verify(b"FastTransfer: 250.000000 XCR", &fast_sig));
        let fast_dec = Signature::from_bytes(&fast_sig.to_bytes()).unwrap();
        assert!(fast_pk.verify(msg, &fast_dec));

        // Post-Quantum 2,277-byte WOTS+/Merkle Vault signature:
        let mut pq_kp = Keypair::from_seed(SignatureScheme::HybridPqMlDsa65, [0x43; 32]);
        let pq_pk = pq_kp.public_key();
        let pq_sig = pq_kp.sign(msg);
        assert!(pq_pk.verify(msg, &pq_sig));
        assert!(!pq_pk.verify(b"FastTransfer: 250.000000 XCR", &pq_sig));
        let pq_dec = Signature::from_bytes(&pq_sig.to_bytes()).unwrap();
        assert!(pq_pk.verify(msg, &pq_dec));
    }

    #[test]
    fn stealth_address_roundtrip_and_unlinkability() {
        let bob = StealthKeypair::from_seed(&[0x11; 32]);
        let carol = StealthKeypair::from_seed(&[0x22; 32]);

        let (out1, _) = derive_stealth_output(&bob.meta_address(), &[0xaa; 32]);
        let (out2, _) = derive_stealth_output(&bob.meta_address(), &[0xbb; 32]);
        assert_ne!(out1.one_time_address, out2.one_time_address);
        assert!(bob.scan_output(&out1).is_some());
        assert!(bob.scan_output(&out2).is_some());
        assert!(carol.scan_output(&out1).is_none());
    }
}
