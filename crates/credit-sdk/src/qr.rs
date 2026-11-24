//! Zero-Dependency **ISO/IEC 18004 QR Code Encoder** (`Versions 1..=10`, Byte Mode, ECC Level `L`).
//!
//! Renders standards-compliant scannable QR codes (up to `271` UTF-8 bytes — plenty for full
//! `xcr:xcrstealth1_<128-hex>?chips=...&inv=...&memo=...` payment URIs and `xcr://claim#...`
//! bearer cash vouchers) as both **crisp SVG vector graphics** and **compact Unicode half-block
//! terminal strings (`▀▄█`)** in 100% safe `#![forbid(unsafe_code)]` `std` Rust.

use core::fmt;

/// Maximum byte payload encodable by Version 10-L in Byte Mode (`271` bytes).
pub const MAX_QR_PAYLOAD_BYTES: usize = 271;

/// Errors returned when encoding an oversized QR payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QrError {
    PayloadTooLarge { len: usize, max: usize },
}

impl fmt::Display for QrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadTooLarge { len, max } => {
                write!(f, "QR payload length {len} bytes exceeds {max}-byte limit")
            }
        }
    }
}

/// ISO/IEC 18004 Table 7 & Table 9 specification entry for Error Correction Level `L`.
#[derive(Clone, Copy)]
struct VersionSpec {
    version: u8,
    total_codewords: usize,
    ec_per_block: usize,
    blocks_g1: usize,
    data_cw_g1: usize,
    blocks_g2: usize,
    data_cw_g2: usize,
    align_coords: &'static [usize],
}

impl VersionSpec {
    const fn total_data_codewords(&self) -> usize {
        self.blocks_g1 * self.data_cw_g1 + self.blocks_g2 * self.data_cw_g2
    }

    const fn byte_mode_capacity(&self) -> usize {
        let header_bits = if self.version <= 9 { 4 + 8 } else { 4 + 16 };
        (self.total_data_codewords() * 8 - header_bits) / 8
    }
}

const VERSION_SPECS_L: [VersionSpec; 10] = [
    VersionSpec {
        version: 1,
        total_codewords: 26,
        ec_per_block: 7,
        blocks_g1: 1,
        data_cw_g1: 19,
        blocks_g2: 0,
        data_cw_g2: 0,
        align_coords: &[],
    },
    VersionSpec {
        version: 2,
        total_codewords: 44,
        ec_per_block: 10,
        blocks_g1: 1,
        data_cw_g1: 34,
        blocks_g2: 0,
        data_cw_g2: 0,
        align_coords: &[6, 18],
    },
    VersionSpec {
        version: 3,
        total_codewords: 70,
        ec_per_block: 15,
        blocks_g1: 1,
        data_cw_g1: 55,
        blocks_g2: 0,
        data_cw_g2: 0,
        align_coords: &[6, 22],
    },
    VersionSpec {
        version: 4,
        total_codewords: 100,
        ec_per_block: 20,
        blocks_g1: 1,
        data_cw_g1: 80,
        blocks_g2: 0,
        data_cw_g2: 0,
        align_coords: &[6, 26],
    },
    VersionSpec {
        version: 5,
        total_codewords: 134,
        ec_per_block: 26,
        blocks_g1: 1,
        data_cw_g1: 108,
        blocks_g2: 0,
        data_cw_g2: 0,
        align_coords: &[6, 30],
    },
    VersionSpec {
        version: 6,
        total_codewords: 172,
        ec_per_block: 18,
        blocks_g1: 2,
        data_cw_g1: 68,
        blocks_g2: 0,
        data_cw_g2: 0,
        align_coords: &[6, 34],
    },
    VersionSpec {
        version: 7,
        total_codewords: 196,
        ec_per_block: 20,
        blocks_g1: 2,
        data_cw_g1: 78,
        blocks_g2: 0,
        data_cw_g2: 0,
        align_coords: &[6, 22, 38],
    },
    VersionSpec {
        version: 8,
        total_codewords: 242,
        ec_per_block: 24,
        blocks_g1: 2,
        data_cw_g1: 97,
        blocks_g2: 0,
        data_cw_g2: 0,
        align_coords: &[6, 24, 42],
    },
    VersionSpec {
        version: 9,
        total_codewords: 292,
        ec_per_block: 30,
        blocks_g1: 2,
        data_cw_g1: 116,
        blocks_g2: 0,
        data_cw_g2: 0,
        align_coords: &[6, 26, 46],
    },
    VersionSpec {
        version: 10,
        total_codewords: 346,
        ec_per_block: 18,
        blocks_g1: 2,
        data_cw_g1: 68,
        blocks_g2: 2,
        data_cw_g2: 69,
        align_coords: &[6, 28, 50],
    },
];

/// Encoded ISO/IEC 18004 QR Code matrix (`size x size` dark/light modules).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QrCode {
    version: u8,
    size: usize,
    mask: u8,
    modules: Vec<bool>,
}

impl QrCode {
    /// Encodes arbitrary bytes (up to `271` bytes) into the smallest fitting ISO/IEC 18004 QR code.
    pub fn encode_bytes(data: &[u8]) -> Result<Self, QrError> {
        let spec = VERSION_SPECS_L
            .iter()
            .find(|s| data.len() <= s.byte_mode_capacity())
            .ok_or(QrError::PayloadTooLarge {
                len: data.len(),
                max: MAX_QR_PAYLOAD_BYTES,
            })?;

        let data_cw = build_byte_mode_data_codewords(data, spec);
        let all_cw = interleave_with_reed_solomon(&data_cw, spec);
        debug_assert_eq!(all_cw.len(), spec.total_codewords);

        let size = 17 + 4 * (spec.version as usize);
        let mut base_modules = vec![false; size * size];
        let mut is_function = vec![false; size * size];

        draw_function_patterns(spec, size, &mut base_modules, &mut is_function);
        draw_codewords(&all_cw, size, &mut base_modules, &is_function);

        let mut best_mask = 0u8;
        let mut best_penalty = u32::MAX;
        let mut best_modules = base_modules.clone();

        for mask in 0..8u8 {
            let mut candidate = base_modules.clone();
            apply_mask(mask, size, &mut candidate, &is_function);
            draw_format_bits(mask, size, &mut candidate);
            let pen = compute_penalty_score(size, &candidate);
            if pen < best_penalty {
                best_penalty = pen;
                best_mask = mask;
                best_modules = candidate;
            }
        }

        Ok(Self {
            version: spec.version,
            size,
            mask: best_mask,
            modules: best_modules,
        })
    }

    /// Encodes a UTF-8 string (such as an `xcr:` payment request or `xcr://claim#` voucher URI).
    pub fn encode_str(text: &str) -> Result<Self, QrError> {
        Self::encode_bytes(text.as_bytes())
    }

    #[inline]
    pub const fn version(&self) -> u8 {
        self.version
    }

    #[inline]
    pub const fn size(&self) -> usize {
        self.size
    }

    #[inline]
    pub const fn mask(&self) -> u8 {
        self.mask
    }

    #[inline]
    pub fn is_dark(&self, row: usize, col: usize) -> bool {
        row < self.size && col < self.size && self.modules[row * self.size + col]
    }

    /// Renders a self-contained, crisp SVG string with a 4-module ISO quiet zone.
    pub fn to_svg(&self, quiet_zone: usize) -> String {
        let total = self.size + 2 * quiet_zone;
        let mut path = String::with_capacity(self.size * self.size * 6);
        for r in 0..self.size {
            for c in 0..self.size {
                if self.is_dark(r, c) {
                    let x = c + quiet_zone;
                    let y = r + quiet_zone;
                    path.push_str(&format!("M{x},{y}h1v1h-1z"));
                }
            }
        }
        format!(
            r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {total} {total}" shape-rendering="crispEdges"><rect width="100%" height="100%" fill="#ffffff"/><path d="{path}" fill="#0b1105"/></svg>"##
        )
    }

    /// Renders a compact, scannable terminal QR code using Unicode half-block characters (`▀▄█ `),
    /// packing two vertical QR rows per terminal line so aspect ratio stays 1:1 on monospace fonts.
    pub fn to_terminal_unicode(&self) -> String {
        let qz = 2isize;
        let n = self.size as isize;
        let mut out = String::new();
        let mut r = -qz;
        while r < n + qz {
            for c in (-qz)..(n + qz) {
                let top_dark =
                    r >= 0 && r < n && c >= 0 && c < n && self.is_dark(r as usize, c as usize);
                let bot_dark = (r + 1) >= 0
                    && (r + 1) < n
                    && c >= 0
                    && c < n
                    && self.is_dark((r + 1) as usize, c as usize);
                // Invert onto light background (`█` = light quiet zone, ` ` = dark module) so dark
                // terminal themes provide a bright white quiet-zone border for phone cameras!
                let ch = match (top_dark, bot_dark) {
                    (false, false) => '█',
                    (false, true) => '▀',
                    (true, false) => '▄',
                    (true, true) => ' ',
                };
                out.push(ch);
            }
            out.push('\n');
            r += 2;
        }
        out
    }
}

fn push_bits(buf: &mut Vec<bool>, val: u32, count: usize) {
    for i in (0..count).rev() {
        buf.push(((val >> i) & 1) != 0);
    }
}

fn build_byte_mode_data_codewords(data: &[u8], spec: &VersionSpec) -> Vec<u8> {
    let cap_bits = spec.total_data_codewords() * 8;
    let mut bits = Vec::with_capacity(cap_bits);
    // Byte mode indicator `0100`:
    push_bits(&mut bits, 0b0100, 4);
    let count_bits = if spec.version <= 9 { 8 } else { 16 };
    push_bits(&mut bits, data.len() as u32, count_bits);
    for &b in data {
        push_bits(&mut bits, b as u32, 8);
    }
    // Up to 4 zero terminator bits:
    let term = (cap_bits - bits.len()).min(4);
    bits.extend(std::iter::repeat_n(false, term));
    let rem_pad = (8 - (bits.len() % 8)) % 8;
    bits.extend(std::iter::repeat_n(false, rem_pad));
    let mut out = Vec::with_capacity(spec.total_data_codewords());
    for chunk in bits.as_chunks::<8>().0 {
        let mut byte = 0u8;
        for &bit in chunk {
            byte = (byte << 1) | (bit as u8);
        }
        out.push(byte);
    }
    let pad_bytes = [0xECu8, 0x11u8];
    let mut pad_idx = 0usize;
    while out.len() < spec.total_data_codewords() {
        out.push(pad_bytes[pad_idx & 1]);
        pad_idx += 1;
    }
    out
}

/// Multiplies `a` and `b` in `GF(256)` modulo `x^8 + x^4 + x^3 + x^2 + 1` (`0x11D`).
#[inline]
fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut prod = 0u8;
    for _ in 0..8 {
        if (b & 1) != 0 {
            prod ^= a;
        }
        let hi = (a & 0x80) != 0;
        a <<= 1;
        if hi {
            a ^= 0x1D;
        }
        b >>= 1;
    }
    prod
}

/// Computes the monic Reed-Solomon generator polynomial coefficients `g[0..degree]`
/// (excluding the leading `1 * x^degree` term, ordered from `x^(degree-1)` down to `x^0`).
fn rs_divisor_poly(degree: usize) -> Vec<u8> {
    let mut poly = vec![0u8; degree];
    poly[degree - 1] = 1;
    let mut root = 1u8;
    for _ in 0..degree {
        for j in 0..degree {
            poly[j] = gf256_mul(poly[j], root);
            if j + 1 < degree {
                poly[j] ^= poly[j + 1];
            }
        }
        root = gf256_mul(root, 0x02);
    }
    poly
}

fn rs_compute_remainder(data: &[u8], divisor: &[u8]) -> Vec<u8> {
    let mut rem = vec![0u8; divisor.len()];
    for &byte in data {
        let factor = byte ^ rem[0];
        rem.rotate_left(1);
        *rem.last_mut().unwrap() = 0;
        for (r, &d) in rem.iter_mut().zip(divisor.iter()) {
            *r ^= gf256_mul(d, factor);
        }
    }
    rem
}

fn interleave_with_reed_solomon(data_cw: &[u8], spec: &VersionSpec) -> Vec<u8> {
    let divisor = rs_divisor_poly(spec.ec_per_block);
    let total_blocks = spec.blocks_g1 + spec.blocks_g2;
    let mut data_blocks: Vec<&[u8]> = Vec::with_capacity(total_blocks);
    let mut ec_blocks: Vec<Vec<u8>> = Vec::with_capacity(total_blocks);

    let mut offset = 0usize;
    for i in 0..total_blocks {
        let len = if i < spec.blocks_g1 {
            spec.data_cw_g1
        } else {
            spec.data_cw_g2
        };
        let slice = &data_cw[offset..offset + len];
        offset += len;
        ec_blocks.push(rs_compute_remainder(slice, &divisor));
        data_blocks.push(slice);
    }

    let max_data_len = spec.data_cw_g1.max(spec.data_cw_g2);
    let mut result = Vec::with_capacity(spec.total_codewords);
    for col in 0..max_data_len {
        for blk in &data_blocks {
            if col < blk.len() {
                result.push(blk[col]);
            }
        }
    }
    for col in 0..spec.ec_per_block {
        for ec in &ec_blocks {
            result.push(ec[col]);
        }
    }
    result
}

fn set_func(
    row: usize,
    col: usize,
    dark: bool,
    size: usize,
    modules: &mut [bool],
    is_func: &mut [bool],
) {
    let idx = row * size + col;
    modules[idx] = dark;
    is_func[idx] = true;
}

fn draw_finder_with_sep(
    center_r: isize,
    center_c: isize,
    size: usize,
    modules: &mut [bool],
    is_func: &mut [bool],
) {
    for dr in -4..=4isize {
        for dc in -4..=4isize {
            let r = center_r + dr;
            let c = center_c + dc;
            if r >= 0 && r < size as isize && c >= 0 && c < size as isize {
                let dist = dr.unsigned_abs().max(dc.unsigned_abs());
                let dark = dist != 2 && dist != 4;
                set_func(r as usize, c as usize, dark, size, modules, is_func);
            }
        }
    }
}

fn draw_alignment_pattern(
    center_r: usize,
    center_c: usize,
    size: usize,
    modules: &mut [bool],
    is_func: &mut [bool],
) {
    for dr in -2..=2isize {
        for dc in -2..=2isize {
            let dist = dr.unsigned_abs().max(dc.unsigned_abs());
            let r = (center_r as isize + dr) as usize;
            let c = (center_c as isize + dc) as usize;
            set_func(r, c, dist != 1, size, modules, is_func);
        }
    }
}

/// Computes the 15-bit BCH `(15, 5)` Format Information word for EC Level `L` (`0b01`) and `mask`.
pub(crate) fn format_info_bits_level_l(mask: u8) -> u16 {
    let data = (0b01u16 << 3) | ((mask & 7) as u16);
    let mut rem = data << 10;
    for i in (0..5).rev() {
        if ((rem >> (i + 10)) & 1) != 0 {
            rem ^= 0x537u16 << i;
        }
    }
    ((data << 10) | rem) ^ 0x5412
}

/// Computes the 18-bit BCH `(18, 6)` Version Information word for `version >= 7`.
pub(crate) fn version_info_bits(version: u8) -> u32 {
    let data = version as u32;
    let mut rem = data << 12;
    for i in (0..6).rev() {
        if ((rem >> (i + 12)) & 1) != 0 {
            rem ^= 0x1F25u32 << i;
        }
    }
    (data << 12) | rem
}

fn draw_format_bits(mask: u8, size: usize, modules: &mut [bool]) {
    let bits = format_info_bits_level_l(mask);
    let bit = |idx: usize| -> bool { ((bits >> idx) & 1) != 0 };

    // Copy 1: around top-left finder (MSB = bit 14 at `(8, 0)`, LSB = bit 0 at `(0, 8)`):
    let tl_coords: [(usize, usize); 15] = [
        (0, 8),
        (1, 8),
        (2, 8),
        (3, 8),
        (4, 8),
        (5, 8),
        (7, 8),
        (8, 8),
        (8, 7),
        (8, 5),
        (8, 4),
        (8, 3),
        (8, 2),
        (8, 1),
        (8, 0),
    ];
    for (idx, &(r, c)) in tl_coords.iter().enumerate() {
        modules[r * size + c] = bit(idx);
    }

    // Copy 2: top-right (`bits 0..=7`) and bottom-left (`bits 8..=14`):
    for idx in 0..8 {
        let c = size - 1 - idx;
        modules[8 * size + c] = bit(idx);
    }
    for idx in 8..15 {
        let r = size - 15 + idx;
        modules[r * size + 8] = bit(idx);
    }
    // Always-dark module at `(size - 8, 8)`:
    modules[(size - 8) * size + 8] = true;
}

fn draw_function_patterns(
    spec: &VersionSpec,
    size: usize,
    modules: &mut [bool],
    is_func: &mut [bool],
) {
    // Timing patterns along row 6 and col 6:
    for i in 0..size {
        let dark = i.is_multiple_of(2);
        set_func(6, i, dark, size, modules, is_func);
        set_func(i, 6, dark, size, modules, is_func);
    }

    // Three 7x7 finder patterns + 1-module white separators:
    draw_finder_with_sep(3, 3, size, modules, is_func);
    draw_finder_with_sep(3, size as isize - 4, size, modules, is_func);
    draw_finder_with_sep(size as isize - 4, 3, size, modules, is_func);

    // Alignment patterns (excluding the 3 finder corners):
    let k = spec.align_coords.len();
    for (ri, &r) in spec.align_coords.iter().enumerate() {
        for (ci, &c) in spec.align_coords.iter().enumerate() {
            let is_finder_corner =
                (ri == 0 && ci == 0) || (ri == 0 && ci + 1 == k) || (ri + 1 == k && ci == 0);
            if !is_finder_corner {
                draw_alignment_pattern(r, c, size, modules, is_func);
            }
        }
    }

    // Reserve Format Information + Dark Module positions:
    for i in 0..9 {
        if i != 6 {
            set_func(8, i, false, size, modules, is_func);
            set_func(i, 8, false, size, modules, is_func);
        }
    }
    for i in 0..8 {
        set_func(8, size - 1 - i, false, size, modules, is_func);
        set_func(size - 1 - i, 8, false, size, modules, is_func);
    }
    set_func(size - 8, 8, true, size, modules, is_func);

    // Version Information blocks for Version >= 7:
    if spec.version >= 7 {
        let vbits = version_info_bits(spec.version);
        for i in 0..18usize {
            let dark = ((vbits >> i) & 1) != 0;
            let a = i / 3;
            let b = (i % 3) + (size - 11);
            set_func(b, a, dark, size, modules, is_func);
            set_func(a, b, dark, size, modules, is_func);
        }
    }
}

fn draw_codewords(codewords: &[u8], size: usize, modules: &mut [bool], is_func: &[bool]) {
    let mut bit_idx = 0usize;
    let total_bits = codewords.len() * 8;
    let mut right = size as isize - 1;
    let mut upward = true;

    while right >= 1 {
        if right == 6 {
            right = 5; // Skip vertical timing column 6
        }
        for step in 0..size {
            let r = if upward { size - 1 - step } else { step };
            for dx in 0..2isize {
                let c = (right - dx) as usize;
                let pos = r * size + c;
                if !is_func[pos] {
                    let dark = if bit_idx < total_bits {
                        ((codewords[bit_idx >> 3] >> (7 - (bit_idx & 7))) & 1) != 0
                    } else {
                        false
                    };
                    modules[pos] = dark;
                    bit_idx += 1;
                }
            }
        }
        upward = !upward;
        right -= 2;
    }
}

#[inline]
fn mask_bit(mask: u8, r: usize, c: usize) -> bool {
    match mask {
        0 => (r + c).is_multiple_of(2),
        1 => r.is_multiple_of(2),
        2 => c.is_multiple_of(3),
        3 => (r + c).is_multiple_of(3),
        4 => ((r / 2) + (c / 3)).is_multiple_of(2),
        5 => ((r * c) % 2) + ((r * c) % 3) == 0,
        6 => (((r * c) % 2) + ((r * c) % 3)).is_multiple_of(2),
        _ => (((r + c) % 2) + ((r * c) % 3)).is_multiple_of(2),
    }
}

fn apply_mask(mask: u8, size: usize, modules: &mut [bool], is_func: &[bool]) {
    for r in 0..size {
        for c in 0..size {
            let idx = r * size + c;
            if !is_func[idx] && mask_bit(mask, r, c) {
                modules[idx] = !modules[idx];
            }
        }
    }
}

fn compute_penalty_score(size: usize, modules: &[bool]) -> u32 {
    let mut penalty = 0u32;

    // Rule 1: runs of >= 5 identical modules in rows and columns:
    for r in 0..size {
        let mut run_color = modules[r * size];
        let mut run_len = 1usize;
        for c in 1..size {
            let cur = modules[r * size + c];
            if cur == run_color {
                run_len += 1;
            } else {
                if run_len >= 5 {
                    penalty += 3 + (run_len as u32 - 5);
                }
                run_color = cur;
                run_len = 1;
            }
        }
        if run_len >= 5 {
            penalty += 3 + (run_len as u32 - 5);
        }
    }
    for c in 0..size {
        let mut run_color = modules[c];
        let mut run_len = 1usize;
        for r in 1..size {
            let cur = modules[r * size + c];
            if cur == run_color {
                run_len += 1;
            } else {
                if run_len >= 5 {
                    penalty += 3 + (run_len as u32 - 5);
                }
                run_color = cur;
                run_len = 1;
            }
        }
        if run_len >= 5 {
            penalty += 3 + (run_len as u32 - 5);
        }
    }

    // Rule 2: 2x2 solid-color blocks:
    for r in 0..(size - 1) {
        for c in 0..(size - 1) {
            let v = modules[r * size + c];
            if modules[r * size + c + 1] == v
                && modules[(r + 1) * size + c] == v
                && modules[(r + 1) * size + c + 1] == v
            {
                penalty += 3;
            }
        }
    }

    // Rule 4: dark/light balance deviation from 50%:
    let dark_count = modules.iter().filter(|&&b| b).count() as u32;
    let total = (size * size) as u32;
    let k = (dark_count.abs_diff(total - dark_count) * 10) / total;
    penalty += k * 10;

    penalty
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_18004_tables_and_bch_vectors_are_exact() {
        // Verify Version 7 BCH Annex D Table D.1 (`0x07C94`):
        assert_eq!(version_info_bits(7), 0x07C94);
        assert_eq!(version_info_bits(10), 0x0A4D3);

        // Verify every Version 1..=10 has exact `free_modules / 8 == total_codewords`:
        for spec in &VERSION_SPECS_L {
            let size = 17 + 4 * (spec.version as usize);
            let mut mods = vec![false; size * size];
            let mut is_func = vec![false; size * size];
            draw_function_patterns(spec, size, &mut mods, &mut is_func);
            let free_bits = is_func.iter().filter(|&&f| !f).count();
            assert_eq!(
                free_bits / 8,
                spec.total_codewords,
                "version {} free bits mismatch",
                spec.version
            );
        }
    }

    #[test]
    fn qr_roundtrip_unmasks_and_passes_reed_solomon_zero_syndrome() {
        let uri = "xcr:xcrstealth1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef?chips=495&inv=POS-108&memo=Flat+White";
        let qr = QrCode::encode_str(uri).expect("fits in Version 8-10 QR");
        assert!(qr.version() >= 8 && qr.version() <= 10);

        // Reconstruct function mask, unmask `qr.modules`, extract codewords, and verify zero RS syndrome + payload!
        let spec = &VERSION_SPECS_L[qr.version() as usize - 1];
        let size = qr.size();
        let mut dummy = vec![false; size * size];
        let mut is_func = vec![false; size * size];
        draw_function_patterns(spec, size, &mut dummy, &mut is_func);

        let mut unmasked = qr.modules.clone();
        apply_mask(qr.mask(), size, &mut unmasked, &is_func);

        let mut extracted_bits = Vec::new();
        let mut right = size as isize - 1;
        let mut upward = true;
        while right >= 1 {
            if right == 6 {
                right = 5;
            }
            for step in 0..size {
                let r = if upward { size - 1 - step } else { step };
                for dx in 0..2isize {
                    let c = (right - dx) as usize;
                    if !is_func[r * size + c] {
                        extracted_bits.push(unmasked[r * size + c]);
                    }
                }
            }
            upward = !upward;
            right -= 2;
        }
        let mut cw = Vec::with_capacity(spec.total_codewords);
        for chunk in extracted_bits
            .as_chunks::<8>()
            .0
            .iter()
            .take(spec.total_codewords)
        {
            let mut b = 0u8;
            for &bit in chunk {
                b = (b << 1) | (bit as u8);
            }
            cw.push(b);
        }
        // De-interleave first block and verify RS remainder == 0:
        let total_blocks = spec.blocks_g1 + spec.blocks_g2;
        let mut blk0 = Vec::new();
        for col in 0..spec.data_cw_g1 {
            blk0.push(cw[col * total_blocks]);
        }
        let ec_start = spec.total_data_codewords();
        for col in 0..spec.ec_per_block {
            blk0.push(cw[ec_start + col * total_blocks]);
        }
        // Evaluate polynomial at roots `2^0 .. 2^(ec_per_block - 1)`:
        let mut root = 1u8;
        for _ in 0..spec.ec_per_block {
            let mut eval = 0u8;
            for &coef in &blk0 {
                eval = gf256_mul(eval, root) ^ coef;
            }
            assert_eq!(eval, 0, "non-zero Reed-Solomon syndrome");
            root = gf256_mul(root, 0x02);
        }

        // Reassemble all data codewords and verify exact UTF-8 URI recovery:
        let max_d = spec.data_cw_g1.max(spec.data_cw_g2);
        let mut blocks_recovered: Vec<Vec<u8>> = (0..total_blocks).map(|_| Vec::new()).collect();
        let mut idx = 0usize;
        for col in 0..max_d {
            for (bi, bvec) in blocks_recovered.iter_mut().enumerate() {
                let limit = if bi < spec.blocks_g1 {
                    spec.data_cw_g1
                } else {
                    spec.data_cw_g2
                };
                if col < limit {
                    bvec.push(cw[idx]);
                    idx += 1;
                }
            }
        }
        let flat: Vec<u8> = blocks_recovered.into_iter().flatten().collect();
        let mut dbits = Vec::new();
        for b in flat {
            for shift in (0..8).rev() {
                dbits.push(((b >> shift) & 1) != 0);
            }
        }
        let count_bits = if spec.version <= 9 { 8 } else { 16 };
        let mut len = 0usize;
        for &bit in &dbits[4..4 + count_bits] {
            len = (len << 1) | (bit as usize);
        }
        assert_eq!(len, uri.len());
        let mut msg = Vec::with_capacity(len);
        for chunk in dbits[4 + count_bits..4 + count_bits + len * 8]
            .as_chunks::<8>()
            .0
        {
            let mut b = 0u8;
            for &bit in chunk {
                b = (b << 1) | (bit as u8);
            }
            msg.push(b);
        }
        assert_eq!(String::from_utf8(msg).unwrap(), uri);

        let svg = qr.to_svg(4);
        assert!(svg.starts_with("<svg ") && svg.contains("<path d=\"M"));
        let term = qr.to_terminal_unicode();
        assert!(term.contains('▀') || term.contains('▄'));
    }
}
