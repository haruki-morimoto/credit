# Credits (`XCR`) Privacy & Edge Compliance Specification

**Version:** 0.3 · **Crates:** `credit-crypto`, `credit-zk`

---

## 1. Guiding Principle: Bearer Privacy with Commercial Compatibility

Physical cash offers two everyday protections that transparent ledgers lost:
1. **Bearer Sovereignty:** Funds held in your wallet cannot be frozen remotely by an intermediary.
2. **Routine Confidentiality:** Paying for groceries does not disclose your savings balance or transaction history to the public.

At the same time, completely opaque ledgers have struggled to integrate with regulated merchants, payroll providers, and exchanges that are legally required to screen against stolen or sanctioned funds.

**Credits addresses both needs cleanly:**
- **Layer 1 remains unfreezable, private-by-default bearer cash** with zero admin, `freeze()`, or `blacklist()` keys.
- **Client-side Zero-Knowledge Proofs of Innocence (Privacy Pools)** allow users to prove clean fund provenance voluntarily at the edge—without revealing their balance, counterparties, or identity.

---

## 2. Default Layer-1 Privacy Primitives

### 2.1 Unlinkable Stealth Addresses (`XCR.STEALTH.V1`)
Recipients share a reusable `StealthMetaAddress` $(P_{\text{scan}}, P_{\text{spend}})$:
1. The sender generates a fresh ephemeral X25519 keypair $(r, R)$ and computes shared secret $s = \text{KDF}(\text{ECDH}(r, P_{\text{scan}}))$.
2. From $s$, the sender derives:
   - **1-Byte View Tag (`v = s[0]`):** Lets recipient wallets filter out $255/256$ of unrelated outputs using a single byte comparison.
   - **One-Time Destination Address (`A_ot`):** Unlinkable on-chain to $P_{\text{spend}}$ or prior payments to the same recipient.

### 2.2 Curve25519 Pedersen Commitments & 672-Byte Bulletproofs
Amounts are committed on Twisted Edwards Curve25519 ($-x^2 + y^2 \equiv 1 + d x^2 y^2 \pmod{2^{255}-19}$, subgroup order $\ell$) via homomorphic Pedersen commitments $C(v, \gamma) = v \cdot B + \gamma \cdot H$, where $H = 8 \cdot \text{HashToCurve}(\text{"XCR.PEDERSEN.H.V1"})$ has no known discrete logarithm relative to $B$:

1. **Logarithmic Inner-Product Bulletproofs (`BulletproofRange64`, 672 Bytes):** Compresses a 64-bit range proof ($v \in [0, 2^{64})$) from `8,192 bytes` down to **`672 bytes` (`12.2x` smaller)** via 6 recursive Inner-Product Argument folding rounds $(L_j, R_j)_{j=1..6}$ and polynomial identity verification.
2. **Homomorphic Balance Conservation (`ConfidentialTransferProof`):** Validators verify exact bit conservation directly over encrypted points via a Schnorr proof on generator $H$:

$$\sum C_{\text{in}} - \sum C_{\text{out}} - \text{fee} \cdot B = r_{\text{excess}} \cdot H$$

---

## 3. Client-Side ZK Proofs of Innocence (Privacy Pools)

When paying a **regulated merchant, employer, or exchange**:

1. **Edge-Curated Association Sets:** Compliance alliances, open-source security auditors, or jurisdictions publish Merkle roots $R_{\text{clean}}$ of verified clean deposits (excluding confirmed hacks, ransomware, and theft outputs). Layer-1 validators never censor transactions; association roots are checked strictly at the receiving edge.
2. **Zero-Knowledge Membership Proof (`ProofOfInnocence`):**
   - The wallet proves locally that its spent commitment belongs to $R_{\text{clean}}$ and emits a domain-separated `nullifier` preventing proof replay.
   - **Disclosed to Merchant:** `association_root`, `nullifier`, `tx_binding_tag`, and succinct proof $\pi$.
   - **Kept Private:** Which leaf in $R_{\text{clean}}$ was spent, remaining wallet balances, and prior transaction history.

---

## 4. Opt-In Encrypted ISO-20022 Commercial Receipts

For retail receipts, B2B invoicing, payroll, and accounting exports, transactions may include an end-to-end encrypted `Iso20022Memo`:

| Field | Description |
| :--- | :--- |
| `message_id` | Unique receipt or settlement identifier (e.g., `pacs.008` / `remt.001` reference) |
| `purpose_code` | Standard 4-character ISO 20022 purpose code (`GDDS` Goods, `SALA` Salary, `SUPP` Supplier) |
| `jurisdiction` | Optional ISO 3166 region code for merchant accounting |
| `invoice_ref` | Order or invoice reference string |
| `tax_amount` | Embedded VAT/GST component denominated in `XCR` |

Payloads are encrypted under an authenticated key derived from the sender-recipient ECDH secret (`XCR.ISO20022.ENC.V1`)—unreadable to validators and third parties, with optional per-receipt **Selective View Key** export when a user chooses to share a specific receipt for auditing.
