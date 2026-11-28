# Credits (`XCR`) Privacy & Edge Compliance Specification

**Version:** 0.3 · **Crates:** `credit-crypto`, `credit-zk`

---

## 1. Guiding Principle: Everyday Privacy with Commercial Compatibility

Physical cash provides two practical qualities valued in daily life:
1. **Direct Bearer Custody:** Funds held in your wallet remain under your direct control.
2. **Routine Confidentiality:** Everyday purchases do not publish your personal savings balance or transaction history to the public.

At the same time, regulated merchants, employers, and financial institutions often need assurance that incoming payments do not originate from stolen or sanctioned sources.

**Credits accommodates both requirements respectfully:**
- **Layer 1 remains bearer-held and private by default**, without protocol-level `freeze()` or `blacklist()` keys.
- **Client-side Zero-Knowledge Proofs of Innocence (Privacy Pools)** let users demonstrate clean fund provenance voluntarily at the edge — without disclosing their wallet balance, counterparties, or personal identity.

---

## 2. Layer-1 Privacy Primitives

### 2.1 Unlinkable Stealth Addresses (`XCR.STEALTH.V1`)
Recipients share a reusable `StealthMetaAddress` $(P_{\text{scan}}, P_{\text{spend}})$:
1. The sender generates an ephemeral X25519 keypair $(r, R)$ and computes shared secret $s = \text{KDF}(\text{ECDH}(r, P_{\text{scan}}))$.
2. From $s$, the sender derives:
   - **1-Byte View Tag (`v = s[0]`):** Allows recipient wallets to skip $255/256$ of unrelated outputs using a single byte check.
   - **One-Time Destination Address (`A_ot`):** Unlinkable on-chain to $P_{\text{spend}}$ or prior payments to the same recipient.

### 2.2 Curve25519 Pedersen Commitments & 672-Byte Bulletproofs
Amounts are committed on Twisted Edwards Curve25519 ($-x^2 + y^2 \equiv 1 + d x^2 y^2 \pmod{2^{255}-19}$, subgroup order $\ell$) via homomorphic Pedersen commitments $C(v, \gamma) = v \cdot B + \gamma \cdot H$, where $H = 8 \cdot \text{HashToCurve}(\text{"XCR.PEDERSEN.H.V1"})$ has no known discrete logarithm relative to $B$:

1. **Logarithmic Inner-Product Bulletproofs (`BulletproofRange64`, 672 Bytes):** Compresses a 64-bit range proof ($v \in [0, 2^{64})$) to **`672 bytes`** through 6 Inner-Product Argument folding rounds $(L_j, R_j)_{j=1..6}$.
2. **Homomorphic Balance Conservation (`ConfidentialTransferProof`):** Validators verify exact bit conservation directly over committed points via a Schnorr proof on generator $H$:

$$\sum C_{\text{in}} - \sum C_{\text{out}} - \text{fee} \cdot B = r_{\text{excess}} \cdot H$$

### 2.3 Opt-In `MLSAG` RingCT Shielded Pool, Viewing Keys & Payment Proofs (`credit-sdk`)
For users who wish to shield sender, receiver, and amount simultaneously with no trusted setup:
1. **1-of-$N$ Curve25519 `MLSAG` RingCT:** Shielded transfers mix the Pedersen-committed note within an on-chain decoy ring and publish a unique **Key Image** $I = x \cdot H_p(P)$ to prevent double-spending without revealing which ring member was spent.
2. **Read-Only Auditor Viewing Keys (`xcrview1_`):** Grants read-only audit visibility for accounting, non-profit transparency, or tax reporting without exposing spending authority.
3. **Chaum-Pedersen DLEQ Payment Proofs (`xcrtxproof1_`):** Allows a sender to prove to a recipient or mediator that a specific payment delivered exact value $v$ without revealing the wallet's master seed.

---

## 3. Client-Side ZK Proofs of Innocence (Privacy Pools)

When transacting with a **regulated merchant, payroll provider, or institution**:

1. **Edge-Curated Association Sets:** Compliance groups, security researchers, or regional institutions publish Merkle roots $R_{\text{clean}}$ of verified clean deposits (excluding confirmed theft or ransomware outputs). Layer-1 validators remain neutral; association roots are verified by the receiving counterparty at the edge.
2. **Zero-Knowledge Membership Proof (`ProofOfInnocence`):**
   - The sender's wallet proves locally that its spent commitment belongs to $R_{\text{clean}}$ and produces a domain-separated `nullifier` to prevent proof replay.
   - **Shared with Counterparty:** `association_root`, `nullifier`, `tx_binding_tag`, and succinct proof $\pi$.
   - **Kept Private:** Which leaf in $R_{\text{clean}}$ was spent, remaining wallet balances, and prior transaction history.

---

## 4. Opt-In Encrypted ISO-20022 Commercial Receipts

For retail receipts, invoicing, payroll, and accounting exports, transactions may include an end-to-end encrypted `Iso20022Memo`:

| Field | Description |
| :--- | :--- |
| `message_id` | Unique receipt or settlement identifier (e.g., `pacs.008` / `remt.001` reference) |
| `purpose_code` | Standard 4-character ISO 20022 purpose code (`GDDS` Goods, `SALA` Salary, `SUPP` Supplier) |
| `jurisdiction` | Optional ISO 3166 region code for merchant accounting |
| `invoice_ref` | Order or invoice reference string |
| `tax_amount` | Embedded VAT/GST component denominated in `XCR` |

Payloads are encrypted under an authenticated key derived from the sender-recipient ECDH secret (`XCR.ISO20022.ENC.V1`) — readable only by the transacting parties, with optional per-receipt **Selective View Key** export when a user chooses to share an individual receipt for accounting or audit review.
