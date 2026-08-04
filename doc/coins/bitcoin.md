## Bitcoin

**Short info**

- **Ticker:** BTC
- **Status:** Active
- **Launch:** 2009-01-03 (Genesis Block)
- **Consensus:** Proof of Work (SHA-256)
- **SLIP-44 coin type:** `0`
- **Notes:** The first decentralized cryptocurrency. Uses the UTXO model and is the reference implementation for many blockchain technologies. Supports Legacy, SegWit, Native SegWit, and Taproot address formats.

| Version | Derivation path | Address form |
|---------|-----------------|--------------|
| Legacy (P2PKH) | `m/44'/0'/0'` | `1...` |
| Nested SegWit (P2SH-P2WPKH) | `m/49'/0'/0'` | `3...` |
| Native SegWit (P2WPKH) | `m/84'/0'/0'` | `bc1q...` |
| Taproot (P2TR) | `m/86'/0'/0'` | `bc1p...` |

**Current status**

- Bitcoin remains the largest and most secure Proof-of-Work blockchain by market capitalization.
- Legacy (`1...`) and Nested SegWit (`3...`) addresses remain fully supported for backward compatibility.
- Native SegWit (`bc1q...`) is the recommended default for most wallets due to lower transaction fees and broad ecosystem support.
- Taproot (`bc1p...`) was activated in November 2021, introducing Schnorr signatures, improved privacy, better smart contract capabilities, and more efficient multisignature transactions.
- Modern wallets should prefer Taproot (`m/86'/0'/0'`) when supported; otherwise Native SegWit (`m/84'/0'/0'`) remains the best default for compatibility.

