# Key Generation Process

eQ generates cryptographic keys using a deterministic, standards-compliant workflow based on BIP-39, BIP-32, SLIP-0010, and the appropriate elliptic-curve algorithms.  
The complete process consists of:

1. Generating cryptographically secure entropy  
2. Converting entropy into mnemonic words (BIP-39)  
3. Converting the mnemonic (and optional passphrase) into a seed  
4. Deriving master and child keys from the seed  
5. Using the correct cryptographic curve (secp256k1 or Ed25519)  

Each step is deterministic: the same entropy always produces the same wallet.


---

## 1. Entropy

The process begins with **cryptographically secure random data**, known as entropy.  
Entropy quality is critical because **every key, address, and signature** ultimately depends on it.

### Entropy Sizes

| Entropy Length | Mnemonic Words |
|----------------|----------------|
| 128 bits       | 12 words       |
| 160 bits       | 15 words       |
| 192 bits       | 18 words       |
| 224 bits       | 21 words       |
| 256 bits       | 24 words       |

Longer entropy - more mnemonic words - higher brute-force resistance.

### Examples

```
128-bit:
659927443d503c1dda1864c211e7d12b

256-bit:
b5d0b44c372e9c433d9567be156b5a80cd004828e74691fe85197db50938a7e3
```

### Technical Notes

- Entropy must be uniformly random; bias reduces security.  
- eQ supports multiple entropy sources (`RNG`, `QRNG`, `File`).  
- Entropy is never reused across wallets unless explicitly saved.  
- Entropy length directly determines checksum size in BIP-39.

---

## 2. Mnemonic Words (BIP-39)

BIP-39 converts entropy into a human-readable mnemonic phrase.  
This step ensures that wallets can be backed up using words instead of raw binary data.

### Conversion Steps

1. Compute a checksum from the entropy (`SHA-256(entropy)` first bits).  
2. Append checksum bits to the entropy.  
3. Split the combined bitstream into 11-bit groups.  
4. Map each 11-bit value to a word from the 2048-word BIP-39 dictionary.

### Examples

```
128-bit entropy:
history jungle affair invest only gravity tilt nut account plate explain note

160-bit entropy:
phone detail foam syrup local spell vital trap begin stick skin castle neither album soft amount miss film

256-bit entropy:
wrestle neither effort grit sort drama tribe lava menu early advice domain clutch special define iron pizza rifle fossil steak dwarf nerve immense crumble
```

### Technical Notes

- 11 bits → 2048 possible words.  
- Mnemonic words **encode both entropy and checksum**.  
- Any change in entropy or checksum produces a completely different mnemonic.  
- Different mnemonic languages produce different seeds even with identical entropy.

---

## 3. Mnemonic Passphrase

BIP-39 supports an optional passphrase, often called the *25th word*.  
It is **not** stored anywhere and must be remembered by the user.

### Why Use a Passphrase?

- Protects against mnemonic exposure attacks.  
- Produces a completely different seed even with the same mnemonic.  
- Adds significant entropy (eQ uses 128 random characters by default).  
- Makes brute-forcing the wallet computationally infeasible.

### Security Impact

A 128-character random ASCII passphrase provides:

- **~850–900 bits of entropy**  
- Far beyond the security level of the mnemonic itself  
- Resistant to all known brute-force methods

### Downside

If the passphrase is lost, the wallet **cannot** be recovered using only the mnemonic words.

---

## 4. Seed Generation

The mnemonic and passphrase are converted into a seed using:

**PBKDF2-HMAC-SHA512**

### Parameters

| Parameter     | Value                                 |
|---------------|----------------------------------------|
| Password      | mnemonic sentence                      |
| Salt          | `"mnemonic"` + passphrase              |
| Iterations    | 2048                                   |
| Output length | 512 bits                               |

### Example Output

```
3fa4a8ccc3c5734874a7d378492b0479c5de893d3c677884cd2a4d038a7bb4068c4cc22225c8a684f43bfe37777b073008f6cd1b9c63fddbb9ba286abd26a01e
```

### Technical Notes

- PBKDF2 intentionally slows down brute-force attempts.  
- The seed is the root of all derived keys.  
- The seed must remain secret; leaking it compromises the entire wallet.

---

## 5. Key Generation with secp256k1

Used by:

- Bitcoin  
- Ethereum  
- Litecoin  
- Dogecoin  
- Most EVM chains  

### Derivation Flow

```
Entropy
  ↓
Mnemonic
  ↓
Seed
  ↓
Master Private Key
  ↓
Child Private Key
  ↓
secp256k1 Public Key
```

### Technical Notes

- secp256k1 is a Koblitz curve optimized for fast verification.  
- BIP-32 derivation uses HMAC-SHA512 to derive child keys.  
- Hardened and non-hardened derivation paths behave differently.  
- Public keys are compressed (33 bytes) by default.

---

## 6. Key Generation with Ed25519

Used by:

- Solana  
- Cardano  
- Near  
- Aptos  
- Sui  
- Many modern proof-of-stake chains  

### Derivation Flow

```
Entropy
  ↓
Mnemonic
  ↓
Seed
  ↓
Ed25519 Master Private Key
  ↓
Ed25519 Master Public Key
```

### Technical Notes

- Ed25519 uses twisted Edwards curves (Curve25519).  
- Most wallets use **SLIP-0010** for deterministic derivation.  
- Ed25519 does **not** support non-hardened derivation (for security reasons).
- Keys are resistant to side-channel attacks and signature malleability.
