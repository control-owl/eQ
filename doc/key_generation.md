# Key Generation Process

eQ derives cryptographic keys through the following process:

1. Generate random entropy
2. Convert entropy into mnemonic words (BIP-39)
3. Convert the mnemonic (and optional passphrase) into a seed
4. Derive private/public key pairs from the seed
5. Use the appropriate cryptographic curve, such as secp256k1 or Ed25519


---

## Entropy

The process starts with cryptographically secure random data called entropy. The randomness quality is critical because all future keys depend on this entropy, also, the longer, the better ;)

**Common entropy sizes:**

| Entropy length | Mnemonic Words |
|----------------|----------------|
| 128 bits       | 12 words       |
| 160 bits       | 15 words       |
| 192 bits       | 18 words       |
| 224 bits       | 21 words       |
| 256 bits       | 24 words       |

**Example:**
```
128-bit:
659927443d503c1dda1864c211e7d12b

256-bit:
b5d0b44c372e9c433d9567be156b5a80cd004828e74691fe85197db50938a7e3
```


---

## Mnemonic Words (BIP-39)

BIP-39 converts entropy into a human-readable list of words.

**Steps:**

1. Compute a checksum from the entropy
2. Append the checksum bits to the entropy
3. Split the resulting bit stream into groups of 11 bits
4. Map each 11-bit value to a word from the BIP-39 word list (2048 words)

**Example:**
```
128-bit entropy:
history jungle affair invest only gravity tilt nut account plate explain note

160-bit entropy:
phone detail foam syrup local spell vital trap begin stick skin castle neither album soft amount miss film

256-bit entropy:
wrestle neither effort grit sort drama tribe lava menu early advice domain clutch special define iron pizza rifle fossil steak dwarf nerve immense crumble
```


---

## Mnemonic Passphrase

BIP-39 supports an optional passphrase. Passphrase is something like an extra word to your mnemonic.

**Why use a passphrase?**

- Anyone with only the mnemonic cannot access the wallet.
- The mnemonic and passphrase together generate the final seed.
- Different passphrases create completely different wallets.
- It increases the total security of your wallet.

**Downside of using a passphrase:**

- If the passphrase is lost, the derived wallet cannot be recovered with just the mnemonic words.


---

## Seed Generation

The mnemonic and passphrase are transformed into a seed using **PBKDF2-HMAC-SHA512**.

**Parameters:**

- Password = mnemonic sentence
- Salt = "mnemonic" + passphrase
- Iterations = 2048
- Output length = 512 bits

**Result:**
```
3fa4a8ccc3c5734874a7d378492b0479c5de893d3c677884cd2a4d038a7bb4068c4cc22225c8a684f43bfe37777b073008f6cd1b9c63fddbb9ba286abd26a01e
```


---

## Key Generation with secp256k1

Used by Bitcoin, Ethereum, Litecoin and many EVM chains...

**Flow:**
```
Entropy -> Mnemonic -> Seed -> Master Private Key -> Child Private Key -> secp256k1 Public Key
```


---

## Key Generation with Ed25519

Used by Solana, Cardano, Near, Aptos, Sui etc...

After seed generation, Ed25519-specific derivation (often SLIP-0010) is applied.

**Flow:**
```
Entropy -> Mnemonic -> Seed -> Ed25519 Private Key -> Ed25519 Public Key
```

eQ automates this entire process with one click while giving you full control over entropy source and passphrase.