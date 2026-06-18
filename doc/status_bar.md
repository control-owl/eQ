# Status Bar

The status bar provides a quick overview of all parameters used during wallet generation.  
It is divided into the following sections:

1. Entropy  
2. Mnemonic  
3. Path  
4. Coins  
5. Addresses  


![Status Bar](doc/attachments/status-bar.png)

---

## 1. Entropy

The `Entropy` section displays the currently selected entropy source used for generating the wallet seed.

### Source

Available options:

- RNG (Default)  
- QRNG  
- File (In development)

---

#### RNG

`RNG` is the default entropy source.  
It uses the local CPU hardware random number generator or OS‑provided cryptographic randomness.  
This method:

- requires **no internet connection**,  
- works on **any machine**,  
- supports **fully offline wallet generation**,  
- avoids network‑based interception risks.

From a security perspective, local RNG is deterministic only in the sense that it depends on the system’s entropy pool, but modern OS RNGs (e.g., `/dev/urandom`, `getrandom()`, RDRAND) are considered cryptographically secure for wallet generation.

---

#### QRNG

Selecting `QRNG` uses quantum entropy downloaded from the ANU Quantum Random Number Generator API.

When `QRNG` is selected and you press `Generate New Wallet`, a dedicated window appears:

![ANU](doc/attachments/anu-default-window.png)

For detailed behavior, extraction modes, and security considerations, refer to the **`ANU QRNG`** documentation section.

---

#### File (In Development)

This option will allow loading entropy from an external file.  
Typical use cases include:

- air‑gapped entropy generation,  
- pre‑generated entropy pools,  
- hardware RNG exports.

This feature is not yet active.

---

## 2. Mnemonic

The `Mnemonic` section defines how the wallet’s BIP‑39 mnemonic phrase is generated.

---

### Mnemonic Words

Specifies the number of mnemonic words derived from entropy.

| Word Count | Entropy Size |
|------------|--------------|
| 12         | 128 bits     |
| 15         | 160 bits     |
| 18         | 192 bits     |
| 21         | 224 bits     |
| 24 (Default) | 256 bits   |

More words = more entropy = stronger resistance against brute‑force attacks.

---

### Mnemonic Dictionary

The mnemonic can be generated in multiple languages.  
Changing the language **changes the resulting seed**, even if the entropy is identical.

Available dictionaries:

- English  
- Czech  
- French  
- Italian  
- Portuguese  
- Spanish  
- Chinese Simplified  
- Chinese Traditional  
- Japanese  
- Korean  

#### Technical Example

Given the same entropy `E`:

```
Entropy E
   ↓
Indices: [123, 456, 789, ...]
   ↓
English mnemonic: able ball car ... 
French mnemonic: acier bambin causer ...
```

Because the mnemonic strings differ:

```
PBKDF2("able ball car ...") ≠ PBKDF2("acier bambin causer ...")
```

This is expected behavior and is explicitly defined in **BIP‑39**.

---

### Mnemonic Passphrase

A mnemonic passphrase (sometimes called the “25th word”) is added by default.  
It is generated using `RNG` and consists of **128 random characters**, providing extremely high entropy.

#### Technical Impact

A 128‑character random ASCII passphrase provides:

- approximately **~850–900 bits of entropy**, depending on character set  
- far beyond the security level of the mnemonic itself  
- effectively impossible to brute‑force with any foreseeable hardware

This means:

Even if an attacker somehow obtained the raw entropy or mnemonic words, the wallet remains cryptographically protected by the passphrase.

---

## 3. Path

The `Path` section defines the BIP derivation path used for generating keys and addresses.

### BIP

Default: `44`  
Alternative: `32`

These correspond to:

- `BIP‑44`: Multi‑account hierarchical deterministic wallets  
- `BIP‑32`: Generic hierarchical deterministic key derivation

### Hardened Addresses

All addresses are generated as **hardened** by default.  
This prevents public‑key‑based derivation attacks and ensures maximum isolation between branches of the derivation tree.

---

## 4. Coins

This section becomes visible after the wallet is created.  
It displays the **total number of supported coins** generated for the wallet.

---

## 5. Addresses

By default, **10 addresses** are generated.

You can adjust the number of addresses by:

- pressing `+` or `–` to add or remove rows  
- clicking the number directly to select a preset value

Available options:

- 1  
- 5  
- 10  
- 20  
- 50  
- 100  

This allows generating a larger address pool without regenerating the entire wallet.