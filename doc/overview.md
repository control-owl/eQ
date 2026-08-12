# Welcome to eQ

eQ is a high-performance, privacy-focused key generator designed for users who want full control over their cryptographic keys. 
It supports **+280** coins, follows all major industry standards, and gives you complete transparency over every step of the key-generation process.

All sensitive operations-entropy generation, mnemonic creation, seed derivation, and key generation-are performed **locally on your machine**. 
No network connection is required unless you explicitly choose to use `QRNG` for quantum-grade entropy.


---

## What is eQ?

eQ is a deterministic, standards-compliant key generator built for:

- users who want **offline, air-gapped wallet creation**
- developers who need **fast, reproducible key derivation**
- security-conscious individuals who want **full control over entropy sources**
- anyone who wants a simple, transparent, and secure way to generate wallets

The application is built in Rust and uses modern cryptographic libraries to ensure correctness, safety, and performance.


---

## Key Features

### Strong Security by Default

- All sensitive data is **zeroed from memory** after use 
- Supports **RNG**, **QRNG**, and (soon) **File-based** entropy 
- Optional **128-character high-entropy mnemonic passphrase** 
- Fully deterministic BIP-39, BIP-32 / SLIP-0010 key derivation 
- Hardened derivation paths enabled by default 
- No telemetry, no tracking, no external dependencies


---


### Quantum-Grade Entropy (Optional)

If you want additional randomness, eQ integrates with the **ANU Quantum Random Number Generator**. 
This provides entropy sourced from quantum vacuum fluctuations.

You remain in control:

- Data is downloaded once
- Bits can be randomized locally 
- Entropy extraction mode is selectable



---


### Encrypted SVG Wallet Files

Wallets are saved as **encrypted SVG images**, allowing:

- portable backups 
- visual identification 
- encrypted storage without exposing sensitive data

Example wallet file:

![Test Wallet File](doc/attachments/test-wallet-file.png)



---


### Standards Support

eQ supports:

- BIP-39 (mnemonics) 
- BIP-32 (Legacy wallets) 
- BIP-44
- BIP-86
- SLIP-0010
- secp256k1 and Ed25519 curves 
- 280+ cryptocurrencies across many chains

---
## Air-Gapped Version: eQ-OS

For users who want maximum isolation, consider: [eQ-OS](https://github.com/control-owl/eQ-OS) 

A bootable, USB-based, air-gapped operating system designed specifically for secure wallet generation.

It runs eQ in a fully isolated environment with:

- no networking
- no external attack surface

Perfect for long-term cold storage and high-security setups.


---

## More Information

For documentation, updates, and new releases, visit:

**GitHub:** [https://github.com/control-owl/eQ](https://github.com/control-owl/eQ)
