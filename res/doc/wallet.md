 - **Status:** Stable

 - **Wallet format version:** 1

 - **Payload format version:** 1

 - **Encoding:** Binary

 - **Integer byte order:** Little-endian

 - **Encryption:** AES-256-GCM

This document specifies the binary format of a wallet file produced by the `encrypt_wallet` function. The format is designed to be self-describing, forward-compatible, and resistant to tampering.
All offsets described in this document are zero-based and inclusive.

---

# High-Level Structure

A wallet file consists of two main parts:

1. **Wallet header** (authenticated, not encrypted)
2. **Encrypted payload** (nonce + ciphertext + authentication tag)

The header is used as **Additional Authenticated Data (AAD)** during encryption.

- All variable-length fields are explicitly length-prefixed
- The format is forward-compatible by design
- Header authentication prevents parameter tampering and downgrade attacks


---

# 1. Wallet Header layout

## Version 1

```
┌────────────────────────────────────────────────────────────┐
│ Header                │ 2 bytes  │ offset 0 .. 1           │
├────────────────────────────────────────────────────────────┤
│ Wallet Version        │ 1 byte   │ offset 2                │
├────────────────────────────────────────────────────────────┤
│ KDF ID                │ 1 byte   │ offset 3                │
│ KDF parameter length  │ 4 bytes  │ offset 4 .. 7           │
│ KDF parameter data    │ X bytes  │ offset 8 .. 8+X-1       │
├────────────────────────────────────────────────────────────┤
│ Salt length           │ 4 bytes  │ offset 8+X .. 11+X      │
│ Salt                  │ S bytes  │ offset 12+X .. 11+X+S   │
├────────────────────────────────────────────────────────────┤
│ Payload length        │ 4 bytes  │ offset 12+X+S .. 15+X+S │
│ Nonce                 │ 12 bytes │ offset 16+X+S .. 27+X+S │
│ Ciphertext + Tag      │ Y bytes  │ offset 28+X+S .. end    │
└────────────────────────────────────────────────────────────┘
```


---

### Wallet Header Fields:

#### Header (2 bytes)
A fixed byte sequence `eq` identifying the file as a wallet container.

#### Wallet Version (1 byte)
Specifies the wallet file format version.
Current version: `1`

#### KDF ID (1 byte)
Identifies the key-derivation function whose parameters are stored in the file.
Current version: `1`

**Note:** The current implementation always derives the encryption key using **PBKDF2**, regardless of the serialized KDF ID.

#### KDF Parameter Length (4 bytes)
Length of the serialized KDF parameter block in bytes.

#### KDF Parameter Data (X bytes)
Serialized parameters required by the selected KDF
(e.g. PBKDF2 iteration count).

#### Salt Length (4 bytes)
Length of the salt used for key derivation.

#### Salt (S bytes)
Random salt input to the key-derivation function.
The current implementation uses a 32-byte salt.

#### Payload Length (4 bytes)
Total length of the encrypted payload data, defined as:

```
payload_length = nonce_length + ciphertext_length + tag_length
```

#### Nonce (12 bytes)
Random AES-GCM nonce generated per wallet encryption.

#### Ciphertext + Authentication Tag (Y bytes)
AES-256-GCM encrypted payload followed by the authentication tag.


---

# 2. Encrypted payload layout

## Version 1

```
┌───────────────────────────────────────────────────────────────┐
│ Payload version       │ 1 byte │ offset 0                     │
├───────────────────────────────────────────────────────────────┤
│ Full entropy length   │ 4 bytes │ offset 1 .. 4               │
│ Full entropy data     │ E bytes │ offset 5 .. 5+E-1           │
├───────────────────────────────────────────────────────────────┤
│ Mnemonic dict length  │ 2 bytes │ offset 5+E .. 6+E           │
│ Mnemonic dict data    │ D bytes │ offset 7+E .. 6+E+D         │
├───────────────────────────────────────────────────────────────┤
│ Mnemonic pass length  │ 2 bytes │ offset 7+E+D .. 8+E+D       │
│ Mnemonic pass data    │ P bytes │ offset 9+E+D .. 8+E+D+P     │
├───────────────────────────────────────────────────────────────┤
│ BIP                   │ 4 bytes │ offset 9+E+D+P .. 12+E+D+P  │
├───────────────────────────────────────────────────────────────┤
│ Last index            │ 4 bytes │ offset 13+E+D+P .. 16+E+D+P │
└───────────────────────────────────────────────────────────────┘
```

### Payload Field Descriptions:

#### Payload Version (1 byte)
Specifies the payload structure version.  
Current version: `1`

#### Full Entropy Length (4 bytes)
Length of the full entropy in bytes.

#### Full Entropy Data (E bytes)
Cryptographically secure entropy used as the root for wallet key material.

#### Mnemonic Dictionary Length (2 bytes)
Length of the mnemonic dictionary identifier.

#### Mnemonic Dictionary Data (D bytes)
Language of the mnemonic word list.

#### Mnemonic Passphrase Length (2 bytes)
Length of the mnemonic passphrase.

#### Mnemonic Passphrase Data (P bytes)
Mnemonic passphrase associated with the wallet generation.

#### BIP (4 bytes)
BIP used when wallet was generated.

#### Last Index (4 bytes)
Last derived index used by the wallet.
Determine how many addresses to generate when wallet is open.

