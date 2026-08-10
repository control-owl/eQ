# version 1.6.0
- new coin: Monero (XMR)
- new coin: Algorand (ALGO)
- new coin: Polkadot (DOT)
- new coin: Kusama (KSM)
- new coin: Nano (XNO)
- new coin: NEM (XEM)
- new coin: Cardano (ADA)
    - Shelly address only supported
    - Byron (legacy) will be added later
- new coin: Zilliqa (ZIL)
    - Legacy address zil... supported
    - New V2 address 0x... supported
- Litecoin:
    - New supporting protocol BIP86
    - Taproot address support ltc1p... (default)
    - Legacy  address support L...
- new option: Standardize EVM addresses (optional)
- new curve: 
    - sr25519
    - ed25519-bip32
- cargo update:
    - egui (0.34.3 -> 0.36.1)
    - eframe (0.34.3 -> 0.36.1)
    - egui_extras (0.34.3 -> 0.36.1)
    - egui_commonmark (0.23.0 -> 0.25.0)
    - sysinfo (0.29.3 -> 0.39.6)
    - ed25519-dalek (2.2.0 -> 3.0.0)
    - curve25519-dalek (4.1.3 -> 5.0.0)
    - num-bigint (0.4.6 -> 0.5.1)
    - base64 (0.22.1 -> 0.23.1)
    - serde (1.0.228 -> 1.0.229)
    - serde_json (1.0.150 -> 1.0.151)
    - egui_keyboard (0.6.0 -> 0.7.0)


---


# version 1.5.0
- new: help window
- cargo update:
    - getrandom (0.4.2 -> 0.4.3)
    - bech32 (0.11.1 -> 0.12.0)
    - zeroize (1.8.2 -> 1.9.0)
- cargo add:
    - egui_commonmark
- new: Coin filter in status bar


---


# version 1.4.0
- Bitcoin:
    - Taproot address support bc1p... (default)
    - New supporting protocol BIP86
    - Legacy  address support 1...
- cargo update:
    - egui (0.34.2 -> 0.34.3)
    - eframe (0.34.2 -> 0.34.3)
    - egui_extras (0.34.2 -> 0.34.3)
    - sysinfo (0.39.0 -> 0.39.3)
    - sha3 (0.11.0 -> 0.12.0)
    - serde_json (1.0.149 -> 1.0.150)
- Help menu:
    - About window
    - License window
    - Disclaimer window
- Status bar:
    - New status bar added
    - Entropy
    - Mnemonic word length:
        - 12
        - 15
        - 18
        - 21
        - 24
    - Mnemonic dictionary:
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
    - Mnemonic passphrase source
        - RNG
        - Custom mnemonic passphrase
        - Off
    - BIP 32/44 path
    - Hardened addresses
    - Add/remove addresses


---


# version 1.3.2
- cargo update:
    - egui (0.34.1 -> 0.34.2)
    - eframe (0.34.1 -> 0.34.2)
    - egui_extras (0.34.1 -> 0.34.2)
    - sysinfo (0.38.4 -> 0.39.0)
- some files renamed
- new release feature added: "osk" (eQ with on-screen keyboard)


---


# version 1.3.1
- change hardened addresses output improved


---


# version 1.3.0
- cargo update:
    - egui (0.33.3 -> 0.34.1)
    - eframe (0.33.3 -> 0.34.1)
    - egui_extras (0.33.3 -> 0.34.1)
    - sysinfo
    - getrandom
    - sha2 (0.10.9 -> 0.11.0)
    - sha3 (0.10.8 -> 0.11.0)
    - ripemd (0.1.3 -> 0.2.0)
    - ureq
- new eQ feature: osk
    - on-screen keyboard


---


# version 1.2.0
- cargo update: sysinfo
- cargo add: ureq
- new: QRNG as entropy source
- new: ANU window
- privacy: hide private keys
- fix: address starting point
- fix: re-saving SVG file


---


# version 1.1.0
- cargo update: getrandom
- git pre-push hook added
- new release: macOS, windows


---


# version 1.0.1
- Secrets window
- Added new coins:
    - Rootstock Bitcoin
    - Pulse Chain
    - SONIC
    - Scroll


---


# version 1.0.0
- First version
- Generate keys for 280 coins
- New coin support: Cosmos (ATOM)
- New coin support: Solana (SOL)
