# ANU QRNG

The ANU Quantum Random Number Generator (QRNG) provides high-quality entropy sourced from quantum vacuum fluctuations.  
This module allows you to download raw ANU data, extract entropy, and generate a new wallet securely.

To begin, press the `Generate QRNG` button.

![ANU](doc/attachments/anu-default-window.png)

The application will request an entropy block from the ANU API using the parameters defined in the `Settings` tab.


---

## Generate QRNG

When you press the `Generate QRNG` button, the interface will display the downloaded data and the extracted entropy:

![ANU Generate QRNG](doc/attachments/anu-generate-qrng.png)


---

### Raw ANU Data

The `Raw ANU data` field shows the exact bytes received from the ANU API:

```
ee e4 84 8d 0e 01 fd 09 0f 5b 87 70 c6 89 03 a3 3e a6 ad a4 6b d3 a2 89 62 c4 75 b6 2e 86 fb f7 7a 13 cf fa 9e 16 24 16 eb e0 cc 4e b8 b9 6a 70 53 42 9c 72 21 c6 eb cc 59 f8 54 29 bd 44 3b 83 3a 06 2e 38 82 0b 21 11 29 b8 87 ff 62 ce 53 83 70 a7 d6 88 50 36 c5 99 fc 24 e9 4f a4 d3 93 8b e0 55 45 64
```

Red-highlighted bytes represent the subset selected for entropy extraction.  
In this example, the extracted bytes are:

```
8d 01 87 a3 3e a6 ad a2 c4 cf 16 b9 6a 70 53 c6 54 29 44 82 ff ce 86 cz 99 4f 93
```


---

## Entropy Extraction Modes

If `Sequential Slice` is selected in the `Settings` tab, the entropy is taken as a continuous slice from the downloaded data:

![ANU Generate QRNG Sequential](doc/attachments/anu-sequential-slice.png)

If `Random Values` is selected, the entropy bytes are chosen randomly from the downloaded block.
In this example, the extracted bytes are:

```
cf fa 9e 16 24 16 ... bd 44 3b 83 31 06 2e
```



---

### Randomize Button

The `Randomize` button allows you to reshuffle the downloaded bits.  
This is useful because ANU enforces a **120-second cooldown per request**, so the application downloads more data than immediately required.  
Shuffling ensures additional entropy variation without needing another API call.


---

### Saving the Wallet

Pressing the `Save` button finalizes the entropy and generates a new wallet.


---

## Settings

![Settings](doc/attachments/anu-settings.png)

The `Settings` tab defines how the ANU API request is constructed and how entropy is extracted.


---

## ANU API Configuration

### Data Types

| Type     | Description |
|----------|-------------|
| `uint8`  | 8-bit unsigned integers |
| `uint16` | 16-bit unsigned integers |
| `hex16`  | 16-bit hexadecimal values (default) |

### Array Length

| Property | Value                                                |
| -------- | ---------------------------------------------------- |
| Range    | `x - 1024`                                           |
| Minimum  | Automatically calculated based on selected data type |
| Default  | `10`                                                 |

### Block Size

| Property | Value                                                |
| -------- | ---------------------------------------------------- |
| Range    | `x - 1024`                                           |
| Minimum  | Automatically calculated based on selected data type |
| Default  | `10`                                                 |

---

## Entropy Options

Entropy extraction modes determine how the final entropy is selected from the downloaded ANU data:

| Mode              | Description |
|-------------------|-------------|
| `Random Values`   | Randomly selects bytes from the downloaded block (default) |
| `Sequential Slice`| Takes a continuous slice of bytes in order |

These settings directly influence the entropy used for wallet generation.


---

## Summary

Is the ANU QRNG safer than a local CPU RNG? From a purely technical standpoint, both have different threat models and neither should be trusted blindly. ANU QRNG provides high-quality quantum entropy, but the data is transmitted over the internet, which introduces the possibility of interception, logging, or manipulation at any point between the server and your application.

For this reason, the application downloads more entropy than required and allows additional randomization of the received bits. This reduces the risk that an observer who captures the raw transmission can directly reconstruct the final entropy used for wallet generation.

Security is further strengthened by the use of an additional mnemonic passphrase. Even if an attacker were able to record the downloaded ANU data, the default mnemonic passphrase consists of 128 random characters, making brute-forcing the resulting wallet computationally infeasible. The final security level therefore depends on the combination of entropy extraction, local processing, and the strength of the mnemonic passphrase rather than on any single entropy source.
