# eQ

## Early beta

Trying to port [QR2M](https://www.github.com/control-owl/QR2M) from [GTK4](https://www.gtk.org/) to [egui](https://docs.rs/egui/latest/egui/)


## Basics

```
 ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄ 
▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌
▐░▌          ▐░▌       ▐░▌
▐░█▄▄▄▄▄▄▄▄▄ ▐░▌       ▐░▌
▐░░░░░░░░░░░▌▐░▌       ▐░▌
▐░█▀▀▀▀▀▀▀▀▀ ▐░█▄▄▄▄▄▄▄█░▌
▐░▌          ▐░░░░░░░░░░░▌
▐░█▄▄▄▄▄▄▄▄▄  ▀▀▀▀▀▀█░█▀▀ 
▐░░░░░░░░░░░▌        ▐░▌  
 ▀▀▀▀▀▀▀▀▀▀▀          ▀   
CC-BY-NC-ND-4.0
Control Owl [2025]
```

**eQ** is a **cryptographic key generator** built with **Rust** and **egui**. It supports generating secure addresses for +250 crypto coins. Designed with speed in mind, QR2M allows entropy generation from multiple sources: hardware-based **RNG**, ANU quantum RNG (**QRNG**), and user-provided **files**.

This is second generation of key generator, with [QR2M](https://github.com/control-owl/QR2M) as a first one.

Now, focus is on speed and no system dependencies.


## Table of Contents

- [License](#license)
- [Project Status](#project-status)
- [Features](#features)
- [Installation](#installation)
- [Screenshots](#screenshots)
- [Third-Party Libraries](#third-party-libraries)


## License

This project is licensed under a **Creative Commons Attribution Non Commercial No Derivatives 4.0 International license**. Check the [deed](https://creativecommons.org/licenses/by-nc-nd/4.0/deed.en).


## Project status

Early beta, still playing with egui's gui

| **Security Status**  |
| -------------------- |
| Verify GPG Signature |
| CodeQL               |

| **Build Status**     |
| -------------------- |
| Linux x86_64 GNU     |
| macOS aarch64 Darwin |


## Features

- currently there is no features for now


## Installation

1. git clone
2. cargo


## Screenshots

### Light theme
![Screenshot](./.github/preview/0.1.0-light.png "Light theme")

### Dark theme
![Screenshot](./.github/preview/0.1.0-dark.png "Dark theme")


## Third-Party Libraries

- [egui](https://docs.rs/egui/latest/egui)
- [sysinfo](https://docs.rs/sysinfo/latest/sysinfo)