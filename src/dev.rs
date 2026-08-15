// authors = ["Control Owl <eq[at]r-o0-t[dot]wtf>"]
// license = "CC-BY-NC-ND-4.0  [2023-2026]  Control Owl"

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

// #[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
// pub struct PathComponent {
//   pub index: u32,
//   pub hardened: bool,
// }
//
// impl PathComponent {
//   pub fn new(
//     index: u32,
//     hardened: bool,
//   ) -> Self {
//     Self { index, hardened }
//   }
//
//   pub fn hardened(index: u32) -> Self {
//     Self { index, hardened: true }
//   }
//
//   pub fn soft(index: u32) -> Self {
//     Self { index, hardened: false }
//   }
//
//   pub fn to_string_component(&self) -> String {
//     if self.hardened {
//       format!("{}'", self.index)
//     } else {
//       self.index.to_string()
//     }
//   }
// }
//
// #[derive(Debug, Clone, PartialEq, Eq)]
// pub enum Curve {
//   Secp256k1,
//   Ed25519,
//   Sr25519,
//   Bip32Ed25519, // Cardano-style
// }
//
// #[derive(Debug, Clone, Copy, PartialEq, Eq)]
// pub enum DerivationScheme {
//   Bip32,
//   Bip44,
//   Bip86,
//   Slip10,   // common for ed25519
//   Polkadot, // sr25519 / Substrate style
//   Cip1852,  // Cardano bip32-ed25519
// }
//
// #[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
// pub enum DerivationPath {
//   Secp256k1(Secp256k1Path),
//   Ed25519(Ed25519Path),
//   Sr25519(Sr25519Path),
//   Bip32Ed25519(Bip32Ed25519Path),
// }
//
// /// secp256k1 paths
// #[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
// pub enum Secp256k1Path {
//   /// BIP32: m / account' / change' / address{'}
//   Bip32 {
//     account: PathComponent,
//     change: PathComponent,
//     address: PathComponent,
//   },
//
//   /// BIP44: m / 44' / coin' / account' / change / address{'}
//   Bip44 {
//     coin: PathComponent,    // usually hardened
//     account: PathComponent, // usually hardened
//     change: PathComponent,  // usually soft
//     address: PathComponent, // usually soft
//   },
//
//   /// BIP86 (Taproot): m / 86' / coin' / account' / change / address{'}
//   Bip86 {
//     coin: PathComponent,
//     account: PathComponent,
//     change: PathComponent,
//     address: PathComponent,
//   },
// }
//
// /// ed25519 paths
// #[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
// pub enum Ed25519Path {
//   /// BIP32: m / account' / change' / address'
//   Bip32 {
//     account: PathComponent,
//     change: PathComponent,
//     address: PathComponent,
//   },
//
//   /// BIP44: m / 44' / coin' / account' / change' / address'
//   Bip44 {
//     coin: PathComponent,
//     account: PathComponent,
//     change: PathComponent,
//     address: PathComponent,
//   },
//
//   /// SLIP-0010: m / 44' / coin' / address'
//   Slip10 { coin: PathComponent, address: PathComponent },
// }
//
// /// sr25519 / Substrate paths
// #[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
// pub enum Sr25519Path {
//   /// BIP32: m / account' / change' / address'
//   Bip32 {
//     account: PathComponent,
//     change: PathComponent,
//     address: PathComponent,
//   },
//
//   Polkadot {
//     coin: PathComponent,
//     account: PathComponent,
//   },
// }
//
// /// Cardano-style bip32-ed25519 (CIP-1852)
// #[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
// pub enum Bip32Ed25519Path {
//   Cip1852 {
//     coin: PathComponent,
//     account: PathComponent,
//
//     /// 0 = external, 1 = internal, 2 = staking,
//     role: PathComponent,
//     address: PathComponent,
//   },
// }
//
// impl DerivationPath {
//   pub fn to_path_string(&self) -> Zeroizing<String> {
//     let s = match self {
//       DerivationPath::Secp256k1(p) => match p {
//         Secp256k1Path::Bip32 { account, change, address } => {
//           format!(
//             "m/{}/{}/{}",
//             account.to_string_component(),
//             change.to_string_component(),
//             address.to_string_component()
//           )
//         }
//         Secp256k1Path::Bip44 {
//           coin,
//           account,
//           change,
//           address,
//         } => {
//           format!(
//             "m/44'/{}/{}/{}/{}",
//             coin.to_string_component(),
//             account.to_string_component(),
//             change.to_string_component(),
//             address.to_string_component()
//           )
//         }
//         Secp256k1Path::Bip86 {
//           coin,
//           account,
//           change,
//           address,
//         } => {
//           format!(
//             "m/86'/{}/{}/{}/{}",
//             coin.to_string_component(),
//             account.to_string_component(),
//             change.to_string_component(),
//             address.to_string_component()
//           )
//         }
//       },
//
//       DerivationPath::Ed25519(p) => match p {
//         Ed25519Path::Bip32 { account, change, address } => {
//           format!(
//             "m/{}/{}/{}",
//             account.to_string_component(),
//             change.to_string_component(),
//             address.to_string_component()
//           )
//         }
//         Ed25519Path::Bip44 {
//           coin,
//           account,
//           change,
//           address,
//         } => {
//           format!(
//             "m/44'/{}/{}/{}/{}",
//             coin.to_string_component(),
//             account.to_string_component(),
//             change.to_string_component(),
//             address.to_string_component()
//           )
//         }
//         Ed25519Path::Slip10 { coin, address } => {
//           format!("m/44'/{}/{}", coin.to_string_component(), address.to_string_component())
//         }
//       },
//
//       DerivationPath::Sr25519(p) => match p {
//         Sr25519Path::Bip32 { account, change, address } => {
//           format!(
//             "m/{}/{}/{}",
//             account.to_string_component(),
//             change.to_string_component(),
//             address.to_string_component()
//           )
//         }
//         Sr25519Path::Polkadot { coin, account } => {
//           format!("m/44'/{}/{}", coin.to_string_component(), account.to_string_component())
//         }
//       },
//
//       DerivationPath::Bip32Ed25519(Bip32Ed25519Path::Cip1852 {
//         coin,
//         account,
//         role,
//         address,
//       }) => {
//         format!(
//           "m/1852'/{}/{}/{}/{}",
//           coin.to_string_component(),
//           account.to_string_component(),
//           role.to_string_component(),
//           address.to_string_component()
//         )
//       }
//     };
//
//     Zeroizing::new(s)
//   }
//
//   pub fn curve(&self) -> Curve {
//     match self {
//       DerivationPath::Secp256k1(_) => Curve::Secp256k1,
//       DerivationPath::Ed25519(_) => Curve::Ed25519,
//       DerivationPath::Sr25519(_) => Curve::Sr25519,
//       DerivationPath::Bip32Ed25519(_) => Curve::Bip32Ed25519,
//     }
//   }
// }
