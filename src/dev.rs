// authors = ["Control Owl <eq[at]r-o0-t[dot]wtf>"]
// license = "CC-BY-NC-ND-4.0  [2023-2025]  Control Owl"

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

// use crate::{AppError, FunctionOutput, MasterKeyData, d3bug};

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

// #[cfg(test)]
// mod tests {
//   use super::*;
//
//   #[test]
//   fn test_solana() {
//     let seed_hex = "e97ab93c4961c77c62521f305aac17851bea814d05a78d3b5c254a3e5007456c856506c09f956d67808fb0e429ec6393825359bbd94d1a0e291aa468815f394b";
//     let master = generate_master_keys_ed25519(seed_hex).unwrap();
//     let path = "m/44'/501'/1'/0'";
//     // Thank you https://solana.com/developers/cookbook/wallets/restore-from-mnemonic for test vectors <3
//     // m/44'/501'/0'/0' => 5vftMkHL72JaJG6ExQfGAsT2uGVHpRR7oTNUPMs68Y2N
//     // m/44'/501'/1'/0' => GcXbfQ5yY3uxCyBNDPBbR5FjumHf89E7YHXuULfGDBBv
//     // m/44'/501'/2'/0' => 7QPgyQwNLqnoSwHEuK8wKy2Y3Ani6EHoZRihTuWkwxbc
//     // m/44'/501'/3'/0' => 5aE8UprEEWtpVskhxo3f8ETco2kVKiZT9SS3D5Lcg8s2
//     // m/44'/501'/4'/0' => 5n6afo6LZmzH1J4R38ZCaNSwaztLjd48nWwToLQkCHxp
//     // m/44'/501'/5'/0' => 2Gr1hWnbaqGXMghicSTHncqV7GVLLddNFJDC7YJoso8M
//     // m/44'/501'/6'/0' => BNMDY3tCyYbayMzBjZm8RW59unpDWcQRfVmWXCJhLb7D
//     // m/44'/501'/7'/0' => 9CySTpi4iC85gMW6G4BMoYbNBsdyJrfseHoGmViLha63
//     // m/44'/501'/8'/0' => ApteF7PmUWS8Lzm6tJPkWgrxSFW5LwYGWCUJ2ByAec91
//     // m/44'/501'/9'/0' => 6frdqXQAgJMyKwmZxkLYbdGjnYTvUceh6LNhkQt2siQp
//
//     let final_key = derive_from_path_ed25519(
//       &master.master_private_key_bytes,
//       &master.master_chain_code_bytes,
//       path,
//     )
//     .unwrap();
//
//     let address = bs58::encode(&final_key.child_public_key_bytes).into_string();
//     assert_eq!(address, "GcXbfQ5yY3uxCyBNDPBbR5FjumHf89E7YHXuULfGDBBv");
//     println!("Correct address: {address}");
//   }
// }
// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..
