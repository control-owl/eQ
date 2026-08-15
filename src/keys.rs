// authors = ["Control Owl <eq[at]r-o0-t[dot]wtf>"]
// license = "CC-BY-NC-ND-4.0  [2023-2026]  Control Owl"

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

use crate::{
  AddressPrivateData, AppError, ChildEd25519KeySecretData, ChildSecp256k1KeySecretData, CryptoPublicKey, CryptoWallet, DerivationPathData,
  FunctionOutput, MnemonicLanguage, MoneroKeys, Zeroizing,
};
use base32::Alphabet;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bech32::{Bech32, Hrp, encode, segwit};
use blake2::{Blake2b512, Digest as BlakeDigest};
use blake2b_simd::Params;
use crc32fast::Hasher as Crc32;
use curve25519_dalek::Scalar;
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, edwards::EdwardsPoint};
use digest::consts::U5;
use ed25519_bip32::{DerivationScheme, XPrv, XPub};
use ed25519_dalek::SigningKey;
use num_bigint::BigUint;
use ring::hmac;
use ring::pbkdf2;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use sp_core::crypto::Ss58Codec;
use sp_core::{DeriveJunction, Pair, sr25519};
use std::io::BufRead;
use std::num::NonZeroU32;
use tiny_keccak::{Hasher, Keccak};
use zeroize::Zeroize;

const WALLET_MAX_ADDRESSES: u32 = 2_147_483_647;
const MNEMONIC_PASSPHRASE_LENGTH: u32 = 128;
const MONERO_PREFIX_LEN: usize = 3;
const NANO_ALPHABET: &[u8] = b"13456789abcdefghijkmnopqrstuwxyz";

//                                    SEED
// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

pub fn generate_seed(
  wallet: &mut CryptoWallet,
  entropy_source: Zeroizing<String>,
) -> FunctionOutput<()> {
  let full_entropy: Zeroizing<String>;
  let mnemonic_dictionary: Zeroizing<MnemonicLanguage>;

  match entropy_source.as_str() {
    "SVG" => {
      full_entropy = wallet.seed_secret.full_entropy.clone();
      mnemonic_dictionary = wallet.seed_secret.mnemonic_dictionary.clone();
    }
    "QRNG" => {
      let raw_entropy: Zeroizing<String> = wallet.seed_secret.raw_entropy.clone();

      let entropy_checksum: Zeroizing<String> = e_q::calculate_checksum_for_entropy(raw_entropy.clone());
      wallet.seed_secret.entropy_checksum = entropy_checksum.clone();

      full_entropy = Zeroizing::new(format!("{}{}", *raw_entropy, *entropy_checksum));
      wallet.seed_secret.full_entropy = full_entropy.clone();

      mnemonic_dictionary = wallet.seed_secret.mnemonic_dictionary.clone();
    }
    "RNG" => {
      let entropy_length: Zeroizing<usize> = wallet.seed_secret.entropy_length.clone();
      mnemonic_dictionary = wallet.seed_secret.mnemonic_dictionary.clone();

      let raw_entropy: Zeroizing<String> = generate_raw_entropy(entropy_source.clone(), Some(entropy_length))?;
      wallet.seed_secret.raw_entropy = raw_entropy.clone();

      let entropy_checksum: Zeroizing<String> = e_q::calculate_checksum_for_entropy(raw_entropy.clone());
      wallet.seed_secret.entropy_checksum = entropy_checksum.clone();

      full_entropy = Zeroizing::new(format!("{}{}", *raw_entropy, *entropy_checksum));
      wallet.seed_secret.full_entropy = full_entropy.clone();
    }
    "MULTI" => {
      let raw_entropy: Zeroizing<String> = wallet.seed_secret.raw_entropy.clone();

      let entropy_checksum: Zeroizing<String> = e_q::calculate_checksum_for_entropy(raw_entropy.clone());
      wallet.seed_secret.entropy_checksum = entropy_checksum.clone();

      full_entropy = Zeroizing::new(format!("{}{}", *raw_entropy, *entropy_checksum));

      mnemonic_dictionary = wallet.seed_secret.mnemonic_dictionary.clone();

      wallet.seed_secret.full_entropy = full_entropy.clone();
    }
    _ => {
      return Err(AppError::log(format!("Unknown entropy source: {:?}", entropy_source)));
    }
  }

  match wallet.seed_secret.mnemonic_passphrase_source.as_str() {
    "RNG" => {
      match generate_raw_mnemonic_passphrase(MNEMONIC_PASSPHRASE_LENGTH as usize) {
        Ok(pass) => {
          wallet.seed_secret.mnemonic_passphrase = pass;
        }
        Err(err) => return Err(AppError::log(format!("Error: {:?}", err))),
      };
    }
    "Custom" => {}
    _ => {}
  }

  let mnemonic_words: Zeroizing<String> = match generate_mnemonic_words(full_entropy.clone(), mnemonic_dictionary) {
    Ok(words) => words,
    Err(err) => {
      return Err(AppError::log(format!("Problem with generating mnemonic words: {}", err)));
    }
  };

  let salt: Zeroizing<String> = Zeroizing::new(format!("mnemonic{}", *wallet.seed_secret.mnemonic_passphrase));

  let mut seed: Zeroizing<[u8; 64]> = Zeroizing::new([0u8; 64]);

  let iter = match std::num::NonZeroU32::new(2048) {
    Some(number) => number,
    _ => {
      return Err(AppError::log(String::from("Problem with pbkdf2 iter")));
    }
  };

  pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA512, iter, salt.as_bytes(), mnemonic_words.as_bytes(), &mut *seed);

  let seed_hex: Zeroizing<String> = Zeroizing::new(hex::encode(&seed[..]));

  wallet.seed_secret.mnemonic_words = mnemonic_words;
  wallet.seed_secret.seed = seed_hex;

  // Monero
  let wordlist: Vec<&str> = e_q::load_monero_wordlist();
  let key = hmac::Key::new(hmac::HMAC_SHA512, b"Bitcoin seed");
  let tag = hmac::sign(&key, &*seed);

  let mut priv_key: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
  let mut chain: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);

  priv_key.copy_from_slice(&tag.as_ref()[..32]);
  chain.copy_from_slice(&tag.as_ref()[32..]);

  let path: Vec<(u32, bool)> = match wallet.wallet_data.active_bip {
    32 => {
      vec![(0, true), (0, true), (0, true)]
    }
    _ => {
      vec![(wallet.wallet_data.active_bip, true), (128, true), (0, true)]
    }
  };

  for (index, hardened) in path {
    let parent_priv_vec: Zeroizing<Vec<u8>> = Zeroizing::new(priv_key.to_vec());
    let parent_chain_vec: Zeroizing<Vec<u8>> = Zeroizing::new(chain.to_vec());
    let hardened_z: Zeroizing<bool> = Zeroizing::new(hardened);
    let index_z: Zeroizing<u32> = Zeroizing::new(index);

    let derived = crate::keys::derive_secp256k1_child(parent_priv_vec, parent_chain_vec, index_z, hardened_z).expect("BIP32 child derivation failed");

    priv_key.copy_from_slice(&derived.child_private_key_bytes);
    chain.copy_from_slice(&derived.child_chain_code_bytes);
  }

  let hashed: Zeroizing<[u8; 32]> = cn_fast_hash(&Zeroizing::new(priv_key.to_vec()))?;
  let spend_key: Zeroizing<[u8; 32]> = Zeroizing::new(monero_sc_reduce32(hashed)?.to_bytes());
  let monero_words: Zeroizing<String> = monero_seed_to_mnemonic(spend_key.clone(), &wordlist)?;

  wallet.secret_keys.monero_keys.monero_mnemonic_words = monero_words;
  wallet.secret_keys.monero_keys.monero_spend_key = Zeroizing::new(hex::encode(spend_key).to_string());

  Ok(())
}

pub fn generate_raw_entropy(
  _source: Zeroizing<String>,
  entropy_length: Option<Zeroizing<usize>>,
) -> FunctionOutput<Zeroizing<String>> {
  let entropy_length: Zeroizing<usize> = entropy_length.unwrap_or(Zeroizing::new(256));
  let bytes_needed: Zeroizing<usize> = Zeroizing::new(entropy_length.div_ceil(8));
  let mut buffer: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; *bytes_needed]);

  match getrandom::fill(&mut buffer) {
    Ok(value) => value,
    Err(err) => {
      return Err(AppError::log(format!("Can not generate raw entropy with getrandom: {:?}", err)));
    }
  }

  let mut result: Zeroizing<String> = Zeroizing::new(String::with_capacity(*entropy_length));
  for byte in buffer.iter() {
    for bit in 0..8 {
      if result.len() == *entropy_length {
        break;
      }

      let bit_val = (byte >> bit) & 1;
      result.push(if bit_val == 1 { '1' } else { '0' });
    }
  }

  Ok(result)
}

fn generate_raw_mnemonic_passphrase(length: usize) -> FunctionOutput<Zeroizing<String>> {
  let mut bytes = vec![0u8; length];
  match getrandom::fill(&mut bytes) {
    Ok(value) => value,
    Err(err) => {
      return Err(AppError::log(format!("Can not generate raw mnemonic passphrase getrandom: {:?}", err)));
    }
  }
  let mut result = Zeroizing::new(String::with_capacity(length));
  let mut i = 0;

  while result.len() < length {
    if i >= bytes.len() {
      match getrandom::fill(&mut bytes) {
        Ok(value) => value,
        Err(err) => {
          return Err(AppError::log(format!("Can not generate raw mnemonic passphrase getrandom: {:?}", err)));
        }
      }
      i = 0;
    }
    let byte = bytes[i];
    i += 1;

    if byte < 188 {
      let idx = byte % 94;
      let ch = 33u8 + idx;
      result.push(char::from(ch));
    }
  }

  Ok(result)
}

pub fn generate_mnemonic_words(
  final_entropy_binary: Zeroizing<String>,
  dictionary: Zeroizing<MnemonicLanguage>,
) -> FunctionOutput<Zeroizing<String>> {
  let chunks: Zeroizing<Vec<String>> = Zeroizing::new(
    final_entropy_binary
      .chars()
      .collect::<Vec<char>>()
      .chunks(11)
      .map(|chunk| chunk.iter().collect())
      .collect(),
  );

  let mnemonic_decimal: Zeroizing<Vec<u32>> = {
    let mut decoded = Vec::new();
    for chunk in chunks.iter() {
      match u32::from_str_radix(chunk, 2) {
        Ok(num) => decoded.push(num),
        Err(err) => {
          return Err(AppError::log(format!("Failed to parse binary chunk '{}': {:?}", chunk, err)));
        }
      }
    }
    Zeroizing::new(decoded)
  };

  let dictionary_file = dictionary.filename();

  let wordlist_path = std::path::Path::new("wordlists").join(dictionary_file);
  let wordlist_location: Zeroizing<String> = match wordlist_path.to_str() {
    Some(path) => Zeroizing::new(path.to_string()),
    _ => {
      return Err(AppError::log(String::from("Can not open/find mnemonic dictionary file")));
    }
  };

  let wordlist: Zeroizing<String> = e_q::get_text_from_resources(wordlist_location);
  let mnemonic_words_vector: Zeroizing<Vec<String>> = Zeroizing::new(wordlist.lines().map(|line| line.to_string()).collect());
  let mnemonic_result: Zeroizing<Vec<String>> = Zeroizing::new(
    mnemonic_decimal
      .iter()
      .map(|&decimal| {
        if (decimal as usize) < mnemonic_words_vector.len() {
          mnemonic_words_vector[decimal as usize].clone()
        } else {
          "ERROR".to_string()
        }
      })
      .collect(),
  );

  Ok(Zeroizing::new(mnemonic_result.join(" ")))
}

pub fn get_derivation_path(
  curve: &str,
  wallet: &mut CryptoWallet,
) -> FunctionOutput<Zeroizing<String>> {
  let path: Zeroizing<DerivationPathData> = wallet.address_components.derivation_path.clone();

  let coin = *wallet.address_components.derivation_path.coin;

  let tap_bip = match coin {
    0 if !wallet.wallet_data.bitcoin_legacy_addresses => Some(86),
    2 if !wallet.wallet_data.litecoin_legacy_addresses => Some(86),
    _ => None,
  };

  let derivation_path: Zeroizing<String> = match curve {
    "ed25519" | "sr25519" => {
      match *path.purpose {
        32 => {
          // m / account' / change' / address{'}
          Zeroizing::new(format!("m/{}'/{}'/{}'", *path.account, *path.change, *path.address,))
        }

        // 44
        _ => {
          if wallet.wallet_data.slip_derivation_path || *wallet.address_components.coin_name == "Monero" {
            // m / purpose' / coin' / address'
            Zeroizing::new(format!("m/{}'/{}'/{}'", wallet.wallet_data.active_bip, *path.coin, *path.address,))
          } else {
            // m / purpose' / coin' / account' / change' / address'
            Zeroizing::new(format!(
              "m/{}'/{}'/{}'/{}'/{}'",
              wallet.wallet_data.active_bip, *path.coin, *path.account, *path.change, *path.address,
            ))
          }
        }
      }
    }

    "bip32-ed25519" => {
      // m / 1852' / 1815' / account' / role / address{'}
      Zeroizing::new(format!(
        "m/1852'/{}'/{}'/{}/{}{}",
        *path.coin,
        *path.account,
        *path.change,
        *path.address,
        if *path.address_hardened { "'" } else { "" },
      ))
    }

    // "secp256k1"
    _ => {
      match *path.purpose {
        32 => {
          // m / account / change / address{'}
          Zeroizing::new(format!(
            "m/{}'/{}'/{}{}",
            *path.account,
            *path.change,
            *path.address,
            if *path.address_hardened { "'" } else { "" },
          ))
        }

        // 44 & 86
        _ => {
          // m / purpose' / coin' / account' / change / address{'}
          Zeroizing::new(format!(
            "m/{}'/{}'/{}'/{}/{}{}",
            tap_bip.unwrap_or(*path.purpose),
            *path.coin,
            *path.account,
            *path.change,
            *path.address,
            if *path.address_hardened { "'" } else { "" },
          ))
        }
      }
    }
  };

  Ok(derivation_path)
}

//                                SECP256K1 KEYS
// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

pub fn generate_secp256k1_master_keys(wallet: &mut CryptoWallet) -> FunctionOutput<()> {
  let private_header: Zeroizing<String> = Zeroizing::new(String::from("0x0488ADE4"));
  let public_header: Zeroizing<String> = Zeroizing::new(String::from("0x0488B21E"));
  let seed: Zeroizing<String> = wallet.seed_secret.seed.clone();

  let private_header: Zeroizing<u32> = match u32::from_str_radix(private_header.trim_start_matches("0x"), 16) {
    Ok(value) => Zeroizing::new(value),
    Err(err) => {
      return Err(AppError::log(format!("Parse error: Problem with parsing private_header: {:?}", err)));
    }
  };

  let public_header: Zeroizing<u32> = match u32::from_str_radix(public_header.trim_start_matches("0x"), 16) {
    Ok(value) => Zeroizing::new(value),
    Err(err) => {
      return Err(AppError::log(format!("Parsing error: Problem with parsing public_header: {:?}", err)));
    }
  };

  let seed_bytes: Zeroizing<Vec<u8>> = match hex::decode(seed) {
    Ok(bytes) => Zeroizing::new(bytes),
    Err(err) => {
      return Err(AppError::log(format!("Problem with decoding seed_bytes: {}", err)));
    }
  };

  let message: Zeroizing<Vec<u8>> = Zeroizing::new(String::from("Bitcoin seed").as_bytes().to_vec());
  let hmac_result: Zeroizing<Vec<u8>> = e_q::calculate_hmac_sha512_hash(message, seed_bytes);
  let master_private_key_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(hmac_result.split_at(32).0.to_vec());
  let master_chain_code_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(hmac_result.split_at(32).1.to_vec());

  let mut master_private_key: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
  master_private_key.extend_from_slice(&u32::to_be_bytes(*private_header));
  master_private_key.push(0x00);
  master_private_key.extend([0x00; 4].iter());
  master_private_key.extend([0x00; 4].iter());
  master_private_key.extend_from_slice(master_chain_code_bytes.as_slice());
  master_private_key.push(0x00);
  master_private_key.extend_from_slice(master_private_key_bytes.as_slice());

  let checksum: Zeroizing<[u8; 4]> = e_q::calculate_checksum_for_master_keys(master_private_key.clone());
  master_private_key.extend_from_slice(&*checksum);

  let master_private_key_encoded: Zeroizing<String> = Zeroizing::new(bs58::encode(&master_private_key).into_string());

  let array: Zeroizing<[u8; 32]> = {
    if master_private_key_bytes.len() != 32 {
      return Err(AppError::log(String::from("master_private_key_bytes must be 32 bytes")));
    }

    let mut arr: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    arr.copy_from_slice(master_private_key_bytes.as_ref());

    Zeroizing::new(*arr)
  };

  let master_secret_key =
    secp256k1::SecretKey::from_byte_array(*array).map_err(|err| AppError::log(format!("Invalid master_secret_key: {err:?}")))?;

  let secp = secp256k1::Secp256k1::new();

  let master_public_key_bytes: Zeroizing<[u8; 33]> = Zeroizing::new(secp256k1::PublicKey::from_secret_key(&secp, &master_secret_key).serialize());
  master_secret_key.secret_bytes().zeroize();

  let mut master_public_key: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());

  master_public_key.extend_from_slice(&u32::to_be_bytes(*public_header));
  master_public_key.push(0x00);
  master_public_key.extend([0x00; 4].iter());
  master_public_key.extend([0x00; 4].iter());
  master_public_key.extend_from_slice(&master_chain_code_bytes);
  master_public_key.extend_from_slice(&*master_public_key_bytes);

  let checksum: Zeroizing<[u8; 4]> = e_q::calculate_checksum_for_master_keys(master_public_key.clone());

  master_public_key.extend_from_slice(&*checksum);

  let master_public_key_encoded: Zeroizing<String> = Zeroizing::new(bs58::encode(&master_public_key).into_string());

  let master_chain_code_bytes: Zeroizing<[u8; 32]> = {
    if master_chain_code_bytes.len() != 32 {
      return Err(AppError::log(String::from("master_chain_code_bytes must be 32 bytes")));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(master_chain_code_bytes.as_ref());

    Zeroizing::new(arr)
  };

  let master_private_key_bytes: Zeroizing<[u8; 32]> = {
    if master_private_key_bytes.len() != 32 {
      return Err(AppError::log(String::from("master_private_key_bytes must be 32 bytes")));
    }

    let mut arr: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    arr.copy_from_slice(master_private_key_bytes.as_ref());

    arr
  };

  wallet.secret_keys.master_secp256k1_keys.master_private_key_encoded = master_private_key_encoded;
  wallet.secret_keys.master_secp256k1_keys.master_private_key_bytes = Zeroizing::new(master_private_key_bytes.to_vec());
  wallet.secret_keys.master_secp256k1_keys.master_public_key_encoded = master_public_key_encoded;
  wallet.secret_keys.master_secp256k1_keys.master_public_key_bytes = Zeroizing::new(master_public_key_bytes.to_vec());
  wallet.secret_keys.master_secp256k1_keys.master_chain_code_bytes = Zeroizing::new(master_chain_code_bytes.to_vec());

  Ok(())
}

pub fn generate_secp256k1_child_keys(wallet: &mut CryptoWallet) -> FunctionOutput<()> {
  let mut private_key: Zeroizing<Vec<u8>> = Zeroizing::new(wallet.secret_keys.master_secp256k1_keys.master_private_key_bytes.to_vec());
  let mut chain_code: Zeroizing<Vec<u8>> = Zeroizing::new(wallet.secret_keys.master_secp256k1_keys.master_chain_code_bytes.to_vec());
  let mut public_key: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());

  let derivation_path: Zeroizing<String> = get_derivation_path("secp256k1", wallet)?;

  for part in derivation_path.split('/') {
    if part == "m" {
      continue;
    }

    let hardened: Zeroizing<bool> = Zeroizing::new(part.ends_with("'"));
    let index: Zeroizing<u32> = match part.trim_end_matches("'").parse() {
      Ok(index) => Zeroizing::new(index),
      Err(err) => {
        return Err(AppError::log(format!("Parse error: Unable to parse index from path part: {:?}", err)));
      }
    };

    let derived_child_keys: Zeroizing<ChildSecp256k1KeySecretData> = match derive_secp256k1_child(private_key, chain_code, index, hardened) {
      Ok(keys) => Zeroizing::new(keys),
      Err(err) => {
        return Err(AppError::log(format!("Problem with deriving child keys: {:?}", err)));
      }
    };

    private_key = Zeroizing::new(derived_child_keys.child_private_key_bytes.to_vec());
    chain_code = Zeroizing::new(derived_child_keys.child_chain_code_bytes.to_vec());
    public_key = Zeroizing::new(derived_child_keys.child_public_key_bytes.to_vec());
  }

  if chain_code.len() != 32 {
    return Err(AppError::log(format!("Invalid chain code length {:?}", chain_code.len())));
  }

  let array: Zeroizing<[u8; 32]> =
    Zeroizing::new(<[u8; 32]>::try_from(private_key.as_slice()).map_err(|err| AppError::log(format!("private_key must be 32 bytes {:?}", err)))?);

  let secret_key = secp256k1::SecretKey::from_byte_array(*array).map_err(|err| AppError::log(format!("Invalid secret_key: {:?}", err)))?;

  let mut chain_code_array: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
  chain_code_array.copy_from_slice(&chain_code);

  let mut public_key_array: Zeroizing<[u8; 33]> = Zeroizing::new([0u8; 33]);
  public_key_array.copy_from_slice(&public_key);

  wallet.secret_keys.child_secp256k1_keys.child_private_key_bytes = Zeroizing::new(secret_key.secret_bytes().to_vec());
  wallet.secret_keys.child_secp256k1_keys.child_public_key_bytes = Zeroizing::new(public_key_array.to_vec());
  wallet.secret_keys.child_secp256k1_keys.child_chain_code_bytes = Zeroizing::new(chain_code_array.to_vec());

  Ok(())
}

pub fn derive_secp256k1_child(
  parent_key: Zeroizing<Vec<u8>>,
  parent_chain_code: Zeroizing<Vec<u8>>,
  index: Zeroizing<u32>,
  hardened: Zeroizing<bool>,
) -> FunctionOutput<ChildSecp256k1KeySecretData> {
  if *index & 0x80000000 != 0 && !*hardened {
    return Err(AppError::log(format!("Problem with index {:?}", index)));
  }

  let secp = secp256k1::Secp256k1::new();
  let mut data: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(37));

  if *hardened {
    data.push(0x00);
    data.extend_from_slice(&parent_key);
  } else {
    let array: Zeroizing<[u8; 32]> = Zeroizing::new(
      <[u8; 32]>::try_from(parent_key.as_slice()).map_err(|err| AppError::log(format!("Slice error: parent_key must be 32 bytes: {:?}", err)))?,
    );

    let parent_secret_key = secp256k1::SecretKey::from_byte_array(*array).map_err(|err| AppError::log(format!("Invalid SecretKey: {err}")))?;
    let parent_pubkey = secp256k1::PublicKey::from_secret_key(&secp, &parent_secret_key);

    data.extend_from_slice(&parent_pubkey.serialize()[..]);
  }

  let index_bytes: Zeroizing<[u8; 4]> = if *hardened {
    let index: Zeroizing<u32> = Zeroizing::new(*index + WALLET_MAX_ADDRESSES + 1);
    Zeroizing::new(index.to_be_bytes())
  } else {
    Zeroizing::new(index.to_be_bytes())
  };

  data.extend_from_slice(&*index_bytes);

  let result: Zeroizing<Vec<u8>> = e_q::calculate_hmac_sha512_hash(parent_chain_code, data);

  let child_private_key_bytes: Zeroizing<[u8; 32]> = Zeroizing::new(
    result[..32]
      .try_into()
      .map_err(|err| AppError::log(format!("Slice with incorrect length for private key: {:?}", err)))?,
  );

  let combined_bytes_padded: Zeroizing<[u8; 32]> = {
    let curve_order = BigUint::from_bytes_be(&secp256k1::constants::CURVE_ORDER);
    let combined_int = (BigUint::from_bytes_be(&*child_private_key_bytes) + BigUint::from_bytes_be(&parent_key)) % &curve_order;

    let combined_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(combined_int.to_bytes_be());
    let mut padded: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);

    let offset = 32 - combined_bytes.len();
    padded[offset..].copy_from_slice(&combined_bytes);

    padded
  };

  let child_private_key =
    secp256k1::SecretKey::from_byte_array(*combined_bytes_padded).map_err(|err| AppError::log(format!("Invalid child_private_key: {err}")))?;
  let child_private_key_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(child_private_key.secret_bytes().to_vec());

  let child_public_key_bytes: Zeroizing<Vec<u8>> =
    Zeroizing::new(secp256k1::PublicKey::from_secret_key(&secp, &child_private_key).serialize().to_vec());

  Ok(ChildSecp256k1KeySecretData {
    child_private_key_bytes,
    child_chain_code_bytes: Zeroizing::new(result[32..].to_vec()),
    child_public_key_bytes,
  })
}

pub fn generate_secp256k1_address(wallet: &mut CryptoWallet) -> FunctionOutput<()> {
  let public_key: CryptoPublicKey = generate_public_key(wallet)?;

  let coin_index: Zeroizing<u32> = wallet.address_components.derivation_path.coin.clone();
  let mut coin_name: Zeroizing<String> = wallet.address_components.coin_name.clone();
  let public_key_hash: Zeroizing<String> = wallet.address_components.public_key_hash.clone();
  let mut hash: Zeroizing<String> = wallet.address_components.hash.clone();
  let key_derivation: Zeroizing<String> = wallet.address_components.key_derivation.clone();
  let wallet_import_format: Zeroizing<String> = wallet.address_components.wallet_import_format.clone();
  let coin_symbol: Zeroizing<String> = wallet.address_components.symbol.clone();

  let child_private_key_bytes: Zeroizing<Vec<u8>> = wallet.secret_keys.child_secp256k1_keys.child_private_key_bytes.clone();

  let private_key: Zeroizing<[u8; 32]> = Zeroizing::new(
    child_private_key_bytes
      .as_slice()
      .try_into()
      .map_err(|err| AppError::log(format!("Slice error: Invalid private key length (expected 32 bytes): {:?}", err)))?,
  );

  let derivation_path: Zeroizing<String> = match get_derivation_path("secp256k1", wallet) {
    Ok(path) => path,
    Err(err) => {
      return Err(AppError::log(format!("Can not parse derivation path: {:?}", err)));
    }
  };

  match *coin_index {
    // Bitcoin
    0 => {
      if !wallet.wallet_data.bitcoin_legacy_addresses {
        return generate_taproot_address(wallet, &public_key, &derivation_path, private_key);
      } else {
        wallet.address_components.derivation_path.purpose = Zeroizing::new(wallet.wallet_data.active_bip);

        let old_derivation_path: Zeroizing<String> = match get_derivation_path("secp256k1", wallet) {
          Ok(path) => path,
          Err(err) => {
            return Err(AppError::log(format!("Can not parse derivation path: {:?}", err)));
          }
        };

        return generate_legacy_address(wallet, &public_key, &old_derivation_path, private_key);
      }
    }

    // Litecoin
    2 => {
      if !wallet.wallet_data.litecoin_legacy_addresses {
        return generate_taproot_address(wallet, &public_key, &derivation_path, private_key);
      } else {
        wallet.address_components.derivation_path.purpose = Zeroizing::new(wallet.wallet_data.active_bip);

        let old_derivation_path: Zeroizing<String> = match get_derivation_path("secp256k1", wallet) {
          Ok(path) => path,
          Err(err) => {
            return Err(AppError::log(format!("Can not parse derivation path: {:?}", err)));
          }
        };

        return generate_legacy_address(wallet, &public_key, &old_derivation_path, private_key);
      }
    }

    // Cosmos Coin
    118 => {
      let secp_pubkey = match &public_key {
        CryptoPublicKey::Secp256k1(pk) => pk,
        _ => {
          return Err(AppError::log(String::from("Only Secp256k1 for generating Secp256k1 addresses")));
        }
      };

      let pub_compressed: Zeroizing<Vec<u8>> = Zeroizing::new(secp_pubkey.serialize().to_vec());

      let address: Zeroizing<String> = generate_atom_address(pub_compressed.clone())?;
      let public_key_encoded: Zeroizing<String> = encode_cosmos_pubkey_bech32(pub_compressed)?;
      let private_key_encoded: Zeroizing<String> = Zeroizing::new(BASE64.encode(private_key));

      wallet
        .addresses_by_coin
        .0
        .entry(coin_name.to_string())
        .or_default()
        .push(AddressPrivateData {
          coin_index,
          symbol: coin_symbol,
          path: derivation_path,
          address,
          public_key: public_key_encoded,
          private_key: private_key_encoded,
        });

      return Ok(());
    }

    // Open Assets Coin
    21 => {
      return generate_open_assets_address(wallet, &public_key, &derivation_path, private_key);
    }

    // Zilliqa
    313 => {
      if wallet.wallet_data.zilliqa_legacy_addresses {
        let secp_pubkey = match &public_key {
          CryptoPublicKey::Secp256k1(pk) => pk,
          _ => {
            return Err(AppError::log(String::from("Only Secp256k1 for generating Secp256k1 addresses")));
          }
        };

        let pub_compressed: Zeroizing<Vec<u8>> = Zeroizing::new(secp_pubkey.serialize().to_vec());

        let address: Zeroizing<String> = generate_zilliqa_address(pub_compressed.clone())?;
        let public_key_encoded: Zeroizing<String> = Zeroizing::new(hex::encode(pub_compressed.as_slice()));
        let private_key_encoded: Zeroizing<String> = Zeroizing::new(hex::encode(private_key));

        wallet
          .addresses_by_coin
          .0
          .entry(coin_name.to_string())
          .or_default()
          .push(AddressPrivateData {
            coin_index,
            symbol: coin_symbol,
            path: derivation_path,
            address,
            public_key: public_key_encoded,
            private_key: private_key_encoded,
          });

        return Ok(());
      } else {
        coin_name = Zeroizing::new(String::from("Zilliqa"));
        hash = Zeroizing::new(String::from("keccak256"));
      }
    }

    _ => {}
  }

  let public_key_hash_vec: Zeroizing<Vec<u8>> = {
    let trimmed: Zeroizing<String> = Zeroizing::new(public_key_hash.trim_start_matches("0x").to_string());
    let hex: Zeroizing<Vec<u8>> = match hex::decode(trimmed) {
      Ok(hex) => Zeroizing::new(hex),
      Err(err) => return Err(AppError::log(format!("Invalid public_key_hash: {:?}", err))),
    };
    hex
  };

  let public_key_encoded: Zeroizing<String> = encode_public_key(hash.clone(), coin_index.clone(), &public_key)?;

  let address: Zeroizing<String> = generate_address_internal(hash.clone(), coin_index.clone(), &public_key, public_key_hash_vec)?;

  let priv_key_wif: Zeroizing<String> = encode_private_key(key_derivation, wallet_import_format, hash, coin_index.clone(), private_key)?;

  wallet
    .addresses_by_coin
    .0
    .entry(coin_name.to_string())
    .or_default()
    .push(AddressPrivateData {
      coin_index,
      symbol: coin_symbol,
      path: derivation_path,
      address,
      public_key: public_key_encoded,
      private_key: priv_key_wif,
    });

  Ok(())
}

//                                ED25519 KEYS
// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

pub fn generate_ed25519_master_keys(wallet: &mut CryptoWallet) -> FunctionOutput<()> {
  let seed: Zeroizing<String> = wallet.seed_secret.seed.clone();
  let message: Zeroizing<Vec<u8>> = Zeroizing::new(String::from("ed25519 seed").as_bytes().to_vec());

  let seed_bytes: Zeroizing<Vec<u8>> = match hex::decode(seed.clone()) {
    Ok(values) => Zeroizing::new(values),
    Err(err) => {
      return Err(AppError::log(format!("Hex error: Can not decode seed: {}", err)));
    }
  };

  let result: Zeroizing<Vec<u8>> = e_q::calculate_hmac_sha512_hash(message, seed_bytes);
  if result.len() != 64 {
    return Err(AppError::log(String::from("Wrong hash length output in calculate_hmac_sha512_hash")));
  }

  let mut master_private_key: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
  master_private_key.copy_from_slice(&result[..32]);

  let mut master_chain_code: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
  master_chain_code.copy_from_slice(&result[32..]);

  let signing_key = SigningKey::from_bytes(&master_private_key);
  let public_key = signing_key.verifying_key();

  let master_xprv: Zeroizing<String> = Zeroizing::new(bs58::encode(&master_private_key).into_string());
  let master_xpub: Zeroizing<String> = Zeroizing::new(bs58::encode(&public_key.as_bytes()).into_string());

  wallet.secret_keys.master_ed25519_keys.master_private_key_bytes = Zeroizing::new(master_private_key.to_vec());
  wallet.secret_keys.master_ed25519_keys.master_public_key_bytes = Zeroizing::new(public_key.to_bytes().to_vec());
  wallet.secret_keys.master_ed25519_keys.master_chain_code_bytes = Zeroizing::new(master_chain_code.to_vec());
  wallet.secret_keys.master_ed25519_keys.master_private_key_encoded = master_xprv;
  wallet.secret_keys.master_ed25519_keys.master_public_key_encoded = master_xpub;

  Ok(())
}

pub fn generate_ed25519_child_keys(wallet: &mut CryptoWallet) -> FunctionOutput<()> {
  let master_key: Zeroizing<Vec<u8>> = Zeroizing::new(wallet.secret_keys.master_ed25519_keys.master_private_key_bytes.to_vec());

  let master_chain_code: Zeroizing<Vec<u8>> = Zeroizing::new(wallet.secret_keys.master_ed25519_keys.master_chain_code_bytes.to_vec());

  let derivation_path: Zeroizing<String> = match get_derivation_path("ed25519", wallet) {
    Ok(path) => path,
    Err(err) => {
      return Err(AppError::log(format!("Can not parse derivation path: {:?}", err)));
    }
  };

  if master_key.len() != 32 {
    return Err(AppError::log(format!("Master key must be 32 bytes, got {}", master_key.len())));
  };

  if master_chain_code.len() != 32 {
    return Err(AppError::log(format!(
      "Master chain key must be 32 bytes, got {}",
      master_chain_code.len()
    )));
  };

  if !derivation_path.starts_with("m/") {
    return Err(AppError::log("Path must start with: m/".to_string()));
  }

  let mut private_key: Zeroizing<Vec<u8>> = master_key;
  let mut chain_code: Zeroizing<Vec<u8>> = master_chain_code;
  let coin_index: Zeroizing<u32> = wallet.address_components.derivation_path.coin.clone();

  for part in derivation_path.split('/').skip(1) {
    let hardened: Zeroizing<bool> = Zeroizing::new(part.ends_with("'"));
    let index_str: Zeroizing<String> = Zeroizing::new(part.trim_end_matches("'").to_string());
    let index: Zeroizing<u32> = Zeroizing::new(
      index_str
        .parse()
        .map_err(|err| AppError::log(format!("Parsing error. Invalid index: {:?}, Error: {:?}", index_str, err)))?,
    );

    let child_index: Zeroizing<u32> = if *hardened { (*index | 0x80000000).into() } else { index };

    let derived: Zeroizing<ChildEd25519KeySecretData> = Zeroizing::new(derive_ed25519_child(private_key, chain_code, child_index)?);

    private_key = derived.child_private_key_bytes.clone();
    chain_code = derived.child_chain_code_bytes.clone();
  }

  let mut master_key: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
  master_key.copy_from_slice(&private_key);

  let mut child_priv32: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
  child_priv32.copy_from_slice(&private_key);

  let child_pub_bytes = match *coin_index {
    // NEM (NIS1)
    43 => nem_pubkey_from_child_priv(child_priv32)?.to_vec(),

    // Nano (Blake2b)
    165 => generate_nano_public_key(&child_priv32)?.to_vec(),

    // Algorand / Solana / standard RFC 8032
    283 | 501 => SigningKey::from_bytes(&child_priv32).verifying_key().to_bytes().to_vec(),

    // Default RFC 8032
    _ => SigningKey::from_bytes(&child_priv32).verifying_key().to_bytes().to_vec(),
  };

  wallet.secret_keys.child_ed25519_keys.child_private_key_bytes = Zeroizing::new(private_key.to_vec());
  wallet.secret_keys.child_ed25519_keys.child_chain_code_bytes = Zeroizing::new(chain_code.to_vec());
  wallet.secret_keys.child_ed25519_keys.child_public_key_bytes = Zeroizing::new(child_pub_bytes);

  Ok(())
}

pub fn derive_ed25519_child(
  parent_key: Zeroizing<Vec<u8>>,
  parent_chain_code: Zeroizing<Vec<u8>>,
  index: Zeroizing<u32>,
) -> FunctionOutput<ChildEd25519KeySecretData> {
  let prefix_byte: u8 = 0x00;

  if parent_key.len() != 32 || parent_chain_code.len() != 32 {
    return Err(AppError::log(String::from("Invalid parent_key or parent_chain_code length")));
  }

  if *index < 0x80000000 {
    return Err(AppError::log(String::from("Ed25519 only supports hardened derivation")));
  }

  let data: Zeroizing<Vec<u8>> = Zeroizing::new(
    std::iter::once(prefix_byte)
      .chain(parent_key.iter().copied())
      .chain(index.to_be_bytes())
      .collect(),
  );

  let hmac: Zeroizing<Vec<u8>> = e_q::calculate_hmac_sha512_hash(parent_chain_code, data);

  if hmac.len() != 64 {
    return Err(AppError::log("calculate_hmac_sha512_hash len is not 64".to_string()));
  }

  Ok(ChildEd25519KeySecretData {
    child_private_key_bytes: Zeroizing::new(hmac[..32].to_vec()),
    child_chain_code_bytes: Zeroizing::new(hmac[32..].to_vec()),
    child_public_key_bytes: Zeroizing::new(Vec::new()),
  })
}

pub fn generate_ed25519_address(wallet: &mut CryptoWallet) -> FunctionOutput<()> {
  let child_public_key_bytes: Zeroizing<Vec<u8>> = wallet.secret_keys.child_ed25519_keys.child_public_key_bytes.clone();
  let child_private_key_bytes: Zeroizing<Vec<u8>> = wallet.secret_keys.child_ed25519_keys.child_private_key_bytes.clone();
  let coin_index: Zeroizing<u32> = wallet.address_components.derivation_path.coin.clone();
  let coin_name: Zeroizing<String> = wallet.address_components.coin_name.clone();
  let pub_key_hash: Zeroizing<String> = wallet.address_components.public_key_hash.clone();
  let coin_symbol: Zeroizing<String> = wallet.address_components.symbol.clone();

  let derivation_path: Zeroizing<String> = match get_derivation_path("ed25519", wallet) {
    Ok(path) => path,
    Err(err) => {
      return Err(AppError::log(format!("Can not parse derivation path: {:?}", err)));
    }
  };

  let (address, public_key, private_key) = match *coin_index {
    // NEM
    43 => {
      let pubkey_array: Zeroizing<[u8; 32]> = {
        match child_public_key_bytes.as_slice().try_into() {
          Ok(array) => Zeroizing::new(array),
          Err(err) => {
            return Err(AppError::log(format!("Failed to convert public key bytes to [u8; 32]: {:?}", err)));
          }
        }
      };

      let address = generate_nem_address(pubkey_array, pub_key_hash)?;
      (
        address,
        Zeroizing::new(hex::encode(&child_public_key_bytes)),
        Zeroizing::new(hex::encode(&child_private_key_bytes)),
      )
    }

    // Monero
    128 => {
      let monero_spend_priv: Zeroizing<[u8; 32]> = match hex::decode(wallet.secret_keys.monero_keys.monero_spend_key.clone()) {
        Ok(decoded) => match decoded.try_into() {
          Ok(array) => Zeroizing::new(array),
          Err(_) => {
            return Err(AppError::log("Monero spend_key must be exactly 32 bytes".to_string()));
          }
        },
        Err(err) => {
          return Err(AppError::log(format!("Failed to decode spend_key: {:?}", err)));
        }
      };

      let monero_view_priv: Zeroizing<[u8; 32]> =
        Zeroizing::new(Scalar::from_bytes_mod_order(*cn_fast_hash(&Zeroizing::new(monero_spend_priv.to_vec()))?).to_bytes());

      let address_index: Zeroizing<u32> = wallet.address_components.derivation_path.address.clone();

      let (address, public_key_str, private_key_str) = if *address_index == 0 {
        let spend_pub: Zeroizing<[u8; 32]> = monero_pubkey(monero_spend_priv.clone())?;
        let view_pub: Zeroizing<[u8; 32]> = monero_pubkey(monero_view_priv.clone())?;
        let address: Zeroizing<String> = generate_monero_address(spend_pub.clone(), view_pub.clone())?;

        let public_key_str: Zeroizing<String> = Zeroizing::new(format!("spend: {}\nview: {}", hex::encode(spend_pub), hex::encode(view_pub)));

        let private_key_str: Zeroizing<String> = Zeroizing::new(format!(
          "spend: {}\nview: {}",
          hex::encode(monero_spend_priv),
          hex::encode(monero_view_priv)
        ));

        (address, public_key_str, private_key_str)
      } else {
        let (sub_spend_priv, sub_view_priv, sub_spend_pub, sub_view_pub) =
          monero_subaddress_keys(monero_spend_priv, monero_view_priv, Zeroizing::new(0), address_index)?;

        let address: Zeroizing<String> = generate_monero_subaddress(sub_spend_pub.clone(), sub_view_pub.clone())?;

        let public_key_str: Zeroizing<String> = Zeroizing::new(format!("spend: {}\nview: {}", hex::encode(sub_spend_pub), hex::encode(sub_view_pub)));

        let private_key_str: Zeroizing<String> =
          Zeroizing::new(format!("spend: {}\nview: {}", hex::encode(sub_spend_priv), hex::encode(sub_view_priv)));

        (address, public_key_str, private_key_str)
      };

      (address, public_key_str, private_key_str)
    }

    // Nano
    165 => {
      let address = generate_nano_address(&child_public_key_bytes)?;

      (
        address,
        Zeroizing::new(hex::encode(child_public_key_bytes)),
        Zeroizing::new(hex::encode(&child_private_key_bytes)),
      )
    }

    // Algorand
    283 => {
      let address = generate_algorand_address(child_public_key_bytes.clone())?;
      (
        address,
        Zeroizing::new(hex::encode(&child_public_key_bytes)),
        Zeroizing::new(hex::encode(&child_private_key_bytes)),
      )
    }

    // Solana
    501 => {
      let address = bs58::encode(child_public_key_bytes.clone()).into_string();
      (
        Zeroizing::new(address),
        Zeroizing::new(hex::encode(&child_public_key_bytes)),
        Zeroizing::new(hex::encode(&child_private_key_bytes)),
      )
    }

    _ => {
      return Err(AppError::log(format!("Unsupported ed25519 coin_index: {:?}", coin_index)));
    }
  };

  wallet
    .addresses_by_coin
    .0
    .entry(coin_name.to_string())
    .or_default()
    .push(AddressPrivateData {
      coin_index,
      symbol: coin_symbol,
      path: derivation_path,
      address,
      public_key,
      private_key,
    });

  Ok(())
}

//                                SR25519 KEYS
// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

pub fn generate_sr25519_master_keys(wallet: &mut CryptoWallet) -> FunctionOutput<()> {
  let (pair, seed) = sr25519::Pair::from_phrase(&wallet.seed_secret.mnemonic_words, Some(&wallet.seed_secret.mnemonic_passphrase))
    .map_err(|err| AppError::log(format!("Failed to create sr25519 keypair from mnemonic: {:?}", err)))?;

  let public_key = pair.public().to_string();

  wallet.secret_keys.master_sr25519_keys.master_private_key_bytes = Zeroizing::new(seed.to_vec());
  wallet.secret_keys.master_sr25519_keys.master_private_key_encoded = Zeroizing::new(hex::encode(seed));
  wallet.secret_keys.master_sr25519_keys.master_public_key_bytes = Zeroizing::new(hex::encode(public_key.clone()).into_bytes());
  wallet.secret_keys.master_sr25519_keys.master_public_key_encoded = Zeroizing::new(public_key);

  Ok(())
}

pub fn generate_sr25519_child_keys(wallet: &mut CryptoWallet) -> FunctionOutput<()> {
  let full_derivation_path: Zeroizing<String> = get_derivation_path("sr25519", wallet)?;
  let account_path: Zeroizing<String> = get_sr25519_account_path(full_derivation_path)?;
  let (child_pair, child_seed) = get_sr25519_pair_for_path(wallet, &account_path)?;
  let child_public_key = child_pair.public();

  wallet.secret_keys.child_sr25519_keys.child_private_key_bytes = child_seed;
  wallet.secret_keys.child_sr25519_keys.child_public_key_bytes = Zeroizing::new(child_public_key.to_vec());

  Ok(())
}

//                                  ADDRESSES
// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

pub fn generate_public_key(wallet: &mut CryptoWallet) -> FunctionOutput<CryptoPublicKey> {
  let key_derivation: Zeroizing<String> = wallet.address_components.key_derivation.clone();

  match key_derivation.as_str() {
    "secp256k1" => {
      let secp = secp256k1::Secp256k1::new();

      let child_private_key: Zeroizing<[u8; 32]> = Zeroizing::new(
        wallet
          .secret_keys
          .child_secp256k1_keys
          .child_private_key_bytes
          .as_slice()
          .try_into()
          .map_err(|_| AppError::log(String::from("secp256k1 Child key not 32 bytes")))?,
      );

      let secret_key =
        secp256k1::SecretKey::from_byte_array(*child_private_key).map_err(|err| AppError::log(format!("Invalid SecretKey: {:?}", err)))?;
      let secp_pub_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);

      Ok(CryptoPublicKey::Secp256k1(secp_pub_key))
    }
    "ed25519" => {
      let child_private_key: Zeroizing<[u8; 32]> = Zeroizing::new(
        wallet
          .secret_keys
          .child_ed25519_keys
          .child_private_key_bytes
          .as_slice()
          .try_into()
          .map_err(|_| AppError::log(String::from("ed25519 Child private key not 32 bytes")))?,
      );

      match *wallet.address_components.derivation_path.coin {
        43 => {
          use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, edwards::EdwardsPoint, scalar::Scalar};
          use ed25519_dalek::VerifyingKey;
          use tiny_keccak::{Hasher, Keccak};

          let mut h = [0u8; 64];
          let mut hasher = Keccak::v512();
          hasher.update(&*child_private_key);
          hasher.finalize(&mut h);

          let mut s = [0u8; 32];
          s.copy_from_slice(&h[..32]);
          s[0] &= 248;
          s[31] &= 127;
          s[31] |= 64;

          let a = Scalar::from_bytes_mod_order(s);

          let point: EdwardsPoint = ED25519_BASEPOINT_POINT * a;
          let pk_bytes = point.compress().to_bytes();

          let verifying_key = VerifyingKey::from_bytes(&pk_bytes).map_err(|e| AppError::log(format!("Invalid NEM Ed25519 public key: {:?}", e)))?;
          Ok(CryptoPublicKey::Ed25519(verifying_key))
        }
        _ => {
          let signing_key = ed25519_dalek::SigningKey::from_bytes(&child_private_key);
          let verifying_key = signing_key.verifying_key();

          Ok(CryptoPublicKey::Ed25519(verifying_key))
        }
      }
    }
    _ => Err(AppError::log(format!("Unsupported key derivation method: {:?}", key_derivation))),
  }
}

fn encode_public_key(
  hash: Zeroizing<String>,
  coin_index: Zeroizing<u32>,
  public_key: &CryptoPublicKey,
) -> FunctionOutput<Zeroizing<String>> {
  match hash.as_str() {
    "sha256" | "sha256+ripemd160" => match public_key {
      CryptoPublicKey::Secp256k1(pk) => Ok(Zeroizing::new(hex::encode(pk.serialize()))),
      _ => Err(AppError::log(format!(
        "Problem with Secp256k1 public key and hash in encode_public_key: {:?}",
        hash
      ))),
    },

    "keccak256" => match public_key {
      CryptoPublicKey::Secp256k1(pk) => {
        let serialized: Zeroizing<[u8; 33]> = Zeroizing::new(pk.serialize());

        if *coin_index == 195 {
          Ok(Zeroizing::new(hex::encode(serialized)))
        } else {
          Ok(Zeroizing::new(format!("0x{}", hex::encode(serialized))))
        }
      }
      _ => Err(AppError::log(format!(
        "Problem with Secp256k1 public key and hash in encode_public_key: {:?}",
        hash
      ))),
    },

    _ => Err(AppError::log(format!("Unsupported hash method: {:?}", hash))),
  }
}

pub fn get_public_key(public_key: &CryptoPublicKey) -> FunctionOutput<Zeroizing<Vec<u8>>> {
  let public_key_bytes: Zeroizing<Vec<u8>> = match public_key {
    CryptoPublicKey::Secp256k1(key) => Zeroizing::new(key.serialize().to_vec()),
    CryptoPublicKey::Ed25519(key) => Zeroizing::new(key.to_bytes().to_vec()),
  };

  Ok(public_key_bytes)
}

pub fn create_private_key_for_address(
  private_key: Option<&secp256k1::SecretKey>,
  compressed: Option<Zeroizing<bool>>,
  wif: Option<Zeroizing<String>>,
  hash: Zeroizing<String>,
  coin_index: Zeroizing<u32>,
) -> FunctionOutput<Zeroizing<String>> {
  let wallet_import_format: Zeroizing<String> = match wif.as_ref() {
    Some(w) if !w.is_empty() => Zeroizing::new(w.trim_start_matches("0x").to_string()),
    _ => Zeroizing::new(String::from("80")),
  };

  let compressed: Zeroizing<bool> = compressed.unwrap_or(Zeroizing::new(true));

  let wallet_import_format_bytes: Zeroizing<Vec<u8>> = match hex::decode(wallet_import_format) {
    Ok(bytes) => Zeroizing::new(bytes),
    Err(err) => {
      return Err(AppError::log(format!("Invalid WIF format {:?}", err)));
    }
  };

  match hash.as_str() {
    "sha256" => {
      let mut extended_key: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(34));
      extended_key.extend_from_slice(&wallet_import_format_bytes);

      if let Some(private_key) = private_key {
        extended_key.extend_from_slice(&private_key.secret_bytes());

        if *compressed {
          extended_key.push(0x01);
        }
      } else {
        return Err(AppError::log(String::from("Private key must be provided")));
      }

      let checksum: Zeroizing<Vec<u8>> = e_q::calculate_double_sha256_hash(extended_key.clone());

      let address_checksum: Zeroizing<[u8; 4]> = Zeroizing::new(
        checksum[0..4]
          .try_into()
          .map_err(|err| AppError::log(format!("Address checksum can not be calculated: {:?}", err)))?,
      );

      extended_key.extend_from_slice(address_checksum.as_slice());

      Ok(Zeroizing::new(bs58::encode(extended_key).into_string()))
    }
    "keccak256" => {
      if let Some(private_key) = private_key {
        if *coin_index == 195 {
          Ok(Zeroizing::new(hex::encode(private_key.secret_bytes())))
        } else {
          Ok(Zeroizing::new(format!("0x{}", hex::encode(private_key.secret_bytes()))))
        }
      } else {
        Err(AppError::log("Private key must be provided".to_string()))
      }
    }
    "sha256+ripemd160" => match private_key {
      Some(key) => {
        let private_key_hex = hex::encode(key.secret_bytes());
        Ok(Zeroizing::new(private_key_hex))
      }
      None => Err(AppError::log(String::from("Private key must be provided"))),
    },
    _ => Err(AppError::log(format!("Unsupported hash method: {:?}", hash))),
  }
}

fn encode_private_key(
  key_derivation: Zeroizing<String>,
  wallet_import_format: Zeroizing<String>,
  hash: Zeroizing<String>,
  coin_index: Zeroizing<u32>,
  private_key_bytes: Zeroizing<[u8; 32]>,
) -> FunctionOutput<Zeroizing<String>> {
  if *key_derivation == "ed25519" {
    Ok(Zeroizing::new(bs58::encode(private_key_bytes).into_string()))
  } else {
    let secret_key =
      secp256k1::SecretKey::from_byte_array(*private_key_bytes).map_err(|err| AppError::log(format!("Invalid SecretKey: {:?}", err)))?;

    create_private_key_for_address(
      Some(&secret_key),
      Some(Zeroizing::new(true)), // compressed
      Some(wallet_import_format),
      hash,
      coin_index,
    )
    .map_err(|err| AppError::log(format!("Failed to convert private key to WIF: {:?}", err)))
  }
}

fn generate_address_internal(
  hash: Zeroizing<String>,
  coin_index: Zeroizing<u32>,
  public_key: &CryptoPublicKey,
  public_key_hash_vec: Zeroizing<Vec<u8>>,
) -> FunctionOutput<Zeroizing<String>> {
  match hash.as_str() {
    "sha256" => generate_sha256_address(public_key, public_key_hash_vec),
    "keccak256" => generate_keccak256_address(public_key, public_key_hash_vec, coin_index),
    "sha256+ripemd160" => generate_sha256_ripemd160_address(coin_index, public_key, public_key_hash_vec),
    _ => Err(AppError::log(format!("Unsupported hash method: {:?}", hash))),
  }
}

pub fn generate_sha256_address(
  public_key: &CryptoPublicKey,
  public_key_hash: Zeroizing<Vec<u8>>,
) -> FunctionOutput<Zeroizing<String>> {
  let public_key_bytes: Zeroizing<Vec<u8>> = match get_public_key(public_key) {
    Ok(key) => key,
    Err(err) => {
      return Err(AppError::log(format!("Can not get public key: {err:?}")));
    }
  };

  let hash160: Zeroizing<Vec<u8>> = e_q::calculate_sha256_and_ripemd160_hash(public_key_bytes);

  let mut payload: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(public_key_hash.len() + hash160.len()));
  payload.extend_from_slice(&public_key_hash);
  payload.extend_from_slice(&hash160);

  let checksum: Zeroizing<Vec<u8>> = e_q::calculate_double_sha256_hash(payload.clone());

  let address_checksum: Zeroizing<[u8; 4]> = Zeroizing::new(
    checksum[0..4]
      .try_into()
      .map_err(|err| AppError::log(format!("Wrong address checksum: {:?}", err)))?,
  );

  let mut address_payload: Zeroizing<Vec<u8>> = payload;
  address_payload.extend_from_slice(&*address_checksum);

  let address: Zeroizing<String> = Zeroizing::new(bs58::encode(address_payload).into_string());

  Ok(address)
}

pub fn generate_keccak256_address(
  public_key: &CryptoPublicKey,
  public_key_hash: Zeroizing<Vec<u8>>,
  coin_index: Zeroizing<u32>,
) -> FunctionOutput<Zeroizing<String>> {
  let public_key_bytes: Zeroizing<Vec<u8>> = match public_key {
    CryptoPublicKey::Secp256k1(key) => Zeroizing::new(key.serialize_uncompressed().to_vec()),
    CryptoPublicKey::Ed25519(key) => Zeroizing::new(key.to_bytes().to_vec()),
  };

  let public_key_slice: Zeroizing<Vec<u8>> = match public_key {
    CryptoPublicKey::Secp256k1(_) => Zeroizing::new(public_key_bytes[1..].to_vec()),
    CryptoPublicKey::Ed25519(_) => Zeroizing::new(public_key_bytes[..].to_vec()),
  };

  let keccak_result = {
    let mut keccak = Keccak256::new();
    keccak.update(public_key_slice);
    keccak.finalize()
  };

  let address_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(keccak_result[12..].to_vec());

  let address: Zeroizing<String> = match *coin_index {
    // Icon
    74 => Zeroizing::new(format!("hx{}", hex::encode(address_bytes))),

    // Tron
    195 => {
      let mut tron_prefixed: Zeroizing<Vec<u8>> = public_key_hash;
      tron_prefixed.extend_from_slice(&address_bytes);

      let checksum: Zeroizing<Vec<u8>> = {
        let hash = Sha256::digest(&tron_prefixed);
        let hash2 = Sha256::digest(hash);
        Zeroizing::new(hash2[..4].to_vec())
      };

      let mut full_payload: Zeroizing<Vec<u8>> = tron_prefixed.clone();
      full_payload.extend_from_slice(&checksum);

      Zeroizing::new(bs58::encode(full_payload).into_string())
    }

    _ => Zeroizing::new(format!("0x{}", hex::encode(address_bytes))),
  };

  Ok(address)
}

pub fn generate_sha256_ripemd160_address(
  coin_index: Zeroizing<u32>,
  public_key: &CryptoPublicKey,
  public_key_hash: Zeroizing<Vec<u8>>,
) -> FunctionOutput<Zeroizing<String>> {
  let public_key_bytes: Zeroizing<Vec<u8>> = match get_public_key(public_key) {
    Ok(key) => key,
    Err(err) => {
      return Err(AppError::log(format!(
        "Can not get public key for sha256 and ripemd160 address: {:?}",
        err
      )));
    }
  };

  let hash: Zeroizing<Vec<u8>> = e_q::calculate_sha256_and_ripemd160_hash(public_key_bytes);

  let mut address_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
  address_bytes.extend_from_slice(&public_key_hash);
  address_bytes.extend(&*hash);

  let checksum: Zeroizing<Vec<u8>> = Zeroizing::new(Sha256::digest(Sha256::digest(&address_bytes))[..4].to_vec());

  let mut full_address_bytes: Zeroizing<Vec<u8>> = address_bytes.clone();
  full_address_bytes.extend_from_slice(&checksum);

  let alphabet = match *coin_index {
    144 => bs58::Alphabet::RIPPLE,
    _ => bs58::Alphabet::DEFAULT,
  };

  let encoded_address: Zeroizing<String> = Zeroizing::new(bs58::encode(full_address_bytes).with_alphabet(alphabet).into_string());

  Ok(encoded_address)
}

pub fn generate_addresses_for_all_coins(wallet: &mut CryptoWallet) -> FunctionOutput<()> {
  let active_coins = if cfg!(feature = "dev") { 2 } else { 1 };

  let last_index = *wallet.address_components.derivation_path.last_index;

  let (start_index, end_index) = {
    if wallet.addresses_by_coin.0.is_empty() {
      (0, wallet.wallet_data.address_count)
    } else {
      (last_index, last_index.saturating_add(wallet.wallet_data.address_count))
    }
  };

  // ECDB: Extended Coin DataBase
  let resource_path = std::path::Path::new("coin").join("ECDB.csv");
  let resource_path_str: Zeroizing<String> = Zeroizing::new(resource_path.into_os_string().into_string().unwrap_or_default());
  let ecdb_file = e_q::get_file_from_resources(resource_path_str);

  if let Ok(file) = ecdb_file {
    let reader = std::io::BufReader::new(file.contents());

    for line_result in reader.lines() {
      match line_result {
        Ok(line) => {
          let columns: Vec<&str> = line.split(',').collect();
          let inactive_coin = columns.first().unwrap_or(&"0");
          if *inactive_coin != active_coins.to_string() {
            continue;
          }

          wallet.address_components.derivation_path.purpose = Zeroizing::new(wallet.wallet_data.active_bip);
          wallet.address_components.derivation_path.coin = Zeroizing::new(columns[1].parse().unwrap_or(0));
          wallet.address_components.derivation_path.purpose_hardened = Zeroizing::new(true);
          wallet.address_components.derivation_path.coin_hardened = Zeroizing::new(true);

          wallet.address_components.derivation_path.account_hardened = Zeroizing::new(true);
          wallet.address_components.derivation_path.change_hardened = Zeroizing::new(wallet.wallet_data.active_bip == 32);

          wallet.address_components.derivation_path.address_hardened = Zeroizing::new(wallet.wallet_data.hardened_address);

          wallet.address_components.coin_name = Zeroizing::new(columns[3].to_string());
          wallet.address_components.key_derivation = Zeroizing::new(columns[4].to_string());
          wallet.address_components.hash = Zeroizing::new(columns[5].to_string());
          wallet.address_components.public_key_hash = Zeroizing::new(columns[8].to_string());
          wallet.address_components.wallet_import_format = Zeroizing::new(columns[10].to_string());
          wallet.address_components.evm = Zeroizing::new(columns[11].trim().eq_ignore_ascii_case("true"));

          wallet.address_components.symbol = Zeroizing::new(columns[2].parse().unwrap_or(String::from("???")));

          // JUMP: GENERATE NEW ADDRESSES
          for address_index in start_index..end_index {
            wallet.address_components.derivation_path.address = Zeroizing::new(address_index);

            if wallet.wallet_data.unify_evm && *wallet.address_components.evm {
              wallet.address_components.derivation_path.coin = Zeroizing::new(60);
            }

            match wallet.address_components.key_derivation.as_str() {
              "secp256k1" => {
                match generate_secp256k1_child_keys(wallet) {
                  Ok(_) => {}
                  Err(err) => {
                    return Err(AppError::log(format!("Can not derive child keys: {}", err)));
                  }
                };

                match generate_secp256k1_address(wallet) {
                  Ok(_) => {}
                  Err(err) => {
                    return Err(AppError::log(format!("Can not derive secp256k1 address: {}", err)));
                  }
                };
              }

              "ed25519" => {
                match generate_ed25519_child_keys(wallet) {
                  Ok(_) => {}
                  Err(err) => {
                    return Err(AppError::log(format!("Can not derive child keys: {}", err)));
                  }
                };

                match generate_ed25519_address(wallet) {
                  Ok(_) => {}
                  Err(err) => {
                    return Err(AppError::log(format!("Can not derive ed25519 address: {}", err)));
                  }
                };
              }

              "sr25519" => {
                match generate_sr25519_child_keys(wallet) {
                  Ok(_) => {}
                  Err(err) => {
                    return Err(AppError::log(format!("Can not derive child keys: {}", err)));
                  }
                };

                match generate_sr25519_address(wallet) {
                  Ok(_) => {}
                  Err(err) => {
                    return Err(AppError::log(format!("Can not derive ed25519 address: {}", err)));
                  }
                };
              }

              "bip32-ed25519" => {
                let _ = derive_cardano_address_from_seed_bytes(wallet);
              }

              _ => {
                return Err(AppError::log(format!(
                  "Unsupported key derivation: {:?}",
                  wallet.address_components.key_derivation
                )));
              }
            }
          }
        }
        Err(err) => {
          eprintln!("ECDB file error: Skipping invalid line: {}", err);
          continue;
        }
      }
    }

    *wallet.address_components.derivation_path.last_index = end_index;
  }

  Ok(())
}

//                                 COSMOS (ATOM)
// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

fn generate_atom_address(pub_compressed: Zeroizing<Vec<u8>>) -> FunctionOutput<Zeroizing<String>> {
  let hash20: Zeroizing<Vec<u8>> = e_q::calculate_sha256_and_ripemd160_hash(pub_compressed);

  let address: Zeroizing<String> = match bech32_encode::<Bech32>(Zeroizing::new(String::from("cosmos")), hash20) {
    Ok(address) => address,
    Err(err) => {
      return Err(AppError::log(format!("Problem with bech32 encoding: {:?}", err)));
    }
  };

  Ok(address)
}

fn encode_cosmos_pubkey_bech32(pub_compressed: Zeroizing<Vec<u8>>) -> FunctionOutput<Zeroizing<String>> {
  let prefix: Zeroizing<[u8; 5]> = Zeroizing::new([0xEB, 0x5A, 0xE9, 0x87, 0x21]);
  let mut data: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(38));

  data.extend_from_slice(&*prefix);
  data.extend_from_slice(&pub_compressed);

  let key: Zeroizing<String> = match bech32_encode::<Bech32>(Zeroizing::new(String::from("cosmospub")), data) {
    Ok(key) => key,
    Err(err) => {
      return Err(AppError::log(format!("Problem with encoding public key with bech32: {:?}", err)));
    }
  };

  Ok(key)
}

fn bech32_encode<Checksum: bech32::Checksum>(
  hrp: Zeroizing<String>,
  data: Zeroizing<Vec<u8>>,
) -> FunctionOutput<Zeroizing<String>> {
  let hrp_parsed = Hrp::parse(&hrp).map_err(|err| AppError::log(format!("Invalid HRP '{:?}': {:?}", hrp, err)))?;

  let data: Zeroizing<String> = match encode::<Checksum>(hrp_parsed, &data) {
    Ok(data) => Zeroizing::new(data),
    Err(err) => {
      return Err(AppError::log(format!("Bech32 encode error: {:?}", err)));
    }
  };

  Ok(data)
}

//                                   NEM (XEM)
// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

pub fn generate_nem_address(
  pubkey_bytes: Zeroizing<[u8; 32]>,
  pub_key_hash: Zeroizing<String>,
) -> FunctionOutput<Zeroizing<String>> {
  let k256 = keccak256_nis1(Zeroizing::new(pubkey_bytes.to_vec()));
  let ripemd_hash = Ripemd160::digest(&k256);

  let trimmed = pub_key_hash.trim_start_matches("0x").to_lowercase();
  let version: u8 = u8::from_str_radix(&trimmed, 16).map_err(|err| AppError::log(format!("Invalid public_key_hash hex: {:?}", err)))?;

  let mut payload = Zeroizing::new(Vec::new());
  payload.push(version);
  payload.extend_from_slice(&ripemd_hash);

  let checksum = keccak256_nis1(payload.clone());
  payload.extend_from_slice(&checksum[..4]);

  let b32 = base32::encode(Alphabet::Rfc4648 { padding: false }, &payload);
  let nem_address = b32.chars().enumerate().fold(String::new(), |mut acc, (i, c)| {
    if i > 0 && i % 6 == 0 {
      acc.push('-');
    }

    acc.push(c);

    acc
  });

  Ok(Zeroizing::new(nem_address))
}

fn nem_pubkey_from_child_priv(child_private_key: Zeroizing<[u8; 32]>) -> FunctionOutput<Zeroizing<[u8; 32]>> {
  let mut hash = [0u8; 64];
  let mut keccak512 = Keccak::v512();
  keccak512.update(child_private_key.as_slice());
  keccak512.finalize(&mut hash);

  let mut scalar_bytes = [0u8; 32];
  scalar_bytes.copy_from_slice(&hash[..32]);
  scalar_bytes[0] &= 248;
  scalar_bytes[31] &= 127;
  scalar_bytes[31] |= 64;

  let scalar = Scalar::from_bytes_mod_order(scalar_bytes);

  let edward_point: EdwardsPoint = ED25519_BASEPOINT_POINT * scalar;

  Ok(Zeroizing::new(edward_point.compress().to_bytes()))
}

fn keccak256_nis1(data: Zeroizing<Vec<u8>>) -> Zeroizing<[u8; 32]> {
  let mut out = Zeroizing::new([0u8; 32]);
  let mut k256 = Keccak::v256();

  k256.update(&data);
  k256.finalize(&mut *out);

  out
}

//                               OPEN ASSETS (OA)
// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

fn generate_open_assets_address(
  wallet: &mut CryptoWallet,
  public_key: &CryptoPublicKey,
  derivation_path: &Zeroizing<String>,
  private_key: Zeroizing<[u8; 32]>,
) -> FunctionOutput<()> {
  let coin_name = wallet.address_components.coin_name.clone();
  let coin_index = wallet.address_components.derivation_path.coin.clone();
  let public_key_hash = wallet.address_components.public_key_hash.clone();
  let hash = wallet.address_components.hash.clone();
  let key_derivation = wallet.address_components.key_derivation.clone();
  let wallet_import_format = wallet.address_components.wallet_import_format.clone();

  let public_key_hash_vec: Zeroizing<Vec<u8>> = {
    let trimmed: Zeroizing<String> = Zeroizing::new(public_key_hash.trim_start_matches("0x").to_string());
    let hex: Zeroizing<Vec<u8>> = match hex::decode(trimmed) {
      Ok(hex) => Zeroizing::new(hex),
      Err(err) => return Err(AppError::log(format!("Invalid public_key_hash: {:?}", err))),
    };
    hex
  };

  let public_key_encoded: Zeroizing<String> = encode_public_key(hash.clone(), coin_index.clone(), public_key)?;
  let address: Zeroizing<String> = generate_address_internal(hash.clone(), coin_index.clone(), public_key, public_key_hash_vec)?;
  let priv_key_wif: Zeroizing<String> = encode_private_key(
    key_derivation.clone(),
    wallet_import_format.clone(),
    hash.clone(),
    coin_index.clone(),
    private_key,
  )?;

  let btc_decoded = bs58::decode(address.clone())
    .into_vec()
    .map_err(|e| AppError::log(format!("Invalid Base58 address: {e}")))?;

  if btc_decoded.len() < 1 + 20 + 4 {
    return Err(AppError::log(format!(
      "Unexpected Base58 length for Open Assets address: {} (need ≥ 25 bytes: 1+20+4)",
      btc_decoded.len()
    )));
  }

  let (btc_body, btc_checksum_bytes) = btc_decoded.split_at(btc_decoded.len() - 4);

  let btc_hash_twice = {
    let mut sha256_btc_1 = Sha256::new();
    sha256_btc_1.update(btc_body);
    let once = sha256_btc_1.finalize();

    let mut sha256_btc_2 = Sha256::new();
    sha256_btc_2.update(once);
    sha256_btc_2.finalize()
  };

  if btc_checksum_bytes != &btc_hash_twice[0..4] {
    return Err(AppError::log("BTC Base58Check checksum mismatch"));
  }

  if btc_body.len() != 1 + 20 {
    return Err(AppError::log(format!(
      "Unexpected BTC body length: {} (expected 21 bytes: 1+20)",
      btc_body.len()
    )));
  }

  let btc_version = btc_body[0];
  let btc_payload_hash160 = &btc_body[1..];

  let oa_namespace: u8 = 0x13;
  let mut oa_address_body = Vec::with_capacity(1 + 1 + btc_payload_hash160.len());
  oa_address_body.push(oa_namespace);
  oa_address_body.push(btc_version);
  oa_address_body.extend_from_slice(btc_payload_hash160);

  let oa_hash_twice = {
    let mut sha256_oa_1 = Sha256::new();
    sha256_oa_1.update(&oa_address_body);
    let once = sha256_oa_1.finalize();

    let mut sha256_oa_2 = Sha256::new();
    sha256_oa_2.update(once);
    sha256_oa_2.finalize()
  };

  let mut oa_address_bytes = oa_address_body;
  oa_address_bytes.extend_from_slice(&oa_hash_twice[0..4]);

  let oa_colored_address = Zeroizing::new(bs58::encode(oa_address_bytes).into_string());

  wallet
    .addresses_by_coin
    .0
    .entry(coin_name.to_string())
    .or_default()
    .push(AddressPrivateData {
      coin_index: coin_index.clone(),
      symbol: Zeroizing::new(String::from("OA")),
      path: derivation_path.clone(),
      address: oa_colored_address,
      public_key: public_key_encoded,
      private_key: priv_key_wif,
    });

  Ok(())
}

//                                   TAPROOT
// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

fn encode_taproot_bech32m(
  coin_name: &str,
  tweaked_key: Zeroizing<[u8; 32]>,
) -> FunctionOutput<Zeroizing<String>> {
  let hrp_str = match coin_name {
    "Bitcoin" => "bc",
    "Litecoin" => "ltc",
    _ => return Err(AppError::log(format!("Unsupported coin: {}", coin_name))),
  };

  let hrp = Hrp::parse(hrp_str).map_err(|e| AppError::log(format!("HRP error: {:?}", e)))?;

  let address = segwit::encode(hrp, segwit::VERSION_1, &*tweaked_key).map_err(|e| AppError::log(format!("Bech32m encoding failed: {:?}", e)))?;

  Ok(Zeroizing::new(address))
}

fn tweak_taproot_key(internal_key: Zeroizing<[u8; 32]>) -> FunctionOutput<Zeroizing<[u8; 32]>> {
  let merkle_root: &[u8] = &[];

  let mut hasher = Sha256::new();
  hasher.update(b"TapTweak");

  let tag_hash = hasher.finalize_reset();

  let mut hasher = Sha256::new();
  hasher.update(tag_hash);
  hasher.update(tag_hash);
  hasher.update(internal_key.clone());
  hasher.update(merkle_root);
  let tweak = hasher.finalize();

  let secp = secp256k1::Secp256k1::new();
  let internal_pubkey =
    secp256k1::XOnlyPublicKey::from_byte_array(*internal_key).map_err(|e| AppError::log(format!("Invalid x-only public key: {}", e)))?;

  let tweak_scalar = secp256k1::Scalar::from_be_bytes(tweak.into()).map_err(|_| AppError::log("Invalid tweak scalar"))?;

  let tweaked = internal_pubkey
    .add_tweak(&secp, &tweak_scalar)
    .map_err(|e| AppError::log(format!("Taproot tweak failed: {}", e)))?;

  let serialized: Zeroizing<[u8; 32]> = Zeroizing::new(tweaked.0.serialize());

  Ok(serialized)
}

pub fn generate_legacy_address(
  wallet: &mut CryptoWallet,
  public_key: &CryptoPublicKey,
  derivation_path: &Zeroizing<String>,
  private_key: Zeroizing<[u8; 32]>,
) -> FunctionOutput<()> {
  let coin_index: Zeroizing<u32> = wallet.address_components.derivation_path.coin.clone();
  let coin_name: Zeroizing<String> = wallet.address_components.coin_name.clone();
  let public_key_hash: Zeroizing<String> = wallet.address_components.public_key_hash.clone();
  let hash: Zeroizing<String> = wallet.address_components.hash.clone();
  let key_derivation: Zeroizing<String> = wallet.address_components.key_derivation.clone();
  let wallet_import_format: Zeroizing<String> = wallet.address_components.wallet_import_format.clone();
  let coin_symbol: Zeroizing<String> = wallet.address_components.symbol.clone();

  let public_key_hash_vec: Zeroizing<Vec<u8>> = {
    let trimmed: Zeroizing<String> = Zeroizing::new(public_key_hash.trim_start_matches("0x").to_string());
    let hex: Zeroizing<Vec<u8>> = match hex::decode(trimmed) {
      Ok(hex) => Zeroizing::new(hex),
      Err(err) => return Err(AppError::log(format!("Invalid public_key_hash: {:?}", err))),
    };
    hex
  };

  let public_key_encoded: Zeroizing<String> = encode_public_key(hash.clone(), coin_index.clone(), public_key)?;

  let address: Zeroizing<String> = generate_address_internal(hash.clone(), coin_index.clone(), public_key, public_key_hash_vec)?;

  let priv_key_wif: Zeroizing<String> = encode_private_key(
    key_derivation.clone(),
    wallet_import_format.clone(),
    hash.clone(),
    coin_index.clone(),
    private_key,
  )?;

  let new_address = AddressPrivateData {
    coin_index: coin_index.clone(),
    symbol: coin_symbol,
    path: derivation_path.clone(),
    address,
    public_key: public_key_encoded,
    private_key: priv_key_wif,
  };

  wallet.addresses_by_coin.0.entry(coin_name.to_string()).or_default().push(new_address);

  Ok(())
}

pub fn generate_taproot_address(
  wallet: &mut CryptoWallet,
  public_key: &CryptoPublicKey,
  derivation_path: &Zeroizing<String>,
  private_key: Zeroizing<[u8; 32]>,
) -> FunctionOutput<()> {
  let coin_index: Zeroizing<u32> = wallet.address_components.derivation_path.coin.clone();
  let coin_name: Zeroizing<String> = wallet.address_components.coin_name.clone();
  let hash: Zeroizing<String> = wallet.address_components.hash.clone();
  let key_derivation: Zeroizing<String> = wallet.address_components.key_derivation.clone();
  let wallet_import_format: Zeroizing<String> = wallet.address_components.wallet_import_format.clone();
  let coin_symbol: Zeroizing<String> = wallet.address_components.symbol.clone();

  let secp_pubkey = match public_key {
    CryptoPublicKey::Secp256k1(pk) => pk,
    _ => {
      return Err(AppError::log("Only Secp256k1 supported for Bitcoin Taproot"));
    }
  };

  let compressed_pubkey: Zeroizing<Vec<u8>> = Zeroizing::new(secp_pubkey.serialize().to_vec());
  let public_key_encoded: Zeroizing<String> = Zeroizing::new(hex::encode(&compressed_pubkey));
  let pubkey_bytes: Zeroizing<[u8; 65]> = Zeroizing::new(secp_pubkey.serialize_uncompressed());

  let internal_key: Zeroizing<[u8; 32]> =
    Zeroizing::new(<[u8; 32]>::try_from(&pubkey_bytes[1..33]).map_err(|_| AppError::log("Failed to extract x-only internal key"))?);

  let tweaked_key: Zeroizing<[u8; 32]> = tweak_taproot_key(internal_key)?;
  let taproot_address: Zeroizing<String> = encode_taproot_bech32m(&coin_name, tweaked_key)?;

  let priv_key_wif: Zeroizing<String> = encode_private_key(
    key_derivation.clone(),
    wallet_import_format.clone(),
    hash.clone(),
    coin_index.clone(),
    private_key,
  )?;

  let new_address: AddressPrivateData = AddressPrivateData {
    coin_index: coin_index.clone(),
    symbol: coin_symbol,
    path: derivation_path.clone(),
    address: taproot_address,
    public_key: public_key_encoded,
    private_key: priv_key_wif,
  };

  wallet.addresses_by_coin.0.entry(coin_name.to_string()).or_default().push(new_address);

  Ok(())
}

//                                 ZILLIQA (ZIL)
// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

fn generate_zilliqa_address(pub_compressed: Zeroizing<Vec<u8>>) -> FunctionOutput<Zeroizing<String>> {
  let full_hash: Zeroizing<Vec<u8>> = e_q::calculate_sha256_hash(pub_compressed);
  let hash20: Zeroizing<Vec<u8>> = Zeroizing::new(full_hash[12..].to_vec());

  let address: Zeroizing<String> = match bech32_encode::<Bech32>(Zeroizing::new(String::from("zil")), hash20) {
    Ok(address) => address,
    Err(err) => {
      return Err(AppError::log(format!("Problem with bech32 encoding: {:?}", err)));
    }
  };

  Ok(address)
}

//                                 MONERO (XMR)
// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

pub fn monero_seed_to_mnemonic(
  seed: Zeroizing<[u8; 32]>,
  wordlist: &[&str],
) -> FunctionOutput<Zeroizing<String>> {
  let n = wordlist.len() as u32;
  let mut words: Zeroizing<Vec<String>> = Zeroizing::new(Vec::with_capacity(25));
  let mut checksum_input: Zeroizing<String> = Zeroizing::new(String::with_capacity(24 * MONERO_PREFIX_LEN));

  for i in 0..8 {
    let start = i * 4;

    let chunk: Zeroizing<[u8; 4]> = Zeroizing::new([seed[start], seed[start + 1], seed[start + 2], seed[start + 3]]);

    let mut v: Zeroizing<u32> = Zeroizing::new(u32::from_le_bytes(*chunk));

    let w1: Zeroizing<usize> = Zeroizing::new((*v % n) as usize);
    *v /= n;

    let w2_raw: Zeroizing<usize> = Zeroizing::new((*v % n) as usize);
    *v /= n;

    let w3_raw: Zeroizing<usize> = Zeroizing::new((*v % n) as usize);

    let w2: Zeroizing<usize> = Zeroizing::new(((*w2_raw as u32 + *w1 as u32) % n) as usize);
    let w3: Zeroizing<usize> = Zeroizing::new(((*w3_raw as u32 + *w2 as u32) % n) as usize);

    words.push(wordlist[*w1].to_string());
    words.push(wordlist[*w2].to_string());
    words.push(wordlist[*w3].to_string());

    checksum_input.push_str(&wordlist[*w1][..MONERO_PREFIX_LEN]);
    checksum_input.push_str(&wordlist[*w2][..MONERO_PREFIX_LEN]);
    checksum_input.push_str(&wordlist[*w3][..MONERO_PREFIX_LEN]);
  }

  let mut hasher = Crc32::new();
  hasher.update(checksum_input.as_bytes());

  let crc: Zeroizing<u32> = Zeroizing::new(hasher.finalize());
  let checksum_index: Zeroizing<usize> = Zeroizing::new((*crc % 24) as usize);
  let idx: Zeroizing<usize> = Zeroizing::new(*checksum_index);
  let checksum_word: Zeroizing<String> = Zeroizing::new(words[*idx].clone());

  words.push(checksum_word.to_string());

  Ok(Zeroizing::new(words.join(" ")))
}

pub fn monero_sc_reduce32(bytes: Zeroizing<[u8; 32]>) -> FunctionOutput<Zeroizing<Scalar>> {
  Ok(Zeroizing::new(Scalar::from_bytes_mod_order(*bytes)))
}

pub fn cn_fast_hash(data: &Zeroizing<Vec<u8>>) -> FunctionOutput<Zeroizing<[u8; 32]>> {
  let mut hasher = Keccak256::new();
  hasher.update(&**data);

  Ok(Zeroizing::new(hasher.finalize().into()))
}

pub fn monero_pubkey(priv_bytes: Zeroizing<[u8; 32]>) -> FunctionOutput<Zeroizing<[u8; 32]>> {
  let scalar: Zeroizing<Scalar> = Zeroizing::new(Scalar::from_bytes_mod_order(*priv_bytes));
  let pubkey: Zeroizing<[u8; 32]> = Zeroizing::new((ED25519_BASEPOINT_POINT * *scalar).compress().to_bytes());

  Ok(pubkey)
}

pub fn generate_monero_address(
  spend_pub: Zeroizing<[u8; 32]>,
  view_pub: Zeroizing<[u8; 32]>,
) -> FunctionOutput<Zeroizing<String>> {
  let mut data: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(69));
  data.push(0x12); // Monero mainnet

  data.extend_from_slice(&*spend_pub);
  data.extend_from_slice(&*view_pub);

  let checksum: Zeroizing<[u8; 32]> = cn_fast_hash(&data)?;
  data.extend_from_slice(&checksum[..4]);

  let address: Zeroizing<String> = match base58_monero::encode(&data) {
    Ok(addr) => Zeroizing::new(addr),
    Err(err) => {
      return Err(AppError::log(format!("Problem with Monero base58 encoding: {:?}", err)));
    }
  };

  Ok(address)
}

pub fn monero_subaddress_keys(
  spend_priv: Zeroizing<[u8; 32]>,
  view_priv: Zeroizing<[u8; 32]>,
  major: Zeroizing<u32>,
  minor: Zeroizing<u32>,
) -> FunctionOutput<MoneroKeys> {
  let mut data = Zeroizing::new(Vec::with_capacity(8 + 32 + 4 + 4));
  data.extend_from_slice(b"SubAddr\0");
  data.extend_from_slice(&*view_priv);
  data.extend_from_slice(&major.to_le_bytes());
  data.extend_from_slice(&minor.to_le_bytes());

  let m_hash: Zeroizing<[u8; 32]> = cn_fast_hash(&data)?;
  let m: Zeroizing<Scalar> = Zeroizing::new(Scalar::from_bytes_mod_order(*m_hash));

  let spend_scalar: Zeroizing<Scalar> = Zeroizing::new(Scalar::from_bytes_mod_order(*spend_priv));
  let view_scalar: Zeroizing<Scalar> = Zeroizing::new(Scalar::from_bytes_mod_order(*view_priv));
  let spend_pub: Zeroizing<[u8; 32]> = monero_pubkey(spend_priv.clone())?;

  let d_point: Zeroizing<EdwardsPoint> = {
    let decompressed = match curve25519_dalek::edwards::CompressedEdwardsY(*spend_pub).decompress() {
      Some(point) => point,
      None => {
        return Err(AppError::log("Failed to decompress Edwards point from spend_pub"));
      }
    };
    Zeroizing::new(ED25519_BASEPOINT_POINT * *m + decompressed)
  };

  let d: Zeroizing<[u8; 32]> = Zeroizing::new(d_point.compress().to_bytes());

  let c_point: Zeroizing<EdwardsPoint> = Zeroizing::new(*d_point * *view_scalar);
  let c: Zeroizing<[u8; 32]> = Zeroizing::new(c_point.compress().to_bytes());

  let sub_spend_priv: Zeroizing<[u8; 32]> = Zeroizing::new((*spend_scalar + *m).to_bytes());
  let sub_view_priv: Zeroizing<[u8; 32]> = view_priv;

  Ok((sub_spend_priv, sub_view_priv, d, c))
}

pub fn generate_monero_subaddress(
  spend_pub: Zeroizing<[u8; 32]>,
  view_pub: Zeroizing<[u8; 32]>,
) -> FunctionOutput<Zeroizing<String>> {
  let mut data: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(69));
  data.push(0x2A);

  data.extend_from_slice(&*spend_pub);
  data.extend_from_slice(&*view_pub);

  let checksum: Zeroizing<[u8; 32]> = cn_fast_hash(&data)?;
  data.extend_from_slice(&checksum[..4]);

  let address: Zeroizing<String> = match base58_monero::encode(&data) {
    Ok(addr) => Zeroizing::new(addr),
    Err(err) => {
      return Err(AppError::log(format!("Problem with Monero base58 encoding: {:?}", err)));
    }
  };

  Ok(address)
}

//                                   NANO (XNO)
// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

pub fn generate_nano_public_key(private_key: &Zeroizing<[u8; 32]>) -> FunctionOutput<Zeroizing<[u8; 32]>> {
  let mut hasher = Blake2b512::new();
  hasher.update(private_key.as_ref());
  let hash = hasher.finalize();

  let mut scalar_bytes: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
  scalar_bytes.copy_from_slice(&hash[..32]);

  scalar_bytes[0] &= 248;
  scalar_bytes[31] &= 63;
  scalar_bytes[31] |= 64;

  let scalar: Zeroizing<Scalar> = Zeroizing::new(Scalar::from_bytes_mod_order(*scalar_bytes));
  let point: Zeroizing<EdwardsPoint> = Zeroizing::new(&*scalar * ED25519_BASEPOINT_TABLE);
  let public_key: Zeroizing<[u8; 32]> = Zeroizing::new(point.compress().to_bytes());

  Ok(public_key)
}

fn nano_base32_encode(data: &[u8]) -> FunctionOutput<Zeroizing<String>> {
  let mut bits: Vec<bool> = Vec::with_capacity(data.len() * 8);

  for &byte in data {
    for i in (0..8).rev() {
      bits.push((byte >> i) & 1 == 1);
    }
  }

  if data.len() == 32 {
    bits.splice(0..0, std::iter::repeat_n(false, 4));
  }

  let mut result: Zeroizing<String> = Zeroizing::new(String::with_capacity(bits.len().div_ceil(5)));

  for chunk in bits.chunks(5) {
    let mut value = 0u8;
    for (i, &bit) in chunk.iter().enumerate() {
      if bit {
        value |= 1 << (4 - i);
      }
    }
    result.push(NANO_ALPHABET[value as usize] as char);
  }

  Ok(result)
}

pub fn generate_nano_address(public_key: &Zeroizing<Vec<u8>>) -> FunctionOutput<Zeroizing<String>> {
  if public_key.len() != 32 {
    return Err(AppError::log(format!("Nano public key must be 32 bytes, got {}", public_key.len())));
  }

  let mut hasher = blake2::Blake2b::<U5>::new();
  hasher.update(public_key.as_slice());
  let checksum = hasher.finalize();

  let mut reversed_checksum: Zeroizing<Vec<u8>> = Zeroizing::new(checksum.to_vec());
  reversed_checksum.reverse();

  let encoded_pubkey: Zeroizing<String> = nano_base32_encode(public_key.as_slice())?;
  let encoded_checksum: Zeroizing<String> = nano_base32_encode(&reversed_checksum)?;

  let address: Zeroizing<String> = Zeroizing::new(format!("nano_{}{}", *encoded_pubkey, *encoded_checksum));

  Ok(address)
}

//                                Cardano (ADA)
// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

fn blake2b_224(input: Zeroizing<Vec<u8>>) -> FunctionOutput<Zeroizing<Vec<u8>>> {
  let hash = Params::new().hash_length(28).to_state().update(&input).finalize();

  let output: Zeroizing<Vec<u8>> = Zeroizing::new(hash.as_bytes().to_vec());

  Ok(output)
}

fn derive_child(
  prv: &XPrv,
  index: u32,
  hardened: bool,
) -> XPrv {
  let idx = if hardened { index | 0x8000_0000 } else { index };

  prv.derive(DerivationScheme::V2, idx)
}

pub fn derive_payment_and_stake_xpubs_from_seed(wallet: &mut CryptoWallet) -> FunctionOutput<(XPub, XPub)> {
  let entropy: Zeroizing<Vec<u8>> = binary_string_to_bytes(wallet.seed_secret.raw_entropy.clone()).unwrap();
  let master = xprv_from_entropy(entropy).unwrap();

  let account = *wallet.address_components.derivation_path.account;
  let address_index = *wallet.address_components.derivation_path.address;

  // m / 1852' / 1815' / account'
  let purpose = derive_child(&master, 1852, true);
  let coin = derive_child(&purpose, 1815, true);
  let account_prv = derive_child(&coin, account, true);

  // payment: role 0 / address_index
  let pay_role = derive_child(&account_prv, 0, false);
  let pay_prv = derive_child(&pay_role, address_index, wallet.wallet_data.hardened_address);
  let pay_xpub = pay_prv.public();

  // stake: role 2 / 0
  let stake_role = derive_child(&account_prv, 2, false);
  let stake_prv = derive_child(&stake_role, 0, false);
  let stake_xpub = stake_prv.public();

  // let pay_xprv_bytes = pay_prv.as_ref(); // &[u8; 96]
  // let pay_xpub_bytes = pay_xpub.as_ref(); // &[u8; 64]
  // let stake_xprv_bytes = stake_prv.as_ref();
  // let stake_xpub_bytes = stake_xpub.as_ref();

  wallet.secret_keys.cardano_keys.payment_private_key = Zeroizing::new(hex::encode(&pay_prv.as_ref()[..64])); // 64-byte extended secret
  wallet.secret_keys.cardano_keys.payment_chain_code = Zeroizing::new(hex::encode(&pay_prv.as_ref()[64..])); // 32-byte chain code
  wallet.secret_keys.cardano_keys.payment_public_key = Zeroizing::new(hex::encode(&pay_xpub.as_ref()[..32])); // 32-byte public key

  wallet.secret_keys.cardano_keys.stake_private_key = Zeroizing::new(hex::encode(&stake_prv.as_ref()[..64]));
  wallet.secret_keys.cardano_keys.stake_chain_code = Zeroizing::new(hex::encode(&stake_prv.as_ref()[64..]));
  wallet.secret_keys.cardano_keys.stake_public_key = Zeroizing::new(hex::encode(&stake_xpub.as_ref()[..32]));

  Ok((pay_xpub, stake_xpub))
}

pub fn build_shelley_base_address_from_xpubs(
  payment_xpub: &XPub,
  stake_xpub: &XPub,
) -> FunctionOutput<Zeroizing<String>> {
  let payment_pub: Zeroizing<Vec<u8>> = Zeroizing::new(payment_xpub.as_ref()[..32].into());
  let stake_pub: Zeroizing<Vec<u8>> = Zeroizing::new(stake_xpub.as_ref()[..32].into());

  let payment_hash: Zeroizing<Vec<u8>> = match blake2b_224(payment_pub.clone()) {
    Ok(hash) => hash,
    Err(err) => {
      return Err(AppError::log(format!("Problem with blake2b_224 for payment key: {}", err)));
    }
  };

  let stake_hash: Zeroizing<Vec<u8>> = match blake2b_224(stake_pub.clone()) {
    Ok(hash) => hash,
    Err(err) => {
      return Err(AppError::log(format!("Problem with blake2b_224 for stake key: {}", err)));
    }
  };

  let header: u8 = 0x01;

  let mut payload: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(57));
  payload.push(header);
  payload.extend_from_slice(&payment_hash);
  payload.extend_from_slice(&stake_hash);

  let hrp = Hrp::parse("addr").unwrap();
  let address: Zeroizing<String> = Zeroizing::new(encode::<Bech32>(hrp, &payload).unwrap());

  Ok(address)
}

pub fn derive_cardano_address_from_seed_bytes(wallet: &mut CryptoWallet) -> FunctionOutput<Zeroizing<String>> {
  let (pay, stake) = derive_payment_and_stake_xpubs_from_seed(wallet).unwrap();

  let address: Zeroizing<String> = match build_shelley_base_address_from_xpubs(&pay, &stake) {
    Ok(address) => address,
    Err(err) => return Err(AppError::log(format!("Problem with building shelly base address from xpubs: {}", err))),
  };

  let path = get_derivation_path("bip32-ed25519", wallet).unwrap();

  let public_keys_str: Zeroizing<String> = Zeroizing::new(format!(
    "payment: {}\nstake: {}",
    *wallet.secret_keys.cardano_keys.payment_public_key.clone(),
    *wallet.secret_keys.cardano_keys.stake_public_key.clone()
  ));

  let private_keys_str: Zeroizing<String> = Zeroizing::new(format!(
    "payment: {}\nstake: {}",
    *wallet.secret_keys.cardano_keys.payment_private_key.clone(),
    *wallet.secret_keys.cardano_keys.stake_private_key.clone()
  ));

  wallet
    .addresses_by_coin
    .0
    .entry("Cardano".to_string())
    .or_default()
    .push(AddressPrivateData {
      coin_index: Zeroizing::new(1815_u32),
      symbol: Zeroizing::new(String::from("ADA")),
      path,
      address: Zeroizing::new(address.clone().to_string()),
      public_key: public_keys_str,
      private_key: private_keys_str,
    });

  Ok(address)
}

fn xprv_from_entropy(entropy: Zeroizing<Vec<u8>>) -> FunctionOutput<XPrv> {
  let mut data: Zeroizing<[u8; 96]> = Zeroizing::new([0u8; 96]);
  let iters = NonZeroU32::new(4096).unwrap();

  pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA512, iters, &entropy, b"", &mut *data);

  data[0] &= 0xf8;
  data[31] &= 0x1f;
  data[31] |= 0x40;

  let mut private_key: Zeroizing<[u8; 64]> = Zeroizing::new([0u8; 64]);
  let mut chain_code: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);

  private_key.copy_from_slice(&data[..64]);
  chain_code.copy_from_slice(&data[64..]);

  Ok(XPrv::from_extended_and_chaincode(&private_key, &chain_code))
}

fn binary_string_to_bytes(bits: Zeroizing<String>) -> FunctionOutput<Zeroizing<Vec<u8>>> {
  if bits.is_empty() || !bits.len().is_multiple_of(8) {
    return Err(AppError::log("Binary string length must be a multiple of 8".to_string()));
  }

  let mut bytes: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(bits.len() / 8));
  for chunk in bits.as_bytes().chunks(8) {
    let mut byte = 0u8;
    for (i, &b) in chunk.iter().enumerate() {
      match b {
        b'1' => byte |= 1 << (7 - i),
        b'0' => {}
        _ => return Err(AppError::log(format!("Invalid bit character: {}", b as char))),
      }
    }
    bytes.push(byte);
  }

  Ok(bytes)
}

//                                Algorand (ALGO)
// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

pub fn generate_algorand_address(pubkey: Zeroizing<Vec<u8>>) -> FunctionOutput<Zeroizing<String>> {
  use sha2::{Digest, Sha512_256};

  if pubkey.len() != 32 {
    return Err(AppError::log(format!("Algorand public key must be 32 bytes, got {}", pubkey.len())));
  }

  let mut hasher = Sha512_256::new();
  hasher.update(&pubkey);
  let hash = hasher.finalize(); // 32 bytes
  let checksum: Zeroizing<[u8; 4]> = Zeroizing::new(
    hash[28..32]
      .try_into()
      .map_err(|_| AppError::log("Failed to extract checksum".to_string()))?,
  );

  let mut payload: Zeroizing<[u8; 36]> = Zeroizing::new([0u8; 36]);
  payload[..32].copy_from_slice(&pubkey);
  payload[32..].copy_from_slice(&*checksum);

  let address = Zeroizing::new(base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &*payload));
  // let address = address.trim_end_matches('=').to_string();

  if address.len() != 58 {
    return Err(AppError::log(format!("Unexpected Algorand address length: {}", address.len())));
  }

  Ok(address)
}

//                                Polkadot (DOT)
// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

fn get_sr25519_account_path(full_derivation_path: Zeroizing<String>) -> FunctionOutput<Zeroizing<String>> {
  let path = full_derivation_path.trim();
  if path.is_empty() {
    return Err(AppError::log("sr25519 derivation path cannot be empty".to_string()));
  }

  let path_without_m = path.strip_prefix("m/").or_else(|| path.strip_prefix("M/")).unwrap_or(path);

  let components: Vec<&str> = path_without_m.split('/').filter(|c| !c.is_empty()).collect();

  if components.len() < 3 {
    return Err(AppError::log(format!(
      "sr25519 derivation path '{}' does not contain enough components for an account path",
      *full_derivation_path
    )));
  }

  let account_components = &components[..components.len() - 1];
  if account_components.is_empty() {
    return Err(AppError::log(format!(
      "Unable to determine sr25519 account path from '{}'",
      *full_derivation_path
    )));
  }

  let mut account_path = String::from("m/");
  account_path.push_str(&account_components.join("/"));
  Ok(Zeroizing::new(account_path))
}

pub fn get_sr25519_pair_for_path(
  wallet: &CryptoWallet,
  derivation_path: &str,
) -> FunctionOutput<(sr25519::Pair, Zeroizing<Vec<u8>>)> {
  let master_private_key: Zeroizing<Vec<u8>> = wallet.secret_keys.master_sr25519_keys.master_private_key_bytes.clone();

  if master_private_key.len() != 32 {
    return Err(AppError::log(format!(
      "sr25519 master seed must be 32 bytes, got {}",
      master_private_key.len()
    )));
  }

  let master_seed: Zeroizing<[u8; 32]> = Zeroizing::new(
    master_private_key
      .as_slice()
      .try_into()
      .map_err(|_| AppError::log("Failed to convert sr25519 master seed to [u8; 32]".to_string()))?,
  );

  let master_pair = sr25519::Pair::from_seed(&master_seed);
  let junctions = parse_sr25519_hardened_path(derivation_path)?;

  let (child_pair, child_seed) = master_pair
    .derive(junctions.into_iter(), Some(*master_seed))
    .map_err(|err| AppError::log(format!("Failed to derive sr25519 path '{}': {:?}", derivation_path, err)))?;

  let child_seed: Zeroizing<Vec<u8>> = Zeroizing::new(
    child_seed
      .ok_or_else(|| AppError::log(format!("sr25519 derivation '{}' did not return a child seed", derivation_path)))?
      .to_vec(),
  );

  Ok((child_pair, child_seed))
}

fn get_sr25519_address_pair_for_index(
  wallet: &CryptoWallet,
  address_index: u32,
) -> FunctionOutput<(sr25519::Pair, Zeroizing<Vec<u8>>)> {
  let child_master_private_key: Zeroizing<Vec<u8>> = wallet.secret_keys.child_sr25519_keys.child_private_key_bytes.clone();

  if child_master_private_key.len() != 32 {
    return Err(AppError::log(format!(
      "sr25519 child master seed must be 32 bytes, got {}",
      child_master_private_key.len()
    )));
  }

  let child_master_seed: Zeroizing<[u8; 32]> = Zeroizing::new(
    child_master_private_key
      .as_slice()
      .try_into()
      .map_err(|_| AppError::log("Failed to convert sr25519 child master seed to [u8; 32]".to_string()))?,
  );

  let child_master_pair = sr25519::Pair::from_seed(&child_master_seed);
  let junction = sp_core::crypto::DeriveJunction::hard(address_index);

  let (address_pair, address_seed) = child_master_pair
    .derive(std::iter::once(junction), Some(*child_master_seed))
    .map_err(|err| AppError::log(format!("Failed to derive sr25519 address index {}: {:?}", address_index, err)))?;

  let address_seed: Zeroizing<Vec<u8>> = Zeroizing::new(
    address_seed
      .ok_or_else(|| {
        AppError::log(format!(
          "sr25519 address derivation for index {} did not return a child seed",
          address_index
        ))
      })?
      .to_vec(),
  );

  Ok((address_pair, address_seed))
}

pub fn generate_sr25519_address(wallet: &mut CryptoWallet) -> FunctionOutput<Zeroizing<String>> {
  if wallet.secret_keys.child_sr25519_keys.child_private_key_bytes.is_empty() {
    generate_sr25519_child_keys(wallet)?;
  }

  let full_derivation_path: Zeroizing<String> = get_derivation_path("sr25519", wallet)?;
  let address_index: Zeroizing<u32> = wallet.address_components.derivation_path.address.clone();
  let address_path: Zeroizing<String> = Zeroizing::new(full_derivation_path.to_string());

  let (pair, address_seed) = get_sr25519_address_pair_for_index(wallet, *address_index)?;
  let public_key = pair.public();

  let ss58_prefix: u16 = wallet.address_components.wallet_import_format.parse().unwrap_or(0);
  let address: Zeroizing<String> = Zeroizing::new(public_key.to_ss58check_with_version(sp_core::crypto::Ss58AddressFormat::custom(ss58_prefix)));
  let coin_index: Zeroizing<u32> = wallet.address_components.derivation_path.coin.clone();
  let symbol: Zeroizing<String> = wallet.address_components.symbol.clone();

  wallet
    .addresses_by_coin
    .0
    .entry(wallet.address_components.coin_name.to_string())
    .or_default()
    .push(AddressPrivateData {
      coin_index,
      symbol,
      path: address_path,
      address: address.clone(),
      public_key: Zeroizing::new(hex::encode(public_key)),
      private_key: Zeroizing::new(hex::encode(address_seed.as_slice())),
    });

  Ok(address)
}

fn parse_sr25519_hardened_path(path: &str) -> FunctionOutput<Vec<DeriveJunction>> {
  let path = path.trim();

  if path.is_empty() {
    return Err(AppError::log("sr25519 derivation path cannot be empty".to_string()));
  }

  let path = path.strip_prefix("m/").or_else(|| path.strip_prefix("M/")).unwrap_or(path);

  if path.is_empty() {
    return Err(AppError::log("sr25519 derivation path contains no components".to_string()));
  }

  let components: Vec<&str> = path.split('/').collect();
  parse_sr25519_hardened_components(&components)
}

fn parse_sr25519_hardened_components(components: &[&str]) -> FunctionOutput<Vec<DeriveJunction>> {
  let mut junctions = Vec::with_capacity(components.len());

  for component in components {
    let component = component.trim();
    if component.is_empty() {
      return Err(AppError::log("sr25519 derivation path contains an empty component".to_string()));
    }

    if !component.ends_with('\'') {
      return Err(AppError::log(format!(
        "sr25519 derivation component '{}' must be hardened (example: 44')",
        component
      )));
    }

    let number = &component[..component.len() - 1];
    if number.is_empty() {
      return Err(AppError::log("sr25519 derivation path contains an empty hardened index".to_string()));
    }

    let index: u32 = number
      .parse()
      .map_err(|_| AppError::log(format!("Invalid sr25519 hardened derivation index '{}'", number)))?;

    junctions.push(sp_core::crypto::DeriveJunction::hard(index));
  }

  Ok(junctions)
}
