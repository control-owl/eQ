// authors = ["Control Owl <eq[at]r-o0-t[dot]wtf>"]
// license = "CC-BY-NC-ND-4.0  [2023-2026]  Control Owl"

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

use crate::{
  AddressPrivateData, AppError, ChildEd25519KeySecretData, ChildSecp256k1KeySecretData,
  CryptoPublicKey, CryptoWallet, FunctionOutput, MnemonicLanguage, Zeroizing,
};
use base32::Alphabet;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bech32::{Bech32, Hrp, encode, segwit};
use curve25519_dalek::Scalar;
use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, edwards::EdwardsPoint};
use ed25519_dalek::SigningKey;
use num_bigint::BigUint;
use ring::pbkdf2;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use std::io::BufRead;
use tiny_keccak::{Hasher, Keccak};
use zeroize::Zeroize;

const WALLET_MAX_ADDRESSES: u32 = 2_147_483_647;
const MNEMONIC_PASSPHRASE_LENGTH: u32 = 128;

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

      let entropy_checksum: Zeroizing<String> =
        e_q::calculate_checksum_for_entropy(raw_entropy.clone());
      wallet.seed_secret.entropy_checksum = entropy_checksum.clone();

      full_entropy = Zeroizing::new(format!("{}{}", *raw_entropy, *entropy_checksum));
      wallet.seed_secret.full_entropy = full_entropy.clone();

      mnemonic_dictionary = wallet.seed_secret.mnemonic_dictionary.clone();
    }
    "RNG" => {
      let entropy_length: Zeroizing<usize> = wallet.seed_secret.entropy_length.clone();
      mnemonic_dictionary = wallet.seed_secret.mnemonic_dictionary.clone();

      let raw_entropy: Zeroizing<String> =
        generate_raw_entropy(entropy_source.clone(), Some(entropy_length))?;
      wallet.seed_secret.raw_entropy = raw_entropy.clone();

      let entropy_checksum: Zeroizing<String> =
        e_q::calculate_checksum_for_entropy(raw_entropy.clone());
      wallet.seed_secret.entropy_checksum = entropy_checksum.clone();

      full_entropy = Zeroizing::new(format!("{}{}", *raw_entropy, *entropy_checksum));
      wallet.seed_secret.full_entropy = full_entropy.clone();
    }
    _ => {
      return Err(AppError::log(format!(
        "Unknown entropy source: {:?}",
        entropy_source
      )));
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

  let mnemonic_words: Zeroizing<String> =
    match generate_mnemonic_words(full_entropy.clone(), mnemonic_dictionary) {
      Ok(words) => words,
      Err(err) => {
        return Err(AppError::log(format!(
          "Problem with generating mnemonic words: {}",
          err
        )));
      }
    };

  let salt: Zeroizing<String> = Zeroizing::new(format!(
    "mnemonic{}",
    *wallet.seed_secret.mnemonic_passphrase
  ));
  let mut seed: Zeroizing<[u8; 64]> = Zeroizing::new([0u8; 64]);

  let iter = match std::num::NonZeroU32::new(2048) {
    Some(number) => number,
    _ => {
      return Err(AppError::log(String::from("Problem with pbkdf2 iter")));
    }
  };

  pbkdf2::derive(
    pbkdf2::PBKDF2_HMAC_SHA512,
    iter,
    salt.as_bytes(),
    mnemonic_words.as_bytes(),
    &mut *seed,
  );

  let seed_hex: Zeroizing<String> = Zeroizing::new(hex::encode(&seed[..]));

  wallet.seed_secret.mnemonic_words = mnemonic_words;
  wallet.seed_secret.seed = seed_hex;

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
      return Err(AppError::log(format!(
        "Can not generate raw entropy with getrandom: {:?}",
        err
      )));
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
      return Err(AppError::log(format!(
        "Can not generate raw mnemonic passphrase getrandom: {:?}",
        err
      )));
    }
  }
  let mut result = Zeroizing::new(String::with_capacity(length));
  let mut i = 0;

  while result.len() < length {
    if i >= bytes.len() {
      match getrandom::fill(&mut bytes) {
        Ok(value) => value,
        Err(err) => {
          return Err(AppError::log(format!(
            "Can not generate raw mnemonic passphrase getrandom: {:?}",
            err
          )));
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

  let mnemonic_decimal: Zeroizing<Vec<u32>> = Zeroizing::new(
    chunks
      .iter()
      .map(|chunk| u32::from_str_radix(chunk, 2).unwrap())
      .collect(),
  );

  let dictionary_file = dictionary.filename();

  let wordlist_path = std::path::Path::new("wordlists").join(dictionary_file);
  let wordlist_location: Zeroizing<String> = match wordlist_path.to_str() {
    Some(path) => Zeroizing::new(path.to_string()),
    _ => {
      return Err(AppError::log(String::from(
        "Can not open/find mnemonic dictionary file",
      )));
    }
  };

  let wordlist: Zeroizing<String> = e_q::get_text_from_resources(wordlist_location);
  let mnemonic_words_vector: Zeroizing<Vec<String>> =
    Zeroizing::new(wordlist.lines().map(|line| line.to_string()).collect());
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

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

pub fn generate_secp256k1_master_keys(wallet: &mut CryptoWallet) -> FunctionOutput<()> {
  let private_header: Zeroizing<String> = Zeroizing::new(String::from("0x0488ADE4"));
  let public_header: Zeroizing<String> = Zeroizing::new(String::from("0x0488B21E"));
  let seed: Zeroizing<String> = wallet.seed_secret.seed.clone();

  let private_header: Zeroizing<u32> =
    match u32::from_str_radix(private_header.trim_start_matches("0x"), 16) {
      Ok(value) => Zeroizing::new(value),
      Err(err) => {
        return Err(AppError::log(format!(
          "Parse error: Problem with parsing private_header: {:?}",
          err
        )));
      }
    };

  let public_header: Zeroizing<u32> =
    match u32::from_str_radix(public_header.trim_start_matches("0x"), 16) {
      Ok(value) => Zeroizing::new(value),
      Err(err) => {
        return Err(AppError::log(format!(
          "Parsing error: Problem with parsing public_header: {:?}",
          err
        )));
      }
    };

  let seed_bytes: Zeroizing<Vec<u8>> = match hex::decode(seed) {
    Ok(bytes) => Zeroizing::new(bytes),
    Err(err) => {
      return Err(AppError::log(format!(
        "Problem with decoding seed_bytes: {}",
        err
      )));
    }
  };

  let message: Zeroizing<Vec<u8>> =
    Zeroizing::new(String::from("Bitcoin seed").as_bytes().to_vec());
  let hmac_result: Zeroizing<Vec<u8>> = e_q::calculate_hmac_sha512_hash(message, seed_bytes);
  let master_private_key_bytes: Zeroizing<Vec<u8>> =
    Zeroizing::new(hmac_result.split_at(32).0.to_vec());
  let master_chain_code_bytes: Zeroizing<Vec<u8>> =
    Zeroizing::new(hmac_result.split_at(32).1.to_vec());

  let mut master_private_key: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
  master_private_key.extend_from_slice(&u32::to_be_bytes(*private_header));
  master_private_key.push(0x00);
  master_private_key.extend([0x00; 4].iter());
  master_private_key.extend([0x00; 4].iter());
  master_private_key.extend_from_slice(master_chain_code_bytes.as_slice());
  master_private_key.push(0x00);
  master_private_key.extend_from_slice(master_private_key_bytes.as_slice());

  let checksum: Zeroizing<[u8; 4]> =
    e_q::calculate_checksum_for_master_keys(master_private_key.clone());
  master_private_key.extend_from_slice(&*checksum);

  let master_private_key_encoded: Zeroizing<String> =
    Zeroizing::new(bs58::encode(&master_private_key).into_string());

  let array: Zeroizing<[u8; 32]> = {
    if master_private_key_bytes.len() != 32 {
      return Err(AppError::log(String::from(
        "master_private_key_bytes must be 32 bytes",
      )));
    }

    let mut arr: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    arr.copy_from_slice(master_private_key_bytes.as_ref());

    Zeroizing::new(*arr)
  };

  let master_secret_key = secp256k1::SecretKey::from_byte_array(*array)
    .map_err(|err| AppError::log(format!("Invalid master_secret_key: {err:?}")))?;

  let secp = secp256k1::Secp256k1::new();

  let master_public_key_bytes: Zeroizing<[u8; 33]> =
    Zeroizing::new(secp256k1::PublicKey::from_secret_key(&secp, &master_secret_key).serialize());
  master_secret_key.secret_bytes().zeroize();

  let mut master_public_key: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());

  master_public_key.extend_from_slice(&u32::to_be_bytes(*public_header));
  master_public_key.push(0x00);
  master_public_key.extend([0x00; 4].iter());
  master_public_key.extend([0x00; 4].iter());
  master_public_key.extend_from_slice(&master_chain_code_bytes);
  master_public_key.extend_from_slice(&*master_public_key_bytes);

  let checksum: Zeroizing<[u8; 4]> =
    e_q::calculate_checksum_for_master_keys(master_public_key.clone());

  master_public_key.extend_from_slice(&*checksum);

  let master_public_key_encoded: Zeroizing<String> =
    Zeroizing::new(bs58::encode(&master_public_key).into_string());

  let master_chain_code_bytes: Zeroizing<[u8; 32]> = {
    if master_chain_code_bytes.len() != 32 {
      return Err(AppError::log(String::from(
        "master_chain_code_bytes must be 32 bytes",
      )));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(master_chain_code_bytes.as_ref());

    Zeroizing::new(arr)
  };

  let master_private_key_bytes: Zeroizing<[u8; 32]> = {
    if master_private_key_bytes.len() != 32 {
      return Err(AppError::log(String::from(
        "master_private_key_bytes must be 32 bytes",
      )));
    }

    let mut arr: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    arr.copy_from_slice(master_private_key_bytes.as_ref());

    arr
  };

  wallet
    .secret_keys
    .master_secp256k1_keys
    .master_private_key_encoded = master_private_key_encoded;
  wallet
    .secret_keys
    .master_secp256k1_keys
    .master_private_key_bytes = Zeroizing::new(master_private_key_bytes.to_vec());
  wallet
    .secret_keys
    .master_secp256k1_keys
    .master_public_key_encoded = master_public_key_encoded;
  wallet
    .secret_keys
    .master_secp256k1_keys
    .master_public_key_bytes = Zeroizing::new(master_public_key_bytes.to_vec());
  wallet
    .secret_keys
    .master_secp256k1_keys
    .master_chain_code_bytes = Zeroizing::new(master_chain_code_bytes.to_vec());

  Ok(())
}

pub fn generate_secp256k1_child_keys(wallet: &mut CryptoWallet) -> FunctionOutput<()> {
  let mut private_key: Zeroizing<Vec<u8>> = Zeroizing::new(
    wallet
      .secret_keys
      .master_secp256k1_keys
      .master_private_key_bytes
      .to_vec(),
  );
  let mut chain_code: Zeroizing<Vec<u8>> = Zeroizing::new(
    wallet
      .secret_keys
      .master_secp256k1_keys
      .master_chain_code_bytes
      .to_vec(),
  );
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
        return Err(AppError::log(format!(
          "Parse error: Unable to parse index from path part: {:?}",
          err
        )));
      }
    };

    let derived_child_keys: Zeroizing<ChildSecp256k1KeySecretData> =
      match derive_secp256k1_child(private_key, chain_code, index, hardened) {
        Ok(keys) => Zeroizing::new(keys),
        Err(err) => {
          return Err(AppError::log(format!(
            "Problem with deriving child keys: {:?}",
            err
          )));
        }
      };

    private_key = Zeroizing::new(derived_child_keys.child_private_key_bytes.to_vec());
    chain_code = Zeroizing::new(derived_child_keys.child_chain_code_bytes.to_vec());
    public_key = Zeroizing::new(derived_child_keys.child_public_key_bytes.to_vec());
  }

  if chain_code.len() != 32 {
    return Err(AppError::log(format!(
      "Invalid chain code length {:?}",
      chain_code.len()
    )));
  }

  let array: Zeroizing<[u8; 32]> = Zeroizing::new(
    <[u8; 32]>::try_from(private_key.as_slice())
      .map_err(|err| AppError::log(format!("private_key must be 32 bytes {:?}", err)))?,
  );

  let secret_key = secp256k1::SecretKey::from_byte_array(*array)
    .map_err(|err| AppError::log(format!("Invalid secret_key: {:?}", err)))?;

  let mut chain_code_array: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
  chain_code_array.copy_from_slice(&chain_code);

  let mut public_key_array: Zeroizing<[u8; 33]> = Zeroizing::new([0u8; 33]);
  public_key_array.copy_from_slice(&public_key);

  wallet
    .secret_keys
    .child_secp256k1_keys
    .child_private_key_bytes = Zeroizing::new(secret_key.secret_bytes().to_vec());
  wallet
    .secret_keys
    .child_secp256k1_keys
    .child_public_key_bytes = Zeroizing::new(public_key_array.to_vec());
  wallet
    .secret_keys
    .child_secp256k1_keys
    .child_chain_code_bytes = Zeroizing::new(chain_code_array.to_vec());

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
    let array: Zeroizing<[u8; 32]> =
      Zeroizing::new(<[u8; 32]>::try_from(parent_key.as_slice()).map_err(|err| {
        AppError::log(format!(
          "Slice error: parent_key must be 32 bytes: {:?}",
          err
        ))
      })?);

    let parent_secret_key = secp256k1::SecretKey::from_byte_array(*array)
      .map_err(|err| AppError::log(format!("Invalid SecretKey: {err}")))?;
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

  let child_private_key_bytes: Zeroizing<[u8; 32]> =
    Zeroizing::new(result[..32].try_into().map_err(|err| {
      AppError::log(format!(
        "Slice with incorrect length for private key: {:?}",
        err
      ))
    })?);

  let combined_bytes_padded: Zeroizing<[u8; 32]> = {
    let curve_order = BigUint::from_bytes_be(&secp256k1::constants::CURVE_ORDER);
    let combined_int = (BigUint::from_bytes_be(&*child_private_key_bytes)
      + BigUint::from_bytes_be(&parent_key))
      % &curve_order;

    let combined_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(combined_int.to_bytes_be());
    let mut padded: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);

    let offset = 32 - combined_bytes.len();
    padded[offset..].copy_from_slice(&combined_bytes);

    padded
  };

  let child_private_key = secp256k1::SecretKey::from_byte_array(*combined_bytes_padded)
    .map_err(|err| AppError::log(format!("Invalid child_private_key: {err}")))?;
  let child_private_key_bytes: Zeroizing<Vec<u8>> =
    Zeroizing::new(child_private_key.secret_bytes().to_vec());

  let child_public_key_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(
    secp256k1::PublicKey::from_secret_key(&secp, &child_private_key)
      .serialize()
      .to_vec(),
  );

  Ok(ChildSecp256k1KeySecretData {
    child_private_key_bytes,
    child_chain_code_bytes: Zeroizing::new(result[32..].to_vec()),
    child_public_key_bytes,
  })
}

pub fn generate_secp256k1_address(wallet: &mut CryptoWallet) -> FunctionOutput<()> {
  let public_key: CryptoPublicKey = generate_public_key(wallet)?;

  let coin_index: Zeroizing<u32> = wallet.address_components.derivation_path.coin.clone();
  let coin_name: Zeroizing<String> = wallet.address_components.coin_name.clone();
  let public_key_hash: Zeroizing<String> = wallet.address_components.public_key_hash.clone();
  let hash: Zeroizing<String> = wallet.address_components.hash.clone();
  let key_derivation: Zeroizing<String> = wallet.address_components.key_derivation.clone();
  let wallet_import_format: Zeroizing<String> =
    wallet.address_components.wallet_import_format.clone();

  let child_private_key_bytes: Zeroizing<Vec<u8>> = wallet
    .secret_keys
    .child_secp256k1_keys
    .child_private_key_bytes
    .clone();

  let private_key: Zeroizing<[u8; 32]> = Zeroizing::new(
    child_private_key_bytes
      .as_slice()
      .try_into()
      .map_err(|err| {
        AppError::log(format!(
          "Slice error: Invalid private key length (expected 32 bytes): {:?}",
          err
        ))
      })?,
  );

  let derivation_path: Zeroizing<String> = match get_derivation_path("secp256k1", wallet) {
    Ok(path) => path,
    Err(err) => {
      return Err(AppError::log(format!(
        "Can not parse derivation path: {:?}",
        err
      )));
    }
  };

  match *coin_index {
    // Bitcoin: Legacy + Taproot addresses
    0 => {
      if !wallet.wallet_data.bitcoin_legacy_addresses {
        // if wallet.wallet_data.active_bip != 32 && !wallet.wallet_data.bitcoin_legacy_addresses {
        //   wallet.address_components.derivation_path.purpose = Zeroizing::new(86);
        // }

        return generate_bitcoin_taproot_address(
          wallet,
          &public_key,
          &derivation_path,
          private_key,
        );
      } else {
        wallet.address_components.derivation_path.purpose =
          Zeroizing::new(wallet.wallet_data.active_bip);

        let old_derivation_path: Zeroizing<String> = match get_derivation_path("secp256k1", wallet)
        {
          Ok(path) => path,
          Err(err) => {
            return Err(AppError::log(format!(
              "Can not parse derivation path: {:?}",
              err
            )));
          }
        };

        return generate_bitcoin_legacy_address(
          wallet,
          &public_key,
          &old_derivation_path,
          private_key,
        );
      }
    }

    // Cosmos Coin
    118 => {
      let secp_pubkey = match &public_key {
        CryptoPublicKey::Secp256k1(pk) => pk,
        _ => {
          return Err(AppError::log(String::from(
            "Only Secp256k1 for generating Secp256k1 addresses",
          )));
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

    _ => {}
  }

  let public_key_hash_vec: Zeroizing<Vec<u8>> = {
    let trimmed: Zeroizing<String> =
      Zeroizing::new(public_key_hash.trim_start_matches("0x").to_string());
    let hex: Zeroizing<Vec<u8>> = match hex::decode(trimmed) {
      Ok(hex) => Zeroizing::new(hex),
      Err(err) => return Err(AppError::log(format!("Invalid public_key_hash: {:?}", err))),
    };
    hex
  };

  let public_key_encoded: Zeroizing<String> =
    encode_public_key(hash.clone(), coin_index.clone(), &public_key)?;
  let address: Zeroizing<String> = generate_address_internal(
    hash.clone(),
    coin_index.clone(),
    &public_key,
    public_key_hash_vec,
  )?;
  let priv_key_wif: Zeroizing<String> = encode_private_key(
    key_derivation,
    wallet_import_format,
    hash,
    coin_index.clone(),
    private_key,
  )?;

  wallet
    .addresses_by_coin
    .0
    .entry(coin_name.to_string())
    .or_default()
    .push(AddressPrivateData {
      coin_index,
      path: derivation_path,
      address,
      public_key: public_key_encoded,
      private_key: priv_key_wif,
    });

  Ok(())
}

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..
// Zeroizing

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

      let secret_key = secp256k1::SecretKey::from_byte_array(*child_private_key)
        .map_err(|err| AppError::log(format!("Invalid SecretKey: {:?}", err)))?;
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
          use curve25519_dalek::{
            constants::ED25519_BASEPOINT_POINT, edwards::EdwardsPoint, scalar::Scalar,
          };
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

          let verifying_key = VerifyingKey::from_bytes(&pk_bytes)
            .map_err(|e| AppError::log(format!("Invalid NEM Ed25519 public key: {:?}", e)))?;
          Ok(CryptoPublicKey::Ed25519(verifying_key))
        }
        _ => {
          let signing_key = ed25519_dalek::SigningKey::from_bytes(&child_private_key);
          let verifying_key = signing_key.verifying_key();

          Ok(CryptoPublicKey::Ed25519(verifying_key))
        }
      }
    }
    _ => Err(AppError::log(format!(
      "Unsupported key derivation method: {:?}",
      key_derivation
    ))),
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
    // "ed25519" | "sha3-256" => match public_key {
    //   CryptoPublicKey::Ed25519(pk) => Ok(Zeroizing::new(bs58::encode(pk.to_bytes()).into_string())),
    //   _ => Err(AppError::log(format!("Problem with ed25519 public key and hash in encode_public_key: {:?}", hash))),
    // },
    _ => Err(AppError::log(format!(
      "Unsupported hash method: {:?}",
      hash
    ))),
  }
}

pub fn get_public_key(public_key: &CryptoPublicKey) -> FunctionOutput<Zeroizing<Vec<u8>>> {
  let public_key_bytes: Zeroizing<Vec<u8>> = match public_key {
    CryptoPublicKey::Secp256k1(key) => Zeroizing::new(key.serialize().to_vec()),
    CryptoPublicKey::Ed25519(key) => Zeroizing::new(key.to_bytes().to_vec()),
  };

  Ok(public_key_bytes)
}

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

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

      let address_checksum: Zeroizing<[u8; 4]> =
        Zeroizing::new(checksum[0..4].try_into().map_err(|err| {
          AppError::log(format!("Address checksum can not be calculated: {:?}", err))
        })?);

      extended_key.extend_from_slice(address_checksum.as_slice());

      Ok(Zeroizing::new(bs58::encode(extended_key).into_string()))
    }
    "keccak256" => {
      if let Some(private_key) = private_key {
        if *coin_index == 195 {
          Ok(Zeroizing::new(hex::encode(private_key.secret_bytes())))
        } else {
          Ok(Zeroizing::new(format!(
            "0x{}",
            hex::encode(private_key.secret_bytes())
          )))
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
    _ => Err(AppError::log(format!(
      "Unsupported hash method: {:?}",
      hash
    ))),
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
    Ok(Zeroizing::new(
      bs58::encode(private_key_bytes).into_string(),
    ))
  } else {
    let secret_key = secp256k1::SecretKey::from_byte_array(*private_key_bytes)
      .map_err(|err| AppError::log(format!("Invalid SecretKey: {:?}", err)))?;

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

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

fn generate_address_internal(
  hash: Zeroizing<String>,
  coin_index: Zeroizing<u32>,
  public_key: &CryptoPublicKey,
  public_key_hash_vec: Zeroizing<Vec<u8>>,
) -> FunctionOutput<Zeroizing<String>> {
  match hash.as_str() {
    "sha256" => generate_sha256_address(public_key, public_key_hash_vec),
    "keccak256" => generate_keccak256_address(public_key, public_key_hash_vec, coin_index),
    "sha256+ripemd160" => {
      generate_sha256_ripemd160_address(coin_index, public_key, public_key_hash_vec)
    }
    _ => Err(AppError::log(format!(
      "Unsupported hash method: {:?}",
      hash
    ))),
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

  let mut payload: Zeroizing<Vec<u8>> =
    Zeroizing::new(Vec::with_capacity(public_key_hash.len() + hash160.len()));
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

  let checksum: Zeroizing<Vec<u8>> =
    Zeroizing::new(Sha256::digest(Sha256::digest(&address_bytes))[..4].to_vec());

  let mut full_address_bytes: Zeroizing<Vec<u8>> = address_bytes.clone();
  full_address_bytes.extend_from_slice(&checksum);

  let alphabet = match *coin_index {
    144 => bs58::Alphabet::RIPPLE,
    _ => bs58::Alphabet::DEFAULT,
  };

  let encoded_address: Zeroizing<String> = Zeroizing::new(
    bs58::encode(full_address_bytes)
      .with_alphabet(alphabet)
      .into_string(),
  );

  Ok(encoded_address)
}

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

fn generate_atom_address(pub_compressed: Zeroizing<Vec<u8>>) -> FunctionOutput<Zeroizing<String>> {
  let hash20: Zeroizing<Vec<u8>> = e_q::calculate_sha256_and_ripemd160_hash(pub_compressed);

  let address: Zeroizing<String> =
    match bech32_encode::<Bech32>(Zeroizing::new(String::from("cosmos")), hash20) {
      Ok(address) => address,
      Err(err) => {
        return Err(AppError::log(format!(
          "Problem with bech32 encoding: {:?}",
          err
        )));
      }
    };

  Ok(address)
}

fn encode_cosmos_pubkey_bech32(
  pub_compressed: Zeroizing<Vec<u8>>
) -> FunctionOutput<Zeroizing<String>> {
  let prefix: Zeroizing<[u8; 5]> = Zeroizing::new([0xEB, 0x5A, 0xE9, 0x87, 0x21]);
  let mut data: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(38));

  data.extend_from_slice(&*prefix);
  data.extend_from_slice(&pub_compressed);

  let key: Zeroizing<String> =
    match bech32_encode::<Bech32>(Zeroizing::new(String::from("cosmospub")), data) {
      Ok(key) => key,
      Err(err) => {
        return Err(AppError::log(format!(
          "Problem with encoding public key with bech32: {:?}",
          err
        )));
      }
    };

  Ok(key)
}

fn bech32_encode<Checksum: bech32::Checksum>(
  hrp: Zeroizing<String>,
  data: Zeroizing<Vec<u8>>,
) -> FunctionOutput<Zeroizing<String>> {
  let hrp_parsed =
    Hrp::parse(&hrp).map_err(|err| AppError::log(format!("Invalid HRP '{:?}': {:?}", hrp, err)))?;

  let data: Zeroizing<String> = match encode::<Checksum>(hrp_parsed, &data) {
    Ok(data) => Zeroizing::new(data),
    Err(err) => {
      return Err(AppError::log(format!("Bech32 encode error: {:?}", err)));
    }
  };

  Ok(data)
}

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

pub fn generate_ed25519_master_keys(wallet: &mut CryptoWallet) -> FunctionOutput<()> {
  let seed: Zeroizing<String> = wallet.seed_secret.seed.clone();
  let message: Zeroizing<Vec<u8>> =
    Zeroizing::new(String::from("ed25519 seed").as_bytes().to_vec());

  let seed_bytes: Zeroizing<Vec<u8>> = match hex::decode(seed.clone()) {
    Ok(values) => Zeroizing::new(values),
    Err(err) => {
      return Err(AppError::log(format!(
        "Hex error: Can not decode seed: {}",
        err
      )));
    }
  };

  let result: Zeroizing<Vec<u8>> = e_q::calculate_hmac_sha512_hash(message, seed_bytes);
  if result.len() != 64 {
    return Err(AppError::log(String::from(
      "Wrong hash length output in calculate_hmac_sha512_hash",
    )));
  }

  let mut master_private_key: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
  master_private_key.copy_from_slice(&result[..32]);

  let mut master_chain_code: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
  master_chain_code.copy_from_slice(&result[32..]);

  let signing_key = SigningKey::from_bytes(&master_private_key);
  let public_key = signing_key.verifying_key();

  let master_xprv: Zeroizing<String> =
    Zeroizing::new(bs58::encode(&master_private_key).into_string());
  let master_xpub: Zeroizing<String> =
    Zeroizing::new(bs58::encode(&public_key.as_bytes()).into_string());

  wallet
    .secret_keys
    .master_ed25519_keys
    .master_private_key_bytes = Zeroizing::new(master_private_key.to_vec());
  wallet
    .secret_keys
    .master_ed25519_keys
    .master_public_key_bytes = Zeroizing::new(public_key.to_bytes().to_vec());
  wallet
    .secret_keys
    .master_ed25519_keys
    .master_chain_code_bytes = Zeroizing::new(master_chain_code.to_vec());
  wallet
    .secret_keys
    .master_ed25519_keys
    .master_private_key_encoded = master_xprv;
  wallet
    .secret_keys
    .master_ed25519_keys
    .master_public_key_encoded = master_xpub;

  Ok(())
}

pub fn generate_ed25519_child_keys(wallet: &mut CryptoWallet) -> FunctionOutput<()> {
  let master_key: Zeroizing<Vec<u8>> = Zeroizing::new(
    wallet
      .secret_keys
      .master_ed25519_keys
      .master_private_key_bytes
      .to_vec(),
  );
  let master_chain_code: Zeroizing<Vec<u8>> = Zeroizing::new(
    wallet
      .secret_keys
      .master_ed25519_keys
      .master_chain_code_bytes
      .to_vec(),
  );

  let derivation_path: Zeroizing<String> = match get_derivation_path("ed25519", wallet) {
    Ok(path) => path,
    Err(err) => {
      return Err(AppError::log(format!(
        "Can not parse derivation path: {:?}",
        err
      )));
    }
  };

  if master_key.len() != 32 {
    return Err(AppError::log(format!(
      "Master key must be 32 bytes, got {}",
      master_key.len()
    )));
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
    let index: Zeroizing<u32> = Zeroizing::new(index_str.parse().map_err(|err| {
      AppError::log(format!(
        "Parsing error. Invalid index: {:?}, Error: {:?}",
        index_str, err
      ))
    })?);

    let child_index: Zeroizing<u32> = if *hardened {
      (*index | 0x80000000).into()
    } else {
      index
    };
    let derived: Zeroizing<ChildEd25519KeySecretData> =
      Zeroizing::new(derive_ed25519_child(private_key, chain_code, child_index)?);

    private_key = derived.child_private_key_bytes.clone();
    chain_code = derived.child_chain_code_bytes.clone();
  }

  let mut master_key: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
  master_key.copy_from_slice(&private_key);

  let mut child_priv32 = Zeroizing::new([0u8; 32]);
  child_priv32.copy_from_slice(&private_key);

  let child_pub_bytes = if *coin_index == 43 {
    // NEM/NIS1
    nem_pubkey_from_child_priv(child_priv32)?.to_vec()
  } else {
    // RFC8032
    SigningKey::from_bytes(&child_priv32)
      .verifying_key()
      .to_bytes()
      .to_vec()
  };

  wallet
    .secret_keys
    .child_ed25519_keys
    .child_private_key_bytes = Zeroizing::new(private_key.to_vec());
  wallet.secret_keys.child_ed25519_keys.child_chain_code_bytes =
    Zeroizing::new(chain_code.to_vec());
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
    return Err(AppError::log(String::from(
      "Invalid parent_key or parent_chain_code length",
    )));
  }

  if *index < 0x80000000 {
    return Err(AppError::log(String::from(
      "Ed25519 only supports hardened derivation",
    )));
  }

  let data: Zeroizing<Vec<u8>> = Zeroizing::new(
    std::iter::once(prefix_byte)
      .chain(parent_key.iter().copied())
      .chain(index.to_be_bytes())
      .collect(),
  );

  let hmac: Zeroizing<Vec<u8>> = e_q::calculate_hmac_sha512_hash(parent_chain_code, data);

  if hmac.len() != 64 {
    return Err(AppError::log(
      "calculate_hmac_sha512_hash len is not 64".to_string(),
    ));
  }

  Ok(ChildEd25519KeySecretData {
    child_private_key_bytes: Zeroizing::new(hmac[..32].to_vec()),
    child_chain_code_bytes: Zeroizing::new(hmac[32..].to_vec()),
    child_public_key_bytes: Zeroizing::new(Vec::new()),
  })
}

pub fn generate_ed25519_address(wallet: &mut CryptoWallet) -> FunctionOutput<()> {
  let child_public_key_bytes: Zeroizing<Vec<u8>> = wallet
    .secret_keys
    .child_ed25519_keys
    .child_public_key_bytes
    .clone();
  let child_private_key_bytes: Zeroizing<Vec<u8>> = wallet
    .secret_keys
    .child_ed25519_keys
    .child_private_key_bytes
    .clone();
  let coin_index: Zeroizing<u32> = wallet.address_components.derivation_path.coin.clone();
  let coin_name: Zeroizing<String> = wallet.address_components.coin_name.clone();
  let pub_key_hash: Zeroizing<String> = wallet.address_components.public_key_hash.clone();

  let derivation_path: Zeroizing<String> = match get_derivation_path("ed25519", wallet) {
    Ok(path) => path,
    Err(err) => {
      return Err(AppError::log(format!(
        "Can not parse derivation path: {:?}",
        err
      )));
    }
  };

  let (address, public_key, private_key) = match *coin_index {
    501 => {
      let address = bs58::encode(child_public_key_bytes.clone()).into_string();
      (
        Zeroizing::new(address),
        Zeroizing::new(hex::encode(&child_public_key_bytes)),
        Zeroizing::new(hex::encode(&child_private_key_bytes)),
      )
    }
    43 => {
      let pubkey_array: Zeroizing<[u8; 32]> =
        Zeroizing::new(child_public_key_bytes.as_slice().try_into().unwrap());
      let address = generate_nem_address(pubkey_array, pub_key_hash)?;
      (
        address,
        Zeroizing::new(hex::encode(&child_public_key_bytes)),
        Zeroizing::new(hex::encode(&child_private_key_bytes)),
      )
    }
    _ => {
      return Err(AppError::log(format!(
        "Unsupported ed25519 coin_index: {:?}",
        coin_index
      )));
    }
  };

  wallet
    .addresses_by_coin
    .0
    .entry(coin_name.to_string())
    .or_default()
    .push(AddressPrivateData {
      coin_index,
      path: derivation_path,
      address,
      public_key,
      private_key,
    });

  Ok(())
}

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

pub fn get_derivation_path(
  curve: &str,
  wallet: &mut CryptoWallet,
) -> FunctionOutput<Zeroizing<String>> {
  let extra_hard = !matches!(curve, "secp256k1");

  let path = wallet.address_components.derivation_path.clone();

  let tap_bip = if *wallet.address_components.derivation_path.coin == 0
    && !wallet.wallet_data.bitcoin_legacy_addresses
  {
    Some(86)
  } else {
    None
  };

  let derivation_path: Zeroizing<String> = match *path.purpose {
    32 => Zeroizing::new(format!(
      "m/{}{}/{}{}/{}{}",
      *path.account,
      if *path.account_hardened || extra_hard {
        "'"
      } else {
        ""
      },
      *path.change,
      if *path.change_hardened || extra_hard {
        "'"
      } else {
        ""
      },
      *path.address,
      if *path.address_hardened || extra_hard {
        "'"
      } else {
        ""
      },
    )),
    _ => match curve {
      "secp256k1" => Zeroizing::new(format!(
        "m/{}{}/{}{}/{}{}/{}{}/{}{}",
        tap_bip.unwrap_or(*path.purpose),
        if *path.purpose_hardened || extra_hard {
          "'"
        } else {
          ""
        },
        *path.coin,
        if *path.coin_hardened || extra_hard {
          "'"
        } else {
          ""
        },
        *path.account,
        if *path.account_hardened || extra_hard {
          "'"
        } else {
          ""
        },
        *path.change,
        if *path.change_hardened || extra_hard {
          "'"
        } else {
          ""
        },
        *path.address,
        if *path.address_hardened || extra_hard {
          "'"
        } else {
          ""
        },
      )),
      _ => Zeroizing::new(format!(
        "m/{}{}/{}{}/{}{}/{}{}/{}{}",
        wallet.wallet_data.active_bip,
        if *path.purpose_hardened || extra_hard {
          "'"
        } else {
          ""
        },
        *path.coin,
        if *path.coin_hardened || extra_hard {
          "'"
        } else {
          ""
        },
        *path.account,
        if *path.account_hardened || extra_hard {
          "'"
        } else {
          ""
        },
        *path.change,
        if *path.change_hardened || extra_hard {
          "'"
        } else {
          ""
        },
        *path.address,
        if *path.address_hardened || extra_hard {
          "'"
        } else {
          ""
        },
      )),
    },
  };

  Ok(derivation_path)
}

pub fn generate_nem_address(
  pubkey_bytes: Zeroizing<[u8; 32]>,
  pub_key_hash: Zeroizing<String>,
) -> FunctionOutput<Zeroizing<String>> {
  let k256 = keccak256_nis1(Zeroizing::new(pubkey_bytes.to_vec()));
  let ripemd_hash = Ripemd160::digest(&k256);

  let trimmed = pub_key_hash.trim_start_matches("0x").to_lowercase();
  let version: u8 = u8::from_str_radix(&trimmed, 16)
    .map_err(|err| AppError::log(format!("Invalid public_key_hash hex: {:?}", err)))?;

  let mut payload = Zeroizing::new(Vec::new());
  payload.push(version);
  payload.extend_from_slice(&ripemd_hash);

  let checksum = keccak256_nis1(payload.clone());
  payload.extend_from_slice(&checksum[..4]);

  let b32 = base32::encode(Alphabet::Rfc4648 { padding: false }, &payload);
  let nem_address = b32
    .chars()
    .enumerate()
    .fold(String::new(), |mut acc, (i, c)| {
      if i > 0 && i % 6 == 0 {
        acc.push('-');
      }

      acc.push(c);

      acc
    });

  Ok(Zeroizing::new(nem_address))
}

fn nem_pubkey_from_child_priv(
  child_private_key: Zeroizing<[u8; 32]>
) -> FunctionOutput<Zeroizing<[u8; 32]>> {
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
    let trimmed: Zeroizing<String> =
      Zeroizing::new(public_key_hash.trim_start_matches("0x").to_string());
    let hex: Zeroizing<Vec<u8>> = match hex::decode(trimmed) {
      Ok(hex) => Zeroizing::new(hex),
      Err(err) => return Err(AppError::log(format!("Invalid public_key_hash: {:?}", err))),
    };
    hex
  };

  let public_key_encoded: Zeroizing<String> =
    encode_public_key(hash.clone(), coin_index.clone(), public_key)?;
  let address: Zeroizing<String> = generate_address_internal(
    hash.clone(),
    coin_index.clone(),
    public_key,
    public_key_hash_vec,
  )?;
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
      path: derivation_path.clone(),
      address: oa_colored_address,
      public_key: public_key_encoded,
      private_key: priv_key_wif,
    });

  Ok(())
}

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

fn encode_taproot_bech32m(tweaked_key: Zeroizing<[u8; 32]>) -> FunctionOutput<Zeroizing<String>> {
  let address = segwit::encode(
    Hrp::parse("bc").map_err(|e| AppError::log(format!("HRP error: {:?}", e)))?,
    segwit::VERSION_1,
    &*tweaked_key,
  )
  .map_err(|e| AppError::log(format!("Bech32m encoding failed: {:?}", e)))?;

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
  let internal_pubkey = secp256k1::XOnlyPublicKey::from_byte_array(*internal_key)
    .map_err(|e| AppError::log(format!("Invalid x-only public key: {}", e)))?;

  let tweak_scalar = secp256k1::Scalar::from_be_bytes(tweak.into())
    .map_err(|_| AppError::log("Invalid tweak scalar"))?;

  let tweaked = internal_pubkey
    .add_tweak(&secp, &tweak_scalar)
    .map_err(|e| AppError::log(format!("Taproot tweak failed: {}", e)))?;

  let serialized: Zeroizing<[u8; 32]> = Zeroizing::new(tweaked.0.serialize());

  Ok(serialized)
}

pub fn generate_bitcoin_legacy_address(
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
  let wallet_import_format: Zeroizing<String> =
    wallet.address_components.wallet_import_format.clone();

  let public_key_hash_vec: Zeroizing<Vec<u8>> = {
    let trimmed: Zeroizing<String> =
      Zeroizing::new(public_key_hash.trim_start_matches("0x").to_string());
    let hex: Zeroizing<Vec<u8>> = match hex::decode(trimmed) {
      Ok(hex) => Zeroizing::new(hex),
      Err(err) => return Err(AppError::log(format!("Invalid public_key_hash: {:?}", err))),
    };
    hex
  };

  let public_key_encoded: Zeroizing<String> =
    encode_public_key(hash.clone(), coin_index.clone(), public_key)?;

  let address: Zeroizing<String> = generate_address_internal(
    hash.clone(),
    coin_index.clone(),
    public_key,
    public_key_hash_vec,
  )?;

  let priv_key_wif: Zeroizing<String> = encode_private_key(
    key_derivation.clone(),
    wallet_import_format.clone(),
    hash.clone(),
    coin_index.clone(),
    private_key,
  )?;

  let new_address = AddressPrivateData {
    coin_index: coin_index.clone(),
    path: derivation_path.clone(),
    address,
    public_key: public_key_encoded,
    private_key: priv_key_wif,
  };

  wallet
    .addresses_by_coin
    .0
    .entry(coin_name.to_string())
    .or_default()
    .push(new_address);

  Ok(())
}

pub fn generate_bitcoin_taproot_address(
  wallet: &mut CryptoWallet,
  public_key: &CryptoPublicKey,
  derivation_path: &Zeroizing<String>,
  private_key: Zeroizing<[u8; 32]>,
) -> FunctionOutput<()> {
  let coin_index: Zeroizing<u32> = wallet.address_components.derivation_path.coin.clone();
  let coin_name: Zeroizing<String> = wallet.address_components.coin_name.clone();
  let hash: Zeroizing<String> = wallet.address_components.hash.clone();
  let key_derivation: Zeroizing<String> = wallet.address_components.key_derivation.clone();
  let wallet_import_format: Zeroizing<String> =
    wallet.address_components.wallet_import_format.clone();

  let secp_pubkey = match public_key {
    CryptoPublicKey::Secp256k1(pk) => pk,
    _ => {
      return Err(AppError::log(
        "Only Secp256k1 supported for Bitcoin Taproot",
      ));
    }
  };

  let compressed_pubkey: Zeroizing<Vec<u8>> = Zeroizing::new(secp_pubkey.serialize().to_vec());
  let public_key_encoded: Zeroizing<String> = Zeroizing::new(hex::encode(&compressed_pubkey));
  let pubkey_bytes: Zeroizing<[u8; 65]> = Zeroizing::new(secp_pubkey.serialize_uncompressed());

  let internal_key: Zeroizing<[u8; 32]> = Zeroizing::new(
    <[u8; 32]>::try_from(&pubkey_bytes[1..33])
      .map_err(|_| AppError::log("Failed to extract x-only internal key"))?,
  );

  let tweaked_key: Zeroizing<[u8; 32]> = tweak_taproot_key(internal_key)?;
  let taproot_address: Zeroizing<String> = encode_taproot_bech32m(tweaked_key)?;

  let priv_key_wif: Zeroizing<String> = encode_private_key(
    key_derivation.clone(),
    wallet_import_format.clone(),
    hash.clone(),
    coin_index.clone(),
    private_key,
  )?;

  let new_address: AddressPrivateData = AddressPrivateData {
    coin_index: coin_index.clone(),
    path: derivation_path.clone(),
    address: taproot_address,
    public_key: public_key_encoded,
    private_key: priv_key_wif,
  };

  wallet
    .addresses_by_coin
    .0
    .entry(coin_name.to_string())
    .or_default()
    .push(new_address);

  Ok(())
}

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

pub fn generate_addresses_for_all_coins(wallet: &mut CryptoWallet) -> FunctionOutput<()> {
  let active_coins = 1;

  let last_index = *wallet.address_components.derivation_path.last_index;

  let (start_index, end_index) = {
    if wallet.addresses_by_coin.0.is_empty() {
      (0, wallet.wallet_data.address_count)
    } else {
      (
        last_index,
        last_index.saturating_add(wallet.wallet_data.address_count),
      )
    }
  };

  // ECDB: Extended Coin DataBase
  let resource_path = std::path::Path::new("coin").join("ECDB.csv");
  let resource_path_str: Zeroizing<String> = Zeroizing::new(
    resource_path
      .into_os_string()
      .into_string()
      .unwrap_or_default(),
  );
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

          wallet.address_components.derivation_path.purpose =
            Zeroizing::new(wallet.wallet_data.active_bip);
          wallet.address_components.derivation_path.coin =
            Zeroizing::new(columns[1].parse().unwrap_or(0));
          wallet.address_components.derivation_path.purpose_hardened = Zeroizing::new(true);
          wallet.address_components.derivation_path.coin_hardened = Zeroizing::new(true);

          wallet.address_components.derivation_path.account_hardened = Zeroizing::new(true);
          wallet.address_components.derivation_path.change_hardened =
            Zeroizing::new(wallet.wallet_data.active_bip == 32);

          wallet.address_components.derivation_path.address_hardened =
            Zeroizing::new(wallet.wallet_data.hardened_address);

          wallet.address_components.coin_name = Zeroizing::new(columns[3].to_string());
          wallet.address_components.key_derivation = Zeroizing::new(columns[4].to_string());
          wallet.address_components.hash = Zeroizing::new(columns[5].to_string());
          wallet.address_components.public_key_hash = Zeroizing::new(columns[8].to_string());
          wallet.address_components.wallet_import_format = Zeroizing::new(columns[10].to_string());
          wallet.address_components.evm =
            Zeroizing::new(columns[11].trim().eq_ignore_ascii_case("true"));

          for address_index in start_index..end_index {
            wallet.address_components.derivation_path.address = Zeroizing::new(address_index);

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
                    return Err(AppError::log(format!(
                      "Can not derive secp256k1 address: {}",
                      err
                    )));
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
                    return Err(AppError::log(format!(
                      "Can not derive ed25519 address: {}",
                      err
                    )));
                  }
                };
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

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..
