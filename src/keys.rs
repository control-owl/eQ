// authors = ["Control Owl <eq[at]r-o0-t[dot]wtf>"]
// license = "CC-BY-NC-ND-4.0  [2023-2025]  Control Owl"

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

use crate::{AddressData, AppError, FunctionOutput, MasterKeyData, SeedData, d3bug};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bech32::{Bech32, Hrp, encode};
use ed25519_dalek::SigningKey;
use num_bigint::BigUint;
use ring::pbkdf2;
use sha2::{Digest, Sha256, Sha512};
use sha3::Keccak256;

const WALLET_MAX_ADDRESSES: u32 = 2_147_483_647;

// pub type AddressResult = Option<Address>;

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

#[derive(Debug)]
pub enum CryptoPublicKey {
  Secp256k1(secp256k1::PublicKey),
  Ed25519(ed25519_dalek::VerifyingKey),
}

#[derive(Debug)]
pub struct Addresses {
  pub address: String,
  pub public_key: String,
  pub private_key: String,
}

#[derive(Clone, Debug)]
pub struct ChildKeys {
  pub child_secret_key_bytes: Vec<u8>,
  pub child_chain_code_bytes: Vec<u8>,
  pub child_public_key_bytes: Vec<u8>,
}

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

pub fn generate_seed(
  source: &str,
  entropy_length: Option<usize>,
  passphrase_text: Option<&str>,
  dictionary: Option<&str>,
) -> FunctionOutput<SeedData> {
  d3bug("<<< generate_seed", "debug");
  d3bug(&format!("entropy_length {entropy_length:?}"), "debug");
  d3bug(&format!("passphrase_text {passphrase_text:?}"), "debug");
  d3bug(&format!("dictionary {dictionary:?}"), "debug");

  let pre_entropy = generate_pre_entropy(source, entropy_length);
  let checksum = e_q::calculate_checksum_for_entropy(&pre_entropy);
  let full_entropy = format!("{}{}", &pre_entropy, &checksum);
  let mnemonic_words = match generate_mnemonic_words(&full_entropy, dictionary) {
    Ok(words) => words,
    Err(err) => {
      return Err(AppError::Custom(format!(
        "Problem with generating mnemonic words: {}",
        err
      )));
    }
  };

  let password = passphrase_text.unwrap_or("");
  let salt = format!("mnemonic{password}");
  let mut seed = [0u8; 64];

  // TODO: Create support for QRNG, File
  pbkdf2::derive(
    pbkdf2::PBKDF2_HMAC_SHA512,
    std::num::NonZeroU32::new(2048).unwrap(),
    salt.as_bytes(),
    mnemonic_words.as_bytes(),
    &mut seed,
  );

  let seed_hex = hex::encode(&seed[..]);

  d3bug(&format!("pre_entropy {pre_entropy:?}"), "debug");
  d3bug(&format!("checksum {checksum:?}"), "debug");
  d3bug(&format!("full_entropy {full_entropy:?}"), "debug");
  d3bug(&format!("mnemonic_words {mnemonic_words:?}"), "debug");
  d3bug(&format!("password {password:?}"), "debug");
  d3bug(&format!("seed_hex {seed_hex:?}"), "debug");

  Ok(SeedData {
    entropy: pre_entropy,
    entropy_checksum: checksum,
    full_entropy,
    mnemonic_words,
    mnemonic_passphrase: String::from(password),
    seed: seed_hex,
  })
}

pub fn generate_pre_entropy(_source: &str, entropy_length: Option<usize>) -> String {
  d3bug("<<< generate_pre_entropy", "debug");
  d3bug(&format!("entropy_length {entropy_length:?}"), "debug");

  let entropy_length = entropy_length.unwrap_or(256);

  let bytes_needed = entropy_length.div_ceil(8);
  let mut buffer = vec![0u8; bytes_needed];

  let _ = getrandom::fill(&mut buffer);

  let mut result = String::with_capacity(entropy_length);
  for byte in buffer {
    for bit in 0..8 {
      if result.len() == entropy_length {
        break;
      }

      let bit_val = (byte >> bit) & 1;
      result.push(if bit_val == 1 { '1' } else { '0' });
    }
  }

  result
}

pub fn generate_mnemonic_words(
  final_entropy_binary: &str,
  dictionary: Option<&str>,
) -> FunctionOutput<String> {
  d3bug("<<< generate_mnemonic_words", "debug");
  d3bug(
    &format!("final_entropy_binary {final_entropy_binary:?}"),
    "debug",
  );
  d3bug(&format!("dictionary {dictionary:?}"), "debug");

  let chunks: Vec<String> = final_entropy_binary
    .chars()
    .collect::<Vec<char>>()
    .chunks(11)
    .map(|chunk| chunk.iter().collect())
    .collect();

  let mnemonic_decimal: Vec<u32> = chunks
    .iter()
    .map(|chunk| u32::from_str_radix(chunk, 2).unwrap())
    .collect();

  let dictionary_file = match dictionary.unwrap_or_default() {
    "Czech" => "czech.txt",
    "French" => "french.txt",
    "Italian" => "italian.txt",
    "Portuguese" => "portuguese.txt",
    "Spanish" => "spanish.txt",
    "Chinese simplified" => "chinese_simplified.txt",
    "Chinese traditional" => "chinese_traditional.txt",
    "Japanese" => "japanese.txt",
    "Korean" => "korean.txt",
    _ => "english.txt",
  };

  let wordlist_path = std::path::Path::new("wordlists").join(dictionary_file);
  let wordlist = e_q::get_text_from_resources(wordlist_path.to_str().unwrap());
  let mnemonic_words_vector: Vec<&str> = wordlist.lines().collect();
  let mnemonic_words_vector: Vec<&str> = mnemonic_decimal
    .iter()
    .map(|&decimal| {
      if (decimal as usize) < mnemonic_words_vector.len() {
        mnemonic_words_vector[decimal as usize]
      } else {
        "ERROR"
      }
    })
    .collect();

  Ok(mnemonic_words_vector.join(" "))
}

pub fn generate_master_keys_secp256k1(
  seed: &str,
  private_header: Option<&str>,
  public_header: Option<&str>,
) -> FunctionOutput<MasterKeyData> {
  d3bug("<<< generate_master_keys_secp256k1", "debug");
  d3bug(&format!("seed {seed:?}"), "debug");

  let private_header = private_header.unwrap_or("0x0488ADE4");
  let public_header = public_header.unwrap_or("0x0488B21E");
  d3bug(&format!("private_header {private_header:?}"), "debug");
  d3bug(&format!("public_header {public_header:?}"), "debug");

  let private_header = match u32::from_str_radix(private_header.trim_start_matches("0x"), 16) {
    Ok(value) => value,
    Err(err) => {
      return Err(AppError::Custom(format!(
        "Problem with parsing private_header: {}",
        err
      )));
    }
  };

  let public_header = match u32::from_str_radix(public_header.trim_start_matches("0x"), 16) {
    Ok(value) => value,
    Err(err) => {
      return Err(AppError::Custom(format!(
        "Problem with parsing public_header: {}",
        err
      )));
    }
  };

  let seed_bytes = match hex::decode(seed) {
    Ok(value) => value,
    Err(err) => {
      return Err(AppError::Custom(format!(
        "Problem with decoding seed_bytes: {}",
        err
      )));
    }
  };

  let message = "Bitcoin seed";
  let hmac_result = calculate_hmac_sha512_hash(message.as_bytes(), &seed_bytes);
  let (master_private_key_bytes, master_chain_code_bytes) = hmac_result.split_at(32);
  let mut master_private_key = Vec::new();

  master_private_key.extend_from_slice(&u32::to_be_bytes(private_header));
  master_private_key.push(0x00);
  master_private_key.extend([0x00; 4].iter());
  master_private_key.extend([0x00; 4].iter());
  master_private_key.extend_from_slice(master_chain_code_bytes);
  master_private_key.push(0x00);
  master_private_key.extend_from_slice(master_private_key_bytes);

  let checksum: [u8; 4] = calculate_checksum_for_master_keys(&master_private_key);

  master_private_key.extend_from_slice(&checksum);

  let secp = secp256k1::Secp256k1::new();

  let master_private_key_encoded = bs58::encode(&master_private_key).into_string();

  let array: [u8; 32] = master_private_key_bytes
    .try_into()
    .map_err(|_| AppError::Custom("master_private_key_bytes must be 32 bytes".into()))?;

  let master_secret_key = secp256k1::SecretKey::from_byte_array(array)
    .map_err(|err| AppError::Custom(format!("Invalid master_secret_key: {err:?}")))?;

  let master_public_key_bytes: [u8; 33] =
    secp256k1::PublicKey::from_secret_key(&secp, &master_secret_key).serialize();

  let mut master_public_key = Vec::new();

  master_public_key.extend_from_slice(&u32::to_be_bytes(public_header));
  master_public_key.push(0x00);
  master_public_key.extend([0x00; 4].iter());
  master_public_key.extend([0x00; 4].iter());
  master_public_key.extend_from_slice(master_chain_code_bytes);
  master_public_key.extend_from_slice(&master_public_key_bytes);

  let checksum: [u8; 4] = calculate_checksum_for_master_keys(&master_public_key);

  master_public_key.extend_from_slice(&checksum);

  let master_public_key_encoded = bs58::encode(&master_public_key).into_string();
  let master_chain_code_bytes: [u8; 32] = master_chain_code_bytes.try_into().unwrap();
  let master_private_key_bytes: [u8; 32] = master_private_key_bytes.try_into().unwrap();

  d3bug(
    &format!("master_private_key_encoded {master_private_key_encoded:?}"),
    "debug",
  );
  d3bug(
    &format!("master_private_key_bytes {master_private_key_bytes:?}"),
    "debug",
  );
  d3bug(
    &format!("master_public_key_encoded {master_public_key_encoded:?}"),
    "debug",
  );
  d3bug(
    &format!("master_public_key_bytes {master_public_key_bytes:?}"),
    "debug",
  );
  d3bug(
    &format!("master_chain_code_bytes {master_chain_code_bytes:?}"),
    "debug",
  );

  Ok(MasterKeyData {
    master_private_key_encoded,
    master_private_key_bytes: master_private_key_bytes.to_vec(),
    master_public_key_encoded,
    master_public_key_bytes: master_public_key_bytes.to_vec(),
    master_chain_code_bytes: master_chain_code_bytes.to_vec(),
  })
}

fn calculate_hmac_sha512_hash(key: &[u8], data: &[u8]) -> Vec<u8> {
  d3bug("<<< calculate_hmac_sha512_hash", "debug");
  d3bug(&format!("key {key:?}"), "debug");
  d3bug(&format!("data {data:?}"), "debug");

  const BLOCK_SIZE: usize = 128;
  const HASH_SIZE: usize = 64;

  let padded_key = if key.len() > BLOCK_SIZE {
    let mut hasher = Sha512::new();
    hasher.update(key);
    let mut hashed_key = vec![0u8; HASH_SIZE];
    hashed_key.copy_from_slice(&hasher.finalize());
    hashed_key.resize(BLOCK_SIZE, 0x00);
    hashed_key
  } else {
    let mut padded_key = vec![0x00; BLOCK_SIZE];
    padded_key[..key.len()].copy_from_slice(key);
    padded_key
  };

  assert_eq!(padded_key.len(), BLOCK_SIZE, "Padded key length mismatch");

  let mut inner_pad = vec![0x36; BLOCK_SIZE];
  let mut outer_pad = vec![0x5c; BLOCK_SIZE];
  for (i, &b) in padded_key.iter().enumerate() {
    inner_pad[i] ^= b;
    outer_pad[i] ^= b;
  }

  let mut hasher = Sha512::new();
  hasher.update(&inner_pad);
  hasher.update(data);
  let inner_hash = hasher.finalize();
  let mut hasher = Sha512::new();
  hasher.update(&outer_pad);
  hasher.update(inner_hash);
  let final_hash = hasher.finalize().to_vec();

  assert_eq!(final_hash.len(), HASH_SIZE, "Final hash length mismatch");

  final_hash
}

fn calculate_checksum_for_master_keys(data: &[u8]) -> [u8; 4] {
  d3bug("<<< calculate_checksum_for_master_keys", "debug");
  d3bug(&format!("data {data:?}"), "debug");

  let hash = Sha256::digest(data);
  let double_hash = Sha256::digest(hash);
  let mut checksum = [0u8; 4];
  checksum.copy_from_slice(&double_hash[..4]);
  checksum
}

pub fn generate_secp256k1_address(ingredients: AddressData) -> FunctionOutput<Addresses> {
  d3bug("<<< generate_secp256k1_address", "debug");
  d3bug(&format!("ingredients {ingredients:?}"), "debug");

  let derived_child_keys = match derive_child_keys(&ingredients) {
    Ok(keys) => keys,
    Err(err) => {
      return Err(AppError::Custom(format!(
        "Can not derive child keys: {}",
        err
      )));
    }
  };

  let public_key = generate_public_key(&ingredients, derived_child_keys.clone())?;

  let private_key: [u8; 32] = match derived_child_keys.child_secret_key_bytes.try_into() {
    Ok(key) => key,
    Err(err) => {
      return Err(AppError::Custom(
        format!("Can not convert child private key: {:?}", err).to_string(),
      ));
    }
  };

  if ingredients.coin_index == 118 {
    let secp_pubkey = match &public_key {
      CryptoPublicKey::Secp256k1(pk) => pk,
      _ => {
        return Err(AppError::Custom(
          "Only Secp256k1 for generating Secp256k1 addresses".to_string(),
        ));
      }
    };
    let pub_compressed: [u8; 33] = secp_pubkey.serialize();
    let address = generate_atom_address(&pub_compressed)?;
    let public_key_encoded = encode_pubkey_bech32(&pub_compressed)?;
    let private_key_encoded = BASE64.encode(private_key);

    Ok(Addresses {
      address,
      public_key: public_key_encoded,
      private_key: private_key_encoded,
    })
  } else {
    let public_key_hash_vec = {
      let trimmed = ingredients.public_key_hash.trim_start_matches("0x");
      hex::decode(trimmed)
        .map_err(|err| AppError::Custom(format!("Invalid public_key_hash: {err}")))?
    };

    let public_key_encoded = encode_public_key(&ingredients, &public_key)?;
    let address = generate_address_internal(&ingredients, &public_key, &public_key_hash_vec)?;
    let priv_key_wif = encode_private_key(&ingredients, &private_key)?;

    Ok(Addresses {
      address,
      public_key: public_key_encoded,
      private_key: priv_key_wif,
    })
  }
}

pub fn derive_child_keys(ingredients: &AddressData) -> FunctionOutput<ChildKeys> {
  d3bug("<<< derive_child_keys", "debug");
  d3bug(&format!("ingredients {ingredients:?}"), "debug");

  match ingredients.key_derivation.as_str() {
    "secp256k1" => derive_from_path_secp256k1(
      &ingredients.master_private_key_bytes,
      &ingredients.master_chain_code_bytes,
      &ingredients.derivation_path,
    ),
    "ed25519" => derive_from_path_ed25519(
      &ingredients.master_private_key_bytes,
      &ingredients.master_chain_code_bytes,
      &ingredients.derivation_path,
    ),
    _ => Err(AppError::Custom(format!(
      "Unsupported key derivation method: {}",
      ingredients.key_derivation
    ))),
  }
}

fn generate_public_key(
  ingredients: &AddressData,
  derived_child_keys: ChildKeys,
) -> FunctionOutput<CryptoPublicKey> {
  d3bug("<<< generate_public_key", "debug");
  d3bug(&format!("ingredients {ingredients:?}"), "debug");
  d3bug(
    &format!("derived_child_keys {derived_child_keys:?}"),
    "debug",
  );

  match ingredients.key_derivation.as_str() {
    "secp256k1" => {
      let secp = secp256k1::Secp256k1::new();

      let child_secret_key: [u8; 32] = match derived_child_keys.child_secret_key_bytes.try_into() {
        Ok(key) => key,
        Err(err) => {
          return Err(AppError::Custom(
            format!("Can not convert child private key: {:?}", err).to_string(),
          ));
        }
      };

      let secret_key = secp256k1::SecretKey::from_byte_array(child_secret_key)
        .map_err(|err| AppError::Custom(format!("Invalid SecretKey: {err}")))?;
      let secp_pub_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);

      Ok(CryptoPublicKey::Secp256k1(secp_pub_key))
    }
    "ed25519" => {
      let child_secret_key: [u8; 32] = match derived_child_keys.child_secret_key_bytes.try_into() {
        Ok(key) => key,
        Err(err) => {
          return Err(AppError::Custom(
            format!("Can not convert child private key: {:?}", err).to_string(),
          ));
        }
      };
      let sign_key = ed25519_dalek::SigningKey::from_bytes(&child_secret_key);
      let pub_key = sign_key.verifying_key();

      Ok(CryptoPublicKey::Ed25519(pub_key))
    }
    _ => Err(AppError::Custom(format!(
      "Unsupported key derivation method: {}",
      ingredients.key_derivation
    ))),
  }
}

fn encode_public_key(
  ingredients: &AddressData,
  public_key: &CryptoPublicKey,
) -> FunctionOutput<String> {
  d3bug("<<< encode_public_key", "debug");
  d3bug(&format!("ingredients {ingredients:?}"), "debug");
  d3bug(&format!("public_key {public_key:?}"), "debug");

  match ingredients.hash.as_str() {
    "sha256" | "sha256+ripemd160" => match public_key {
      CryptoPublicKey::Secp256k1(pk) => Ok(hex::encode(pk.serialize())),
      _ => Ok(String::new()),
    },
    "keccak256" => match public_key {
      CryptoPublicKey::Secp256k1(pk) => {
        let serialized = pk.serialize();
        if ingredients.coin_index == 195 {
          Ok(hex::encode(serialized))
        } else {
          Ok(format!("0x{}", hex::encode(serialized)))
        }
      }
      _ => Ok(String::new()),
    },
    "ed25519" => match public_key {
      CryptoPublicKey::Ed25519(pk) => Ok(bs58::encode(pk.to_bytes()).into_string()),
      _ => Ok(String::new()),
    },
    _ => Err(AppError::Custom(format!(
      "Unsupported hash method: {}",
      ingredients.hash
    ))),
  }
}

fn generate_address_internal(
  ingredients: &AddressData,
  public_key: &CryptoPublicKey,
  public_key_hash_vec: &[u8],
) -> FunctionOutput<String> {
  d3bug("<<< generate_address_internal", "debug");
  d3bug(&format!("ingredients {ingredients:?}"), "debug");
  d3bug(&format!("public_key {public_key:?}"), "debug");
  d3bug(
    &format!("public_key_hash_vec {public_key_hash_vec:?}"),
    "debug",
  );

  match ingredients.hash.as_str() {
    "sha256" => generate_address_sha256(public_key, public_key_hash_vec),
    "keccak256" => {
      generate_address_keccak256(public_key, public_key_hash_vec, ingredients.coin_index)
    }
    "sha256+ripemd160" => {
      generate_sha256_ripemd160_address(ingredients.coin_index, public_key, public_key_hash_vec)
    }
    _ => Err(AppError::Custom(format!(
      "Unsupported hash method: {}",
      ingredients.hash
    ))),
  }
}

fn encode_private_key(
  ingredients: &AddressData,
  private_key_bytes: &[u8; 32],
) -> FunctionOutput<String> {
  d3bug("<<< encode_private_key", "debug");
  d3bug(&format!("ingredients {ingredients:?}"), "debug");
  d3bug(&format!("private_key_bytes {private_key_bytes:?}"), "debug");

  if ingredients.key_derivation == "ed25519" {
    Ok(bs58::encode(private_key_bytes).into_string())
  } else {
    let secret_key = secp256k1::SecretKey::from_byte_array(*private_key_bytes)
      .map_err(|err| AppError::Custom(format!("Invalid SecretKey: {err}")))?;

    create_private_key_for_address(
      Some(&secret_key),
      Some(true), // compressed
      Some(&ingredients.wallet_import_format),
      &ingredients.hash,
      ingredients.coin_index,
    )
    .map_err(|err| AppError::Custom(format!("Failed to convert private key to WIF: {err}")))
  }
}

pub fn create_private_key_for_address(
  private_key: Option<&secp256k1::SecretKey>,
  compressed: Option<bool>,
  wif: Option<&str>,
  hash: &str,
  coin_index: u32,
) -> FunctionOutput<String> {
  d3bug("<<< create_private_key_for_address", "debug");
  d3bug(&format!("private_key {private_key:?}"), "debug");
  d3bug(&format!("compressed {compressed:?}"), "debug");
  d3bug(&format!("wif {wif:?}"), "debug");
  d3bug(&format!("hash {hash:?}"), "debug");
  d3bug(&format!("coin_index {coin_index:?}"), "debug");

  let wallet_import_format = match wif {
    Some(w) => {
      if w.is_empty() {
        "80"
      } else {
        w.trim_start_matches("0x")
      }
    }
    None => "80",
  };

  let compressed = compressed.unwrap_or(true);

  let wallet_import_format_bytes = match hex::decode(wallet_import_format) {
    Ok(bytes) => bytes,
    Err(err) => return Err(AppError::Custom(format!("Invalid WIF format {err:?}"))),
  };

  match hash {
    "sha256" => {
      let mut extended_key = Vec::with_capacity(34);
      extended_key.extend_from_slice(&wallet_import_format_bytes);

      if let Some(private_key) = private_key {
        extended_key.extend_from_slice(&private_key.secret_bytes());

        if compressed {
          extended_key.push(0x01);
        }
      } else {
        return Err(AppError::Custom("Private key must be provided".to_string()));
      }

      let checksum = e_q::calculate_double_sha256_hash(&extended_key);
      let address_checksum = &checksum[0..4];
      extended_key.extend_from_slice(address_checksum);

      Ok(bs58::encode(extended_key).into_string())
    }
    "keccak256" => {
      if let Some(private_key) = private_key {
        if coin_index == 195 {
          Ok(hex::encode(private_key.secret_bytes()))
        } else {
          Ok(format!("0x{}", hex::encode(private_key.secret_bytes())))
        }
      } else {
        Err(AppError::Custom("Private key must be provided".to_string()))
      }
    }
    "sha256+ripemd160" => match private_key {
      Some(key) => {
        let private_key_hex = hex::encode(key.secret_bytes());
        // d3bug(&format!("private_key_hex {private_key_hex:?}"), "debug");
        Ok(private_key_hex)
      }
      None => Err(AppError::Custom("Private key must be provided".to_string())),
    },
    _ => Err(AppError::Custom(format!("Unsupported hash method: {hash}"))),
  }
}

pub fn derive_from_path_secp256k1(
  master_key: &[u8],
  master_chain_code: &[u8],
  path: &str,
) -> FunctionOutput<ChildKeys> {
  d3bug("<<< derive_from_path_secp256k1", "debug");
  d3bug(&format!("master_key {master_key:?}"), "debug");
  d3bug(&format!("master_chain_code {master_chain_code:?}"), "debug");
  d3bug(&format!("path {path:?}"), "debug");

  let mut private_key = master_key.to_vec();
  let mut chain_code = master_chain_code.to_vec();
  let mut public_key = Vec::new();

  for part in path.split('/') {
    if part == "m" {
      continue;
    }

    let hardened = part.ends_with("'");
    let index: u32 = match part.trim_end_matches("'").parse() {
      Ok(index) => {
        // d3bug(&format!("index {index:?}"), "debug");

        index
      }
      Err(err) => {
        return Err(AppError::Custom(format!(
          "Error: Unable to parse index from path part: {err}"
        )));
      }
    };

    let derived_child_keys =
      match derive_child_key_secp256k1(&private_key, &chain_code, index, hardened) {
        Ok(keys) => keys,
        Err(err) => {
          return Err(AppError::Custom(format!(
            "Problem with deriving child keys: {err:?}"
          )));
        }
      };

    private_key = derived_child_keys.child_secret_key_bytes;
    chain_code = derived_child_keys.child_chain_code_bytes;
    public_key = derived_child_keys.child_public_key_bytes;
  }

  let array: [u8; 32] = private_key
    .try_into()
    .map_err(|_| AppError::Custom("private_key must be 32 bytes".into()))?;

  let secret_key = secp256k1::SecretKey::from_byte_array(array)
    .map_err(|err| AppError::Custom(format!("Invalid secret_key: {err}")))?;

  if chain_code.len() != 32 {
    return Err(AppError::Custom(format!(
      "Invalid chain code length {:?}",
      chain_code.len()
    )));
  }

  let mut chain_code_array = [0u8; 32];
  chain_code_array.copy_from_slice(&chain_code);

  let mut public_key_array = [0u8; 33];
  public_key_array.copy_from_slice(&public_key);

  Ok(ChildKeys {
    child_secret_key_bytes: secret_key.secret_bytes().to_vec(),
    child_chain_code_bytes: chain_code_array.to_vec(),
    child_public_key_bytes: public_key_array.to_vec(),
  })
}

pub fn generate_address_sha256(
  public_key: &CryptoPublicKey,
  public_key_hash: &[u8],
) -> FunctionOutput<String> {
  d3bug("<<< generate_address_sha256", "debug");
  d3bug(&format!("public_key {public_key:?}"), "debug");
  d3bug(&format!("public_key_hash {public_key_hash:?}"), "debug");

  let public_key_bytes = match get_public_key(public_key) {
    Ok(key) => key,
    Err(err) => return Err(AppError::Custom(format!("Can not get public key: {err:?}"))),
  };

  // #[cfg(debug_assertions)]
  // println!("Public key bytes: {public_key_bytes:?}");

  let hash160 = e_q::calculate_sha256_and_ripemd160_hash(&public_key_bytes);

  let mut payload = Vec::with_capacity(public_key_hash.len() + hash160.len());
  payload.extend_from_slice(public_key_hash);
  payload.extend_from_slice(&hash160);

  // #[cfg(debug_assertions)]
  // println!("Extended sha256_and_ripemd160 payload: {payload:?}");

  let checksum = e_q::calculate_double_sha256_hash(&payload);
  let address_checksum = &checksum[0..4];

  // #[cfg(debug_assertions)]
  // println!("Address checksum: {address_checksum:?}");

  let mut address_payload = payload;
  address_payload.extend_from_slice(address_checksum);

  // #[cfg(debug_assertions)]
  // println!("Extended Address payload: {address_payload:?}");

  Ok(bs58::encode(address_payload).into_string())
}

pub fn generate_address_keccak256(
  public_key: &CryptoPublicKey,
  public_key_hash: &[u8],
  coin_index: u32,
) -> FunctionOutput<String> {
  d3bug("<<< generate_address_keccak256", "debug");
  d3bug(&format!("public_key {public_key:?}"), "debug");
  d3bug(&format!("public_key_hash {public_key_hash:?}"), "debug");
  d3bug(&format!("coin_index {coin_index:?}"), "debug");

  let public_key_bytes = match public_key {
    CryptoPublicKey::Secp256k1(key) => key.serialize_uncompressed().to_vec(),
    CryptoPublicKey::Ed25519(key) => key.to_bytes().to_vec(),
  };

  let public_key_slice = match public_key {
    CryptoPublicKey::Secp256k1(_) => &public_key_bytes[1..],
    CryptoPublicKey::Ed25519(_) => &public_key_bytes[..],
  };

  let mut keccak = Keccak256::new();
  keccak.update(public_key_slice);
  let keccak_result = keccak.finalize();

  let address_bytes = &keccak_result[12..];

  let address = match coin_index {
    195 => {
      let mut tron_prefixed = public_key_hash.to_vec();
      tron_prefixed.extend_from_slice(address_bytes);

      let checksum = {
        let hash = Sha256::digest(&tron_prefixed);
        let hash2 = Sha256::digest(hash);
        hash2[..4].to_vec()
      };

      let mut full_payload = tron_prefixed.clone();
      full_payload.extend_from_slice(&checksum);

      bs58::encode(full_payload).into_string()
    }
    _ => {
      format!("0x{}", hex::encode(address_bytes))
    }
  };

  Ok(address)
}

pub fn generate_sha256_ripemd160_address(
  coin_index: u32,
  public_key: &CryptoPublicKey,
  public_key_hash: &[u8],
) -> FunctionOutput<String> {
  d3bug("<<< generate_sha256_ripemd160_address", "debug");
  d3bug(&format!("coin_index {coin_index:?}"), "debug");
  d3bug(&format!("public_key {public_key:?}"), "debug");
  d3bug(&format!("public_key_hash {public_key_hash:?}"), "debug");

  let public_key_bytes = match get_public_key(public_key) {
    Ok(key) => key,
    Err(err) => return Err(AppError::Custom(format!("Can not get public key: {err:?}"))),
  };

  // #[cfg(debug_assertions)]
  // println!("Public key bytes: {public_key_bytes:?}");

  let hash = e_q::calculate_sha256_and_ripemd160_hash(&public_key_bytes);
  let mut address_bytes = Vec::new();

  address_bytes.extend_from_slice(public_key_hash);
  address_bytes.extend(&hash);

  let checksum = Sha256::digest(Sha256::digest(&address_bytes));
  let checksum = &checksum[0..4];

  let mut full_address_bytes = address_bytes.clone();
  full_address_bytes.extend(checksum);

  let alphabet = match coin_index {
    144 => bs58::Alphabet::RIPPLE,
    _ => bs58::Alphabet::DEFAULT,
  };

  let encoded_address = bs58::encode(full_address_bytes)
    .with_alphabet(alphabet)
    .into_string();

  // #[cfg(debug_assertions)]
  // println!("Base58 encoded address: {encoded_address}");

  Ok(encoded_address)
}

pub fn derive_child_key_secp256k1(
  parent_key: &[u8],
  parent_chain_code: &[u8],
  index: u32,
  hardened: bool,
) -> FunctionOutput<ChildKeys> {
  d3bug("<<< derive_child_key_secp256k1", "debug");
  d3bug(&format!("parent_key {parent_key:?}"), "debug");
  d3bug(&format!("parent_chain_code {parent_chain_code:?}"), "debug");
  d3bug(&format!("index {index:?}"), "debug");
  d3bug(&format!("hardened {hardened:?}"), "debug");

  if index & 0x80000000 != 0 && !hardened {
    return Err(AppError::Custom(format!("Problem with index {index:?}")));
  }

  let secp = secp256k1::Secp256k1::new();
  let mut data = Vec::with_capacity(37);

  if hardened {
    data.push(0x00);
    data.extend_from_slice(parent_key);
  } else {
    let array: [u8; 32] = parent_key
      .try_into()
      .map_err(|_| AppError::Custom("parent_key must be 32 bytes".into()))?;

    let parent_secret_key = secp256k1::SecretKey::from_byte_array(array)
      .map_err(|err| AppError::Custom(format!("Invalid SecretKey: {err}")))?;

    let parent_pubkey = secp256k1::PublicKey::from_secret_key(&secp, &parent_secret_key);
    data.extend_from_slice(&parent_pubkey.serialize()[..]);
  }

  let index_bytes = if hardened {
    let index = index + WALLET_MAX_ADDRESSES + 1;
    index.to_be_bytes()
  } else {
    index.to_be_bytes()
  };

  data.extend_from_slice(&index_bytes);

  // d3bug(&format!("data_for_hmac_sha512 {data:?}"), "debug");

  let result = e_q::calculate_hmac_sha512_hash(parent_chain_code, &data);

  let child_private_key_bytes: [u8; 32] = result[..32]
    .try_into()
    .map_err(|_| AppError::Custom("Slice with incorrect length for private key".to_string()))?;

  let child_chain_code_bytes: [u8; 32] = result[32..]
    .try_into()
    .map_err(|_| AppError::Custom("Slice with incorrect length for chain code".to_string()))?;

  let child_key_int = BigUint::from_bytes_be(&child_private_key_bytes);
  let parent_key_int = BigUint::from_bytes_be(parent_key);
  let curve_order = BigUint::from_bytes_be(&secp256k1::constants::CURVE_ORDER);
  let combined_int = (parent_key_int + child_key_int) % &curve_order;
  let combined_bytes = combined_int.to_bytes_be();
  let combined_bytes_padded = {
    let mut padded = [0u8; 32];
    let offset = 32 - combined_bytes.len();
    padded[offset..].copy_from_slice(&combined_bytes);
    padded
  };
  // let array: [u8; 32] = combined_bytes_padded
  //   .try_into()
  //   .map_err(|_| AppError::Custom("combined_bytes_padded must be 32 bytes".into()))?;

  let child_secret_key = secp256k1::SecretKey::from_byte_array(combined_bytes_padded)
    .map_err(|err| AppError::Custom(format!("Invalid child_secret_key: {err}")))?;

  let child_secret_key_bytes = child_secret_key.secret_bytes();
  let child_pubkey = secp256k1::PublicKey::from_secret_key(&secp, &child_secret_key);
  let child_public_key_bytes = child_pubkey.serialize().to_vec();

  Ok(ChildKeys {
    child_secret_key_bytes: child_secret_key_bytes.to_vec(),
    child_chain_code_bytes: child_chain_code_bytes.to_vec(),
    child_public_key_bytes,
  })
}

fn get_public_key(public_key: &CryptoPublicKey) -> FunctionOutput<Vec<u8>> {
  d3bug("<<< get_public_key", "debug");
  d3bug(&format!("public_key {public_key:?}"), "debug");

  let public_key_bytes = match public_key {
    CryptoPublicKey::Secp256k1(key) => key.serialize().to_vec(),
    CryptoPublicKey::Ed25519(key) => key.to_bytes().to_vec(),
  };

  Ok(public_key_bytes)
}

pub fn _generate_seed_from_mnemonic(
  mnemonic: &str,
  passphrase: Option<&str>,
) -> FunctionOutput<[u8; 64]> {
  d3bug("<<< _generate_seed_from_mnemonic", "debug");
  d3bug(&format!("mnemonic {mnemonic:?}"), "debug");
  d3bug(&format!("passphrase {passphrase:?}"), "debug");

  let mnemonic_passphrase = passphrase.unwrap_or("");
  let salt = format!("mnemonic{mnemonic_passphrase}");
  let mut seed = [0u8; 64];
  ring::pbkdf2::derive(
    ring::pbkdf2::PBKDF2_HMAC_SHA512,
    std::num::NonZeroU32::new(2048).unwrap(),
    salt.as_bytes(),
    mnemonic.as_bytes(),
    &mut seed,
  );

  Ok(seed)
}

pub fn _convert_seed_to_mnemonic(seed: &[u8]) -> FunctionOutput<String> {
  d3bug("<<< _convert_seed_to_mnemonic", "debug");
  d3bug(&format!("seed {seed:?}"), "debug");

  let mut hex = String::with_capacity(128);

  for byte in seed.iter() {
    hex.push_str(&format!("{byte:02x}"));
  }

  Ok(hex)
}

fn generate_atom_address(pub_compressed: &[u8]) -> Result<String, AppError> {
  let hash20 = e_q::calculate_sha256_and_ripemd160_hash(pub_compressed);
  bech32_encode::<Bech32>("cosmos", &hash20)
}

fn encode_pubkey_bech32(pub_compressed: &[u8]) -> Result<String, AppError> {
  let prefix = [0xEB, 0x5A, 0xE9, 0x87, 0x21];
  let mut data = Vec::with_capacity(38);

  data.extend_from_slice(&prefix);
  data.extend_from_slice(pub_compressed);

  bech32_encode::<Bech32>("cosmospub", &data)
}

fn bech32_encode<Checksum: bech32::Checksum>(hrp: &str, data: &[u8]) -> Result<String, AppError> {
  let hrp_parsed =
    Hrp::parse(hrp).map_err(|e| AppError::Custom(format!("Invalid HRP '{}': {}", hrp, e)))?;

  encode::<Checksum>(hrp_parsed, data)
    .map_err(|e| AppError::Custom(format!("Bech32 encode error: {}", e)))
}

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

pub fn derive_from_path_ed25519(
  master_key: &[u8],
  master_chain_code: &[u8],
  path: &str,
) -> FunctionOutput<crate::keys::ChildKeys> {
  d3bug(">>> derive_from_path_ed25519", "debug");
  d3bug(&format!("master_key {master_key:?}"), "debug");
  d3bug(&format!("master_chain_code {master_chain_code:?}"), "debug");
  d3bug(&format!("path {path:?}"), "debug");

  if master_key.len() != 32 {
    return Err(AppError::Custom(format!(
      "Master key must be 32 bytes, got {}",
      master_key.len()
    )));
  } else {
    d3bug(
      &format!("master_key length {:?}", master_key.len()),
      "debug",
    );
  }

  if master_chain_code.len() != 32 {
    return Err(AppError::Custom(format!(
      "Master chain key must be 32 bytes, got {}",
      master_chain_code.len()
    )));
  } else {
    d3bug(
      &format!("master_chain_code length {:?}", master_chain_code.len()),
      "debug",
    );
  }

  if !path.starts_with("m/") {
    return Err(AppError::Custom("Path must start with: m/".to_string()));
  }

  let mut private_key = <[u8; 32]>::try_from(master_key)
    .map_err(|_| AppError::Custom("Master key must be 32 bytes".into()))?;

  let mut chain_code = <[u8; 32]>::try_from(master_chain_code)
    .map_err(|_| AppError::Custom("Chain code must be 32 bytes".into()))?;

  for part in path.split('/').skip(1) {
    let hardened = part.ends_with("'");
    let index_str = part.trim_end_matches("'");
    let index: u32 = index_str
      .parse()
      .map_err(|_| AppError::Custom(format!("Invalid index: {index_str}")))?;

    let child_index = if hardened { index | 0x80000000 } else { index };
    let derived = derive_child_key_ed25519(&private_key, &chain_code, child_index)?;

    private_key = derived
      .child_secret_key_bytes
      .try_into()
      .map_err(|_| AppError::Custom("Child key not 32 bytes".into()))?;

    d3bug(&format!("private_key {private_key:?}"), "debug");

    chain_code = derived
      .child_chain_code_bytes
      .try_into()
      .map_err(|_| AppError::Custom("Chain code not 32 bytes".into()))?;

    d3bug(&format!("chain_code {chain_code:?}"), "debug");
  }

  let signing_key = SigningKey::from_bytes(&private_key);
  let verifying_key = signing_key.verifying_key();

  Ok(crate::keys::ChildKeys {
    child_secret_key_bytes: private_key.to_vec(),
    child_chain_code_bytes: chain_code.to_vec(),
    child_public_key_bytes: verifying_key.to_bytes().to_vec(),
  })
}

pub fn derive_child_key_ed25519(
  parent_key: &[u8],
  parent_chain_code: &[u8],
  index: u32,
) -> FunctionOutput<crate::keys::ChildKeys> {
  d3bug(">>> derive_child_key_ed25519", "debug");
  d3bug(&format!("parent_key {parent_key:?}"), "debug");
  d3bug(&format!("parent_chain_code {parent_chain_code:?}"), "debug");
  d3bug(&format!("index {index:?}"), "debug");

  if parent_key.len() != 32 || parent_chain_code.len() != 32 {
    return Err(AppError::Custom(
      "Invalid parent_key or parent_chain_code length".to_string(),
    ));
  }

  if index < 0x80000000 {
    return Err(AppError::Custom(
      "Ed25519 only supports hardened derivation".into(),
    ));
  }

  let mut data = vec![0x00];
  data.extend_from_slice(parent_key);
  data.extend_from_slice(&index.to_be_bytes());
  d3bug(&format!("data {data:?}"), "debug");

  let hmac = e_q::calculate_hmac_sha512_hash(parent_chain_code, &data);
  d3bug(&format!("hmac {hmac:?}"), "debug");
  if hmac.len() != 64 {
    return Err(AppError::Custom(
      "calculate_hmac_sha512_hash len is not 64".to_string(),
    ));
  }

  let mut child_secret = [0u8; 32];
  let mut child_chain = [0u8; 32];
  child_secret.copy_from_slice(&hmac[..32]);
  child_chain.copy_from_slice(&hmac[32..]);

  d3bug(&format!("child_secret {child_secret:?}"), "debug");
  d3bug(&format!("child_chain {child_chain:?}"), "debug");

  Ok(crate::keys::ChildKeys {
    child_secret_key_bytes: child_secret.to_vec(),
    child_chain_code_bytes: child_chain.to_vec(),
    child_public_key_bytes: vec![],
    // child_public_key_bytes: SigningKey::from_bytes(&child_secret)
    //   .verifying_key()
    //   .to_bytes()
    //   .to_vec(),
  })
}

pub fn generate_ed25519_address(
  ingredients: crate::AddressData,
) -> FunctionOutput<crate::keys::Addresses> {
  d3bug(">>> generate_ed25519_address", "debug");
  d3bug(&format!("ingredients {ingredients:?}"), "debug");

  let path = if ingredients.bip == 32 {
    "m/0'/0'/0'"
  } else {
    &format!(
      "m/{}'/{}'/0'/0'/0'",
      ingredients.bip, ingredients.coin_index,
    )
  };

  d3bug(&format!("path {path:?}"), "debug");

  let master_key = &ingredients.master_private_key_bytes;
  let chain_code = &ingredients.master_chain_code_bytes;
  d3bug(&format!("master_key {master_key:?}"), "debug");
  d3bug(&format!("chain_code {chain_code:?}"), "debug");

  let final_keys = derive_from_path_ed25519(master_key, chain_code, path)?;
  d3bug(&format!("final_keys {final_keys:?}"), "debug");

  let address = bs58::encode(&final_keys.child_public_key_bytes).into_string();
  let public_key = hex::encode(&final_keys.child_public_key_bytes);
  let private_key = hex::encode(&final_keys.child_secret_key_bytes);

  d3bug(&format!("address {address:?}"), "debug");
  d3bug(&format!("public_key {public_key:?}"), "debug");
  d3bug(&format!("private_key {private_key:?}"), "debug");

  Ok(crate::keys::Addresses {
    address,
    public_key,
    private_key,
  })
}

pub fn generate_master_keys_ed25519(seed: &str) -> FunctionOutput<MasterKeyData> {
  d3bug(">>> generate_master_keys_ed25519", "debug");
  d3bug(&format!("seed {seed:?}"), "debug");

  let message = b"ed25519 seed";
  let seed_bytes = match hex::decode(seed) {
    Ok(values) => values,
    Err(err) => {
      return Err(AppError::Custom(format!("Can not decode seed: {}", err)));
    }
  };

  let result = e_q::calculate_hmac_sha512_hash(message, &seed_bytes);
  d3bug(&format!("result {result:?}"), "debug");

  if result.len() != 64 {
    return Err(AppError::Custom(
      "Wrong hash length output in calculate_hmac_sha512_hash".to_string(),
    ));
  }

  let mut master_private_key = [0u8; 32];
  master_private_key.copy_from_slice(&result[..32]);
  d3bug(
    &format!("master_private_key {master_private_key:?}"),
    "debug",
  );

  let mut master_chain_code = [0u8; 32];
  master_chain_code.copy_from_slice(&result[32..]);
  d3bug(&format!("master_chain_code {master_chain_code:?}"), "debug");

  let signing_key = SigningKey::from_bytes(&master_private_key);
  let public_key = signing_key.verifying_key();
  d3bug(&format!("signing_key {signing_key:?}"), "debug");
  d3bug(&format!("public_key {public_key:?}"), "debug");

  let master_xprv = bs58::encode(&master_private_key).into_string();
  let master_xpub = bs58::encode(&public_key.as_bytes()).into_string();

  Ok(MasterKeyData {
    master_private_key_encoded: master_xprv,
    master_private_key_bytes: master_private_key.to_vec(),
    master_public_key_encoded: master_xpub,
    master_public_key_bytes: public_key.to_bytes().to_vec(),
    master_chain_code_bytes: master_chain_code.to_vec(),
  })
}
