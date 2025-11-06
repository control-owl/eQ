// authors = ["Control Owl <eq[at]r-o0-t[dot]wtf>"]
// license = "CC-BY-NC-ND-4.0  [2023-2025]  Control Owl"

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

use getrandom;
use ring::pbkdf2;
use sha2::{Digest, Sha256, Sha512};
use crate::{AppError, FunctionOutput};

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

pub fn generate_seed(
  source: &str,
  entropy_length: Option<usize>,
  passphrase_text: Option<&str>,
  dictionary: Option<&str>,
) -> (String, String, String) {
  let pre_entropy = generate_pre_entropy(source, entropy_length);
  let checksum = e_q::calculate_checksum_for_entropy(&pre_entropy);
  let full_entropy = format!("{}{}", &pre_entropy, &checksum);

  let mnemonic_words = generate_mnemonic_words(&full_entropy, dictionary);
  let password = passphrase_text.unwrap_or("");
  let salt = format!("mnemonic{password}");
  let mut seed = [0u8; 64];
  
  // TODO: Create support for QRNG, File

  pbkdf2::derive(
    pbkdf2::PBKDF2_HMAC_SHA512,
    std::num::NonZeroU32::new(2048).unwrap(),
    salt.as_bytes(),
    &mnemonic_words.as_bytes(),
    &mut seed,
  );

  let seed_hex = hex::encode(&seed[..]);
  
  (full_entropy, mnemonic_words, seed_hex)
}


pub fn generate_pre_entropy(_source: &str, entropy_length: Option<usize>) -> String {
  let entropy_length = entropy_length.unwrap_or(256);

  let bytes_needed = (entropy_length + 7) / 8;
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
) -> String {
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

  let mnemonic_words_as_string = mnemonic_words_vector.join(" ");

  mnemonic_words_as_string
}


pub fn generate_master_keys_secp256k1(
  seed: &str,
  private_header: Option<&str>,
  public_header: Option<&str>,
) -> FunctionOutput<(String, String)> {
  let private_header = match private_header {
    Some(value) => value,
    None => "0x0488ADE4",
  };

  let public_header = match public_header {
    Some(value) => value,
    None => "0x0488B21E",
  };

  let private_header = match u32::from_str_radix(private_header.trim_start_matches("0x"), 16) {
    Ok(value) => value,
    Err(err) => {
      return Err(AppError::Custom(format!("Problem with parsing private_header: {}", err)));
    }
  };

  let public_header = match u32::from_str_radix(public_header.trim_start_matches("0x"), 16) {
    Ok(value) => value,
    Err(err) => {
      return Err(AppError::Custom(format!("Problem with parsing public_header: {}", err)));
    }
  };

  let seed_bytes = match hex::decode(seed) {
    Ok(value) => value,
    Err(err) => {
      return Err(AppError::Custom(format!("Problem with decoding seed_bytes: {}", err)));
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

  let master_private_key_encoded = bs58::encode(&master_private_key).into_string();
  let secp = secp256k1::Secp256k1::new();

  let array: [u8; 32] = master_private_key_bytes
    .try_into()
    .map_err(|_| AppError::Custom("master_private_key_bytes must be 32 bytes".into()))?;

  let master_secret_key = secp256k1::SecretKey::from_byte_array(array)
    .map_err(|err| AppError::Custom(format!("Invalid master_secret_key: {err:?}")))?;

  let master_public_key_bytes =
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

  // println!("Parsed private header {private_header:?}");
  // println!("Parsed public header {public_header:?}");
  // println!("Seed: {seed_bytes:?}");
  // println!("Hmac sha512 hash: {hmac_result:?}");
  // println!("Master key private bytes: {master_private_key_bytes:?}");
  // println!("Master key chain code: {master_chain_code_bytes:?}");
  // println!("Master private key: {master_private_key_encoded:?}");
  // println!("Master secret key {master_secret_key:?}");
  // println!("Master public key {master_public_key_bytes:?}");
  // println!("Master public key: {master_public_key_encoded:?}");

  Ok((master_private_key_encoded, master_public_key_encoded))
}

fn calculate_hmac_sha512_hash(key: &[u8], data: &[u8]) -> Vec<u8> {
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
  let hash = Sha256::digest(data);
  let double_hash = Sha256::digest(hash);
  let mut checksum = [0u8; 4];
  checksum.copy_from_slice(&double_hash[..4]);
  checksum
}