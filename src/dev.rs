// authors = ["Control Owl <qr2m[at]r-o0-t[dot]wtf>"]
// license = "CC-BY-NC-ND-4.0  [2023-2025]  Control Owl"

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

use crate::{AppError, FunctionOutput, MasterKeyData, d3bug};
use ed25519_dalek::SigningKey;

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

// SOLANA

pub fn derive_from_path_ed25519(
  master_key: &[u8],
  master_chain_code: &[u8],
  path: &str,
) -> FunctionOutput<crate::keys::DerivationResult> {
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
    d3bug(&format!("master_key len {:?}", master_key.len()), "debug");
  }

  if master_chain_code.len() != 32 {
    return Err(AppError::Custom(format!(
      "Master chain key must be 32 bytes, got {}",
      master_chain_code.len()
    )));
  } else {
    d3bug(
      &format!("master_chain_code len {:?}", master_chain_code.len()),
      "debug",
    );
  }

  if !path.starts_with("m/") {
    return Err(AppError::Custom("Path must start with 'm/'".to_string()));
  }

  let mut private_key = master_key.to_vec();
  let mut chain_code = master_chain_code.to_vec();
  let mut public_key = Vec::new();

  for part in path.split('/').skip(1) {
    let hardened = part.ends_with("'");
    let index: u32 = match part.trim_end_matches("'").parse() {
      Ok(index) => index,
      Err(_) => return Err(AppError::Custom(format!("Invalid path index: {part}"))),
    };

    let effective_index = if hardened { index + 0x80000000 } else { index };
    // #[cfg(debug_assertions)]
    // dbg!(&effective_index);

    let derived = match derive_child_key_ed25519(&private_key, &chain_code, effective_index) {
      Some(derived) => derived,
      None => {
        return Err(AppError::Custom(format!(
          "Failed to derive child key for index: {part}"
        )));
      }
    };

    let derivation_result = match derived {
      Some(value) => value,
      None => return Err(AppError::Custom("Wrong derivation result".to_string())),
    };

    private_key = derivation_result.0.to_vec();
    chain_code = derivation_result.1.to_vec();
    public_key = derivation_result.2;
  }

  let chain_code_array: [u8; 32] = chain_code
    .try_into()
    .map_err(|err| AppError::Custom(format!("Chain code length invalid: {err:?}")))?;

  Ok(Some((
    private_key.try_into().map_err(|err| {
      AppError::Custom(format!("private_key expected a Vec of length 32: {err:?}"))
    })?,
    chain_code_array,
    public_key,
  )))
}

pub fn derive_child_key_ed25519(
  parent_key: &[u8],
  parent_chain_code: &[u8],
  index: u32,
) -> Option<crate::keys::DerivationResult> {
  if parent_key.len() != 32 || parent_chain_code.len() != 32 {
    eprintln!("Invalid parent_key or parent_chain_code length");
    return None;
  }

  let is_hard = index >= 0x80000000;

  // let data = if is_hard {
  //   let mut d = Vec::with_capacity(37);
  //   d.push(0u8);
  //   d.extend_from_slice(parent_key);
  //   d.extend_from_slice(&index.to_be_bytes());
  //   d
  // } else {
  //   let parent_sk = match SigningKey::try_from(parent_key) {
  //     Ok(sk) => sk,
  //     Err(_) => {
  //       eprintln!("Invalid parent private key");
  //       return None;
  //     }
  //   };
  //   let parent_public_key = parent_sk.verifying_key().to_bytes();
  //   let mut d = Vec::with_capacity(36);
  //   d.extend_from_slice(&parent_public_key);
  //   d.extend_from_slice(&index.to_be_bytes());
  //   d
  // };

  let data = if is_hard {
    let mut d = Vec::with_capacity(37);
    d.push(0u8); // Hardened derivation prefix
    d.extend_from_slice(parent_key);
    d.extend_from_slice(&index.to_be_bytes());
    d
  } else {
    // non-hard derivation, use public key (not supported for Ed25519 in solAna)
    eprintln!("Non-hardened derivation not supported for Ed25519");
    return None;
  };

  let result = e_q::calculate_hmac_sha512_hash(parent_chain_code, &data);
  if result.len() != 64 {
    eprintln!("calculate_hmac_sha512_hash len is not 64");
    return None;
  }

  let mut child_private_key_bytes: [u8; 32] = [0; 32];
  let mut child_chain_code_bytes: [u8; 32] = [0; 32];
  child_private_key_bytes.copy_from_slice(&result[..32]);
  child_chain_code_bytes.copy_from_slice(&result[32..]);

  clamp_ed25519_private_key(&mut child_private_key_bytes);

  let secret_key = SigningKey::from(child_private_key_bytes);
  let public_key = secret_key.verifying_key().to_bytes().to_vec();

  Some((child_private_key_bytes, child_chain_code_bytes, public_key).into())
}

pub fn generate_ed25519_address(
  public_key: &crate::keys::CryptoPublicKey,
) -> FunctionOutput<String> {
  let public_key_bytes = match public_key {
    crate::keys::CryptoPublicKey::Ed25519(key) => key.to_bytes().to_vec(),
    _ => {
      return Err(AppError::Custom(
        "generate_ed25519_address called with non-ed25519 key".to_string(),
      ));
    }
  };

  Ok(
    bs58::encode(&public_key_bytes)
      .with_alphabet(bs58::Alphabet::DEFAULT)
      .into_string(),
  )
}

// Helper function to clamp Ed25519 private key
fn clamp_ed25519_private_key(key: &mut [u8; 32]) {
  key[0] &= 0b1111_1000; // Clear lowest 3 bits
  key[31] &= 0b0111_1111; // Clear highest bit
  key[31] |= 0b0100_0000; // Set second-highest bit
}

pub fn generate_master_keys_ed25519(seed: &str) -> FunctionOutput<MasterKeyData> {
  let message = "ed25519 seed";
  let seed_bytes = hex::decode(seed).expect("Invalid seed format");
  let result = e_q::calculate_hmac_sha512_hash(message.as_bytes(), &seed_bytes);

  if result.len() != 64 {
    return Err(AppError::Custom(
      "Wrong hash length output in calculate_hmac_sha512_hash".to_string(),
    ));
  }

  let mut private_key = [0u8; 32];
  private_key.copy_from_slice(&result[..32]);

  let mut chain_code = [0u8; 32];
  chain_code.copy_from_slice(&result[32..]);

  clamp_ed25519_private_key(&mut private_key);

  let signing_key = SigningKey::from(private_key);
  let public_key = signing_key.verifying_key().to_bytes();

  let master_xprv = bs58::encode(&private_key).into_string();
  let master_xpub = bs58::encode(&public_key).into_string();

  Ok(MasterKeyData {
    master_private_key_encoded: master_xprv,
    master_private_key_bytes: private_key.to_vec(),
    master_public_key_encoded: master_xpub,
    master_public_key_bytes: public_key.to_vec(),
    master_chain_code_bytes: chain_code.to_vec(),
  })
}

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..
