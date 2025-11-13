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

    let derived_keys = match derive_child_key_ed25519(&private_key, &chain_code, effective_index) {
      Ok(keys) => keys,
      Err(err) => {
        return Err(AppError::Custom(format!(
          "Failed to derive child key for index: {err}"
        )));
      }
    };

    private_key = derived_keys.child_secret_key_bytes;
    chain_code = derived_keys.child_chain_code_bytes;
    public_key = derived_keys.child_public_key_bytes;
  }

  let chain_code_array: [u8; 32] = chain_code
    .try_into()
    .map_err(|err| AppError::Custom(format!("Chain code length invalid: {err:?}")))?;

  Ok(crate::keys::ChildKeys {
    child_secret_key_bytes: private_key.try_into().map_err(|err| {
      AppError::Custom(format!("private_key expected a Vec of length 32: {err:?}"))
    })?,
    child_chain_code_bytes: chain_code_array.to_vec(),
    child_public_key_bytes: public_key,
  })
}

pub fn derive_child_key_ed25519(
  parent_key: &[u8],
  parent_chain_code: &[u8],
  index: u32,
) -> FunctionOutput<crate::keys::ChildKeys> {
  if parent_key.len() != 32 || parent_chain_code.len() != 32 {
    return Err(AppError::Custom(
      "Invalid parent_key or parent_chain_code length".to_string(),
    ));
  }

  let is_hard = index >= 0x80000000;

  let data = if is_hard {
    let mut d = Vec::with_capacity(37);
    d.push(0u8); // Hardened derivation prefix
    d.extend_from_slice(parent_key);
    d.extend_from_slice(&index.to_be_bytes());
    d
  } else {
    return Err(AppError::Custom(
      "Non-hardened derivation not supported for Ed25519".to_string(),
    ));
  };

  let result = e_q::calculate_hmac_sha512_hash(parent_chain_code, &data);
  if result.len() != 64 {
    return Err(AppError::Custom(
      "calculate_hmac_sha512_hash len is not 64".to_string(),
    ));
  }

  let mut child_private_key_bytes: [u8; 32] = [0; 32];
  let mut child_chain_code_bytes: [u8; 32] = [0; 32];
  child_private_key_bytes.copy_from_slice(&result[..32]);
  child_chain_code_bytes.copy_from_slice(&result[32..]);

  clamp_ed25519_private_key(&mut child_private_key_bytes);

  let secret_key = SigningKey::from(child_private_key_bytes);
  let public_key = secret_key.verifying_key().to_bytes().to_vec();

  Ok(crate::keys::ChildKeys {
    child_secret_key_bytes: child_private_key_bytes.to_vec(),
    child_chain_code_bytes: child_chain_code_bytes.to_vec(),
    child_public_key_bytes: public_key,
  })
}

pub fn generate_ed25519_address(
  ingredients: crate::AddressData,
) -> FunctionOutput<crate::keys::AddressResult> {
  let alphabet = match ingredients.coin_index {
    144 => bs58::Alphabet::RIPPLE,
    _ => bs58::Alphabet::DEFAULT,
  };

  let address = bs58::encode(ingredients.public_key_hash)
    .with_alphabet(alphabet)
    .into_string();

  // HOW?????
  let public_key = "".to_string();
  let private_key = "".to_string();

  Ok(Some(crate::keys::Address {
    address,
    public_key,
    private_key,
  }))
}

fn clamp_ed25519_private_key(key: &mut [u8; 32]) {
  key[0] &= 0b1111_1000; // Clear lowest 3 bits
  key[31] &= 0b0111_1111; // Clear highest bit
  key[31] |= 0b0100_0000; // Set second-highest bit
}

pub fn generate_master_keys_ed25519(seed: &str) -> FunctionOutput<MasterKeyData> {
  let message = b"ed25519 seed";
  let seed_bytes = match hex::decode(seed) {
    Ok(values) => values,
    Err(err) => {
      return Err(AppError::Custom(format!("Can not decode seed: {}", err)));
    }
  };

  let result = e_q::calculate_hmac_sha512_hash(message, &seed_bytes);

  if result.len() != 64 {
    return Err(AppError::Custom(
      "Wrong hash length output in calculate_hmac_sha512_hash".to_string(),
    ));
  }

  let mut master_private_key = [0u8; 32];
  master_private_key.copy_from_slice(&result[..32]);

  let mut master_chain_code = [0u8; 32];
  master_chain_code.copy_from_slice(&result[32..]);

  let signing_key = SigningKey::from_bytes(&master_private_key);
  let public_key = signing_key.verifying_key();

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

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..
