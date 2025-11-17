// authors = ["Control Owl <qr2m[at]r-o0-t[dot]wtf>"]
// license = "CC-BY-NC-ND-4.0  [2023-2025]  Control Owl"

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

use crate::{AppError, FunctionOutput, MasterKeyData, d3bug};
use ed25519_dalek::SigningKey;

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

  let mut private_key = <[u8; 32]>::try_from(&master_key[..])
    .map_err(|_| AppError::Custom("Master key must be 32 bytes".into()))?;

  let mut chain_code = <[u8; 32]>::try_from(&master_chain_code[..])
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

  let final_keys = derive_from_path_ed25519(master_key, chain_code, &path)?;
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

fn clamp_scalar(mut scalar: [u8; 32]) -> [u8; 32] {
  scalar[0] &= 0b1111_1000; // clear lowest 3 bits
  scalar[31] &= 0b0111_1111; // clear highest bit
  scalar[31] |= 0b0100_0000; // set second‑highest bit
  scalar
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

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_solana() {
    let seed_hex = "e97ab93c4961c77c62521f305aac17851bea814d05a78d3b5c254a3e5007456c856506c09f956d67808fb0e429ec6393825359bbd94d1a0e291aa468815f394b";
    let master = generate_master_keys_ed25519(seed_hex).unwrap();
    let path = "m/44'/501'/1'/0'";
    // Thank you https://solana.com/developers/cookbook/wallets/restore-from-mnemonic for test vectors <3
    // m/44'/501'/0'/0' => 5vftMkHL72JaJG6ExQfGAsT2uGVHpRR7oTNUPMs68Y2N
    // m/44'/501'/1'/0' => GcXbfQ5yY3uxCyBNDPBbR5FjumHf89E7YHXuULfGDBBv
    // m/44'/501'/2'/0' => 7QPgyQwNLqnoSwHEuK8wKy2Y3Ani6EHoZRihTuWkwxbc
    // m/44'/501'/3'/0' => 5aE8UprEEWtpVskhxo3f8ETco2kVKiZT9SS3D5Lcg8s2
    // m/44'/501'/4'/0' => 5n6afo6LZmzH1J4R38ZCaNSwaztLjd48nWwToLQkCHxp
    // m/44'/501'/5'/0' => 2Gr1hWnbaqGXMghicSTHncqV7GVLLddNFJDC7YJoso8M
    // m/44'/501'/6'/0' => BNMDY3tCyYbayMzBjZm8RW59unpDWcQRfVmWXCJhLb7D
    // m/44'/501'/7'/0' => 9CySTpi4iC85gMW6G4BMoYbNBsdyJrfseHoGmViLha63
    // m/44'/501'/8'/0' => ApteF7PmUWS8Lzm6tJPkWgrxSFW5LwYGWCUJ2ByAec91
    // m/44'/501'/9'/0' => 6frdqXQAgJMyKwmZxkLYbdGjnYTvUceh6LNhkQt2siQp

    let final_key = derive_from_path_ed25519(
      &master.master_private_key_bytes,
      &master.master_chain_code_bytes,
      path,
    )
    .unwrap();

    let address = bs58::encode(&final_key.child_public_key_bytes).into_string();
    assert_eq!(address, "GcXbfQ5yY3uxCyBNDPBbR5FjumHf89E7YHXuULfGDBBv");
    println!("Correct address: {address}");
  }
}
