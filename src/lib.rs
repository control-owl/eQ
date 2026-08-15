// authors = ["Control Owl <eq[at]r-o0-t[dot]wtf>"]
// license = "CC-BY-NC-ND-4.0  [2023-2026]  Control Owl"

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

use include_dir::{Dir, include_dir};
use sha2::{Digest, Sha256, Sha512};
use sysinfo::{RefreshKind, System};
use zeroize::Zeroizing;

pub static RES_DIR: Dir<'_> = include_dir!("res");
pub static DOC_DIR: Dir<'_> = include_dir!("doc");

const BLOCK_SIZE: usize = 128;
const HASH_SIZE: usize = 64;
// TODO: Check how many bytes is one address entry
const BYTES_PER_ROW: u64 = 450; // estimated, ????

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

pub fn get_free_memory_size() -> usize {
  let mut system = System::new_with_specifics(RefreshKind::everything().without_memory());
  system.refresh_memory();

  let available_memory = system.available_memory();

  if available_memory > 0 {
    ((available_memory as f64 * 0.8) / BYTES_PER_ROW as f64) as usize
  } else {
    // TODO: get total active coins number from ECDB
    // Minimum fallback
    300
  }
}

pub fn calculate_max_text_width(
  ui: &mut egui::Ui,
  texts: &[&str],
  font_id: egui::FontId,
  color: egui::Color32,
) -> f32 {
  ui.fonts_mut(|font| {
    texts
      .iter()
      .map(|text| font.layout_no_wrap(text.to_string(), font_id.clone(), color).size().x)
      .fold(0.0, f32::max)
  })
}

pub fn calculate_checksum_for_entropy(entropy: Zeroizing<String>) -> Zeroizing<String> {
  let entropy_binary: Zeroizing<Vec<u8>> = convert_string_to_binary(entropy.clone());
  let hash_raw_binary: Zeroizing<String> = convert_binary_to_string(Zeroizing::new(Sha256::digest(&entropy_binary).to_vec()));

  let checksum_length: Zeroizing<usize> = match entropy.len() {
    128 => Zeroizing::new(4),
    160 => Zeroizing::new(5),
    192 => Zeroizing::new(6),
    224 => Zeroizing::new(7),
    256 => Zeroizing::new(8),
    _ => {
      eprintln!("Wrong entropy length! Checksum not done");
      Zeroizing::new(0)
    }
  };

  Zeroizing::new(hash_raw_binary.chars().take(*checksum_length).collect())
}

pub fn convert_string_to_binary(input_value: Zeroizing<String>) -> Zeroizing<Vec<u8>> {
  Zeroizing::new(
    input_value
      .chars()
      .collect::<Vec<char>>()
      .chunks(8)
      .map(|chunk| chunk.iter().fold(0, |acc, &bit| (acc << 1) | (bit as u8 - b'0')))
      .collect(),
  )
}

pub fn convert_binary_to_string(input_value: Zeroizing<Vec<u8>>) -> Zeroizing<String> {
  Zeroizing::new(
    input_value
      .iter()
      .flat_map(|byte| (0..8).rev().map(move |i| ((byte >> i) & 1).to_string()))
      .collect(),
  )
}

pub fn get_text_from_resources(file_name: Zeroizing<String>) -> Zeroizing<String> {
  match RES_DIR.get_file(file_name.clone()) {
    Some(file) => match std::str::from_utf8(file.contents()) {
      Ok(text) => Zeroizing::new(text.to_string()),
      Err(err) => {
        eprintln!("Failed to read {file:?} as UTF-8: {err:?}");
        Zeroizing::new(String::new())
      }
    },
    None => {
      eprintln!("Failed to get {file_name:?} from embedded resources");
      Zeroizing::new(String::new())
    }
  }
}

pub fn get_file_from_resources(file_name: Zeroizing<String>) -> Result<&'static include_dir::File<'static>, String> {
  RES_DIR
    .get_file(file_name.as_str())
    .ok_or_else(|| format!("File '{:?}' not found in resources", file_name))
}

pub fn get_doc_from_resources(file_name: &str) -> Result<&'static include_dir::File<'static>, String> {
  DOC_DIR
    .get_file(file_name)
    .ok_or_else(|| format!("File '{:?}' not found in resources", file_name))
}

pub fn calculate_double_sha256_hash(input: Zeroizing<Vec<u8>>) -> Zeroizing<Vec<u8>> {
  let mut hasher = Sha256::new();
  hasher.update(input);

  let first_hash = hasher.finalize();

  let mut hasher = Sha256::new();
  hasher.update(first_hash);

  Zeroizing::new(hasher.finalize().to_vec())
}

pub fn calculate_sha256_and_ripemd160_hash(input: Zeroizing<Vec<u8>>) -> Zeroizing<Vec<u8>> {
  let mut hasher = Sha256::new();
  hasher.update(input);

  let sha256_hash: Zeroizing<Vec<u8>> = Zeroizing::new(hasher.finalize().to_vec());

  use ripemd::Digest;
  let mut ripemd = ripemd::Ripemd160::new();
  ripemd.update(sha256_hash);

  let ripemd160_hash: Zeroizing<Vec<u8>> = Zeroizing::new(ripemd.finalize().to_vec());

  ripemd160_hash
}

pub fn calculate_hmac_sha512_hash(
  key: Zeroizing<Vec<u8>>,
  data: Zeroizing<Vec<u8>>,
) -> Zeroizing<Vec<u8>> {
  let padded_key: Zeroizing<Vec<u8>> = if key.len() > BLOCK_SIZE {
    let mut hasher = Sha512::new();
    hasher.update(key);

    let mut hashed_key: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; HASH_SIZE]);
    hashed_key.copy_from_slice(&hasher.finalize());
    hashed_key.resize(BLOCK_SIZE, 0x00);

    hashed_key
  } else {
    let mut padded_key: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0x00; BLOCK_SIZE]);
    padded_key[..key.len()].copy_from_slice(&key);

    padded_key
  };

  assert_eq!(
    padded_key.len(),
    BLOCK_SIZE,
    "Critical error. Padded key length mismatch in calculate_hmac_sha512_hash"
  );

  let mut inner_pad: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0x36; BLOCK_SIZE]);
  let mut outer_pad: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0x5c; BLOCK_SIZE]);
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

  let final_hash: Zeroizing<Vec<u8>> = Zeroizing::new(hasher.finalize().to_vec());

  assert_eq!(
    final_hash.len(),
    HASH_SIZE,
    "Critical error. Final hash length mismatch in calculate_hmac_sha512_hash"
  );

  final_hash
}

pub fn calculate_sha256_hash(data: Zeroizing<Vec<u8>>) -> Zeroizing<Vec<u8>> {
  let mut hasher = Sha256::new();
  hasher.update(data);

  let sha256_hash: Zeroizing<Vec<u8>> = Zeroizing::new(hasher.finalize().iter().cloned().collect());

  sha256_hash
}

pub fn calculate_checksum_for_master_keys(data: Zeroizing<Vec<u8>>) -> Zeroizing<[u8; 4]> {
  let hash = Sha256::digest(data);
  let double_hash = Sha256::digest(hash);

  let mut checksum: Zeroizing<[u8; 4]> = Zeroizing::new([0u8; 4]);
  checksum.copy_from_slice(&double_hash[..4]);

  checksum
}

pub fn get_active_app_feature() -> &'static str {
  if cfg!(feature = "dev") {
    "dev"
  } else if cfg!(feature = "osk") {
    "osk"
  } else {
    "default"
  }
}

pub fn write_u32_le(
  buf: &mut Vec<u8>,
  v: u32,
) {
  buf.extend_from_slice(&v.to_le_bytes());
}

pub fn write_u16_le(
  buf: &mut Vec<u8>,
  v: u16,
) {
  buf.extend_from_slice(&v.to_le_bytes());
}

pub fn load_monero_wordlist() -> Vec<&'static str> {
  static WORDLIST: &str = include_str!("../res/wordlists/monero-english.txt");
  WORDLIST.lines().collect()
}

pub fn register_doc_images(ctx: &egui::Context) {
  fn register_dir(
    ctx: &egui::Context,
    dir: &include_dir::Dir<'static>,
  ) {
    use egui::load::Bytes;

    for entry in dir.entries() {
      match entry {
        include_dir::DirEntry::Dir(subdir) => {
          register_dir(ctx, subdir);
        }
        include_dir::DirEntry::File(file) => {
          let path = file.path().to_string_lossy().replace('\\', "/");
          let uri = format!("bytes://doc/{}", path);
          let bytes: &'static [u8] = file.contents();

          ctx.include_bytes(uri, Bytes::Static(bytes));
        }
      }
    }
  }

  register_dir(ctx, &crate::DOC_DIR);
}
