// authors = ["Control Owl <eq[at]r-o0-t[dot]wtf>"]
// license = "CC-BY-NC-ND-4.0  [2023-2025]  Control Owl"

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

use sysinfo::{RefreshKind, System};
use sha2::{Digest, Sha256};
use include_dir::{Dir, include_dir};

pub static RES_DIR: Dir<'_> = include_dir!("res");

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

pub fn get_free_memory_size() -> usize {
  let mut system = System::new_with_specifics(RefreshKind::everything().without_memory());
  system.refresh_memory();

  let available_memory = system.available_memory(); // in bytes

  // TODO: Check how many bytes is one address entry
  const BYTES_PER_ROW: u64 = 450; // estimated, ????

  if available_memory > 0 {
    ((available_memory as f64 * 0.8) / BYTES_PER_ROW as f64) as usize
  } else {
    // TODO: get total active coins number from ECDB
    270 // Minimum fallback
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
      .map(|text| {
        font.layout_no_wrap(text.to_string(), font_id.clone(), color)
          .size()
          .x
      })
      .fold(0.0, f32::max)
  })
}

pub fn calculate_checksum_for_entropy(entropy: &str) -> String {
  let entropy_binary = convert_string_to_binary(entropy);
  let hash_raw_binary: String = convert_binary_to_string(&Sha256::digest(&entropy_binary));

  let checksum_length = match entropy.len() {
    128 => 4,
    160 => 5,
    192 => 6,
    224 => 7,
    256 => 8,
    _ => {
      eprintln!("Wrong entropy length! Checksum not done");
      0
    }
  };

  hash_raw_binary
    .chars()
    .take(checksum_length.try_into().unwrap_or_default())
    .collect()
}

pub fn convert_string_to_binary(input_value: &str) -> Vec<u8> {
  input_value
    .chars()
    .collect::<Vec<char>>()
    .chunks(8)
    .map(|chunk| {
      chunk
        .iter()
        .fold(0, |acc, &bit| (acc << 1) | (bit as u8 - b'0'))
    })
    .collect()
}

pub fn convert_binary_to_string(input_value: &[u8]) -> String {
  input_value
    .iter()
    .flat_map(|byte| (0..8).rev().map(move |i| ((byte >> i) & 1).to_string()))
    .collect()
}

pub fn get_text_from_resources(file_name: &str) -> String {
  match RES_DIR.get_file(file_name) {
    Some(file) => match std::str::from_utf8(file.contents()) {
      Ok(text) => {
        text.to_string()
      }
      Err(err) => {
        eprintln!("Failed to read {file_name} as UTF-8: {err}");
        String::new()
      }
    },
    None => {
      eprintln!("Failed to get {file_name} from embedded resources");
      String::new()
    }
  }
}


