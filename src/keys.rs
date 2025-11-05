// authors = ["Control Owl <eq[at]r-o0-t[dot]wtf>"]
// license = "CC-BY-NC-ND-4.0  [2023-2025]  Control Owl"

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

use getrandom;
use ring::pbkdf2;

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
