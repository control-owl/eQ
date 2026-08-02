// authors = ["Control Owl <eq[at]r-o0-t[dot]wtf>"]
// license = "CC-BY-NC-ND-4.0  [2023-2026]  Control Owl"

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

use crc32fast::Hasher as Crc32;
use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
use tiny_keccak::{Hasher, Keccak};

const PREFIX_LEN: usize = 3;

pub fn load_monero_wordlist() -> Vec<&'static str> {
  static WORDLIST: &str = include_str!("../res/wordlists/monero-english.txt");
  WORDLIST.lines().collect()
}

pub fn monero_seed_to_mnemonic(
  seed: &[u8; 32],
  wordlist: &[&str],
) -> String {
  let n = wordlist.len() as u32;
  assert!(n > 0, "wordlist must not be empty");
  assert!(PREFIX_LEN <= 3, "prefix length should be 3");

  let mut words: Vec<&str> = Vec::with_capacity(25);
  let mut checksum_input = String::with_capacity(24 * PREFIX_LEN);

  for i in 0..8 {
    let start = i * 4;
    let chunk: [u8; 4] = [
      seed[start],
      seed[start + 1],
      seed[start + 2],
      seed[start + 3],
    ];

    let mut v: u32 = u32::from_le_bytes(chunk);

    let w1 = (v % n) as usize;
    v /= n;

    let w2_raw = (v % n) as usize;
    v /= n;

    let w3_raw = (v % n) as usize;

    let w2 = ((w2_raw as u32 + w1 as u32) % n) as usize;
    let w3 = ((w3_raw as u32 + w2 as u32) % n) as usize;

    words.push(wordlist[w1]);
    words.push(wordlist[w2]);
    words.push(wordlist[w3]);

    checksum_input.push_str(&wordlist[w1][..PREFIX_LEN]);
    checksum_input.push_str(&wordlist[w2][..PREFIX_LEN]);
    checksum_input.push_str(&wordlist[w3][..PREFIX_LEN]);
  }

  let mut hasher = Crc32::new();
  hasher.update(checksum_input.as_bytes());

  let crc = hasher.finalize();
  let checksum_index = (crc % 24) as usize;

  words.push(words[checksum_index]);

  words.join(" ")
}

pub fn cn_fast_hash(data: &[u8]) -> [u8; 32] {
  let mut keccak = Keccak::v256();
  let mut out = [0u8; 32];

  keccak.update(data);
  keccak.finalize(&mut out);

  out
}

pub fn monero_sc_reduce32(bytes: &[u8; 32]) -> Scalar {
  Scalar::from_bytes_mod_order(*bytes)
}

pub fn monero_secret_spend_key(seed: &[u8; 32]) -> [u8; 32] {
  monero_sc_reduce32(seed).to_bytes()
}

pub fn monero_secret_view_key(spend_priv: &[u8; 32]) -> [u8; 32] {
  let hash = cn_fast_hash(spend_priv);

  monero_sc_reduce32(&hash).to_bytes()
}

pub fn monero_pubkey(priv_bytes: &[u8; 32]) -> [u8; 32] {
  let scalar = monero_sc_reduce32(priv_bytes);
  let point = ED25519_BASEPOINT_POINT * scalar;

  point.compress().to_bytes()
}

pub fn generate_monero_address(
  spend_pub: &[u8; 32],
  view_pub: &[u8; 32],
) -> String {
  let mut data = Vec::with_capacity(69);

  data.push(0x12);
  data.extend_from_slice(spend_pub);
  data.extend_from_slice(view_pub);

  let checksum = cn_fast_hash(&data);
  data.extend_from_slice(&checksum[..4]);

  base58_monero::encode(&data).unwrap()
}
