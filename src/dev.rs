// authors = ["Control Owl <eq[at]r-o0-t[dot]wtf>"]
// license = "CC-BY-NC-ND-4.0  [2023-2026]  Control Owl"

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

use crc32fast::Hasher as Crc32;
use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
use ring::hmac;
use sha3::{Digest, Keccak256};
use zeroize::Zeroizing;

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

pub fn monero_sc_reduce32(bytes: &[u8; 32]) -> Scalar {
  Scalar::from_bytes_mod_order(*bytes)
}

fn slip10_master(seed: &[u8]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
  let key = hmac::Key::new(hmac::HMAC_SHA512, b"ed25519 seed");
  let tag = hmac::sign(&key, seed);
  let result = tag.as_ref();

  let mut priv_key = Zeroizing::new([0u8; 32]);
  let mut chain = Zeroizing::new([0u8; 32]);

  priv_key.copy_from_slice(&result[..32]);
  chain.copy_from_slice(&result[32..]);

  (priv_key, chain)
}

fn slip10_child(
  parent_priv: &[u8; 32],
  parent_chain: &[u8; 32],
  index: u32,
) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
  debug_assert!(index >= 0x8000_0000);

  let mut data = [0u8; 37];
  data[0] = 0x00;
  data[1..33].copy_from_slice(parent_priv);
  data[33..37].copy_from_slice(&index.to_be_bytes());

  let key = hmac::Key::new(hmac::HMAC_SHA512, parent_chain);
  let tag = hmac::sign(&key, &data);
  let result = tag.as_ref();

  let mut child_priv = Zeroizing::new([0u8; 32]);
  let mut child_chain = Zeroizing::new([0u8; 32]);
  child_priv.copy_from_slice(&result[..32]);
  child_chain.copy_from_slice(&result[32..]);
  (child_priv, child_chain)
}

pub fn monero_slip0010_spend_key(bip39_seed: &[u8]) -> [u8; 32] {
  let (mut priv_key, mut chain) = slip10_master(bip39_seed);

  // m/44'
  let (p, c) = slip10_child(&priv_key, &chain, 44 | 0x8000_0000);
  priv_key = p;
  chain = c;

  // m/44'/128'
  let (p, c) = slip10_child(&priv_key, &chain, 128 | 0x8000_0000);
  priv_key = p;
  chain = c;

  // m/44'/128'/0'
  let (p, _) = slip10_child(&priv_key, &chain, 0 | 0x8000_0000);
  priv_key = p;

  Scalar::from_bytes_mod_order(*priv_key).to_bytes()
}

pub fn cn_fast_hash(data: &[u8]) -> [u8; 32] {
  let mut hasher = Keccak256::new();
  hasher.update(data);
  hasher.finalize().into()
}

pub fn monero_pubkey(priv_bytes: &[u8; 32]) -> [u8; 32] {
  let scalar = Scalar::from_bytes_mod_order(*priv_bytes);
  (ED25519_BASEPOINT_POINT * scalar).compress().to_bytes()
}

pub fn generate_monero_address(
  spend_pub: &[u8; 32],
  view_pub: &[u8; 32],
) -> String {
  let mut data = Vec::with_capacity(69);
  data.push(0x12); // mainnet
  data.extend_from_slice(spend_pub);
  data.extend_from_slice(view_pub);

  let checksum = cn_fast_hash(&data);
  data.extend_from_slice(&checksum[..4]);

  base58_monero::encode(&data).unwrap()
}

pub fn monero_from_bip39_slip0010(bip39_seed: &[u8]) -> (String, [u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
  let spend_priv = monero_slip0010_spend_key(bip39_seed);
  let view_priv = Scalar::from_bytes_mod_order(cn_fast_hash(&spend_priv)).to_bytes();

  let spend_pub = monero_pubkey(&spend_priv);
  let view_pub = monero_pubkey(&view_priv);

  let address = generate_monero_address(&spend_pub, &view_pub);

  (address, spend_priv, view_priv, spend_pub, view_pub)
}
