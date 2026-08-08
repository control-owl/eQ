// authors = ["Control Owl <eq[at]r-o0-t[dot]wtf>"]
// license = "CC-BY-NC-ND-4.0  [2023-2026]  Control Owl"

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

use eframe::egui;
use egui::Color32;
use egui_extras::{Column, TableBuilder};
use std::collections::BTreeMap;
use std::io::Write;
use zeroize::Zeroize;
use zeroize::{ZeroizeOnDrop, Zeroizing};

mod crypt;
mod keys;
mod test_vectors;

#[cfg(feature = "dev")]
mod dev;

mod help;

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

const APP_NAME: Option<&str> = option_env!("CARGO_PKG_NAME");
const APP_DESCRIPTION: Option<&str> = option_env!("CARGO_PKG_DESCRIPTION");
const APP_VERSION: Option<&str> = option_env!("CARGO_PKG_VERSION");
const APP_LICENSE: Option<&str> = option_env!("CARGO_PKG_LICENSE");
const LICENSE_TEXT: &str = include_str!("../LICENSE");
const DISCLAIMER_TEXT: &str = include_str!("../doc/disclaimer.md");
const GUI_MARGIN: f32 = 10.0;
const VALID_ENTROPY_SOURCES: &[&str] = &[
  "RNG",
  "QRNG",
  #[cfg(feature = "dev")]
  "File",
];
const VALID_LANG_CODES: &[&str] = &["EN", "CS", "FR", "IT", "PT", "ES", "ZH-CN", "ZH-TW", "JA", "KO"];
const ADD_ADDRESS_COUNT: &[u32] = &[1, 5, 10, 20, 50, 100];
const VALID_MNEMONIC_SOURCES: &[&str] = &["RNG", "Custom", "Off"];
const VALID_MNEMONIC_LENGTHS: &[usize] = &[24, 21, 18, 15, 12];
// const VALID_BIP_DERIVATIONS: &[u32] = &[32, 44];
const TEXT_WRAPPER: f32 = 350.0;
const PROJECT_MOTO: &str = "Your entropy, your crypto, your control";
const STATUS_BAR_BACKGROUND_COLOR: Color32 = egui::Color32::from_rgb(7, 4, 16);

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

#[derive(Debug)]
pub enum CryptoPublicKey {
  Secp256k1(secp256k1::PublicKey),
  Ed25519(ed25519_dalek::VerifyingKey),
}

pub type FunctionOutput<T> = Result<T, AppError>;

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

#[derive(Debug)]
pub struct AppError(String);

impl AppError {
  #[track_caller]
  pub fn log(msg: impl Into<String>) -> Self {
    let error = AppError(msg.into());

    error.fancy_print();
    error
  }

  pub fn fancy_print(&self) {
    d3bug(&self.0, "error");
  }
}

impl std::fmt::Display for AppError {
  fn fmt(
    &self,
    f: &mut std::fmt::Formatter,
  ) -> std::fmt::Result {
    write!(f, "{}", self.0)
  }
}

pub fn d3bug(
  message: &str,
  msg_type: &str,
) {
  let (color_code, prefix) = match msg_type {
    "info" => ("\x1b[34m", "[INFO] "),       // Blue
    "debug" => ("\x1b[32m", "[DEBUG] "),     // Green
    "error" => ("\x1b[31m", "[ERROR] "),     // Red
    "warning" => ("\x1b[33m", "[WARNING] "), // Yellow
    _ => ("\x1b[0m", "[UNKNOWN] "),          // Default/reset
  };

  let reset = "\x1b[0m";

  #[cfg(debug_assertions)]
  if msg_type == "debug" {
    println!("{color_code}{prefix}{message}{reset}");
  }

  if msg_type != "debug" {
    println!("{color_code}{prefix}{message}{reset}");
  }
}

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

#[derive(Zeroize, ZeroizeOnDrop, Debug, Clone, Default)]
struct SeedSecretData {
  entropy_source: Zeroizing<String>,
  entropy_length: Zeroizing<usize>,
  raw_entropy: Zeroizing<String>,
  entropy_checksum: Zeroizing<String>,
  full_entropy: Zeroizing<String>,
  mnemonic_words: Zeroizing<String>,
  mnemonic_passphrase: Zeroizing<String>,
  mnemonic_passphrase_source: Zeroizing<String>,
  mnemonic_dictionary: Zeroizing<MnemonicLanguage>,
  pub seed: Zeroizing<String>,
}

impl SeedSecretData {
  fn new() -> Self {
    // TODO: Get values from local config
    Self {
      entropy_source: Zeroizing::new(String::from("RNG")),
      mnemonic_dictionary: Zeroizing::new(MnemonicLanguage::English),
      entropy_length: Zeroizing::new(256),
      mnemonic_passphrase: Zeroizing::new(String::new()),
      mnemonic_passphrase_source: Zeroizing::new(String::from("RNG")),
      mnemonic_words: Zeroizing::new(String::new()),
      seed: Zeroizing::new(String::new()),
      full_entropy: Zeroizing::new(String::new()),
      entropy_checksum: Zeroizing::new(String::new()),
      raw_entropy: Zeroizing::new(String::new()),
    }
  }
}

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

#[derive(Zeroize, ZeroizeOnDrop, Debug, Clone, Default)]
struct SecretKeyData {
  master_secp256k1_keys: Zeroizing<MasterSecp256k1KeySecretData>,
  child_secp256k1_keys: Zeroizing<ChildSecp256k1KeySecretData>,
  master_ed25519_keys: Zeroizing<MasterEd25519KeySecretData>,
  child_ed25519_keys: Zeroizing<ChildEd25519KeySecretData>,

  monero_keys: Zeroizing<MoneroKeySecretData>,
  cardano_keys: Zeroizing<CardanoKeySecretData>,
}

#[derive(Zeroize, ZeroizeOnDrop, Debug, Clone, Default)]
struct MasterSecp256k1KeySecretData {
  master_private_key_encoded: Zeroizing<String>,
  master_private_key_bytes: Zeroizing<Vec<u8>>,
  master_public_key_encoded: Zeroizing<String>,
  master_public_key_bytes: Zeroizing<Vec<u8>>,
  master_chain_code_bytes: Zeroizing<Vec<u8>>,
}

#[derive(Zeroize, ZeroizeOnDrop, Clone, Debug, Default)]
struct ChildSecp256k1KeySecretData {
  child_private_key_bytes: Zeroizing<Vec<u8>>,
  child_public_key_bytes: Zeroizing<Vec<u8>>,
  child_chain_code_bytes: Zeroizing<Vec<u8>>,
}

#[derive(Zeroize, ZeroizeOnDrop, Debug, Clone, Default)]
struct MasterEd25519KeySecretData {
  master_private_key_encoded: Zeroizing<String>,
  master_private_key_bytes: Zeroizing<Vec<u8>>,
  master_public_key_encoded: Zeroizing<String>,
  master_public_key_bytes: Zeroizing<Vec<u8>>,
  master_chain_code_bytes: Zeroizing<Vec<u8>>,
}

#[derive(Zeroize, ZeroizeOnDrop, Clone, Debug, Default)]
struct ChildEd25519KeySecretData {
  child_private_key_bytes: Zeroizing<Vec<u8>>,
  child_public_key_bytes: Zeroizing<Vec<u8>>,
  child_chain_code_bytes: Zeroizing<Vec<u8>>,
}

#[derive(Zeroize, ZeroizeOnDrop, Debug, Clone, Default)]
pub struct MoneroKeySecretData {
  monero_mnemonic_words: Zeroizing<String>,
  monero_spend_key: Zeroizing<String>,
}

type MoneroKeys = (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>);

#[derive(Zeroize, ZeroizeOnDrop, Debug, Clone, Default)]
pub struct CardanoKeySecretData {
  pub payment_private_key: Zeroizing<String>,
  pub payment_chain_code: Zeroizing<String>,
  pub payment_public_key: Zeroizing<String>,

  pub stake_private_key: Zeroizing<String>,
  pub stake_chain_code: Zeroizing<String>,
  pub stake_public_key: Zeroizing<String>,
}

// type CardanoKeys = (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>);

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

#[derive(Zeroize, ZeroizeOnDrop, Debug, Clone, Default)]
struct DerivationPathData {
  purpose: Zeroizing<u32>,
  purpose_hardened: Zeroizing<bool>,

  coin: Zeroizing<u32>,
  coin_hardened: Zeroizing<bool>,

  account: Zeroizing<u32>,
  account_hardened: Zeroizing<bool>,

  change: Zeroizing<u32>,
  change_hardened: Zeroizing<bool>,

  address: Zeroizing<u32>,
  address_hardened: Zeroizing<bool>,

  last_index: Zeroizing<u32>,
}

#[derive(Zeroize, ZeroizeOnDrop, Debug, Clone, Default)]
struct AddressPublicData {
  coin_name: Zeroizing<String>,
  derivation_path: Zeroizing<DerivationPathData>,
  public_key_hash: Zeroizing<String>,
  key_derivation: Zeroizing<String>,
  wallet_import_format: Zeroizing<String>,
  hash: Zeroizing<String>,
  evm: Zeroizing<bool>,
}

#[derive(Zeroize, ZeroizeOnDrop, Debug, Clone)]
struct AddressPrivateData {
  coin_index: Zeroizing<u32>,
  path: Zeroizing<String>,
  address: Zeroizing<String>,
  public_key: Zeroizing<String>,
  private_key: Zeroizing<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Addresses(BTreeMap<String, Vec<AddressPrivateData>>);

impl Zeroize for Addresses {
  fn zeroize(&mut self) {
    for vec in self.0.values_mut() {
      vec.zeroize();
    }
    self.0.clear();
  }
}

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

#[derive(Zeroize, ZeroizeOnDrop, Debug, Clone, Default)]
struct ExtraWalletData {
  unify_evm: bool,
  unify_master_keys: bool,
  hardened_address: bool,
  slip_derivation_path: bool,

  bitcoin_legacy_addresses: bool,
  zilliqa_legacy_addresses: bool,
  litecoin_legacy_addresses: bool,
  cardano_byron_derivation: bool,

  active_bip: u32,
  address_count: u32,
}

impl ExtraWalletData {
  fn new() -> Self {
    ExtraWalletData {
      unify_evm: false,
      unify_master_keys: true,
      hardened_address: true,
      slip_derivation_path: true,

      bitcoin_legacy_addresses: false,
      zilliqa_legacy_addresses: false,
      litecoin_legacy_addresses: false,
      cardano_byron_derivation: false,

      active_bip: 44,
      address_count: 10,
    }
  }
}

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

#[derive(Debug, Clone, Default, Zeroize, ZeroizeOnDrop)]
pub enum MnemonicLanguage {
  #[default]
  English,

  Czech,
  French,
  Italian,
  Portuguese,
  Spanish,
  ChineseSimplified,
  ChineseTraditional,
  Japanese,
  Korean,
}

impl MnemonicLanguage {
  pub const ALL: [Self; 10] = [
    Self::English,
    Self::Czech,
    Self::French,
    Self::Italian,
    Self::Portuguese,
    Self::Spanish,
    Self::ChineseSimplified,
    Self::ChineseTraditional,
    Self::Japanese,
    Self::Korean,
  ];

  pub const fn display_name(&self) -> &'static str {
    match self {
      Self::English => "English",
      Self::Czech => "Czech",
      Self::French => "French",
      Self::Italian => "Italian",
      Self::Portuguese => "Portuguese",
      Self::Spanish => "Spanish",
      Self::ChineseSimplified => "Chinese Simplified",
      Self::ChineseTraditional => "Chinese Traditional",
      Self::Japanese => "Japanese",
      Self::Korean => "Korean",
    }
  }

  pub const fn short_name(&self) -> &'static str {
    match self {
      Self::English => "EN",
      Self::Czech => "CS",
      Self::French => "FR",
      Self::Italian => "IT",
      Self::Portuguese => "PT",
      Self::Spanish => "ES",
      Self::ChineseSimplified => "ZH-CN",
      Self::ChineseTraditional => "ZH-TW",
      Self::Japanese => "JA",
      Self::Korean => "KO",
    }
  }

  pub const fn filename(&self) -> &'static str {
    match self {
      Self::English => "english.txt",
      Self::Czech => "czech.txt",
      Self::French => "french.txt",
      Self::Italian => "italian.txt",
      Self::Portuguese => "portuguese.txt",
      Self::Spanish => "spanish.txt",
      Self::ChineseSimplified => "chinese_simplified.txt",
      Self::ChineseTraditional => "chinese_traditional.txt",
      Self::Japanese => "japanese.txt",
      Self::Korean => "korean.txt",
    }
  }

  pub fn get_dictionary(language: &str) -> Self {
    match language {
      "Czech" => MnemonicLanguage::Czech,
      "French" => MnemonicLanguage::French,
      "Italian" => MnemonicLanguage::Italian,
      "Portuguese" => MnemonicLanguage::Portuguese,
      "Spanish" => MnemonicLanguage::Spanish,
      "Chinese Simplified" => MnemonicLanguage::ChineseSimplified,
      "Chinese Traditional" => MnemonicLanguage::ChineseTraditional,
      "Japanese" => MnemonicLanguage::Japanese,
      "Korean" => MnemonicLanguage::Korean,
      _ => MnemonicLanguage::English,
    }
  }
}

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

#[derive(Zeroize, ZeroizeOnDrop, Debug, Clone)]
struct GuiSettings {
  theme: String,
  _language: String,
  maximized: bool,
  zoom_factor: f32,

  max_rows: usize,

  save_dialog: crypt::SaveWalletDialog,
  open_dialog: crypt::OpenWalletDialog,
  secrets_dialog: crypt::ShowSecretsDialog,
  anu_dialog: crypt::ShowAnuDialog,

  help_dialog: help::HelpWindow,

  version_dialog: ShowAboutWindow,
  mnemonic_passphrase_dialog: ShowCustomMnemonicWindow,

  hide_private_keys: bool,
  hide_public_keys: bool,

  show_disclaimer: bool,

  coin_filter: String,
}

impl GuiSettings {
  fn new() -> Self {
    let get_max_rows = e_q::get_free_memory_size();

    GuiSettings {
      theme: "Dark".to_string(),
      _language: "English".to_string(),
      maximized: false,
      zoom_factor: 1.0,

      max_rows: get_max_rows,

      save_dialog: crypt::SaveWalletDialog::new(),
      open_dialog: crypt::OpenWalletDialog::default(),
      secrets_dialog: crypt::ShowSecretsDialog::new(),
      anu_dialog: crypt::ShowAnuDialog::new(),

      help_dialog: help::HelpWindow::new(),

      version_dialog: ShowAboutWindow::default(),
      mnemonic_passphrase_dialog: ShowCustomMnemonicWindow::default(),

      hide_private_keys: if cfg!(feature = "dev") { false } else { true },
      hide_public_keys: if cfg!(feature = "dev") { false } else { true },

      show_disclaimer: false,

      coin_filter: String::new(),
    }
  }
}

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

#[derive(Zeroize, ZeroizeOnDrop, Debug, Clone, Default)]
struct CryptoWallet {
  seed_secret: Zeroizing<SeedSecretData>,
  secret_keys: Zeroizing<SecretKeyData>,
  address_components: Zeroizing<AddressPublicData>,
  addresses_by_coin: Zeroizing<Addresses>,
  wallet_data: Zeroizing<ExtraWalletData>,
  wallet_gen_state: WalletGenState,
}

impl CryptoWallet {
  fn new() -> Self {
    // TODO: Get values from local config
    Self {
      seed_secret: Zeroizing::new(SeedSecretData::new()),
      secret_keys: Zeroizing::new(SecretKeyData::default()),
      address_components: Zeroizing::new(AddressPublicData::default()),
      addresses_by_coin: Zeroizing::new(Addresses(BTreeMap::new())),
      wallet_data: Zeroizing::new(ExtraWalletData::new()),
      wallet_gen_state: WalletGenState::Idle,
    }
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Zeroize, ZeroizeOnDrop)]
enum WalletGenState {
  #[default]
  Idle,

  WaitingForQrng,
  WaitingForPassphrase,
  ReadyToGenerate,
}

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

struct EgoQuantum {
  wallet: Zeroizing<CryptoWallet>,
  gui: GuiSettings,
}

impl EgoQuantum {
  fn new() -> Self {
    // TODO: Get values from local config
    Self {
      wallet: Zeroizing::new(CryptoWallet::new()),
      gui: GuiSettings::new(),
    }
  }

  fn generate_new_wallet(
    &mut self,
    entropy_source: Option<Zeroizing<String>>,
  ) -> FunctionOutput<()> {
    let entropy_source = entropy_source.unwrap_or_else(|| self.get_entropy_source());
    self.generate_seed_if_missing(entropy_source.clone())?;
    self.generate_master_keys_if_missing()?;
    self.generate_addresses_for_all_coins()?;

    Ok(())
  }

  fn generate_seed_if_missing(
    &mut self,
    entropy_source: Zeroizing<String>,
  ) -> FunctionOutput<()> {
    if self.wallet.seed_secret.raw_entropy.is_empty() || self.wallet.seed_secret.full_entropy.is_empty() {
      match keys::generate_seed(&mut self.wallet, entropy_source.clone()) {
        Ok(_) => {}
        Err(err) => {
          return Err(AppError::log(format!("Problem with generating seed: {}", err)));
        }
      };
    };

    Ok(())
  }

  fn generate_master_keys_if_missing(&mut self) -> FunctionOutput<()> {
    if self.wallet.secret_keys.master_secp256k1_keys.master_private_key_encoded.is_empty() {
      match keys::generate_secp256k1_master_keys(&mut self.wallet) {
        Ok(_) => {}
        Err(err) => {
          return Err(AppError::log(format!("Problem with generating secp256k1 master keys: {}", err)));
        }
      };
    };

    if self.wallet.secret_keys.master_ed25519_keys.master_private_key_encoded.is_empty() {
      match keys::generate_ed25519_master_keys(&mut self.wallet) {
        Ok(_) => {}
        Err(err) => {
          return Err(AppError::log(format!("Problem with generating ed25519 master keys: {}", err)));
        }
      };
    };

    Ok(())
  }

  fn generate_addresses_for_all_coins(&mut self) -> FunctionOutput<()> {
    match keys::generate_addresses_for_all_coins(&mut self.wallet) {
      Ok(_) => {}
      Err(err) => {
        return Err(AppError::log(format!("Problem with generating seed: {}", err)));
      }
    };

    Ok(())
  }

  fn draw_address_option(
    &mut self,
    ui: &mut egui::Ui,
    active: bool,
    label: &str,
    example: &str,
  ) -> bool {
    let active_text = &mut self.get_text_color();
    let inactive_text = ui.style().visuals.text_color();
    let example_text = inactive_text.gamma_multiply(0.7);
    let row_height = 40.0;
    let left_icon_x = 17.0;
    let text_x_offset = left_icon_x * 2.0;
    let radio_outer_radius = 7.0;
    let radio_inner_radius = 4.0;
    let menu_width: f32 = 350.0;

    let (rect, resp) = ui.allocate_exact_size(egui::Vec2::new(menu_width, row_height), egui::Sense::click());

    if resp.hovered() {
      let hover_fill = ui.style().visuals.widgets.hovered.bg_fill;
      ui.painter().rect_filled(rect.shrink(2.0), 6.0, hover_fill);
    }

    let center = rect.left_center();
    let icon_center = egui::pos2(center.x + left_icon_x, center.y);

    ui.painter().circle_stroke(
      icon_center,
      radio_outer_radius,
      egui::Stroke::new(1.0, inactive_text.linear_multiply(0.18)),
    );
    if active {
      ui.painter().circle_filled(icon_center, radio_inner_radius, *active_text);
    }

    let text_pos = egui::pos2(center.x + text_x_offset, rect.top() + 6.0);
    ui.painter().text(
      text_pos,
      egui::Align2::LEFT_TOP,
      label,
      egui::FontId::proportional(13.0),
      if active { *active_text } else { inactive_text },
    );

    let example_pos = egui::pos2(center.x + text_x_offset, rect.top() + 22.0);
    ui.painter()
      .text(example_pos, egui::Align2::LEFT_TOP, example, egui::FontId::monospace(10.0), example_text);

    resp.clicked() && !active
  }

  fn render_wallet_header(
    &mut self,
    ui: &mut egui::Ui,
  ) {
    let devel = String::from("Still in development");
    let has_addresses = !self.wallet.addresses_by_coin.0.is_empty();

    egui::MenuBar::new().ui(ui, |ui| {
      ui.menu_button("File", |ui| {
        if ui.add_enabled(has_addresses, egui::Button::new("New")).on_hover_text("Create new wallet").clicked() {
          let active_theme = self.gui.theme.clone();

          *self = Self::new();

          self.gui.theme = active_theme;
        }

        if ui.add_enabled(true, egui::Button::new("Open")).on_disabled_hover_text(&devel).on_hover_text("Open wallet from file").clicked() {
          self.gui.open_dialog.password.clear();
          self.gui.open_dialog.selected_svgs.clear();

          self.gui.open_dialog.open = true;
        }


        if ui
          .add_enabled(has_addresses, egui::Button::new("Save"))
          .on_disabled_hover_text("Generate wallet first")
          .on_hover_text("Save wallet to file")
          .clicked()
        {
          use std::{cell::RefCell, rc::Rc};

          self.gui.save_dialog.wallet_name.clear();
          self.gui.save_dialog.password.clear();
          self.gui.save_dialog.password_confirm.clear();
          self.gui.save_dialog.wallet_to_save = Some(Rc::new(RefCell::new(self.wallet.clone())));
          self.gui.save_dialog.open = true;

        }

        ui.separator();

        ui.menu_button("Import...", |ui| {
          if ui.add_enabled(false, egui::Button::new("Entropy")).on_disabled_hover_text(&devel).on_hover_text("Import entropy").clicked() {
            // TODO: Create import entropy
          }

          if ui
            .add_enabled(false, egui::Button::new("Mnemonic words"))
            .on_disabled_hover_text(&devel)
            .on_hover_text("Import mnemonic words")
            .clicked()
          {
            // TODO: Create import mnemonic words
          }

          if ui.add_enabled(false, egui::Button::new("Seed")).on_disabled_hover_text(&devel).on_hover_text("Import seed").clicked() {
            // TODO: Create import Seed
          }

          if ui
            .add_enabled(false, egui::Button::new("Master private key"))
            .on_disabled_hover_text(&devel)
            .on_hover_text("Import master private key")
            .clicked()
          {
            // TODO: Create import Master private key
          }
        });

        ui.menu_button("Export...", |ui| {
          if ui
              .add_enabled(has_addresses, egui::Button::new("Address table (CSV) public"))
              .clicked()
          &&
            let Some(path) = rfd::FileDialog::new()
                .set_file_name("addresses_public.csv")
                .save_file()
            {
                if let Err(e) = export_addresses_csv(&self.wallet.addresses_by_coin, &path, false) {
                    // handle error: show message, log, etc.
                    eprintln!("Export failed: {}", e);
                } else {
                    // success feedback
                }
            }

          if ui
            .add_enabled(has_addresses, egui::Button::new("Address table (CSV) all"))
            .clicked()
          &&
            let Some(path) = rfd::FileDialog::new()
              .set_file_name("addresses_all.csv")
              .save_file()
            {
              if let Err(e) = export_addresses_csv(&self.wallet.addresses_by_coin, &path, true) {
                eprintln!("Export failed: {}", e);
              } else {
                // success feedback
              }
            }
        });

        ui.separator();

        if ui.button("Quit").clicked() {
          ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
        }
      });

      ui.menu_button("Zoom", |ui| {
        if ui.button("Zoom In").clicked() {
          self.gui.zoom_factor = (self.gui.zoom_factor + 0.1).clamp(0.5, 2.0);
          ui.ctx().set_zoom_factor(self.gui.zoom_factor);
        }
        if ui.button("Zoom Out").clicked() {
          self.gui.zoom_factor = (self.gui.zoom_factor - 0.1).clamp(0.5, 2.0);
          ui.ctx().set_zoom_factor(self.gui.zoom_factor);
        }

        ui.separator();

        if ui.button("Reset Zoom").clicked() {
          self.gui.zoom_factor = 1.0;
          ui.ctx().set_zoom_factor(self.gui.zoom_factor);
        }
      });

      ui.menu_button("Theme", |ui| {
        if ui.button("Light").clicked() {
          self.gui.theme = "Light".to_string();
        }

        if ui.button("Dark").clicked() {
          self.gui.theme = "Dark".to_string();
        }
      });

      ui.menu_button("Privacy", |ui| {
        let hide_public_keys_column_label = [
          "When enabled:",
          "Public key column will be hidden.",
          "\n",
          "When disabled:",
          "All public keys will be visible.",
        ];

        let hide_public_keys_column_resp: egui::Response = ui.add_enabled(true,egui::Checkbox::new(&mut self.gui.hide_public_keys, "Hide public keys"));
        hide_public_keys_column_resp.on_hover_text(hide_public_keys_column_label.join("\n")).on_disabled_hover_text(&devel);

        let hide_private_keys_label = [
          "When enabled:",
          "Private keys will be hidden until you move mouse over it.",
          "\n",
          "When disabled:",
          "All private keys will be visible.",
        ];

        let hide_private_keys_resp: egui::Response = ui.add_enabled(true,egui::Checkbox::new(&mut self.gui.hide_private_keys, "Hide private keys"));
        hide_private_keys_resp.on_hover_text(hide_private_keys_label.join("\n")).on_disabled_hover_text(&devel);

        let evm_label = [
          "When enabled:",
          "Normalize how EVM addresses are displayed so they look the same across all networks. This improves usability when managing multiple chains.",
          "\n",
          "When disabled:",
          "Show addresses exactly as derived for each chain, preserving native formatting and reducing cross-chain linkability for greater privacy.",
        ];

        let evm_resp: egui::Response = ui.add_enabled(false,egui::Checkbox::new(&mut self.wallet.wallet_data.unify_evm, "Standardize EVM Addresses"));
        evm_resp.on_hover_text(evm_label.join("\n")).on_disabled_hover_text(&devel);

        let master_label = ["When enabled:",
          "All coins will be generated from Bitcoin's Master Private Keys.",
          "\n",
          "When disabled:",
          "If coin has its own Master Private Key headers then they will be used.",
        ];

        let master_resp: egui::Response = ui.add_enabled(false, egui::Checkbox::new(&mut self.wallet.wallet_data.unify_master_keys, "Unify Master Keys"));
        master_resp.on_hover_text(master_label.join("\n")).on_disabled_hover_text(&devel);

        let slip_derivation_description = [
          "When enabled:",
          "Use SLIP-0010 derivation path: m/44'/{coin_index}'/0'",
          "\n",
          "When disabled:",
          "Use BIP44 derivation path: m/44'/{coin_index}'/0'/0'/0'",
          "or BIP32 derivation path: m/0'/0'/0'",
        ];

        let slip_derivation_resp: egui::Response = ui.add_enabled(true,egui::Checkbox::new(&mut self.wallet.wallet_data.slip_derivation_path, "Use SLIP-0010 derivation"));

        if slip_derivation_resp.changed() && has_addresses {
          self.wallet.addresses_by_coin.0.clear();
          let _ = self.generate_addresses_for_all_coins();
        }


        slip_derivation_resp.on_hover_text(slip_derivation_description.join("\n")).on_disabled_hover_text(&devel);

        ui.separator();

        if ui
          .add_enabled(has_addresses, egui::Button::new("Show secrets"))
          .on_disabled_hover_text("Generate wallet first")
          .on_hover_text("Show all wallet secrets")
          .clicked()
        {
          self.gui.secrets_dialog.full_entropy = self.wallet.seed_secret.full_entropy.clone();
          self.gui.secrets_dialog.entropy = self.wallet.seed_secret.raw_entropy.clone();
          self.gui.secrets_dialog.entropy_checksum = self.wallet.seed_secret.entropy_checksum.clone();

          self.gui.secrets_dialog.mnemonic_words = self.wallet.seed_secret.mnemonic_words.clone();
          self.gui.secrets_dialog.monero_mnemonic_words = self.wallet.secret_keys.monero_keys.monero_mnemonic_words.clone();

          self.gui.secrets_dialog.mnemonic_passphrase = self.wallet.seed_secret.mnemonic_passphrase.clone();
          self.gui.secrets_dialog.seed = self.wallet.seed_secret.seed.clone();

          self.gui.secrets_dialog.master_secp256k1_private_key = self.wallet.secret_keys.master_secp256k1_keys.master_private_key_encoded.clone();
          self.gui.secrets_dialog.master_secp256k1_public_key = self.wallet.secret_keys.master_secp256k1_keys.master_public_key_encoded.clone();

          self.gui.secrets_dialog.master_ed25519_private_key = self.wallet.secret_keys.master_ed25519_keys.master_private_key_encoded.clone();
          self.gui.secrets_dialog.master_ed25519_public_key = self.wallet.secret_keys.master_ed25519_keys.master_public_key_encoded.clone();

          self.gui.secrets_dialog.open = true;
        }
      });

      // JUMP: COIN MENU
      ui.menu_button("Coins", |ui| {
        ui.menu_button("Bitcoin", |ui| {
          egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.vertical(|ui| {
              ui.heading(egui::RichText::new("Address format").size(16.0).strong());
              ui.add_space(GUI_MARGIN);

              let legacy = self.wallet.wallet_data.bitcoin_legacy_addresses;

              if self.draw_address_option(
                ui,
                legacy,
                "Legacy (P2PKH) - starts with '1...'",
                "Example: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
              ) {
                self.wallet.wallet_data.bitcoin_legacy_addresses = true;
                if has_addresses {
                  self.wallet.addresses_by_coin.0.clear();
                  let _ = self.generate_addresses_for_all_coins();
                }
              }

              ui.add_space(GUI_MARGIN);

              if self.draw_address_option(
                ui,
                !legacy,
                "Taproot (P2TR) - starts with 'bc1p...'",
                "Example: bc1p5cyxnuxmeuwuvkwfem96l5x7k9q0v4z0x7gqv",
              ) {
                self.wallet.wallet_data.bitcoin_legacy_addresses = false;
                if has_addresses {
                  self.wallet.addresses_by_coin.0.clear();
                  let _ = self.generate_addresses_for_all_coins();
                }
              }
            });
          });
        });

        ui.menu_button("Cardano", |ui| {
          egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.vertical(|ui| {
              ui.heading(egui::RichText::new("Derivation scheme").size(16.0).strong());
              ui.add_space(GUI_MARGIN);

              let byron = self.wallet.wallet_data.cardano_byron_derivation;

              #[cfg(feature = "dev")]
              {
                if self.draw_address_option(
                  ui,
                  byron,
                  "Byron (Legacy)",
                  "Example: m/44'/1815'/0'/0/0",
                ) {
                  self.wallet.wallet_data.cardano_byron_derivation = true;
                  if has_addresses {
                    self.wallet.addresses_by_coin.0.clear();
                    let _ = self.generate_addresses_for_all_coins();
                  }
                }

                ui.add_space(GUI_MARGIN);
              }

              if self.draw_address_option(
                ui,
                !byron,
                "Shelley (Default)",
                "Example: m/1852'/1815'/0'/0/0",
              ) {
                self.wallet.wallet_data.cardano_byron_derivation = false;
                if has_addresses {
                  self.wallet.addresses_by_coin.0.clear();
                  let _ = self.generate_addresses_for_all_coins();
                }
              }
            });
          });
        });

        ui.menu_button("Litecoin", |ui| {
          egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.vertical(|ui| {
              ui.heading(egui::RichText::new("Address format").size(16.0).strong());
              ui.add_space(GUI_MARGIN);

              let legacy = self.wallet.wallet_data.litecoin_legacy_addresses;

              if self.draw_address_option(
                ui,
                legacy,
                "Legacy (P2PKH) - starts with 'L...'",
                "Example: Ld1q2w3e4r5t6y7u8i9o0pASDFGHJKL",

              ) {
                self.wallet.wallet_data.litecoin_legacy_addresses = true;
                if has_addresses {
                  self.wallet.addresses_by_coin.0.clear();
                  let _ = self.generate_addresses_for_all_coins();
                }
              }

              ui.add_space(GUI_MARGIN);

              if self.draw_address_option(
                ui,
                !legacy,
                "Taproot (P2TR) - starts with 'ltc1p...'",
                "Example: ltc1pqxyz0abcdefghijklmnopqrstuvwx",
              ) {
                self.wallet.wallet_data.litecoin_legacy_addresses = false;
                if has_addresses {
                  self.wallet.addresses_by_coin.0.clear();
                  let _ = self.generate_addresses_for_all_coins();
                }
              }
            });
          });
        });

        ui.menu_button("Zilliqa", |ui| {
          egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.vertical(|ui| {
              ui.heading(egui::RichText::new("Address format").size(16.0).strong());
              ui.add_space(GUI_MARGIN);

              let legacy = self.wallet.wallet_data.zilliqa_legacy_addresses;

              if self.draw_address_option(
                ui,
                legacy,
                "Legacy - starts with 'zil...'",
                "Example: zil1q2w3e4r5t6y7u8i9o0pASDFGHJKL",
              ) {
                self.wallet.wallet_data.zilliqa_legacy_addresses = true;
                if has_addresses {
                  self.wallet.addresses_by_coin.0.clear();
                  let _ = self.generate_addresses_for_all_coins();
                }
              }

              ui.add_space(GUI_MARGIN);

              if self.draw_address_option(
                ui,
                !legacy,
                "Zilliqa 2.0 (EVM) - starts with '0x...'",
                "Example: 0x4bbeEB066eD09B7AEd07bF39EEe0460DFa261520",
              ) {
                self.wallet.wallet_data.zilliqa_legacy_addresses = false;
                if has_addresses {
                  self.wallet.addresses_by_coin.0.clear();
                  let _ = self.generate_addresses_for_all_coins();
                }
              }
            });
          });
        });
      });

      ui.menu_button("Help", |ui| {
        if ui.add_enabled(true, egui::Button::new("Help"))
          .on_hover_text("Read more")
          .clicked()
        {
          self.gui.help_dialog.open = true;
        }

        if ui.add_enabled(true, egui::Button::new("Disclaimer"))
          .on_hover_text("Read before use")
          .clicked()
        {
          self.gui.show_disclaimer = true;
        }

        if ui.add_enabled(true, egui::Button::new("About")).on_hover_text("Check for latest version").clicked() {
          self.gui.version_dialog.open = true;
        }
      });
    });

    ui.vertical_centered_justified(|ui| {
      ui.heading(PROJECT_MOTO);
    });

    if self.gui.show_disclaimer {
      egui::Window::new("Project Disclaimer")
        .open(&mut self.gui.show_disclaimer)
        .show(ui.ctx(), |ui| {
          egui::ScrollArea::both().show(ui, |ui| {
            ui.code(DISCLAIMER_TEXT);
          });
        });
    }
  }

  fn render_wallet_table(
    &mut self,
    ui: &mut egui::Ui,
  ) {
    let available_height = ui.available_height();
    let font = egui::FontId::monospace(12.0);
    let row_height = font.size + (2.0 * GUI_MARGIN);

    let filter_lower = self.gui.coin_filter.trim().to_ascii_lowercase();

    let mut builder = TableBuilder::new(ui)
      .striped(true)
      .resizable(true)
      .scroll_bar_visibility(egui::containers::scroll_area::ScrollBarVisibility::VisibleWhenNeeded)
      .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
      .min_scrolled_height(0.0)
      .auto_shrink([false, false])
      .max_scroll_height(available_height)
      .animate_scrolling(true);

    // Index
    #[cfg(feature = "dev")]
    {
      builder = builder.column(Column::auto().resizable(true).at_least(40.0));
    }

    // Icon
    builder = builder.column(Column::exact(24.0).resizable(false));

    // Coin
    builder = builder.column(Column::auto().resizable(true).at_least(80.0));

    // Path
    builder = builder.column(Column::auto().resizable(true).at_least(100.0));

    // Address
    builder = builder.column(Column::initial(500.0).resizable(true).clip(true).at_least(140.0));

    // Public key
    if !self.gui.hide_public_keys {
      builder = builder.column(Column::initial(500.0).resizable(true).clip(true).at_least(140.0));
    }

    // Private key
    builder = builder.column(Column::remainder().clip(true).at_least(180.0).resizable(false));

    builder
      .header(row_height, |mut header| {
        #[cfg(feature = "dev")]
        header.col(|ui| {
          ui.strong("Index");
        });

        header.col(|ui| {
          ui.strong("Icon");
        });

        header.col(|ui| {
          ui.strong("Coin");
        });

        header.col(|ui| {
          ui.strong("Path");
        });

        header.col(|ui| {
          ui.strong("Address");
        });

        if !self.gui.hide_public_keys {
          header.col(|ui| {
            ui.strong("Public key");
          });
        }

        header.col(|ui| {
          ui.strong("Private Key");
        });
      })
      .body(|mut body| {
        for (coin, addresses) in &self.wallet.addresses_by_coin.0 {
          if !filter_lower.is_empty() && !coin.to_ascii_lowercase().contains(&filter_lower) {
            continue;
          }

          if let Some(first) = addresses.first().cloned() {
            let mut group_expanded = false;

            body.row(row_height, |mut row| {
              // Index
              #[cfg(feature = "dev")]
              row.col(|ui| {
                ui.label(first.coin_index.to_string());
              });

              // Icon
              row.col(|ui| {
                let icon_path = std::path::Path::new("coin").join("logo").join(format!("{}.svg", *first.coin_index));
                let icon_path_str: Zeroizing<String> = Zeroizing::new(icon_path.into_os_string().into_string().unwrap_or_default());

                if let Ok(file) = e_q::get_file_from_resources(icon_path_str) {
                  ui.add(
                    egui::Image::from_bytes(file.path().to_string_lossy(), file.contents())
                      .fit_to_exact_size(egui::vec2(24.0, 24.0))
                      .corner_radius(10),
                  );
                }
              });

              // Coin
              row.col(|ui| {
                ui.with_layout(egui::Layout::top_down(egui::Align::Center), |ui| {
                  ui.add_space(row_height / 4.0);
                  let collapsing_resp = egui::CollapsingHeader::new(format!("{} ({})", coin, addresses.len()))
                    .id_salt(format!("coin_group:{}", coin))
                    .show_background(true)
                    .default_open(false)
                    .show(ui, |_ui| {});

                  group_expanded = collapsing_resp.body_returned.is_some();
                });
              });

              // Path
              row.col(|ui| {
                ui.label(&*first.path);
              });

              // Address
              row.col(|ui| {
                ui.horizontal(|ui| {
                  if ui.button("📋").on_hover_text("Copy address").clicked() {
                    ui.ctx().copy_text(first.address.to_string());
                  }
                  ui.label(&*first.address);
                });
              });

              // Public key
              if !self.gui.hide_public_keys {
                row.col(|ui| {
                  ui.horizontal(|ui| {
                    if ui.button("📋").on_hover_text("Copy public key").clicked() {
                      ui.ctx().copy_text(first.public_key.to_string());
                    }
                    ui.label(first.public_key.to_string());
                  });
                });
              }

              // Private key
              row.col(|ui| {
                ui.horizontal(|ui| {
                  if ui.button("📋").on_hover_text("Copy private key").clicked() {
                    ui.ctx().copy_text(first.private_key.to_string());
                  }

                  let is_visible = ui.ui_contains_pointer() || !self.gui.hide_private_keys;
                  if is_visible {
                    ui.monospace(&*first.private_key);
                  } else {
                    ui.monospace("•••••••");
                  }
                });
              });
            });

            if group_expanded {
              for addr in addresses.iter().skip(1) {
                body.row(row_height, |mut row| {
                  // Index
                  #[cfg(feature = "dev")]
                  row.col(|ui| {
                    ui.label(addr.coin_index.to_string());
                  });

                  // No icon
                  row.col(|ui| {
                    ui.label("");
                  });

                  // Coin name
                  row.col(|ui| {
                    ui.label(coin);
                  });

                  // Path
                  row.col(|ui| {
                    ui.label(addr.path.to_string());
                  });

                  // Address
                  row.col(|ui| {
                    ui.horizontal(|ui| {
                      if ui.button("📋").on_hover_text("Copy address").clicked() {
                        ui.ctx().copy_text(addr.address.to_string());
                      }
                      ui.label(addr.address.to_string());
                    });
                  });

                  // Public key
                  if !self.gui.hide_public_keys {
                    row.col(|ui| {
                      ui.horizontal(|ui| {
                        if ui.button("📋").on_hover_text("Copy public key").clicked() {
                          ui.ctx().copy_text(addr.public_key.to_string());
                        }
                        ui.label(addr.public_key.to_string());
                      });
                    });
                  }

                  // Private key
                  row.col(|ui| {
                    ui.horizontal(|ui| {
                      if ui.button("📋").on_hover_text("Copy private key").clicked() {
                        ui.ctx().copy_text(addr.private_key.to_string());
                      }

                      let is_visible = ui.ui_contains_pointer() || !self.gui.hide_private_keys;
                      if is_visible {
                        ui.monospace(&*addr.private_key);
                      } else {
                        ui.monospace("•••••••");
                      }
                    });
                  });
                });
              }
            }
          }
        }
      });
  }

  fn render_wallet_footer(
    &mut self,
    ui: &mut egui::Ui,
  ) -> FunctionOutput<()> {
    let visuals = ui.visuals_mut();
    visuals.widgets.inactive.bg_fill = egui::Color32::TRANSPARENT;
    visuals.widgets.inactive.weak_bg_fill = egui::Color32::TRANSPARENT;
    visuals.widgets.inactive.bg_stroke = egui::Stroke::NONE;

    ui.horizontal(|ui| {
      ui.add_space(GUI_MARGIN);
      let active_text_color = self.get_text_color();
      let has_addresses = !self.wallet.addresses_by_coin.0.is_empty();

      // JUMP: STATUS ENTROPY
      ui.label(egui::RichText::new("Entropy").monospace().small());

      let source: Zeroizing<String> = self.wallet.seed_secret.entropy_source.clone();
      let source_text = match self.wallet.seed_secret.entropy_source.as_str() {
        "File" => egui::RichText::new(source.as_str()).monospace().color(ui.visuals().weak_text_color()),
        _ => egui::RichText::new(source.as_str()).strong().monospace().color(active_text_color),
      };

      ui.add_enabled_ui(!has_addresses, |ui| {
        let response = ui
          .button(source_text)
          .on_hover_text("Entropy source")
          .on_disabled_hover_text("Entropy source\nCannot modify: wallet already initialized.");

        if response.clicked() {
          let idx = VALID_ENTROPY_SOURCES.iter().position(|&s| s == *source).unwrap_or(0);

          let next_idx = (idx + 1) % VALID_ENTROPY_SOURCES.len();

          self.wallet.seed_secret.entropy_source = Zeroizing::new(VALID_ENTROPY_SOURCES[next_idx].to_string());
        }

        if response.secondary_clicked() {
          let idx = VALID_ENTROPY_SOURCES.iter().position(|&s| s == *source).unwrap_or(0);

          let prev_idx = if idx == 0 { VALID_ENTROPY_SOURCES.len() - 1 } else { idx - 1 };

          self.wallet.seed_secret.entropy_source = Zeroizing::new(VALID_ENTROPY_SOURCES[prev_idx].to_string());
        }
      });

      ui.separator();

      // JUMP: STATUS MNEMONIC
      ui.label(egui::RichText::new("Mnemonic").monospace().small());

      let current_entropy = *self.wallet.seed_secret.entropy_length;
      let current_words = match current_entropy {
        128 => 12,
        160 => 15,
        192 => 18,
        224 => 21,
        _ => 24,
      };

      let words_text = match *self.wallet.seed_secret.entropy_length {
        128 => egui::RichText::new("12").monospace().color(ui.visuals().weak_text_color()),
        160 => egui::RichText::new("15").monospace().color(ui.visuals().weak_text_color()),
        192 => egui::RichText::new("18").monospace().color(ui.visuals().weak_text_color()),
        224 => egui::RichText::new("21").monospace().color(ui.visuals().weak_text_color()),
        _ => egui::RichText::new("24").strong().monospace().color(active_text_color),
      };

      ui.add_enabled_ui(!has_addresses, |ui| {
        let response = ui
          .button(words_text)
          .on_hover_text("Mnemonic word length")
          .on_disabled_hover_text("Mnemonic word length\nCannot modify: wallet already initialized.");

        if response.clicked() {
          let idx = VALID_MNEMONIC_LENGTHS.iter().position(|&w| w == current_words).unwrap_or(0);

          let next_idx = (idx + 1) % VALID_MNEMONIC_LENGTHS.len();
          let next_words = VALID_MNEMONIC_LENGTHS[next_idx];

          let next_entropy = match next_words {
            12 => 128,
            15 => 160,
            18 => 192,
            21 => 224,
            _ => 256,
          };

          self.wallet.seed_secret.entropy_length = Zeroizing::new(next_entropy);
        }

        if response.secondary_clicked() {
          let idx = VALID_MNEMONIC_LENGTHS.iter().position(|&w| w == current_words).unwrap_or(0);

          let prev_idx = if idx == 0 { VALID_MNEMONIC_LENGTHS.len() - 1 } else { idx - 1 };

          let prev_words = VALID_MNEMONIC_LENGTHS[prev_idx];

          let prev_entropy = match prev_words {
            12 => 128,
            15 => 160,
            18 => 192,
            21 => 224,
            _ => 256,
          };

          self.wallet.seed_secret.entropy_length = Zeroizing::new(prev_entropy);
        }
      });

      let current_code = match *self.wallet.seed_secret.mnemonic_dictionary {
        MnemonicLanguage::English => "EN",
        MnemonicLanguage::Czech => "CS",
        MnemonicLanguage::French => "FR",
        MnemonicLanguage::Italian => "IT",
        MnemonicLanguage::Portuguese => "PT",
        MnemonicLanguage::Spanish => "ES",
        MnemonicLanguage::ChineseSimplified => "ZH-CN",
        MnemonicLanguage::ChineseTraditional => "ZH-TW",
        MnemonicLanguage::Japanese => "JA",
        MnemonicLanguage::Korean => "KO",
      };

      let code_text = { egui::RichText::new(current_code).strong().monospace().color(active_text_color) };

      ui.add_enabled_ui(!has_addresses, |ui| {
        let response = ui
          .button(code_text)
          .on_hover_text("Mnemonic dictionary")
          .on_disabled_hover_text("Mnemonic dictionary\nCannot modify: wallet already initialized.");

        if response.clicked() {
          let idx = VALID_LANG_CODES.iter().position(|&c| c == current_code).unwrap_or(0);

          let next_idx = (idx + 1) % VALID_LANG_CODES.len();
          let next_code = VALID_LANG_CODES[next_idx];

          self.wallet.seed_secret.mnemonic_dictionary = match next_code {
            "EN" => Zeroizing::new(MnemonicLanguage::English),
            "CS" => Zeroizing::new(MnemonicLanguage::Czech),
            "FR" => Zeroizing::new(MnemonicLanguage::French),
            "IT" => Zeroizing::new(MnemonicLanguage::Italian),
            "PT" => Zeroizing::new(MnemonicLanguage::Portuguese),
            "ES" => Zeroizing::new(MnemonicLanguage::Spanish),
            "ZH-CN" => Zeroizing::new(MnemonicLanguage::ChineseSimplified),
            "ZH-TW" => Zeroizing::new(MnemonicLanguage::ChineseTraditional),
            "JA" => Zeroizing::new(MnemonicLanguage::Japanese),
            "KO" => Zeroizing::new(MnemonicLanguage::Korean),
            _ => Zeroizing::new(MnemonicLanguage::English),
          };
        }

        if response.secondary_clicked() {
          let idx = VALID_LANG_CODES.iter().position(|&c| c == current_code).unwrap_or(0);

          let prev_idx = if idx == 0 { VALID_LANG_CODES.len() - 1 } else { idx - 1 };

          let prev_code = VALID_LANG_CODES[prev_idx];

          self.wallet.seed_secret.mnemonic_dictionary = match prev_code {
            "EN" => Zeroizing::new(MnemonicLanguage::English),
            "CS" => Zeroizing::new(MnemonicLanguage::Czech),
            "FR" => Zeroizing::new(MnemonicLanguage::French),
            "IT" => Zeroizing::new(MnemonicLanguage::Italian),
            "PT" => Zeroizing::new(MnemonicLanguage::Portuguese),
            "ES" => Zeroizing::new(MnemonicLanguage::Spanish),
            "ZH-CN" => Zeroizing::new(MnemonicLanguage::ChineseSimplified),
            "ZH-TW" => Zeroizing::new(MnemonicLanguage::ChineseTraditional),
            "JA" => Zeroizing::new(MnemonicLanguage::Japanese),
            "KO" => Zeroizing::new(MnemonicLanguage::Korean),
            _ => Zeroizing::new(MnemonicLanguage::English),
          };
        }
      });

      let source: Zeroizing<String> = self.wallet.seed_secret.mnemonic_passphrase_source.clone();
      let source_text = match self.wallet.seed_secret.mnemonic_passphrase_source.as_str() {
        "Off" => egui::RichText::new(source.as_str()).monospace().color(ui.visuals().weak_text_color()),
        _ => egui::RichText::new(source.as_str()).strong().monospace().color(active_text_color),
      };

      ui.add_enabled_ui(!has_addresses, |ui| {
        let response = ui
          .button(source_text)
          .on_hover_text("Mnemonic passphrase source")
          .on_disabled_hover_text("Mnemonic passphrase source\nCannot modify: wallet already initialized.");

        if response.clicked() {
          let idx = VALID_MNEMONIC_SOURCES.iter().position(|&s| s == *source).unwrap_or(0);

          let next_idx = (idx + 1) % VALID_MNEMONIC_SOURCES.len();

          self.wallet.seed_secret.mnemonic_passphrase_source = Zeroizing::new(VALID_MNEMONIC_SOURCES[next_idx].to_string());
        }

        if response.secondary_clicked() {
          let idx = VALID_MNEMONIC_SOURCES.iter().position(|&s| s == *source).unwrap_or(0);

          let prev_idx = if idx == 0 { VALID_MNEMONIC_SOURCES.len() - 1 } else { idx - 1 };

          self.wallet.seed_secret.mnemonic_passphrase_source = Zeroizing::new(VALID_MNEMONIC_SOURCES[prev_idx].to_string());
        }
      });

      ui.separator();

      // JUMP: STATUS PATH
      ui.label(egui::RichText::new("Path").monospace().small());
      let bip_text = if self.wallet.wallet_data.active_bip == 44 {
        egui::RichText::new("BIP 44").strong().monospace().color(active_text_color)
      } else {
        egui::RichText::new("BIP 32").monospace().color(ui.visuals().weak_text_color())
      };
      let bip_response = ui.button(bip_text).on_hover_text("BIP derivation path");

      if bip_response.clicked() || bip_response.secondary_clicked() {
        self.wallet.wallet_data.active_bip = if self.wallet.wallet_data.active_bip == 44 { 32 } else { 44 };

        if has_addresses {
          self.wallet.addresses_by_coin.0.clear();

          let _ = self.generate_addresses_for_all_coins();
        }
      }

      let hardened_text = if self.wallet.wallet_data.hardened_address {
        egui::RichText::new("Hardened").strong().monospace().color(active_text_color)
      } else {
        egui::RichText::new("Non-hard").monospace().color(ui.visuals().weak_text_color())
      };

      let hardened_response = ui.button(hardened_text).on_hover_text("Hardened addresses");

      if hardened_response.clicked() || hardened_response.secondary_clicked() {
        self.wallet.wallet_data.hardened_address = !self.wallet.wallet_data.hardened_address;

        if has_addresses {
          self.wallet.addresses_by_coin.0.clear();

          let _ = self.generate_addresses_for_all_coins();
        }
      }

      // JUMP: STATUS COINS
      if has_addresses {
        ui.separator();

        ui.label(egui::RichText::new("Coins").monospace().small());

        ui.add_enabled_ui(!has_addresses, |ui| {
          ui.label(
            egui::RichText::new(self.wallet.addresses_by_coin.0.len().to_string())
              .monospace()
              .color(self.get_text_color()),
          )
          .on_disabled_hover_text("Total numbers of coins");
        });

        ui.separator();

        // JUMP: STATUS ADDRESSES
        ui.label(egui::RichText::new("Addresses").monospace().small());

        if ui
          .button("-")
          .on_hover_text(format!("Remove {} address from wallet", self.wallet.wallet_data.address_count))
          .clicked()
        {
          let remove_count = self.wallet.wallet_data.address_count as usize;

          for addresses in self.wallet.addresses_by_coin.0.values_mut() {
            if addresses.len() <= 1 {
              continue;
            }

            let can_remove = (addresses.len() - 1).min(remove_count);

            if can_remove > 0 {
              addresses.truncate(addresses.len() - can_remove);
            }
          }

          if let Some((_coin, addresses)) = self.wallet.addresses_by_coin.0.iter().next() {
            self.wallet.address_components.derivation_path.last_index = Zeroizing::new(addresses.len() as u32);
          }
        }

        let address_text = {
          egui::RichText::new(self.wallet.wallet_data.address_count.to_string())
            .strong()
            .monospace()
            .color(active_text_color)
        };

        ui.add_enabled_ui(has_addresses, |ui| {
          let response = ui.button(address_text).on_hover_text("Address number");

          if response.clicked() {
            let idx = ADD_ADDRESS_COUNT
              .iter()
              .position(|&c| c == self.wallet.wallet_data.address_count)
              .unwrap_or(0);

            let next_idx = (idx + 1) % ADD_ADDRESS_COUNT.len();
            self.wallet.wallet_data.address_count = ADD_ADDRESS_COUNT[next_idx];
          }

          if response.secondary_clicked() {
            let idx = ADD_ADDRESS_COUNT
              .iter()
              .position(|&c| c == self.wallet.wallet_data.address_count)
              .unwrap_or(0);

            let prev_idx = if idx == 0 { ADD_ADDRESS_COUNT.len() - 1 } else { idx - 1 };

            self.wallet.wallet_data.address_count = ADD_ADDRESS_COUNT[prev_idx];
          }
        });

        if ui
          .button("+")
          .on_hover_text(format!("Add {} address more to wallet", self.wallet.wallet_data.address_count))
          .clicked()
        {
          let source = self.get_entropy_source();
          let _ = self.generate_new_wallet(Some(source));
        }

        ui.separator();

        // JUMP: STATUS FILTER
        ui.add_enabled_ui(has_addresses, |ui| {
          ui.label(egui::RichText::new("Filter").monospace().small());

          let filter_text = &mut self.gui.coin_filter;
          let response = ui.add(
            egui::TextEdit::singleline(filter_text)
              .desired_width(74.0)
              .hint_text("Coin name")
              .font(egui::TextStyle::Monospace),
          );

          if response.changed() {
            filter_text.make_ascii_lowercase();
            filter_text.truncate(20);
          }

          if !filter_text.is_empty()
            && ui
              .button(egui::RichText::new("X").monospace().strong())
              .on_hover_text("Clear filter")
              .clicked()
          {
            filter_text.clear();
          }

          response.on_hover_text("Filter coins by name");
        });
      }
    });

    Ok(())
  }

  fn get_entropy_source(&mut self) -> Zeroizing<String> {
    self.wallet.seed_secret.entropy_source.clone()
  }

  fn get_text_color(&mut self) -> Color32 {
    match self.gui.theme.as_str() {
      "Light" => egui::Color32::RED,
      _ => egui::Color32::GREEN,
    }
  }
}

impl eframe::App for EgoQuantum {
  fn ui(
    &mut self,
    ui: &mut egui::Ui,
    _frame: &mut eframe::Frame,
  ) {
    let ctx = ui.ctx().clone();

    match self.gui.theme.as_str() {
      "Dark" => ctx.set_theme(egui::Theme::Dark),
      "Light" => ctx.set_theme(egui::Theme::Light),
      // "System" => ctx.set_theme(egui::Theme::from_dark_mode(dark_mode)),
      _ => ctx.set_theme(egui::Theme::Light),
    }

    self.gui.maximized = ctx.input(|i| i.viewport().maximized.unwrap_or(false));

    egui::Panel::top("header").show(ui, |ui| {
      ui.add_space(GUI_MARGIN);
      self.render_wallet_header(ui);
      ui.add_space(GUI_MARGIN);
    });

    egui::Panel::bottom("footer")
      .exact_size(21.0)
      .frame(egui::Frame::new().fill(STATUS_BAR_BACKGROUND_COLOR).inner_margin(2.0).outer_margin(0.0))
      .show(ui, |ui| {
        let _ = self.render_wallet_footer(ui);
      });

    let has_addresses = !self.wallet.addresses_by_coin.0.is_empty();

    if has_addresses {
      egui::CentralPanel::default().show(ui, |ui| {
        egui::ScrollArea::horizontal()
          .scroll_bar_visibility(egui::containers::scroll_area::ScrollBarVisibility::VisibleWhenNeeded)
          .show(ui, |ui| {
            self.render_wallet_table(ui);
          });
      });
    } else {
      egui::CentralPanel::default().show(ui, |ui| {
        ui.vertical_centered(|ui| {
          ui.vertical_centered(|ui| {
            ui.add_space(GUI_MARGIN);

            let text = egui::RichText::new("Generate New Wallet")
              .raised()
              .strong()
              .monospace()
              .color(self.get_text_color());

            if ui.button(text).clicked() {
              let needs_qrng = self.get_entropy_source().as_str() == "QRNG";

              let needs_passphrase = self.wallet.seed_secret.mnemonic_passphrase_source.as_str() == "Custom";

              if needs_qrng {
                self.gui.anu_dialog.entropy_length = self.wallet.seed_secret.entropy_length.clone();
                self.gui.anu_dialog.open = true;
                self.wallet.wallet_gen_state = WalletGenState::WaitingForQrng;
              } else if needs_passphrase {
                self.gui.mnemonic_passphrase_dialog.open = true;
                self.wallet.wallet_gen_state = WalletGenState::WaitingForPassphrase;
              } else {
                let source = self.get_entropy_source();
                let _ = self.generate_new_wallet(Some(source));
              }
            }

            if self.wallet.wallet_gen_state == WalletGenState::WaitingForQrng && !self.gui.anu_dialog.open && self.gui.anu_dialog.save_entropy {
              if !self.gui.anu_dialog.randomized_entropy.is_empty() {
                self.wallet.seed_secret.raw_entropy = self.gui.anu_dialog.randomized_entropy.clone();
              }

              self.gui.anu_dialog.save_entropy = false;

              if self.wallet.seed_secret.mnemonic_passphrase_source.as_str() == "Custom" {
                self.gui.mnemonic_passphrase_dialog.open = true;
                self.wallet.wallet_gen_state = WalletGenState::WaitingForPassphrase;
              } else {
                self.wallet.wallet_gen_state = WalletGenState::ReadyToGenerate;
              }
            }

            if self.wallet.wallet_gen_state == WalletGenState::WaitingForPassphrase
              && !self.gui.mnemonic_passphrase_dialog.open
              && self.gui.mnemonic_passphrase_dialog.save_mnemonic
            {
              self.gui.mnemonic_passphrase_dialog.save_mnemonic = false;
              self.wallet.wallet_gen_state = WalletGenState::ReadyToGenerate;
            }

            if self.wallet.wallet_gen_state == WalletGenState::ReadyToGenerate {
              self.wallet.wallet_gen_state = WalletGenState::Idle;

              let source = self.get_entropy_source();
              let _ = self.generate_new_wallet(Some(source));
            }
          });

          let logo_bytes: &[u8] = include_bytes!("../res/logo/logo.png");
          let logo = egui::Image::from_bytes("logo", logo_bytes).max_height(512.0);

          ui.add(logo);
        })
      });
    }

    // JUMP: WINDOW REGISTER
    self.gui.save_dialog.show(ui.ctx());
    self.gui.open_dialog.show(ui.ctx());
    self.gui.secrets_dialog.show(ui.ctx());
    self.gui.anu_dialog.show(ui.ctx());
    self.gui.version_dialog.show(ui.ctx());
    self.gui.mnemonic_passphrase_dialog.show(ui.ctx());
    self.gui.help_dialog.show(ui.ctx());

    if let Some(loaded_wallet) = ui
      .ctx()
      .data_mut(|d| d.remove_temp::<Zeroizing<CryptoWallet>>(egui::Id::new("loaded_wallet")))
    {
      self.wallet = loaded_wallet;

      if let Err(err) = self.generate_new_wallet(Some(Zeroizing::new(String::from("SVG")))) {
        AppError::log(format!("Problem with generating new wallet: {err:?}"));
      }
    }

    if let Some(loaded_mnemonic_passphrase) = ui
      .ctx()
      .data_mut(|d| d.remove_temp::<Zeroizing<String>>(egui::Id::new("loaded_mnemonic_passphrase")))
    {
      self.wallet.seed_secret.mnemonic_passphrase = loaded_mnemonic_passphrase;
      self.wallet.seed_secret.mnemonic_passphrase_source = Zeroizing::new(String::from("Custom"));

      if let Err(err) = self.generate_new_wallet(None) {
        AppError::log(format!("Problem with generating new wallet: {err:?}"));
      }
    }
  }
}

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

fn set_app_icon() -> FunctionOutput<egui::IconData> {
  let resource_path = std::path::Path::new("logo").join("logo.png");
  let resource_path_str: Zeroizing<String> = Zeroizing::new(resource_path.to_str().unwrap_or_default().to_string());

  let icon_file = match e_q::get_file_from_resources(resource_path_str) {
    Ok(file) => file,
    Err(err) => {
      return Err(AppError::log(format!("Problem with finding app logo file: {}", err)));
    }
  };

  let app_icon = match eframe::icon_data::from_png_bytes(icon_file.contents()) {
    Ok(icon) => icon,
    Err(err) => {
      return Err(AppError::log(format!("Problem with reading app logo icon: {}", err)));
    }
  };

  Ok(app_icon)
}

fn set_app_title() -> FunctionOutput<String> {
  let feature = e_q::get_active_app_feature();

  let title = format!("{} {} ({})", APP_NAME.unwrap_or("eQ"), APP_VERSION.unwrap_or_default(), feature);

  Ok(title)
}

fn main() -> FunctionOutput<()> {
  let app_icon = match set_app_icon() {
    Ok(icon) => icon,
    Err(err) => {
      return Err(AppError::log(format!("Problem with setting app logo icon: {}", err)));
    }
  };

  let app_title = match set_app_title() {
    Ok(title) => title,
    Err(err) => {
      return Err(AppError::log(format!("Problem with setting app title: {}", err)));
    }
  };

  let options = eframe::NativeOptions {
    viewport: egui::ViewportBuilder::default()
      // .with_inner_size([1200.0, 800.0])
      .with_min_inner_size([TEXT_WRAPPER, TEXT_WRAPPER])
      .with_icon(app_icon)
      .with_app_id("eQ"),
    ..Default::default()
  };

  if let Err(err) = eframe::run_native(
    &app_title,
    options,
    Box::new(|cc| {
      egui_extras::install_image_loaders(&cc.egui_ctx);
      Ok(Box::new(EgoQuantum::new()))
    }),
  ) {
    eprintln!("Failed to run native application: {:?}", err);
    std::process::exit(1);
  }

  Ok(())
}

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

fn escape_csv_field(s: &str) -> FunctionOutput<String> {
  if s.contains(',') || s.contains('"') || s.contains('\n') {
    let doubled = s.replace('"', "\"\"");

    Ok(format!("\"{}\"", doubled))
  } else {
    Ok(s.to_string())
  }
}

pub fn export_addresses_csv(
  addresses: &Addresses,
  path: &std::path::Path,
  include_private: bool,
) -> FunctionOutput<()> {
  let mut file = match std::fs::File::create(path) {
    Ok(file) => file,
    Err(err) => return Err(AppError::log(format!("Can not export to CSV: {}", err))),
  };

  if include_private {
    match writeln!(file, "coin,coin_index,path,address,public_key,private_key") {
      Ok(_) => {}
      Err(err) => {
        return Err(AppError::log(format!("Can not create private header in CSV: {}", err)));
      }
    };
  } else {
    match writeln!(file, "coin,coin_index,path,address,public_key") {
      Ok(_) => {}
      Err(err) => {
        return Err(AppError::log(format!("Can not create public header in CSV: {}", err)));
      }
    };
  }

  for (coin, vec) in &addresses.0 {
    for addr in vec {
      let coin_index = addr.coin_index.to_string();
      let path = &*addr.path;
      let address = &*addr.address;
      let public_key = &*addr.public_key;

      let fields = if include_private {
        let private_key = &*addr.private_key;
        vec![
          escape_csv_field(coin)?,
          escape_csv_field(&coin_index)?,
          escape_csv_field(path)?,
          escape_csv_field(address)?,
          escape_csv_field(public_key)?,
          escape_csv_field(private_key)?,
        ]
      } else {
        vec![
          escape_csv_field(coin)?,
          escape_csv_field(&coin_index)?,
          escape_csv_field(path)?,
          escape_csv_field(address)?,
          escape_csv_field(public_key)?,
        ]
      };

      match writeln!(file, "{}", fields.join(",")) {
        Ok(_) => {}
        Err(err) => {
          return Err(AppError::log(format!("Can not export content to CSV: {}", err)));
        }
      };
    }
  }

  match file.flush() {
    Ok(_) => {}
    Err(err) => return Err(AppError::log(format!("Can not flush file: {}", err))),
  };

  Ok(())
}

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

#[derive(Zeroize, ZeroizeOnDrop, Debug, Clone, Default)]
pub struct ShowAboutWindow {
  pub open: bool,
  show_license: bool,
}

impl ShowAboutWindow {
  pub fn new() -> Self {
    Self {
      open: false,
      show_license: false,
    }
  }

  pub fn show(
    &mut self,
    ctx: &egui::Context,
  ) {
    if !self.open {
      return;
    }

    let mut open = self.open;

    egui::Window::new("About").open(&mut open).resizable(true).show(ctx, |ui| {
      let _ = self.ui_content(ui);
    });

    if !open {
      self.close_and_clear();
    }
  }

  fn close_and_clear(&mut self) {
    self.zeroize();

    *self = ShowAboutWindow::new();
  }

  fn ui_content(
    &mut self,
    ui: &mut egui::Ui,
  ) -> FunctionOutput<()> {
    ui.add_space(GUI_MARGIN);

    ui.vertical_centered(|ui| {
      let logo_bytes: &[u8] = include_bytes!("../res/logo/logo.png");
      let logo = egui::Image::from_bytes("logo", logo_bytes).max_height(128.0);

      ui.add(logo);

      ui.add_space(GUI_MARGIN);

      ui.heading(APP_NAME.unwrap_or_default());
      ui.heading(APP_DESCRIPTION.unwrap_or_default());

      ui.add_space(GUI_MARGIN);

      ui.group(|ui| {
        ui.vertical_centered(|ui| {
          ui.heading("Version Information");

          ui.add_space(GUI_MARGIN);

          ui.label(format!("Version: {}", APP_VERSION.unwrap_or_default()));
          ui.label(format!("Feature: {}", e_q::get_active_app_feature()));

          ui.add_space(GUI_MARGIN);

          if ui.link(APP_LICENSE.unwrap_or("License")).clicked() {
            self.show_license = true;
          }

          ui.add_space(GUI_MARGIN);

          #[cfg(not(feature = "eq-os"))]
          {
            let post = concat!("eQ", "@", "r-o0-t", ".", "wtf");
            ui.hyperlink_to("Contact author", format!("mailto:{post}"));
          }
        });

        #[cfg(not(feature = "eq-os"))]
        {
          ui.add_space(GUI_MARGIN);

          ui.hyperlink_to("Open GitHub Releases", "https://github.com/control-owl/eQ/releases");
        }
      });
    });

    if self.show_license {
      egui::Window::new("Project License").open(&mut self.show_license).show(ui.ctx(), |ui| {
        egui::ScrollArea::both().show(ui, |ui| {
          ui.code(LICENSE_TEXT);
        });
      });
    }

    Ok(())
  }
}

impl eframe::App for ShowAboutWindow {
  fn ui(
    &mut self,
    ui: &mut egui::Ui,
    _frame: &mut eframe::Frame,
  ) {
    egui::CentralPanel::default().show(ui, |ui| {
      ui.heading("About");
      self.show(ui.ctx());
    });
  }
}

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

#[derive(Zeroize, ZeroizeOnDrop, Debug, Clone, Default)]
pub struct ShowCustomMnemonicWindow {
  pub open: bool,
  passphrase: Zeroizing<String>,
  show_passphrase: bool,
  pub save_mnemonic: bool,

  #[cfg(feature = "osk")]
  pub keyboard: crypt::VirtualKeyboard,
}

impl ShowCustomMnemonicWindow {
  pub fn new() -> Self {
    Self {
      open: false,
      passphrase: Zeroizing::new(String::new()),
      show_passphrase: false,
      save_mnemonic: false,

      #[cfg(feature = "osk")]
      keyboard: crypt::VirtualKeyboard::default(),
    }
  }

  pub fn show(
    &mut self,
    ctx: &egui::Context,
  ) {
    if !self.open {
      return;
    }

    let mut open = self.open;

    egui::Window::new("Mnemonic Passphrase").open(&mut open).resizable(true).show(ctx, |ui| {
      let _ = self.ui_content(ui);
    });

    if !open {
      self.close_and_clear();
    }
  }

  fn close_and_clear(&mut self) {
    self.zeroize();

    *self = ShowCustomMnemonicWindow::new();
  }

  fn ui_content(
    &mut self,
    ui: &mut egui::Ui,
  ) -> FunctionOutput<()> {
    #[cfg(feature = "osk")]
    self.keyboard.0.pump_events(ui.ctx());

    ui.add_space(GUI_MARGIN);

    ui.vertical_centered(|ui| {
      ui.add_space(GUI_MARGIN);

      ui.add(
        egui::TextEdit::singleline(&mut *self.passphrase)
          .desired_width(ui.available_width())
          .password(!self.show_passphrase),
      );

      #[cfg(feature = "osk")]
      self.keyboard.0.show(ui.ctx());

      ui.add_space(GUI_MARGIN);

      ui.checkbox(&mut self.show_passphrase, "Show mnemonic passphrase");

      ui.add_space(GUI_MARGIN);

      if ui.button("Save").clicked() {
        let mut wallet = CryptoWallet::new();
        wallet.seed_secret.mnemonic_passphrase = self.passphrase.clone();

        ui.ctx().data_mut(|d| {
          d.insert_temp(
            egui::Id::new("loaded_mnemonic_passphrase"),
            Zeroizing::new(wallet.seed_secret.mnemonic_passphrase.to_string()),
          );
        });

        self.close_and_clear();
      }
    });

    ui.add_space(GUI_MARGIN);

    Ok(())
  }
}

impl eframe::App for ShowCustomMnemonicWindow {
  fn ui(
    &mut self,
    ui: &mut egui::Ui,
    _frame: &mut eframe::Frame,
  ) {
    egui::CentralPanel::default().show(ui, |ui| {
      ui.heading("Mnemonic Passphrase");
      self.show(ui.ctx());
    });
  }
}

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..
