// authors = ["Control Owl <eq[at]r-o0-t[dot]wtf>"]
// license = "CC-BY-NC-ND-4.0  [2023-2026]  Control Owl"

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

use eframe::egui;
use egui::{ComboBox, Frame, ThemePreference};
use egui_extras::{Column, TableBuilder};
use std::collections::BTreeMap;
use std::io::BufRead;
use std::io::Write;
use zeroize::Zeroize;
use zeroize::{ZeroizeOnDrop, Zeroizing};

mod crypt;
mod keys;
mod test_vectors;

#[cfg(feature = "dev")]
mod dev;

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

const APP_NAME: Option<&str> = option_env!("CARGO_PKG_NAME");
const APP_DESCRIPTION: Option<&str> = option_env!("CARGO_PKG_DESCRIPTION");
const APP_VERSION: Option<&str> = option_env!("CARGO_PKG_VERSION");
const _APP_AUTHOR: Option<&str> = option_env!("CARGO_PKG_AUTHORS");
const GUI_MARGIN: f32 = 10.0;
const VALID_ENTROPY_SOURCES: &[&str] = &["RNG", "QRNG", "File"];
const VALID_BIP_DERIVATIONS: &[u32] = &[32, 44];
const TEXT_WRAPPER: f32 = 300.0;

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
  mnemonic_dictionary: Zeroizing<String>,
  seed: Zeroizing<String>,
}

impl SeedSecretData {
  fn new() -> Self {
    // TODO: Get values from local config
    Self {
      entropy_source: Zeroizing::new(String::from("RNG")),
      mnemonic_dictionary: Zeroizing::new(String::from("English")),
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
  _coin_name: Zeroizing<String>,
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

#[derive(Zeroize, ZeroizeOnDrop, Debug, Clone)]
struct GuiSettings {
  theme: String,
  _language: String,
  maximized: bool,
  zoom_factor: f32,

  max_rows: usize,
  address_count: u32,

  save_dialog: crypt::SaveWalletDialog,
  open_dialog: crypt::OpenWalletDialog,
  secrets_dialog: crypt::ShowSecretsDialog,
  anu_dialog: crypt::ShowAnuDialog,

  hide_private_keys: bool,
  unify_evm: bool,
  unify_master_keys: bool,
  hardened_address: bool,
}

impl GuiSettings {
  fn new() -> Self {
    let get_max_rows = e_q::get_free_memory_size();

    GuiSettings {
      theme: "System".to_string(),
      _language: "English".to_string(),
      maximized: false,
      zoom_factor: 1.0,

      max_rows: get_max_rows,
      address_count: 10,

      save_dialog: crypt::SaveWalletDialog::new(),
      open_dialog: crypt::OpenWalletDialog::default(),
      secrets_dialog: crypt::ShowSecretsDialog::new(),
      anu_dialog: crypt::ShowAnuDialog::new(),

      hide_private_keys: true,
      unify_evm: false,
      unify_master_keys: true,
      hardened_address: true,
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
}

impl CryptoWallet {
  fn new() -> Self {
    // TODO: Get values from local config
    Self {
      seed_secret: Zeroizing::new(SeedSecretData::new()),
      secret_keys: Zeroizing::new(SecretKeyData::default()),
      address_components: Zeroizing::new(AddressPublicData::default()),
      addresses_by_coin: Zeroizing::new(Addresses(BTreeMap::new())),
    }
  }
}

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

struct EgoQuantum {
  wallet: Zeroizing<CryptoWallet>,
  gui: GuiSettings,
}

impl EgoQuantum {
  fn new() -> Self {
    // TODO: Get values from local config
    Self { wallet: Zeroizing::new(CryptoWallet::new()), gui: GuiSettings::new() }
  }

  fn generate_new_wallet(
    &mut self,
    entropy_source: Option<Zeroizing<String>>,
  ) -> FunctionOutput<()> {
    let entropy_source: Zeroizing<String> = match entropy_source {
      Some(source) => source,
      None => self.get_entropy_source(),
    };

    let bip: Zeroizing<u32> = match entropy_source.as_str() {
      "Load wallet" => self.wallet.address_components.derivation_path.purpose.clone(),
      _ => self.get_bip(),
    };

    if self.wallet.seed_secret.raw_entropy.is_empty() || self.wallet.seed_secret.full_entropy.is_empty() {
      match keys::generate_seed(&mut self.wallet, entropy_source.clone()) {
        Ok(_) => {}
        Err(err) => {
          return Err(AppError::log(format!("Problem with generating seed: {}", err)));
        }
      };
    };

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

    let active_coins = if cfg!(feature = "dev") { 2 } else { 1 };

    // TODO: Add address_count as GUI parameters
    let address_count = 10;
    let last_index = *self.wallet.address_components.derivation_path.last_index;

    let (start_index, end_index) = if entropy_source.as_str() == "SVG" {
      if self.wallet.addresses_by_coin.0.is_empty() {
        // Bootstrap SVG mode
        (0, last_index)
      } else {
        // Continue paging
        (last_index, last_index.saturating_add(address_count))
      }
    } else {
      // Normal mode
      (last_index, last_index.saturating_add(address_count))
    };

    // ECDB: Extended Coin DataBase
    let resource_path = std::path::Path::new("coin").join("ECDB.csv");
    let resource_path_str: Zeroizing<String> = Zeroizing::new(resource_path.into_os_string().into_string().unwrap_or_default());
    let ecdb_file = e_q::get_file_from_resources(resource_path_str);

    if let Ok(file) = ecdb_file {
      let reader = std::io::BufReader::new(file.contents());

      for line_result in reader.lines() {
        match line_result {
          Ok(line) => {
            let columns: Vec<&str> = line.split(',').collect();
            let inactive_coin = columns.first().unwrap_or(&"0");
            if *inactive_coin != active_coins.to_string() {
              continue;
            }

            // TODO: Remove hardcoding, add parameters to GUI selection
            self.wallet.address_components.derivation_path.purpose = bip.clone();
            self.wallet.address_components.derivation_path.coin = Zeroizing::new(columns[1].parse().unwrap_or(0));
            self.wallet.address_components.derivation_path.purpose_hardened = Zeroizing::new(true);
            self.wallet.address_components.derivation_path.coin_hardened = Zeroizing::new(true);
            self.wallet.address_components.derivation_path.account_hardened = Zeroizing::new(true);
            self.wallet.address_components.derivation_path.change_hardened = Zeroizing::new(*bip == 32);
            self.wallet.address_components.derivation_path.address_hardened = Zeroizing::new(self.gui.hardened_address);

            self.wallet.address_components._coin_name = Zeroizing::new(columns[3].to_string());
            self.wallet.address_components.key_derivation = Zeroizing::new(columns[4].to_string());
            self.wallet.address_components.hash = Zeroizing::new(columns[5].to_string());
            self.wallet.address_components.public_key_hash = Zeroizing::new(columns[8].to_string());
            self.wallet.address_components.wallet_import_format = Zeroizing::new(columns[10].to_string());
            self.wallet.address_components.evm = Zeroizing::new(columns[11].trim().eq_ignore_ascii_case("true"));

            for address_index in start_index..end_index {
              self.wallet.address_components.derivation_path.address = Zeroizing::new(address_index);

              match self.wallet.address_components.key_derivation.as_str() {
                "secp256k1" => {
                  match keys::generate_secp256k1_child_keys(&mut self.wallet) {
                    Ok(_) => {}
                    Err(err) => {
                      return Err(AppError::log(format!("Can not derive child keys: {}", err)));
                    }
                  };

                  // match keys::generate_secp256k1_address(&mut self.wallet, Some(self.wallet.address_components.evm)) {
                  match keys::generate_secp256k1_address(&mut self.wallet) {
                    Ok(_) => {}
                    Err(err) => {
                      return Err(AppError::log(format!("Can not derive secp256k1 address: {}", err)));
                    }
                  };
                }
                "ed25519" => {
                  match keys::generate_ed25519_child_keys(&mut self.wallet) {
                    Ok(_) => {}
                    Err(err) => {
                      return Err(AppError::log(format!("Can not derive child keys: {}", err)));
                    }
                  };

                  match keys::generate_ed25519_address(&mut self.wallet) {
                    Ok(_) => {}
                    Err(err) => {
                      return Err(AppError::log(format!("Can not derive ed25519 address: {}", err)));
                    }
                  };
                }
                _ => {
                  return Err(AppError::log(format!("Unsupported key derivation: {:?}", self.wallet.address_components.key_derivation)));
                }
              }
            }
          }
          Err(err) => {
            eprintln!("ECDB file error: Skipping invalid line: {}", err);
            continue;
          }
        }
      }

      *self.wallet.address_components.derivation_path.last_index = end_index;
    }

    Ok(())
  }

  fn render_entropy_dropdown(
    &mut self,
    ui: &mut egui::Ui,
  ) {
    Frame::group(ui.style()).show(ui, |ui| {
      let descriptions = [
        "Uses your device's built-in random number generator (CPU).",
        "Uses quantum processes to create highly unpredictable numbers (ANU).",
        #[cfg(feature = "dev")]
        "Uses the content of a file you provide as a source of randomness.",
      ];

      ComboBox::from_label("Entropy Source")
        .selected_text(if self.wallet.seed_secret.entropy_source.is_empty() {
          VALID_ENTROPY_SOURCES[0]
        } else {
          &self.wallet.seed_secret.entropy_source
        })
        .show_ui(ui, |ui| {
          // RNG
          ui.selectable_value(
            &mut self.wallet.seed_secret.entropy_source,
            Zeroizing::new(VALID_ENTROPY_SOURCES[0].to_string()),
            VALID_ENTROPY_SOURCES[0],
          )
          .on_hover_text_at_pointer(descriptions[0]);

          let resp = ui
            .selectable_value(
              &mut self.wallet.seed_secret.entropy_source,
              Zeroizing::new(VALID_ENTROPY_SOURCES[1].to_string()),
              VALID_ENTROPY_SOURCES[1],
            )
            .on_hover_text_at_pointer(descriptions[1]);

          if resp.clicked() {
            self.gui.anu_dialog.open = true;
          }

          // FILE
          #[cfg(feature = "dev")]
          ui.selectable_value(
            &mut self.wallet.seed_secret.entropy_source,
            Zeroizing::new(VALID_ENTROPY_SOURCES[2].to_string()),
            VALID_ENTROPY_SOURCES[2],
          )
          .on_hover_text_at_pointer(descriptions[2]);
        });
    });
  }

  fn render_derivation_dropdown(
    &mut self,
    ui: &mut egui::Ui,
  ) {
    Frame::group(ui.style()).show(ui, |ui| {
      let descriptions = ["Classic hierarchical wallet derivation.", "Structured derivation path used for multi-coin wallets."];

      if *self.wallet.address_components.derivation_path.purpose == 0 {
        self.wallet.address_components.derivation_path.purpose = Zeroizing::new(44);
      }

      ComboBox::from_label("Derivation Path").selected_text(self.wallet.address_components.derivation_path.purpose.to_string()).show_ui(ui, |ui| {
        ui.selectable_value(
          &mut *self.wallet.address_components.derivation_path.purpose,
          VALID_BIP_DERIVATIONS[0],
          VALID_BIP_DERIVATIONS[0].to_string(),
        )
        .on_hover_text_at_pointer(descriptions[0]);

        ui.selectable_value(
          &mut *self.wallet.address_components.derivation_path.purpose,
          VALID_BIP_DERIVATIONS[1],
          VALID_BIP_DERIVATIONS[1].to_string(),
        )
        .on_hover_text_at_pointer(descriptions[1]);
      });
    });
  }

  fn render_mnemonic_options(
    &mut self,
    ui: &mut egui::Ui,
  ) {
    Frame::group(ui.style()).show(ui, |ui| {
      let sources = ["RNG", "Custom", "Off"];
      let descriptions = ["Randomize mnemonic passphrase with built-in RNG.", "Input your own mnemonic passphrase.", "Disable mnemonic passphrase."];

      if self.wallet.seed_secret.mnemonic_passphrase_source.is_empty() {
        self.wallet.seed_secret.mnemonic_passphrase_source = Zeroizing::new(String::from(sources[0]));
      }

      let current = &*self.wallet.seed_secret.mnemonic_passphrase_source;

      ComboBox::from_label("Mnemonic passphrase").selected_text(current).show_ui(ui, |ui| {
        ui.selectable_value(&mut *self.wallet.seed_secret.mnemonic_passphrase_source, String::from(sources[0]), sources[0])
          .on_hover_text_at_pointer(descriptions[0]);

        ui.selectable_value(&mut *self.wallet.seed_secret.mnemonic_passphrase_source, String::from(sources[1]), sources[1])
          .on_hover_text_at_pointer(descriptions[1]);

        #[cfg(feature = "dev")]
        ui.selectable_value(&mut *self.wallet.seed_secret.mnemonic_passphrase_source, String::from(sources[2]), sources[2])
          .on_hover_text_at_pointer(descriptions[2]);
      });
    });
  }

  fn render_wallet_header(
    &mut self,
    ui: &mut egui::Ui,
  ) {
    let devel = String::from("Still in development");
    let has_addresses = !self.wallet.addresses_by_coin.0.is_empty();

    egui::MenuBar::new().ui(ui, |ui| {
      ui.menu_button("File", |ui| {
        if ui.add_enabled(false, egui::Button::new("New")).on_disabled_hover_text(&devel).on_hover_text("Create new wallet window").clicked() {
          // TODO: Create new wallet window
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

        ui.separator();

        if ui.button("System").clicked() {
          self.gui.theme = "System".to_string();
        }
      });

      ui.menu_button("Privacy", |ui| {
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

        let evm_resp: egui::Response = ui.add_enabled(false,egui::Checkbox::new(&mut self.gui.unify_evm, "Standardize EVM Addresses"));
        evm_resp.on_hover_text(evm_label.join("\n")).on_disabled_hover_text(&devel);

        let master_label = ["When enabled:",
          "All coins will be generated from Bitcoin's Master Private Keys.",
          "\n",
          "When disabled:",
          "If coin has its own Master Private Key headers then they will be used.",
        ];

        let master_resp: egui::Response = ui.add_enabled(false, egui::Checkbox::new(&mut self.gui.unify_master_keys, "Unify Master Keys"));
        master_resp.on_hover_text(master_label.join("\n")).on_disabled_hover_text(&devel);

        let hardened_address_label = ["When enabled:",
          "All addresses will be derived with hardened path",
          "\n",
          "When disabled:",
          "Address follows normal path.",
        ];

        let hardened_address_resp: egui::Response = ui.add_enabled(true, egui::Checkbox::new(&mut self.gui.hardened_address, "Hardened Addresses"));
        hardened_address_resp.on_hover_text(hardened_address_label.join("\n")).on_disabled_hover_text(&devel);

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
          self.gui.secrets_dialog.mnemonic_passphrase = self.wallet.seed_secret.mnemonic_passphrase.clone();
          self.gui.secrets_dialog.seed = self.wallet.seed_secret.seed.clone();

          self.gui.secrets_dialog.master_secp256k1_private_key = self.wallet.secret_keys.master_secp256k1_keys.master_private_key_encoded.clone();
          self.gui.secrets_dialog.master_secp256k1_public_key = self.wallet.secret_keys.master_secp256k1_keys.master_public_key_encoded.clone();

          self.gui.secrets_dialog.master_ed25519_private_key = self.wallet.secret_keys.master_ed25519_keys.master_private_key_encoded.clone();
          self.gui.secrets_dialog.master_ed25519_public_key = self.wallet.secret_keys.master_ed25519_keys.master_public_key_encoded.clone();

          self.gui.secrets_dialog.open = true;
        }
      });

      ui.menu_button("Help", |ui| {
        if ui.add_enabled(false, egui::Button::new("About")).on_disabled_hover_text(&devel).on_hover_text("About this app").clicked() {
          // TODO: Create about window
        }

        if ui.add_enabled(false, egui::Button::new("Version")).on_disabled_hover_text(&devel).on_hover_text("Check for latest version").clicked() {
          // TODO: Create version window
        }
      });
    });

    if ui.available_width() > TEXT_WRAPPER {
      ui.vertical_centered_justified(|ui| {
        ui.heading("Your entropy, your crypto, your control");
      });

      ui.add_space(GUI_MARGIN);
    }

    if ui.available_width() < TEXT_WRAPPER * 2.0 {
      ui.vertical(|ui| {
        ui.vertical_centered_justified(|ui| {
          self.render_entropy_dropdown(ui);
          self.render_derivation_dropdown(ui);
          self.render_mnemonic_options(ui);
        });
      });
    } else {
      ui.vertical_centered_justified(|ui| {
        ui.horizontal_wrapped(|ui| {
          self.render_entropy_dropdown(ui);
          self.render_derivation_dropdown(ui);
          self.render_mnemonic_options(ui);
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
    let row_height = font.size + GUI_MARGIN;

    let column_names = ["Index", "Icon", "Coin", "Path", "Address", "Public key", "Private Key"];

    let active_columns = if cfg!(feature = "dev") { 7 } else { 6 };

    TableBuilder::new(ui)
      .striped(true)
      .resizable(true)
      .scroll_bar_visibility(egui::containers::scroll_area::ScrollBarVisibility::VisibleWhenNeeded)
      .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
      .min_scrolled_height(0.0)
      .max_scroll_height(available_height)
      .animate_scrolling(true)
      .columns(Column::remainder().auto_size_this_frame(true).resizable(true), active_columns)
      .header(row_height, |mut header| {
        #[cfg(feature = "dev")]
        header.col(|ui| {
          ui.strong(column_names[0]);
        });

        header.col(|ui| {
          ui.strong(column_names[1]);
        });

        header.col(|ui| {
          ui.strong(column_names[2]);
        });

        header.col(|ui| {
          ui.strong(column_names[3]);
        });

        header.col(|ui| {
          ui.strong(column_names[4]);
        });

        header.col(|ui| {
          ui.strong(column_names[5]);
        });

        header.col(|ui| {
          ui.strong(column_names[6]);
        });
      })
      .body(|mut body| {
        for (coin, addresses) in &self.wallet.addresses_by_coin.0 {
          if let Some(first) = addresses.first().cloned() {
            let mut group_expanded = false;

            body.row(row_height, |mut row| {
              #[cfg(feature = "dev")]
              row.col(|ui| {
                ui.label(first.coin_index.to_string());
              });

              row.col(|ui| {
                let icon_path = std::path::Path::new("coin").join("logo").join(format!("{}.svg", *first.coin_index));
                let icon_path_str: Zeroizing<String> = Zeroizing::new(icon_path.into_os_string().into_string().unwrap_or_default());

                match e_q::get_file_from_resources(icon_path_str) {
                  Ok(file) => {
                    ui.add(
                      egui::Image::from_bytes(file.path().to_string_lossy(), file.contents())
                        .fit_to_exact_size(egui::vec2(24.0, 24.0))
                        .corner_radius(10),
                    );
                  }
                  Err(_) => {
                    // ui.add(egui::Spinner::new().size(24.0));
                  }
                }
              });

              row.col(|ui| {
                let collapsing_resp = egui::CollapsingHeader::new(format!("{} ({})", coin, addresses.len()))
                  .id_salt(format!("coin_group:{}", coin))
                  .default_open(false)
                  .show(ui, |_ui| {});

                group_expanded = collapsing_resp.body_returned.is_some();
              });

              row.col(|ui| {
                ui.label(&*first.path);
              });

              row.col(|ui| {
                ui.horizontal(|ui| {
                  if ui.button("📋").on_hover_text("Copy address").clicked() {
                    ui.ctx().copy_text(first.address.to_string());
                  }

                  ui.label(&*first.address);
                });
              });

              row.col(|ui| {
                ui.horizontal(|ui| {
                  if ui.button("📋").on_hover_text("Copy public key").clicked() {
                    ui.ctx().copy_text(first.public_key.to_string());
                  }

                  ui.label(first.public_key.to_string());
                });
              });

              row.col(|ui| {
                ui.horizontal(|ui| {
                  if ui.button("📋").on_hover_text("Copy private key").clicked() {
                    ui.ctx().copy_text(first.private_key.to_string());
                  }

                  let display_text = if ui.ui_contains_pointer() || !self.gui.hide_private_keys {
                    &first.private_key
                  } else {
                    "••••••••••••••••"
                  };
                  ui.label(display_text);
                });
              });
            });

            if group_expanded {
              for addr in addresses.iter().skip(1) {
                body.row(row_height, |mut row| {
                  #[cfg(feature = "dev")]
                  row.col(|ui| {
                    ui.label(addr.coin_index.to_string());
                  });

                  row.col(|ui| {
                    ui.label(String::new());
                  });

                  row.col(|ui| {
                    ui.label(coin);
                  });

                  row.col(|ui| {
                    ui.label(addr.path.to_string());
                  });

                  row.col(|ui| {
                    ui.horizontal(|ui| {
                      if ui.button("📋").on_hover_text("Copy address").clicked() {
                        ui.ctx().copy_text(addr.address.to_string());
                      }

                      ui.label(addr.address.to_string());
                    });
                  });

                  row.col(|ui| {
                    ui.horizontal(|ui| {
                      if ui.button("📋").on_hover_text("Copy public key").clicked() {
                        ui.ctx().copy_text(addr.public_key.to_string());
                      }

                      ui.label(addr.public_key.to_string());
                    });
                  });

                  row.col(|ui| {
                    ui.horizontal(|ui| {
                      if ui.button("📋").on_hover_text("Copy private key").clicked() {
                        ui.ctx().copy_text(addr.private_key.to_string());
                      }

                      let display_text = if ui.ui_contains_pointer() || !self.gui.hide_private_keys {
                        &addr.private_key
                      } else {
                        "••••••••••••••••"
                      };
                      ui.label(display_text);
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
    let total_width = ui.available_width();

    ui.horizontal(|ui| {
      let font_id = ui.style().text_styles[&egui::TextStyle::Body].clone();
      let color = ui.style().visuals.text_color();
      let button_descriptions = ["Generate Wallet", "Delete Wallet"];

      ui.add_space(GUI_MARGIN);

      let button_length = e_q::calculate_max_text_width(ui, &button_descriptions, font_id.clone(), color);
      ui.add_space((total_width / 2.0) - button_length - (4.0 * GUI_MARGIN / 2.0));

      let button_label =
        if self.wallet.addresses_by_coin.0.is_empty() { button_descriptions[0] } else { &format!("+{} more addresses", self.gui.address_count) };

      if self.wallet.addresses_by_coin.0.len() < self.gui.max_rows {
        if ui.button(button_label).clicked() {
          let source = self.get_entropy_source();

          if self.gui.anu_dialog.save_entropy {
            self.wallet.seed_secret.raw_entropy = self.gui.anu_dialog.randomized_entropy.clone();
          }

          let _ = self.generate_new_wallet(Some(source));
        }
      } else {
        ui.label("Memory limit reached—cannot generate more addresses.");
      }

      ui.add_space(GUI_MARGIN);

      if ui.button(button_descriptions[1]).clicked() {
        *self = Self::new()
      }
    });

    Ok(())
  }

  fn get_entropy_source(&mut self) -> Zeroizing<String> {
    self.wallet.seed_secret.entropy_source.clone()
  }

  fn get_bip(&mut self) -> Zeroizing<u32> {
    self.wallet.address_components.derivation_path.purpose.clone()
  }
}

impl eframe::App for EgoQuantum {
  fn update(
    &mut self,
    ctx: &egui::Context,
    _frame: &mut eframe::Frame,
  ) {
    match self.gui.theme.as_str() {
      "Dark" => ctx.set_theme(ThemePreference::Dark),
      "Light" => ctx.set_theme(ThemePreference::Light),
      "System" => ctx.set_theme(ThemePreference::System),
      _ => ctx.set_theme(ThemePreference::Light),
    }

    let is_maximized = ctx.input(|i| i.viewport().maximized.unwrap_or(false));
    self.gui.maximized = is_maximized;

    egui::TopBottomPanel::top("header").show(ctx, |ui| {
      ui.add_space(GUI_MARGIN);
      self.render_wallet_header(ui);
      ui.add_space(GUI_MARGIN);
    });

    egui::TopBottomPanel::bottom("footer").show(ctx, |ui| {
      ui.add_space(GUI_MARGIN);
      let _ = self.render_wallet_footer(ui);
      ui.add_space(GUI_MARGIN);
    });

    egui::CentralPanel::default().show(ctx, |ui| {
      egui::ScrollArea::horizontal().scroll_bar_visibility(egui::containers::scroll_area::ScrollBarVisibility::VisibleWhenNeeded).show(ui, |ui| {
        ui.set_height(ui.available_height());
        self.render_wallet_table(ui);
      });
    });

    self.gui.save_dialog.show(ctx);

    self.gui.open_dialog.show(ctx);

    self.gui.secrets_dialog.show(ctx);

    self.gui.anu_dialog.show(ctx);

    if let Some(loaded_wallet) = ctx.data_mut(|d| d.remove_temp::<Zeroizing<CryptoWallet>>(egui::Id::new("loaded_wallet"))) {
      self.wallet = loaded_wallet;
      match self.generate_new_wallet(Some(Zeroizing::new(String::from("SVG")))) {
        Ok(_) => {}
        Err(err) => {
          AppError::log(format!("Problem with generating new wallet: {:?}", err));
        }
      };
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

  let title = format!("{} - {} {} ({})", APP_NAME.unwrap_or("eQ"), APP_DESCRIPTION.unwrap_or_default(), APP_VERSION.unwrap_or_default(), feature);

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
      .with_inner_size([1200.0, 800.0])
      .with_min_inner_size([TEXT_WRAPPER, TEXT_WRAPPER])
      .with_icon(app_icon)
      .with_app_id("eQ"),
    ..Default::default()
  };

  eframe::run_native(
    &app_title,
    options,
    Box::new(|cc| {
      egui_extras::install_image_loaders(&cc.egui_ctx);

      Ok(Box::new(EgoQuantum::new()))
    }),
  )
  .unwrap();

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
      Err(err) => return Err(AppError::log(format!("Can not create private header in CSV: {}", err))),
    };
  } else {
    match writeln!(file, "coin,coin_index,path,address,public_key") {
      Ok(_) => {}
      Err(err) => return Err(AppError::log(format!("Can not create public header in CSV: {}", err))),
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
        Err(err) => return Err(AppError::log(format!("Can not export content to CSV: {}", err))),
      };
    }
  }

  match file.flush() {
    Ok(_) => {}
    Err(err) => return Err(AppError::log(format!("Can not flush file: {}", err))),
  };

  Ok(())
}
