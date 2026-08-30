// authors = ["Control Owl <eq[at]r-o0-t[dot]wtf>"]
// license = "CC-BY-NC-ND-4.0  [2023-2026]  Control Owl"
// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

use crate::{AppError, CryptoWallet, FunctionOutput, GUI_MARGIN, MnemonicLanguage, SeedSecretData, Zeroize, ZeroizeOnDrop, Zeroizing};

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

use core::f32;
use egui::{self, Align, Layout};
use egui::{Color32, Context, RichText, ScrollArea, Ui, scroll_area::ScrollBarVisibility};
#[cfg(feature = "osk")]
use egui_keyboard::Keyboard;
use rand_core::Rng;
use ring::aead::*;
use ring::hmac;
use ring::pbkdf2::{PBKDF2_HMAC_SHA512, derive};
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha512};
use shamir_share::{Config, ShamirShare, Share};
use std::cell::RefCell;
use std::default::Default;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};
use svg::Document;
use svg::node::element::Rectangle;
pub type SharedWallet = Rc<RefCell<Zeroizing<CryptoWallet>>>;
use rand_jitter::JitterRng;

const WALLET_HEADER: &[u8; 2] = b"eQ";
const WALLET_VERSION: u8 = 1;
const PAYLOAD_VERSION: u8 = 1;
const WALLET_KDF_VERSION: u8 = 1;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const SVG_BOX_SIZE: usize = 16;
const ANU_COOLDOWN: u32 = 60 * 2;

// SECTION: KDF
// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KdfParams {
  // Version 1: AES_256_GCM
  Pbkdf2 {
    rounds: u32,
  },

  // Version 2: Argon2id
  #[cfg(feature = "dev")]
  Argon2id {
    iterations: u32,
    memory_kb: u32,
    parallelism: u32,
  },
}

impl KdfParams {
  pub fn parse(
    version: u8,
    data: &[u8],
  ) -> Result<Self, AppError> {
    match version {
      1 => {
        if data.len() != 4 {
          return Err(AppError::log("PBKDF2 param length must be 4"));
        }

        let rounds = match data[..4].try_into() {
          Ok(bytes) => u32::from_le_bytes(bytes),
          Err(err) => {
            return Err(AppError::log(format!("Failed to parse rounds from data: {:?}", err)));
          }
        };
        Ok(KdfParams::Pbkdf2 { rounds })
      }

      // TODO: Implement Argon2id
      //       2 => {
      //         if data.len() != 12 {
      //           return Err(AppError::log("Argon2id params must be 12 bytes"));
      //         }
      //
      //         let mut offset = 0;
      //         let iterations = u32::from_le_bytes(self.read_u32_le(data, &mut offset)?);
      //         let memory_kb = u32::from_le_bytes(self.read_u32_le(data, &mut offset)?);
      //         let parallelism = u32::from_le_bytes(self.read_u32_le(data, &mut offset)?);
      //         Ok(KdfParams::Argon2id { iterations, memory_kb, parallelism })
      //       }
      _ => Err(AppError::log(format!("Unsupported KDF ID: {version}"))),
    }
  }

  pub fn to_bytes(self) -> Vec<u8> {
    match self {
      KdfParams::Pbkdf2 { rounds } => rounds.to_le_bytes().to_vec(),

      #[cfg(feature = "dev")]
      KdfParams::Argon2id {
        iterations,
        memory_kb,
        parallelism,
      } => {
        let mut vector = Vec::with_capacity(12);
        vector.extend_from_slice(&iterations.to_le_bytes());
        vector.extend_from_slice(&memory_kb.to_le_bytes());
        vector.extend_from_slice(&parallelism.to_le_bytes());

        vector
      }
    }
  }

  pub fn kdf_id(&self) -> u8 {
    match self {
      KdfParams::Pbkdf2 { .. } => 1,

      #[cfg(feature = "dev")]
      KdfParams::Argon2id { .. } => 2,
    }
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KdfChoice {
  #[default]
  Pbkdf2,

  #[cfg(feature = "dev")]
  Argon2id,
}

impl Zeroize for KdfChoice {
  fn zeroize(&mut self) {
    *self = KdfChoice::default();
  }
}

impl std::fmt::Display for KdfChoice {
  fn fmt(
    &self,
    f: &mut std::fmt::Formatter<'_>,
  ) -> std::fmt::Result {
    match self {
      KdfChoice::Pbkdf2 => write!(f, "PBKDF2-SHA256"),

      #[cfg(feature = "dev")]
      KdfChoice::Argon2id => write!(f, "Argon2id"),
    }
  }
}

// SECTION: SAVE WALLET DIALOG
// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

#[derive(Zeroize, ZeroizeOnDrop, Debug, Clone, Default)]
pub struct SaveWalletDialog {
  pub open: bool,

  pub wallet_name: String,
  pub password: String,
  pub password_confirm: String,
  pub show_passwords: bool,

  pub use_advance: bool,
  pub use_sss: bool,
  pub total_images: u8,
  pub threshold: u8,

  pub pixel_redundancy: f32,

  // TODO: Improve or migrate from rc
  #[zeroize(skip)]
  pub wallet_to_save: Option<SharedWallet>,
  pub direct_save: bool,
  pub save_location: Option<String>,

  pub kdf_choice: KdfChoice,

  pub pbkdf2_rounds: u32,
  pub argon2_iterations: u32,
  pub argon2_memory_mb: u32,
  pub argon2_parallelism: u32,

  #[cfg(feature = "osk")]
  pub keyboard: VirtualKeyboard,
}

impl SaveWalletDialog {
  pub fn new() -> Self {
    SaveWalletDialog {
      open: false,

      wallet_name: String::new(),
      password: String::new(),
      password_confirm: String::new(),
      show_passwords: false,

      use_advance: false,
      use_sss: false,
      total_images: 1,
      threshold: 1,

      pixel_redundancy: 1.8,

      wallet_to_save: None,
      direct_save: false,
      save_location: None,

      kdf_choice: KdfChoice::default(),

      pbkdf2_rounds: 1_000_000,
      argon2_iterations: 3,
      argon2_memory_mb: 64,
      argon2_parallelism: 4,

      #[cfg(feature = "osk")]
      keyboard: VirtualKeyboard::default(),
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

    egui::Window::new("Save Wallet").open(&mut open).resizable(true).show(ctx, |ui| {
      // TODO: Improve
      let _ = self.ui_content(ui);
    });

    if !open {
      self.close_and_clear();
    }
  }

  fn close_and_clear(&mut self) {
    self.zeroize();
    *self = SaveWalletDialog::new();
  }

  pub fn save_wallet(&mut self) -> FunctionOutput<()> {
    if let Some(wallet_rc) = &self.wallet_to_save.clone() {
      let wallet_data = wallet_rc.borrow();
      let save_dialog = self.clone();

      let total_images = save_dialog.total_images;
      let threshold = save_dialog.threshold;
      let redundancy = save_dialog.pixel_redundancy;

      if threshold == 0 || total_images == 0 || threshold > total_images {
        return Err(AppError::log("Shamir parameters are set wrong".to_string()));
      }

      if wallet_data.addresses_by_coin.0.is_empty() {
        return Err(AppError::log("Empty wallet, nothing to save".to_string()));
      }

      let encrypted_blob: Zeroizing<Vec<u8>> = match encrypt_wallet(
        wallet_data.clone(),
        Zeroizing::new(save_dialog.password.clone()),
        save_dialog.pbkdf2_rounds,
        save_dialog.kdf_choice,
      ) {
        Ok(blob) => blob,
        Err(err) => {
          return Err(AppError::log(format!("Problem with encrypting wallet: {:?}", err)));
        }
      };

      let shamir_config = Config::new().with_integrity_check(false).with_compression(false);

      let shares: Zeroizing<Vec<Vec<u8>>> = if total_images == 1 {
        Zeroizing::new(vec![encrypted_blob.to_vec()])
      } else {
        match shamir_split(
          encrypted_blob.clone(),
          Zeroizing::new(total_images),
          Zeroizing::new(threshold),
          shamir_config.clone(),
        ) {
          Ok(split) => split,
          Err(_) => return Err(AppError::log("Problem with shamir_split")),
        }
      };

      if self.direct_save {
        for (i, share) in shares.iter().enumerate() {
          let svg = match create_svg(Zeroizing::new(share.clone()), redundancy) {
            Ok(image) => image,
            Err(_) => return Err(AppError::log("Problem with creating SVG")),
          };

          let filename = format!("{}-{}.svg", self.wallet_name, i + 1);

          let save_location = match &self.save_location {
            Some(path) => path,
            None => "",
          };

          let mut output_path = PathBuf::from(save_location);
          output_path.push(&filename);

          if let Err(e) = svg::save(&output_path, &svg) {
            return Err(AppError::log(format!("Problem saving SVG image {:?}: {:?}", output_path, e)));
          }
        }
      } else {
        match rfd::FileDialog::new().set_title("Save wallet file(s)").pick_folder() {
          Some(folder) => {
            if !folder.is_dir() {
              return Err(AppError::log("Selected path is not a directory"));
            }

            let base_name = save_dialog.wallet_name.trim();
            let safe_base = base_name
              .chars()
              .map(|c| if c == '/' || c == '\\' || c == ':' || c.is_control() { '_' } else { c })
              .collect::<String>();

            for (i, share) in shares.iter().enumerate() {
              let svg = match create_svg(Zeroizing::new(share.clone()), redundancy) {
                Ok(image) => image,
                Err(_) => return Err(AppError::log("Problem with creating SVG")),
              };

              let filename = format!("{}-{}.svg", safe_base, i + 1);
              let mut out_path: PathBuf = folder.clone();
              out_path.push(&filename);

              if let Err(e) = svg::save(&out_path, &svg) {
                return Err(AppError::log(format!("Problem saving SVG image {:?}: {:?}", out_path, e)));
              }
            }

            {
              let reconstructed: Zeroizing<Vec<u8>> =
                match shamir_combine(shares, Zeroizing::new(total_images), Zeroizing::new(threshold), shamir_config) {
                  Ok(share) => share,
                  Err(_) => return Err(AppError::log("Problem combining Shamir shares")),
                };

              if total_images > 1 {
                assert_eq!(&*encrypted_blob, &*reconstructed);
              } else {
                assert_eq!(&encrypted_blob[1..], &*reconstructed);
              }
            }
          }
          None => {
            // user cancelled folder selection
          }
        };
      }
    }

    Ok(())
  }

  fn ui_content(
    &mut self,
    ui: &mut egui::Ui,
  ) -> FunctionOutput<()> {
    #[cfg(feature = "osk")]
    self.keyboard.0.pump_events(ui.ctx());

    egui::ScrollArea::both()
      .scroll_bar_visibility(egui::containers::scroll_area::ScrollBarVisibility::VisibleWhenNeeded)
      .show(ui, |ui| {
        ui.with_layout(Layout::top_down(Align::Center), |ui| {
          ui.add_space(GUI_MARGIN);

          ui.group(|ui| {
            ui.label("Wallet name");
            ui.add(egui::TextEdit::singleline(&mut self.wallet_name).desired_width(ui.available_width()));

            #[cfg(feature = "osk")]
            self.keyboard.0.show(ui.ctx());
          });

          ui.add_space(GUI_MARGIN);

          ui.group(|ui| {
            ui.label("Password");
            ui.add(
              egui::TextEdit::singleline(&mut self.password)
                .desired_width(ui.available_width())
                .password(!self.show_passwords),
            );

            ui.label("Confirm password");
            ui.add(
              egui::TextEdit::singleline(&mut self.password_confirm)
                .desired_width(ui.available_width())
                .password(!self.show_passwords),
            );

            ui.add_space(GUI_MARGIN);

            ui.checkbox(&mut self.show_passwords, "Show password");
          });

          ui.add_space(GUI_MARGIN);
          ui.separator();
          ui.add_space(GUI_MARGIN);

          ui.checkbox(&mut self.use_advance, "Advance settings");

          if self.use_advance {
            ui.add_space(GUI_MARGIN);

            let min_images: u8 = 2;
            let max_images: u8 = 24;
            let min_redundancy: f32 = 1.0;
            let max_redundancy: f32 = 10.0;
            let min_pbkdf2_rounds: u32 = 500_000;
            let max_pbkdf2_rounds: u32 = 50_000_000;

            ui.group(|ui| {
              ui.heading("Shamir's Secret Sharing");
              ui.add_space(GUI_MARGIN);

              ui.checkbox(&mut self.use_sss, "Use Shamir's Secret Sharing?");
              if self.use_sss {
                ui.horizontal(|ui| {
                  ui.label("Total shares:");

                  ui.add(
                    egui::Slider::new(&mut self.total_images, min_images..=max_images)
                      .smart_aim(true)
                      .trailing_fill(true),
                  )
                });

                ui.add_space(GUI_MARGIN);

                ui.horizontal(|ui| {
                  ui.label("Threshold:");
                  ui.add(
                    egui::Slider::new(&mut self.threshold, min_images..=self.total_images)
                      .smart_aim(true)
                      .trailing_fill(true),
                  )
                });
              }
            });

            ui.add_space(GUI_MARGIN);
            ui.separator();
            ui.add_space(GUI_MARGIN);

            ui.group(|ui| {
              ui.heading("SVG pixel redundancy");
              ui.add_space(GUI_MARGIN);

              ui.horizontal(|ui| {
                ui.label("Redundancy:");

                ui.add(
                  egui::Slider::new(&mut self.pixel_redundancy, min_redundancy..=max_redundancy)
                    .smart_aim(true)
                    .trailing_fill(true),
                )
              });
            });

            ui.add_space(GUI_MARGIN);
            ui.separator();
            ui.add_space(GUI_MARGIN);

            ui.group(|ui| {
              ui.heading("Key derivation function");
              ui.add_space(GUI_MARGIN);

              egui::ComboBox::from_label("Encryption method")
                .selected_text(format!("{}", self.kdf_choice))
                .show_ui(ui, |ui| {
                  ui.selectable_value(&mut self.kdf_choice, KdfChoice::Pbkdf2, "PBKDF2-SHA256");

                  #[cfg(feature = "dev")]
                  ui.selectable_value(&mut self.kdf_choice, KdfChoice::Argon2id, "Argon2id");
                });

              ui.add_space(GUI_MARGIN);

              match self.kdf_choice {
                KdfChoice::Pbkdf2 => {
                  ui.horizontal(|ui| {
                    ui.label("Rounds:");
                    ui.add(egui::Slider::new(&mut self.pbkdf2_rounds, min_pbkdf2_rounds..=max_pbkdf2_rounds).logarithmic(true));
                  });
                }

                #[cfg(feature = "dev")]
                KdfChoice::Argon2id => {
                  let min_argon2_iterations: u32 = 1;
                  let max_argon2_iterations: u32 = 10;
                  let min_argon2_memory: u32 = 16;
                  let max_argon2_memory: u32 = 1024;
                  let min_argon2_parallelism: u32 = 1;
                  let max_argon2_parallelism: u32 = 10;

                  ui.horizontal(|ui| {
                    ui.label("Iterations:");
                    ui.add(
                      egui::Slider::new(&mut self.argon2_iterations, min_argon2_iterations..=max_argon2_iterations)
                        .smart_aim(true)
                        .trailing_fill(true),
                    )
                  });
                  ui.horizontal(|ui| {
                    ui.label("Memory (MB):");
                    ui.add(
                      egui::Slider::new(&mut self.argon2_memory_mb, min_argon2_memory..=max_argon2_memory)
                        .smart_aim(true)
                        .trailing_fill(true),
                    );
                  });
                  ui.horizontal(|ui| {
                    ui.label("Parallelism:");
                    ui.add(
                      egui::Slider::new(&mut self.argon2_parallelism, min_argon2_parallelism..=max_argon2_parallelism)
                        .smart_aim(true)
                        .trailing_fill(true),
                    );
                  });
                }
              }
            });
          }

          ui.add_space(GUI_MARGIN);

          ui.with_layout(egui::Layout::top_down(egui::Align::Center), |ui| {
            if ui.button("Cancel").clicked() {
              self.close_and_clear();
            }

            let save_enabled = !self.wallet_name.trim().is_empty()
              && !self.password.is_empty()
              && self.password == self.password_confirm
              && (!self.use_sss || self.threshold <= self.total_images);

            if ui.add_enabled(save_enabled, egui::Button::new("Save")).clicked() {
              match self.save_wallet() {
                Ok(_) => {}
                Err(err) => {
                  return Err(AppError::log(format!("Can not save wallet, error: {:?}", err)));
                }
              };

              self.close_and_clear();
            }

            Ok(())
          });
        });
      });

    Ok(())
  }
}

impl eframe::App for SaveWalletDialog {
  fn ui(
    &mut self,
    ui: &mut egui::Ui,
    _frame: &mut eframe::Frame,
  ) {
    egui::CentralPanel::default().show(ui, |ui| {
      ui.heading("Save Wallet");
      self.show(ui.ctx());
    });
  }
}

// SECTION: OPEN WALLET DIALOG
// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

#[derive(Zeroize, ZeroizeOnDrop, Default, Debug, Clone)]
pub struct OpenWalletDialog {
  pub open: bool,
  pub password: String,
  pub show_password: bool,

  pub selected_svgs: Vec<String>,
  decoded_shares: Zeroizing<Vec<Vec<u8>>>,

  // TODO: Improve
  #[zeroize(skip)]
  pub loaded_wallet: Option<SharedWallet>,

  #[cfg(feature = "osk")]
  pub keyboard: VirtualKeyboard,
}

impl OpenWalletDialog {
  pub fn new() -> Self {
    Self::default()
  }

  fn try_load_wallet(
    &mut self,
    ctx: &egui::Context,
  ) -> FunctionOutput<()> {
    use ring::hmac;

    if self.decoded_shares.is_empty() {
      return Err(AppError::log("No valid shares decoded"));
    }

    let encrypted_blob: Zeroizing<Vec<u8>> = if self.decoded_shares.len() == 1 {
      Zeroizing::new(self.decoded_shares[0].clone())
    } else {
      let config = Config::new().with_integrity_check(false).with_compression(false);

      let combined_secret: Zeroizing<Vec<u8>> = shamir_combine(
        self.decoded_shares.clone(),
        Zeroizing::new(self.decoded_shares.len() as u8),
        Zeroizing::new(self.decoded_shares.len() as u8),
        config,
      )
      .map_err(|err| AppError::log(format!("Problem with combining shamir's secrets: {:?}", err)))?;

      combined_secret
    };

    let data: Zeroizing<Vec<u8>> = match decrypt_wallet(Zeroizing::new(self.password.clone()), &encrypted_blob) {
      Ok(vector) => vector,
      Err(err) => {
        return Err(AppError::log(format!("Problem with decrypting wallet: {:?}", err)));
      }
    };

    let payload = match parse_payload(data) {
      Ok(vector) => Zeroizing::new(vector),
      Err(err) => {
        return Err(AppError::log(format!("Problem with parsing decrypted wallet: {:?}", err)));
      }
    };

    // Monero
    let wordlist: Vec<&str> = e_q::load_monero_wordlist();
    let key = hmac::Key::new(hmac::HMAC_SHA512, b"Bitcoin seed");
    let tag = hmac::sign(&key, hex::decode(payload.seed_secret.seed.clone()).unwrap().as_slice());

    let mut priv_key = Zeroizing::new([0u8; 32]);
    let mut chain = Zeroizing::new([0u8; 32]);

    priv_key.copy_from_slice(&tag.as_ref()[..32]);
    chain.copy_from_slice(&tag.as_ref()[32..]);

    let path: Vec<(u32, bool)> = match *payload.bip {
      32 => {
        vec![(0, true), (0, true), (0, true)]
      }
      _ => {
        vec![(*payload.bip, true), (128, true), (0, true)]
      }
    };

    for (index, hardened) in path {
      let parent_priv_vec = Zeroizing::new(priv_key.to_vec());
      let parent_chain_vec = Zeroizing::new(chain.to_vec());
      let hardened_z = Zeroizing::new(hardened);
      let index_z = Zeroizing::new(index);

      let derived =
        crate::keys::derive_secp256k1_child(parent_priv_vec, parent_chain_vec, index_z, hardened_z).expect("BIP32 child derivation failed");

      priv_key.copy_from_slice(&derived.child_private_key_bytes);
      chain.copy_from_slice(&derived.child_chain_code_bytes);
    }

    let hashed: Zeroizing<[u8; 32]> = crate::keys::cn_fast_hash(&Zeroizing::new(priv_key.to_vec()))?;
    let spend_key: Zeroizing<[u8; 32]> = Zeroizing::new(crate::keys::monero_sc_reduce32(hashed)?.to_bytes());
    let monero_words: Zeroizing<String> = crate::keys::monero_seed_to_mnemonic(spend_key.clone(), &wordlist)?;

    let mut wallet = CryptoWallet::new();
    wallet.seed_secret = Zeroizing::new(payload.seed_secret.clone());

    wallet.address_components.derivation_path.purpose = payload.bip.clone();
    wallet.address_components.derivation_path.last_index = payload.last_index.clone();

    wallet.secret_keys.monero_keys.monero_mnemonic_words = monero_words;
    wallet.secret_keys.monero_keys.monero_spend_key = Zeroizing::new(hex::encode(spend_key).to_string());

    ctx.data_mut(|d| {
      d.insert_temp(egui::Id::new("loaded_wallet"), Zeroizing::new(wallet));
    });

    Ok(())
  }

  pub fn show(
    &mut self,
    ctx: &egui::Context,
  ) {
    if !self.open {
      return;
    }

    let mut open = self.open;

    egui::Window::new("Open Wallet").open(&mut open).resizable(true).show(ctx, |ui| {
      self.ui_content(ui, ctx);
    });

    if !open {
      self.close_and_clear();
    }
  }

  fn close_and_clear(&mut self) {
    self.zeroize();
    *self = OpenWalletDialog::new();
  }

  fn ui_content(
    &mut self,
    ui: &mut egui::Ui,
    ctx: &egui::Context,
  ) {
    #[cfg(feature = "osk")]
    self.keyboard.0.pump_events(ui.ctx());

    ui.with_layout(egui::Layout::top_down_justified(egui::Align::Center), |ui| {
      ui.add_space(GUI_MARGIN);

      ui.group(|ui| {
        if self.selected_svgs.is_empty() {
          ui.label("No shares selected");
        } else {
          ui.label(format!("Selected {} share(s):", self.selected_svgs.len()));
          for path in &self.selected_svgs {
            let file_name = std::path::Path::new(path).file_name().and_then(|n| n.to_str()).unwrap_or(path);
            ui.label(file_name.to_string());
          }
        }

        ui.add_space(GUI_MARGIN);

        if ui.button("Select SVG shares").clicked() {
          // TODO: Add osk support for direct file read

          self.pick_svg_files();
        }

        if !self.selected_svgs.is_empty() && ui.button("Clear selection").clicked() {
          self.selected_svgs.clear();
          self.decoded_shares.clear();
        }
      });

      ui.add_space(GUI_MARGIN);

      ui.group(|ui| {
        ui.horizontal(|ui| {
          ui.label("Password");

          ui.add(egui::TextEdit::singleline(&mut self.password).password(!self.show_password));

          let icon = if self.show_password { "Hide" } else { "Show" };

          if ui.button(icon).clicked() {
            self.show_password = !self.show_password;
          }

          #[cfg(feature = "osk")]
          self.keyboard.0.show(ui.ctx());

          ui.set_width(ui.available_width());
        });
      });

      ui.add_space(GUI_MARGIN);

      ui.with_layout(egui::Layout::top_down(egui::Align::Center), |ui| {
        if ui.button("Cancel").clicked() {
          self.close_and_clear();
        }

        let can_attempt_load = !self.selected_svgs.is_empty() && !self.password.is_empty();
        if ui.add_enabled(can_attempt_load, egui::Button::new("Load Wallet")).clicked()
          && let Ok(_) = self.try_load_wallet(ctx)
        {
          self.close_and_clear()
        }
      });
    });
  }

  fn pick_svg_files(&mut self) {
    if let Some(paths) = rfd::FileDialog::new()
      .add_filter("SVG", &["svg"])
      .set_title("Select wallet file(s)")
      .pick_files()
    {
      self.selected_svgs = paths.into_iter().map(|p| p.display().to_string()).collect();

      // TODO: Improve
      let _ = self.decode_selected_svgs();
    }
  }

  fn decode_selected_svgs(&mut self) -> FunctionOutput<()> {
    self.decoded_shares.clear();

    for path in &self.selected_svgs {
      match load_svg(path) {
        Ok(share) => {
          self.decoded_shares.push(share);
        }
        Err(err) => {
          return Err(AppError::log(format!("Failed to decode SVG {}: {}", path, err)));
        }
      }
    }

    Ok(())
  }
}

impl eframe::App for OpenWalletDialog {
  fn ui(
    &mut self,
    ui: &mut egui::Ui,
    _frame: &mut eframe::Frame,
  ) {
    egui::CentralPanel::default().show(ui, |ui| {
      ui.heading("Open Wallet");
      self.show(ui.ctx());
    });
  }
}

// SECTION: SHAMIR SECRET SHARING
// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

fn shamir_split(
  secret: Zeroizing<Vec<u8>>,
  total: Zeroizing<u8>,
  threshold: Zeroizing<u8>,
  config: Config,
) -> FunctionOutput<Zeroizing<Vec<Vec<u8>>>> {
  let mut scheme = match ShamirShare::builder(*total, *threshold).with_config(config).build() {
    Ok(share) => share,
    Err(err) => {
      return Err(AppError::log(format!("Problem with generating shamir shares: {:?}", err)));
    }
  };

  let shares_raw = {
    let result = scheme.split(&secret);
    match result {
      Ok(shares) => shares,
      Err(_) => return Err(AppError::log("Failed to split secret")),
    }
  };

  let share_bytes: Zeroizing<Vec<Vec<u8>>> = Zeroizing::new(
    shares_raw
      .into_iter()
      .map(|share| {
        let mut buf = Vec::with_capacity(1 + share.data.len());
        buf.push(share.index);
        buf.extend_from_slice(&share.data);

        buf
      })
      .collect(),
  );

  Ok(share_bytes)
}

fn shamir_combine(
  share_bytes: Zeroizing<Vec<Vec<u8>>>,
  total_shares: Zeroizing<u8>,
  threshold: Zeroizing<u8>,
  config: Config,
) -> FunctionOutput<Zeroizing<Vec<u8>>> {
  if share_bytes.len() < *threshold as usize {
    return Err(AppError::log(format!(
      "Not enough shares provided: got {:?}, need {:?}",
      share_bytes.len(),
      threshold
    )));
  }

  let shares: Vec<Share> = {
    let mut share = Vec::with_capacity(share_bytes.len());
    for b in share_bytes.iter() {
      let index = b[0];
      let data = b[1..].to_vec();

      share.push(Share {
        index,
        data: data.clone(),
        threshold: *threshold,
        total_shares: *total_shares,
        integrity_check: config.integrity_check,
        compression: config.compression,
      });
    }

    share
  };

  let secret: Zeroizing<Vec<u8>> = match ShamirShare::reconstruct(&shares) {
    Ok(secret) => Zeroizing::new(secret),
    Err(err) => {
      return Err(AppError::log(format!("Failed to combine Shamir shares: {:?}", err)));
    }
  };

  Ok(secret)
}

// SECTION: WALLET ENCRYPTION
// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

pub fn encrypt_wallet(
  wallet: Zeroizing<CryptoWallet>,
  password: Zeroizing<String>,
  pbkdf2_rounds: u32,
  kdf_choice: KdfChoice,
) -> FunctionOutput<Zeroizing<Vec<u8>>> {
  let rng = SystemRandom::new();

  let mut salt = vec![0u8; SALT_LEN];
  rng.fill(&mut salt).map_err(|err| AppError::log(format!("RNG salt error: {:?}", err)))?;

  let mut nonce_bytes = [0u8; NONCE_LEN];
  rng.fill(&mut nonce_bytes).map_err(|e| AppError::log(format!("RNG nonce: {e:?}")))?;
  let nonce = Nonce::assume_unique_for_key(nonce_bytes);

  let file_key: Zeroizing<[u8; 32]> = derive_pbkdf2_key(&password, &salt, pbkdf2_rounds);
  let payload: Zeroizing<Vec<u8>> = create_payload(&wallet)?;

  let unbound = UnboundKey::new(&AES_256_GCM, &file_key[..]).map_err(|err| AppError::log(format!("UnboundKey AES_256_GCM: {:?}", err)))?;
  let key = LessSafeKey::new(unbound);

  let mut ciphertext: Zeroizing<Vec<u8>> = Zeroizing::new(payload.to_vec());
  ciphertext.reserve(TAG_LEN);

  let payload_len = (NONCE_LEN + ciphertext.len() + TAG_LEN) as u32;

  let kdf_params = match kdf_choice {
    KdfChoice::Pbkdf2 => KdfParams::Pbkdf2 { rounds: pbkdf2_rounds },

    #[cfg(feature = "dev")]
    KdfChoice::Argon2id => KdfParams::Argon2id {
      iterations: 3,
      memory_kb: 64 * 1024,
      parallelism: 4,
    },
    // _ => return Err(AppError::log("Unsupported KDF")),
  };

  let kdf_id = kdf_params.kdf_id();
  let kdf_param_bytes = kdf_params.to_bytes();

  let mut header: Vec<u8> =
    Vec::with_capacity(WALLET_HEADER.len() + WALLET_VERSION as usize + WALLET_KDF_VERSION as usize + kdf_param_bytes.len() + SALT_LEN + 4);

  header.extend_from_slice(WALLET_HEADER);
  header.push(WALLET_VERSION);
  header.push(kdf_id);
  header.extend_from_slice(&(kdf_param_bytes.len() as u32).to_le_bytes());
  header.extend_from_slice(&kdf_param_bytes);
  header.extend_from_slice(&(salt.len() as u32).to_le_bytes());
  header.extend_from_slice(&salt);
  header.extend_from_slice(&payload_len.to_le_bytes());

  let aad = Aad::from(&header[..]);
  key
    .seal_in_place_append_tag(nonce, aad, &mut *ciphertext)
    .map_err(|err| AppError::log(format!("AES-GCM seal failed: {:?}", err)))?;

  let mut payload: Vec<u8> = Vec::with_capacity(header.len() + NONCE_LEN + ciphertext.len());
  payload.extend_from_slice(&header);
  payload.extend_from_slice(&nonce_bytes);
  payload.extend_from_slice(&ciphertext);

  Ok(Zeroizing::new(payload))
}

pub fn decrypt_wallet(
  password: Zeroizing<String>,
  file: &[u8],
) -> FunctionOutput<Zeroizing<Vec<u8>>> {
  if file.len() < 50 {
    return Err(AppError::log("File too small"));
  }

  let mut offset = 0;

  if &file[offset..offset + WALLET_HEADER.len()] != WALLET_HEADER {
    return Err(AppError::log("Bad magic"));
  }
  offset += WALLET_HEADER.len();

  if file[offset] != WALLET_VERSION {
    return Err(AppError::log("Unsupported wallet version"));
  }
  offset += 1;

  let kdf_id = file[offset];
  if kdf_id != WALLET_KDF_VERSION {
    return Err(AppError::log("Unsupported KDF ID"));
  }
  offset += 1;

  if file.len() < offset + 4 {
    return Err(AppError::log("Truncated KDF parameter length"));
  }

  let kdf_param_len = match file[offset..offset + 4].try_into() {
    Ok(bytes) => u32::from_le_bytes(bytes) as usize,
    Err(err) => {
      return Err(AppError::log(format!("Failed to parse KDF parameter length: {:?}", err)));
    }
  };

  offset += 4;

  if file.len() < offset + kdf_param_len {
    return Err(AppError::log("Truncated KDF parameters"));
  }
  let kdf_param_bytes = &file[offset..offset + kdf_param_len];
  let kdf_params = KdfParams::parse(kdf_id, kdf_param_bytes).map_err(|e| AppError::log(format!("KDF parse error: {e}")))?;
  offset += kdf_param_len;

  match kdf_params {
    KdfParams::Pbkdf2 { rounds } => {
      if kdf_param_len != 4 {
        return Err(AppError::log("PBKDF2 param length must be 4"));
      }

      if file.len() < offset + 4 {
        return Err(AppError::log("Missing salt length"));
      }

      let salt_len = match file[offset..offset + 4].try_into() {
        Ok(bytes) => u32::from_le_bytes(bytes) as usize,
        Err(err) => {
          return Err(AppError::log(format!("Failed to parse salt length: {:?}", err)));
        }
      };

      offset += 4;

      if file.len() < offset + salt_len {
        return Err(AppError::log("Truncated salt"));
      }
      let salt = &file[offset..offset + salt_len];
      offset += salt_len;

      if file.len() < offset + 4 {
        return Err(AppError::log("Missing payload length"));
      }

      let payload_len = match file[offset..offset + 4].try_into() {
        Ok(bytes) => u32::from_le_bytes(bytes) as usize,
        Err(err) => {
          return Err(AppError::log(format!("Failed to parse payload length: {:?}", err)));
        }
      };

      let payload_len_offset = offset;
      offset += 4;

      if file.len() < offset + payload_len {
        return Err(AppError::log("Truncated payload"));
      }
      if payload_len < 12 + 16 {
        return Err(AppError::log("Payload too short"));
      }

      let payload_start = offset;
      let payload = &file[payload_start..payload_start + payload_len];
      let nonce_bytes = &payload[0..12];
      let ct_with_tag = &payload[12..];

      let key_bytes: Zeroizing<[u8; 32]> = derive_pbkdf2_key(&password, salt, rounds);

      let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes[..]).map_err(|_| AppError::log("UnboundKey AES_256_GCM"))?;
      let key = LessSafeKey::new(unbound);
      let nonce = Nonce::try_assume_unique_for_key(nonce_bytes).map_err(|_| AppError::log("Nonce size"))?;

      let aad = Aad::from(&file[..payload_len_offset + 4]);

      let mut buf = ct_with_tag.to_vec();
      let plaintext = key
        .open_in_place(nonce, aad, &mut buf)
        .map_err(|_| AppError::log("AES-GCM open failed"))?;

      Ok(Zeroizing::new(plaintext.to_vec()))
    }

    #[cfg(feature = "dev")]
    KdfParams::Argon2id { .. } => Err(AppError::log("Argon2id not yet supported")),
  }
}

// SECTION: SVG
// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

fn create_svg(
  share: Zeroizing<Vec<u8>>,
  redundancy: f32,
) -> FunctionOutput<Document> {
  let share_len = share.len();
  let min_cells_needed = (share_len as f32 * redundancy).ceil() as usize;

  let possible_grids = [16, 20, 24, 28, 32, 36, 40, 48, 52, 56, 60, 64, 68, 72, 76, 80, 84, 88, 92, 96, 100];
  let grid = possible_grids
    .into_iter()
    .find(|&g| g * g >= min_cells_needed)
    .expect("Payload too large even for 48x48 grid - split into multiple images");

  let size = (grid * SVG_BOX_SIZE) as f32;

  let mut doc = Document::new().set("viewBox", (0, 0, size, size)).set("style", "background:#FFF");

  for (i, &byte) in share.iter().cycle().take(grid * grid).enumerate() {
    let x = (i % grid * SVG_BOX_SIZE) as f32;
    let y = (i / grid * SVG_BOX_SIZE) as f32;

    let r = byte.wrapping_add(40);
    let g = byte.rotate_left(3).wrapping_add(80);
    let b = byte.rotate_right(5).wrapping_add(120);

    let color = format!("#{:02x}{:02x}{:02x}", r, g, b);

    let rect = Rectangle::new()
      .set("x", x)
      .set("y", y)
      .set("width", SVG_BOX_SIZE)
      .set("height", SVG_BOX_SIZE)
      .set("fill", color);

    doc = doc.add(rect);
  }
  Ok(doc)
}

pub fn load_svg(path: &str) -> FunctionOutput<Vec<u8>> {
  let mut content = String::new();

  let parser = match svg::open(path, &mut content) {
    Ok(p) => p,
    Err(e) => {
      return Err(AppError::log(format!("Failed to open SVG: {}", e)));
    }
  };

  let mut secret_bytes = Vec::new();

  for event in parser {
    if let svg::parser::Event::Tag(name, _typ, attributes) = event
      && name == "rect"
      && let Some(fill) = attributes.get("fill")
      && let Some(hex) = fill.strip_prefix('#')
      && hex.len() == 6
      && let (Ok(r), Ok(g), Ok(b)) = (
        u8::from_str_radix(&hex[0..2], 16),
        u8::from_str_radix(&hex[2..4], 16),
        u8::from_str_radix(&hex[4..6], 16),
      )
    {
      let red = r.wrapping_sub(40);
      let green = g.wrapping_sub(80).rotate_right(3);
      let blue = b.wrapping_sub(120).rotate_left(5);

      let vote = [red, green, blue];
      let byte = best_share(&vote).unwrap_or(red);

      secret_bytes.push(byte);
    }
  }

  let best_start = secret_bytes.windows(2).position(|magic| magic == *WALLET_HEADER).unwrap_or(0);
  let recovered = &secret_bytes[best_start..];

  Ok(recovered.to_vec())
}

fn best_share(bytes: &[u8]) -> Option<u8> {
  let mut counts = [0u8; 256];
  for &b in bytes {
    counts[b as usize] += 1;
  }

  counts
    .iter()
    .position(|&c| c == 3)
    .map(|i| i as u8)
    .or_else(|| counts.iter().position(|&c| c == 2).map(|i| i as u8))
}

// SECTION: WALLET PAYLOAD
// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

pub fn create_payload(wallet: &CryptoWallet) -> FunctionOutput<Zeroizing<Vec<u8>>> {
  let mut payload: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());

  // 1 Payload version (1 byte)
  payload.push(PAYLOAD_VERSION);

  // 2 Full entropy (length u32 LE + bytes)
  let entropy_bytes = wallet.seed_secret.full_entropy.as_bytes();
  let entropy_len = entropy_bytes.len();
  let entropy_len_u32: u32 = entropy_len.try_into().expect("Entropy length too large for u32");
  payload.extend_from_slice(&entropy_len_u32.to_le_bytes());
  payload.extend_from_slice(entropy_bytes);

  // 3 Mnemonic dictionary (length u16 LE + bytes)
  let dict_bytes = wallet.seed_secret.mnemonic_dictionary.display_name().as_bytes();

  let dict_len = dict_bytes.len();
  let dict_len_u16: u16 = dict_len.try_into().expect("Mnemonic dictionary length too large for u16");
  payload.extend_from_slice(&dict_len_u16.to_le_bytes());
  payload.extend_from_slice(dict_bytes);

  // 4 Mnemonic passphrase (length u16 LE + bytes)
  let pass_bytes = wallet.seed_secret.mnemonic_passphrase.as_bytes();
  let pass_len = pass_bytes.len();
  let pass_len_u16: u16 = pass_len.try_into().expect("Mnemonic passphrase length too large for u16");
  payload.extend_from_slice(&pass_len_u16.to_le_bytes());
  payload.extend_from_slice(pass_bytes);

  // 5 Derivation path (u32 LE)
  let path: &Zeroizing<crate::DerivationPathData> = &wallet.address_components.derivation_path;
  payload.extend_from_slice(&(*path.purpose).to_le_bytes());

  // 6 Last index (u32 LE)
  let derivation: &Zeroizing<crate::DerivationPathData> = &wallet.address_components.derivation_path;
  payload.extend_from_slice(&(*derivation.last_index).to_le_bytes());

  Ok(payload)
}

pub fn parse_payload(plain: Zeroizing<Vec<u8>>) -> FunctionOutput<WalletPayload> {
  use ring::pbkdf2;
  let mut off = 0usize;

  // 1 Payload version
  let version_bytes = match take(&plain, &mut off, 1) {
    Ok(byte) => byte,
    Err(err) => {
      return Err(AppError::log(format!("reading payload version failed: {:?}", err)));
    }
  };
  let payload_version: u8 = version_bytes[0];

  // 2 Full entropy
  let entropy_len_bytes = match take(&plain, &mut off, 4) {
    Ok(byte) => byte,
    Err(err) => {
      return Err(AppError::log(format!("reading entropy length failed: {:?}", err)));
    }
  };

  let entropy_len_u32 = match read_u32_le(entropy_len_bytes.as_slice()) {
    Ok(length) => length,
    Err(err) => {
      return Err(AppError::log(format!("parsing entropy length failed: {:?}", err)));
    }
  };

  let entropy_len = entropy_len_u32 as usize;

  if entropy_len > (1 << 24) {
    return Err(AppError::log(format!("entropy length too large: {}", entropy_len)));
  }

  let entropy_bytes = match take(&plain, &mut off, entropy_len) {
    Ok(byte) => byte,
    Err(err) => {
      return Err(AppError::log(format!("reading entropy bytes failed: {:?}", err)));
    }
  };

  let entropy = match String::from_utf8(entropy_bytes) {
    Ok(entropy) => entropy,
    Err(err) => return Err(AppError::log(format!("reading entropy failed: {:?}", err))),
  };

  let full_entropy = Zeroizing::new(entropy);

  let (raw_entropy, entropy_checksum) = match split_entropy_zeroizing(&full_entropy) {
    Ok(pair) => pair,
    Err(e) => {
      return Err(AppError::log(format!("splitting entropy failed: {}", e)));
    }
  };

  // 3 Mnemonic dictionary
  let dict_len_bytes = match take(&plain, &mut off, 2) {
    Ok(length) => length,
    Err(err) => {
      return Err(AppError::log(format!("reading dictionary length failed: {:?}", err)));
    }
  };

  let dict_len_u16 = match read_u16_le(dict_len_bytes.as_slice()) {
    Ok(length) => length,
    Err(err) => {
      return Err(AppError::log(format!("parsing dictionary length failed: {:?}", err)));
    }
  };

  let dict_len = dict_len_u16 as usize;

  if dict_len > (1 << 16) {
    return Err(AppError::log(format!("dictionary length too large: {}", dict_len)));
  }

  let dict_bytes = match take(&plain, &mut off, dict_len) {
    Ok(b) => b,
    Err(e) => {
      return Err(AppError::log(format!("reading dictionary bytes failed: {:?}", e)));
    }
  };

  let mnemonic_dictionary: Zeroizing<MnemonicLanguage> = match String::from_utf8(dict_bytes) {
    Ok(dict) => Zeroizing::new(MnemonicLanguage::get_dictionary(&dict)),
    Err(err) => {
      return Err(AppError::log(format!("reading dict_bytes failed: {:?}", err)));
    }
  };

  // 4 Mnemonic passphrase
  let pass_len_bytes = match take(&plain, &mut off, 2) {
    Ok(length) => length,
    Err(err) => {
      return Err(AppError::log(format!("reading passphrase length failed: {:?}", err)));
    }
  };

  let pass_len_u16 = match read_u16_le(pass_len_bytes.as_slice()) {
    Ok(length) => length,
    Err(err) => {
      return Err(AppError::log(format!("parsing passphrase length failed: {:?}", err)));
    }
  };

  let pass_len = pass_len_u16 as usize;

  if pass_len > (1 << 16) {
    return Err(AppError::log(format!("passphrase length too large: {}", pass_len)));
  }

  let pass_bytes = match take(&plain, &mut off, pass_len) {
    Ok(byte) => byte,
    Err(err) => {
      return Err(AppError::log(format!("reading passphrase bytes failed: {:?}", err)));
    }
  };

  let mnemonic_passphrase = match String::from_utf8(pass_bytes) {
    Ok(pass) => Zeroizing::new(pass),
    Err(err) => {
      return Err(AppError::log(format!("reading pass_bytes failed: {:?}", err)));
    }
  };

  let mnemonic_words: Zeroizing<String> = match crate::keys::generate_mnemonic_words(full_entropy.clone(), mnemonic_dictionary.clone()) {
    Ok(words) => words,
    Err(err) => {
      return Err(AppError::log(format!("Problem with generating mnemonic words: {}", err)));
    }
  };

  let salt: Zeroizing<String> = Zeroizing::new(format!("mnemonic{}", *mnemonic_passphrase));
  let mut seed: Zeroizing<[u8; 64]> = Zeroizing::new([0u8; 64]);
  let iter = match std::num::NonZeroU32::new(2048) {
    Some(number) => number,
    _ => {
      return Err(AppError::log(String::from("Problem with pbkdf2 iter")));
    }
  };

  pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA512, iter, salt.as_bytes(), mnemonic_words.as_bytes(), &mut *seed);

  let seed_hex: Zeroizing<String> = Zeroizing::new(hex::encode(&seed[..]));

  // 5 Derivation path purpose (u32 LE)
  let bip_bytes = match take(&plain, &mut off, 4) {
    Ok(byte) => byte,
    Err(err) => {
      return Err(AppError::log(format!("reading derivation purpose failed: {:?}", err)));
    }
  };

  let bip_u32 = match read_u32_le(bip_bytes.as_slice()) {
    Ok(bip) => bip,
    Err(err) => {
      return Err(AppError::log(format!("parsing derivation purpose failed: {:?}", err)));
    }
  };

  let bip = Zeroizing::new(bip_u32);

  // 6 Last index (u32 LE)
  let last_index_bytes = match take(&plain, &mut off, 4) {
    Ok(byte) => byte,
    Err(err) => {
      return Err(AppError::log(format!("reading last index failed: {:?}", err)));
    }
  };

  let last_index = match read_u32_le(last_index_bytes.as_slice()) {
    Ok(index) => Zeroizing::new(index),
    Err(err) => {
      return Err(AppError::log(format!("parsing last index failed: {:?}", err)));
    }
  };

  Ok(WalletPayload {
    payload_version,
    seed_secret: SeedSecretData {
      entropy_source: Zeroizing::new(String::from("SVG")),
      entropy_length: Zeroizing::new(entropy_len),
      full_entropy,

      mnemonic_passphrase_source: Zeroizing::new(String::from("SVG")),
      mnemonic_dictionary,
      mnemonic_passphrase,
      raw_entropy,
      entropy_checksum,

      mnemonic_words,
      seed: seed_hex,
    },
    bip,
    last_index,
  })
}

pub fn split_entropy(full: &str) -> Result<(String, String), String> {
  let total = full.len();

  if !total.is_multiple_of(33) {
    return Err(format!("invalid entropy bit length {}, expected a multiple of 33", total));
  }

  let checksum_len = total / 33; // 4 ... 8
  if !(4..=8).contains(&checksum_len) {
    return Err(format!("unsupported checksum length {}", checksum_len));
  }

  let entropy_len = total - checksum_len;
  let raw_entropy = full[..entropy_len].to_string();
  let checksum = full[entropy_len..].to_string();

  Ok((raw_entropy, checksum))
}

pub fn split_entropy_zeroizing(full: &Zeroizing<String>) -> Result<(Zeroizing<String>, Zeroizing<String>), String> {
  let (raw, cs) = split_entropy(full)?;
  Ok((Zeroizing::new(raw), Zeroizing::new(cs)))
}

fn derive_pbkdf2_key(
  password: &Zeroizing<String>,
  salt: &[u8],
  iterations: u32,
) -> Zeroizing<[u8; 32]> {
  let mut key: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);

  derive(
    PBKDF2_HMAC_SHA512,
    std::num::NonZeroU32::new(iterations).expect("iterations > 0"),
    salt,
    password.as_bytes(),
    &mut key[..],
  );

  key
}

#[derive(Zeroize, ZeroizeOnDrop, Debug, Clone, Default)]
pub struct WalletPayload {
  payload_version: u8,
  pub seed_secret: SeedSecretData,
  bip: Zeroizing<u32>,
  last_index: Zeroizing<u32>,
}

fn read_u16_le(bytes: &[u8]) -> FunctionOutput<u16> {
  if bytes.len() < 2 {
    return Err(AppError::log("u16 underflow"));
  }

  Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32_le(bytes: &[u8]) -> FunctionOutput<u32> {
  if bytes.len() < 4 {
    return Err(AppError::log("u32 underflow"));
  }

  Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn take(
  bytes: &[u8],
  offset: &mut usize,
  count: usize,
) -> FunctionOutput<Vec<u8>> {
  if *offset + count > bytes.len() {
    return Err(AppError::log("buffer underflow"));
  };

  let out = &bytes[*offset..*offset + count];
  *offset += count;

  Ok(out.to_vec())
}

// SECTION: SHOW SECRETS DIALOG
// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

#[derive(Zeroize, ZeroizeOnDrop, Debug, Clone, Default)]
pub struct ShowSecretsDialog {
  pub open: bool,

  pub entropy: Zeroizing<String>,
  pub entropy_checksum: Zeroizing<String>,
  pub full_entropy: Zeroizing<String>,

  pub mnemonic_words: Zeroizing<String>,
  pub monero_mnemonic_words: Zeroizing<String>,

  pub mnemonic_passphrase: Zeroizing<String>,
  pub seed: Zeroizing<String>,

  pub master_secp256k1_private_key: Zeroizing<String>,
  pub master_secp256k1_public_key: Zeroizing<String>,

  pub master_ed25519_private_key: Zeroizing<String>,
  pub master_ed25519_public_key: Zeroizing<String>,

  selected_tab: SecretsTab,
}

#[derive(PartialEq, Eq, Clone, Copy, Zeroize, Debug, Default)]
enum SecretsTab {
  #[default]
  Entropy,

  Seed,
  MasterKeys,
  MoneroKeys,
}

impl ShowSecretsDialog {
  pub fn new() -> Self {
    Self {
      open: false,

      entropy: Zeroizing::new(String::new()),
      entropy_checksum: Zeroizing::new(String::new()),
      full_entropy: Zeroizing::new(String::new()),

      mnemonic_words: Zeroizing::new(String::new()),
      monero_mnemonic_words: Zeroizing::new(String::new()),

      mnemonic_passphrase: Zeroizing::new(String::new()),
      seed: Zeroizing::new(String::new()),

      master_secp256k1_private_key: Zeroizing::new(String::new()),
      master_secp256k1_public_key: Zeroizing::new(String::new()),

      master_ed25519_private_key: Zeroizing::new(String::new()),
      master_ed25519_public_key: Zeroizing::new(String::new()),

      selected_tab: SecretsTab::Entropy,
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

    egui::Window::new("Show secrets").open(&mut open).resizable(true).show(ctx, |ui| {
      let _ = self.ui_content(ui);
    });

    if !open {
      self.close_and_clear();
    }
  }

  fn close_and_clear(&mut self) {
    self.zeroize();

    *self = ShowSecretsDialog::new();
  }

  fn ui_content(
    &mut self,
    ui: &mut egui::Ui,
  ) -> FunctionOutput<()> {
    ui.add_space(GUI_MARGIN);

    ui.horizontal(|ui| {
      ui.selectable_value(&mut self.selected_tab, SecretsTab::Entropy, "Entropy");
      ui.selectable_value(&mut self.selected_tab, SecretsTab::Seed, "Seed");
      ui.selectable_value(&mut self.selected_tab, SecretsTab::MasterKeys, "Master Keys");
      ui.selectable_value(&mut self.selected_tab, SecretsTab::MoneroKeys, "Monero");
    });

    ui.separator();

    egui::ScrollArea::both()
      .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::VisibleWhenNeeded)
      .show(ui, |ui| {
        ui.with_layout(Layout::top_down(Align::Center), |ui| match self.selected_tab {
          SecretsTab::Entropy => self.ui_entropy(ui),
          SecretsTab::Seed => self.ui_seed(ui),
          SecretsTab::MasterKeys => self.ui_master_keys(ui),
          SecretsTab::MoneroKeys => self.ui_monero_keys(ui),
        });
      });

    Ok(())
  }

  fn ui_entropy(
    &mut self,
    ui: &mut egui::Ui,
  ) {
    Self::text_group(ui, "Entropy", &mut self.entropy, true);
    Self::text_group(ui, "Entropy checksum", &mut self.entropy_checksum, false);
    Self::text_group(ui, "Full entropy", &mut self.full_entropy, true);
  }

  fn ui_seed(
    &mut self,
    ui: &mut egui::Ui,
  ) {
    Self::text_group(ui, "Mnemonic words", &mut self.mnemonic_words, true);
    Self::text_group(ui, "Mnemonic passphrase", &mut self.mnemonic_passphrase, true);
    Self::text_group(ui, "Seed", &mut self.seed, true);
  }

  fn ui_master_keys(
    &mut self,
    ui: &mut egui::Ui,
  ) {
    ui.heading("Secp256k1");
    Self::text_group(ui, "Master Private Key", &mut self.master_secp256k1_private_key, true);
    Self::text_group(ui, "Master Public Key", &mut self.master_secp256k1_public_key, true);

    ui.add_space(GUI_MARGIN);

    ui.heading("Ed25519");
    Self::text_group(ui, "Master Private Key", &mut self.master_ed25519_private_key, true);
    Self::text_group(ui, "Master Public Key", &mut self.master_ed25519_public_key, true);
  }

  fn ui_monero_keys(
    &mut self,
    ui: &mut egui::Ui,
  ) {
    Self::text_group(ui, "Monero 25 mnemonic words\nm/44'/128'/0'", &mut self.monero_mnemonic_words, true);
  }

  fn text_group(
    ui: &mut egui::Ui,
    label: &str,
    value: &mut Zeroizing<String>,
    multiline: bool,
  ) {
    ui.group(|ui| {
      ui.label(label);

      ui.vertical_centered(|ui| {
        if multiline {
          ui.add(egui::TextEdit::multiline(&mut value.as_str()).desired_width(ui.available_width()));
        } else {
          ui.add(egui::TextEdit::singleline(&mut value.as_str()).desired_width(ui.available_width()));
        }

        if ui.button("📋").on_hover_text("Copy to clipboard").clicked() {
          ui.ctx().copy_text(value.to_string());
        }
      });
    });
  }
}

impl eframe::App for ShowSecretsDialog {
  fn ui(
    &mut self,
    ui: &mut egui::Ui,
    _frame: &mut eframe::Frame,
  ) {
    egui::CentralPanel::default().show(ui, |ui| {
      ui.heading("Wallet secrets");
      self.show(ui.ctx());
    });
  }
}

// SECTION: ANU DIALOG
// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

#[derive(PartialEq, Eq, Clone, Copy, Zeroize, Debug, Default)]
enum AnuTab {
  #[default]
  Anu,

  Settings,
}

#[derive(PartialEq, Eq, Clone, Copy, Zeroize, Debug, Default)]
enum AnuDataTypes {
  #[default]
  Hex16,

  Uint8,
  Uint16,
}

#[derive(PartialEq, Eq, Clone, Copy, Zeroize, Debug, Default)]
enum EntropyMode {
  #[default]
  RandomValues,
  SequentialSlice,
}

#[derive(Zeroize, ZeroizeOnDrop, Debug, Clone, Default)]
pub struct ShowAnuDialog {
  pub open: bool,

  data_type: Zeroizing<AnuDataTypes>,
  array_length: Zeroizing<u32>,
  block_size: Zeroizing<u32>,

  selected_tab: AnuTab,

  fetched_json: Zeroizing<String>,
  show_randomize: bool,

  cooldown_secs: u32,

  #[zeroize(skip)]
  last_cooldown_update: Option<std::time::Instant>,

  pub randomized_entropy: Zeroizing<String>,
  selected_value_indices: Zeroizing<Vec<usize>>,
  raw_values: Zeroizing<Vec<String>>,

  entropy_mode: Zeroizing<EntropyMode>,
  pub entropy_length: Zeroizing<usize>,

  pub save_entropy: bool,
}

impl ShowAnuDialog {
  pub fn new() -> Self {
    Self {
      open: false,

      data_type: Zeroizing::new(AnuDataTypes::default()),
      array_length: Zeroizing::new(10),
      block_size: Zeroizing::new(10),

      selected_tab: AnuTab::Anu,

      fetched_json: Zeroizing::new(String::new()),
      show_randomize: false,

      cooldown_secs: 0,
      last_cooldown_update: None,

      randomized_entropy: Zeroizing::new(String::new()),
      selected_value_indices: Zeroizing::new(Vec::new()),
      raw_values: Zeroizing::new(Vec::new()),

      entropy_mode: Zeroizing::new(EntropyMode::default()),
      entropy_length: Zeroizing::new(256),

      save_entropy: false,
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

    egui::Window::new("Create QRNG entropy").open(&mut open).resizable(true).show(ctx, |ui| {
      let _ = self.ui_content(ui);
    });

    if !open {
      self.close_and_clear();
    }
  }

  fn close_and_clear(&mut self) {
    self.zeroize();

    *self = ShowAnuDialog::new();
  }

  fn ui_content(
    &mut self,
    ui: &mut egui::Ui,
  ) -> FunctionOutput<()> {
    self.update_cooldown(ui.ctx());

    ui.add_space(GUI_MARGIN);

    ui.horizontal(|ui| {
      ui.selectable_value(&mut self.selected_tab, AnuTab::Anu, "ANU");
      ui.selectable_value(&mut self.selected_tab, AnuTab::Settings, "Settings");
    });

    ui.separator();

    egui::ScrollArea::vertical()
      .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::VisibleWhenNeeded)
      .show(ui, |ui| {
        ui.with_layout(Layout::top_down(Align::Center), |ui| match self.selected_tab {
          AnuTab::Anu => self.ui_anu(ui),
          AnuTab::Settings => self.ui_settings(ui),
        });
      });

    Ok(())
  }

  fn ui_anu(
    &mut self,
    ui: &mut egui::Ui,
  ) -> FunctionOutput<()> {
    ui.heading("ANU QRNG API");

    ui.add_space(GUI_MARGIN);

    ui.label("This interface fetches (Q)uantum (R)andom (N)umbers from the (A)ustralian (N)ational (U)niversity.");

    ui.add_space(GUI_MARGIN);

    if self.show_randomize && !self.randomized_entropy.is_empty() && ui.button("Randomize").clicked() {
      self.randomize_entropy();
    }

    if self.show_randomize && !self.randomized_entropy.is_empty() && ui.button("Save").clicked() {
      self.save_entropy = true;
      self.open = false;
    }

    ui.label(format!("Generated {}-bit entropy:", *self.entropy_length));
    let mut entropy_str = self.randomized_entropy.to_string();

    ui.add(
      egui::TextEdit::multiline(&mut entropy_str)
        .desired_rows(5)
        .desired_width(f32::INFINITY)
        .font(egui::TextStyle::Monospace)
        .interactive(false),
    );

    self.randomized_entropy = Zeroizing::new(entropy_str);

    ui.add_space(GUI_MARGIN);

    let button_label = if self.cooldown_secs == 0 {
      "Generate QRNG".to_string()
    } else {
      format!("Wait {} s", self.cooldown_secs)
    };
    let mut generate_button = egui::Button::new(button_label);

    if self.cooldown_secs > 0 {
      ui.label("One request every 2 minutes");

      ui.ctx().request_repaint_after(std::time::Duration::from_millis(1000));

      generate_button = generate_button.sense(egui::Sense::hover());
    }

    let resp = ui.add(generate_button);

    if self.cooldown_secs > 0 {
      resp.on_hover_text(format!("ANU QRNG API allows only 1 request per {} seconds.", ANU_COOLDOWN));
    } else if resp.clicked() {
      self.show_randomize = true;

      self.fetch_anu_data();

      self.selected_value_indices.clear();
      self.randomize_entropy();

      self.cooldown_secs = ANU_COOLDOWN;
      self.last_cooldown_update = None;
    }

    ui.add_space(GUI_MARGIN);

    ui.label("Raw ANU data:");

    let mut job = egui::text::LayoutJob::default();

    for (i, val) in self.raw_values.iter().enumerate() {
      let color = if self.selected_value_indices.contains(&i) {
        egui::Color32::RED
      } else {
        egui::Color32::PLACEHOLDER
      };

      job.append(&format!("{} ", val), 0.0, egui::TextFormat { color, ..Default::default() });
    }

    ui.label(job);

    ui.add_space(GUI_MARGIN);

    Ok(())
  }

  fn ui_settings(
    &mut self,
    ui: &mut egui::Ui,
  ) -> FunctionOutput<()> {
    ui.group(|ui| {
      ui.heading("ANU API");
      ui.add_space(GUI_MARGIN);

      egui::ComboBox::from_label("Data type")
        .selected_text(format!("{:?}", *self.data_type))
        .show_ui(ui, |ui| {
          ui.selectable_value(&mut *self.data_type, AnuDataTypes::Uint8, "uint8");
          ui.selectable_value(&mut *self.data_type, AnuDataTypes::Uint16, "uint16");
          ui.selectable_value(&mut *self.data_type, AnuDataTypes::Hex16, "hex16");
        });
      ui.add_space(GUI_MARGIN);

      // min length = 256 bit - checksum + place for random
      let min_length = match *self.data_type {
        AnuDataTypes::Uint8 => 42,  // 42 * 8 bits = 336 bits
        AnuDataTypes::Uint16 => 21, // 21 * 16 bits = 336 bits
        AnuDataTypes::Hex16 => 7,   // 7 * 48 bits = 336 bits
      };

      ui.add(egui::Slider::new(&mut *self.array_length, min_length..=1024).text("Array length"));
      ui.add(egui::Slider::new(&mut *self.block_size, min_length..=1024).text("Block size"));

      ui.add_space(GUI_MARGIN);
    });

    ui.group(|ui| {
      ui.heading("Entropy");

      egui::ComboBox::from_label("Entropy extraction mode")
        .selected_text(format!("{:?}", *self.entropy_mode))
        .show_ui(ui, |ui| {
          ui.selectable_value(&mut *self.entropy_mode, EntropyMode::RandomValues, "Random values");
          ui.selectable_value(&mut *self.entropy_mode, EntropyMode::SequentialSlice, "Sequential slice");
        });

      ui.add_space(GUI_MARGIN);
    });

    Ok(())
  }

  fn fetch_anu_data(&mut self) {
    let length = *self.array_length;
    let size = *self.block_size;

    let data_type = match &*self.data_type {
      AnuDataTypes::Uint8 => "uint8",
      AnuDataTypes::Uint16 => "uint16",
      AnuDataTypes::Hex16 => "hex16",
    };

    let url = format!("https://qrng.anu.edu.au/API/jsonI.php?length={}&type={}&size={}", length, data_type, size);

    let result = ureq::get(&url).call();

    self.raw_values.clear();
    self.fetched_json.clear();

    match result {
      Ok(mut resp) => match resp.body_mut().read_to_string() {
        Ok(text) => match serde_json::from_str::<serde_json::Value>(&text) {
          Ok(json) => {
            if let Some(arr) = json.get("data").and_then(|v| v.as_array()) {
              match *self.data_type {
                AnuDataTypes::Hex16 => {
                  let mut vals = Vec::new();
                  let mut bits = String::new();

                  for item in arr {
                    if let Some(s) = item.as_str() {
                      // split into 2-char hex bytes
                      for i in (0..s.len()).step_by(2) {
                        let byte_hex = &s[i..i + 2];
                        vals.push(byte_hex.to_string());

                        if let Ok(byte) = u8::from_str_radix(byte_hex, 16) {
                          bits.push_str(&format!("{:08b}", byte));
                        }
                      }
                    }
                  }

                  *self.raw_values = vals;
                  self.fetched_json = Zeroizing::new(bits);
                }

                AnuDataTypes::Uint8 => {
                  let mut vals = Vec::new();
                  let mut bits = String::new();

                  for item in arr {
                    if let Some(n) = item.as_u64() {
                      vals.push(n.to_string());
                      bits.push_str(&format!("{:08b}", n as u8));
                    }
                  }

                  *self.raw_values = vals;
                  self.fetched_json = Zeroizing::new(bits);
                }

                AnuDataTypes::Uint16 => {
                  let mut vals = Vec::new();
                  let mut bits = String::new();

                  for item in arr {
                    if let Some(n) = item.as_u64() {
                      vals.push(n.to_string());
                      bits.push_str(&format!("{:016b}", n as u16));
                    }
                  }

                  *self.raw_values = vals;
                  self.fetched_json = Zeroizing::new(bits);
                }
              }
            }
          }
          Err(_) => self.fetched_json = Zeroizing::new(text),
        },
        Err(err) => self.fetched_json = Zeroizing::new(format!("Error reading response body: {}", err)),
      },
      Err(err) => self.fetched_json = Zeroizing::new(format!("HTTP error: {}", err)),
    };
  }

  fn update_cooldown(
    &mut self,
    ctx: &egui::Context,
  ) {
    if self.cooldown_secs == 0 {
      self.last_cooldown_update = None;
      return;
    }

    let now = std::time::Instant::now();

    if let Some(last) = self.last_cooldown_update {
      if now.duration_since(last).as_secs() >= 1 {
        let elapsed = now.duration_since(last).as_secs() as u32;
        if elapsed >= self.cooldown_secs {
          self.cooldown_secs = 0;
          self.last_cooldown_update = None;
        } else {
          self.cooldown_secs -= elapsed;
          self.last_cooldown_update = Some(now);
        }
        ctx.request_repaint(); // keep ticking
      }
    } else {
      self.last_cooldown_update = Some(now);
      ctx.request_repaint();
    }
  }

  fn randomize_entropy(&mut self) {
    use ring::rand::{SecureRandom, SystemRandom};

    self.selected_value_indices.clear();
    self.randomized_entropy = Zeroizing::new(String::new());

    if self.raw_values.is_empty() {
      self.randomized_entropy = Zeroizing::new(String::new());
      return;
    }

    let mut per_value_bits: Vec<String> = Vec::new();

    match *self.data_type {
      AnuDataTypes::Hex16 => {
        for v in self.raw_values.iter() {
          if let Ok(byte) = u8::from_str_radix(v, 16) {
            per_value_bits.push(format!("{:08b}", byte));
          }
        }
      }
      AnuDataTypes::Uint8 => {
        for v in self.raw_values.iter() {
          if let Ok(n) = v.parse::<u8>() {
            per_value_bits.push(format!("{:08b}", n));
          }
        }
      }
      AnuDataTypes::Uint16 => {
        for v in self.raw_values.iter() {
          if let Ok(n) = v.parse::<u16>() {
            per_value_bits.push(format!("{:016b}", n));
          }
        }
      }
    }

    let rng = SystemRandom::new();

    // RANDOM VALUE SELECTION
    if *self.entropy_mode == EntropyMode::RandomValues {
      let total_values = per_value_bits.len();
      if total_values == 0 {
        self.randomized_entropy = Zeroizing::new("No values".to_string());
        return;
      }

      let mut buf = [0u8; 4];
      let max_u32 = u32::MAX as u64;
      let bound = (max_u32 / (total_values as u64)) * (total_values as u64);

      let mut collected_bits = String::new();

      while collected_bits.len() < *self.entropy_length {
        let idx = loop {
          rng.fill(&mut buf).expect("SystemRandom failed");
          let v = u32::from_le_bytes(buf) as u64;
          if v < bound {
            break (v % (total_values as u64)) as usize;
          }
        };

        self.selected_value_indices.push(idx);
        collected_bits.push_str(&per_value_bits[idx]);

        if self.selected_value_indices.len() > total_values {
          break;
        }
      }

      if collected_bits.len() < *self.entropy_length {
        self.randomized_entropy = Zeroizing::new("Not enough entropy".to_string());
        self.selected_value_indices.clear();
        return;
      }

      let entropy = collected_bits.chars().take(*self.entropy_length).collect::<String>();
      self.randomized_entropy = Zeroizing::new(entropy);
      return;
    }

    // SEQUENTIAL SLICE
    if *self.entropy_mode == EntropyMode::SequentialSlice {
      let full_bitstring = per_value_bits.join("");

      if full_bitstring.len() < *self.entropy_length {
        self.randomized_entropy = Zeroizing::new("Not enough entropy".to_string());
        return;
      }

      let max_offset = full_bitstring.len() - *self.entropy_length;

      let mut buf = [0u8; 4];
      rng.fill(&mut buf).expect("SystemRandom failed");
      let rand32 = u32::from_le_bytes(buf) as usize;

      let offset = rand32 % max_offset;

      let entropy = full_bitstring[offset..offset + *self.entropy_length].to_string();
      self.randomized_entropy = Zeroizing::new(entropy);

      self.selected_value_indices.clear();

      let mut bit_count = 0;
      for (i, bits) in per_value_bits.iter().enumerate() {
        let start = bit_count;
        let end = bit_count + bits.len();

        if offset < end && offset + *self.entropy_length > start {
          self.selected_value_indices.push(i);
        }

        bit_count = end;
      }
    }
  }
}

impl eframe::App for ShowAnuDialog {
  fn ui(
    &mut self,
    ui: &mut egui::Ui,
    _frame: &mut eframe::Frame,
  ) {
    self.update_cooldown(ui.ctx());

    egui::CentralPanel::default().show(ui, |ui| {
      ui.heading("ANU QRNG");
      self.show(ui.ctx());
    });
  }
}

// SECTION: VIRTUAL KEYBOARD
// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

#[cfg(feature = "osk")]
#[derive(Default)]
pub struct VirtualKeyboard(pub egui_keyboard::Keyboard);

#[cfg(feature = "osk")]
impl Zeroize for VirtualKeyboard {
  fn zeroize(&mut self) {
    self.0 = egui_keyboard::Keyboard::default();
  }
}

#[cfg(feature = "osk")]
impl Clone for VirtualKeyboard {
  fn clone(&self) -> Self {
    VirtualKeyboard(Keyboard::default())
  }
}

#[cfg(feature = "osk")]
impl std::fmt::Debug for VirtualKeyboard {
  fn fmt(
    &self,
    f: &mut std::fmt::Formatter,
  ) -> std::fmt::Result {
    f.debug_tuple("VirtualKeyboard").finish_non_exhaustive()
  }
}

// SECTION: MULTI ENTROPY DIALOG
// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize, Default)]
enum EntropySection {
  #[default]
  Settings,

  Rng,
  Qrng,
  Jitter,
  UserMovement,
  Final,
}

impl EntropySection {
  fn label(&self) -> &'static str {
    match self {
      EntropySection::Settings => "Settings",

      EntropySection::Rng => "Rng",
      EntropySection::Qrng => "Qrng",
      EntropySection::Jitter => "Jitter",
      EntropySection::UserMovement => "Mouse",
      EntropySection::Final => "Final Entropy",
    }
  }
}

#[derive(Zeroize, ZeroizeOnDrop, Debug, Clone)]
pub struct MultiEntropyWindow {
  pub open: bool,
  selected_section: EntropySection,

  pub entropy_length: usize,

  pub mnemonic_dictionary: Zeroizing<MnemonicLanguage>,

  rng_entropy: Zeroizing<String>,
  qrng_entropy: Zeroizing<String>,
  jitter_entropy: Zeroizing<String>,
  mouse_entropy: Zeroizing<String>,
  final_entropy: Zeroizing<String>,

  rng_saved: bool,
  qrng_saved: bool,
  jitter_saved: bool,
  mouse_saved: bool,

  last_mouse_pos: Option<(f32, f32)>,
  mouse_event_count: usize,
  last_mouse_digest: Option<Zeroizing<Vec<u8>>>,

  #[zeroize(skip)]
  pub wallet_to_create: Option<SharedWallet>,

  #[zeroize(skip)]
  randomizing: Option<EntropySection>,

  started: bool,
}

impl Default for MultiEntropyWindow {
  fn default() -> Self {
    Self::new()
  }
}

impl MultiEntropyWindow {
  const ENTROPY_MIN: usize = 128;
  const ENTROPY_MAX: usize = 256;

  pub fn new() -> Self {
    Self {
      open: false,
      selected_section: EntropySection::Settings,
      entropy_length: 256,

      mnemonic_dictionary: Zeroizing::new(MnemonicLanguage::English),

      rng_entropy: Zeroizing::new(String::new()),
      qrng_entropy: Zeroizing::new(String::new()),
      jitter_entropy: Zeroizing::new(String::new()),
      mouse_entropy: Zeroizing::new(String::new()),
      final_entropy: Zeroizing::new(String::new()),

      rng_saved: false,
      qrng_saved: false,
      jitter_saved: false,
      mouse_saved: false,

      last_mouse_pos: None,
      mouse_event_count: 0,
      last_mouse_digest: None,

      wallet_to_create: None,
      randomizing: None,

      started: false,
    }
  }

  pub fn show(
    &mut self,
    ctx: &Context,
  ) {
    if !self.open {
      return;
    }

    let mut open = self.open;

    egui::Window::new("Multi-Entropy")
      .open(&mut open)
      .resizable(true)
      .default_width(700.0)
      .default_height(500.0)
      .show(ctx, |ui| {
        self.ui_content(ui);
      });

    if !open {
      self.close_and_clear();
    }
  }

  fn close_and_clear(&mut self) {
    self.rng_entropy.zeroize();
    self.qrng_entropy.zeroize();
    self.jitter_entropy.zeroize();
    self.mouse_entropy.zeroize();
    self.final_entropy.zeroize();

    *self = MultiEntropyWindow::new();
  }

  fn save_and_advance(
    &mut self,
    section: EntropySection,
  ) {
    self.randomizing = None;

    match section {
      EntropySection::Rng => {
        self.rng_saved = true;
        self.selected_section = EntropySection::Qrng;
      }
      EntropySection::Qrng => {
        self.qrng_saved = true;
        self.selected_section = EntropySection::Jitter;
      }
      EntropySection::Jitter => {
        self.jitter_saved = true;
        self.selected_section = EntropySection::UserMovement;
      }
      EntropySection::UserMovement => {
        self.mouse_saved = true;
        self.selected_section = EntropySection::Final;
      }
      _ => {}
    }
  }

  fn text_group(
    ui: &mut Ui,
    label: &str,
    value: &mut String,
    _sensitive: bool,
  ) {
    ui.vertical(|ui| {
      ui.label(RichText::new(label).strong());

      ui.add(
        egui::TextEdit::multiline(value)
          .font(egui::TextStyle::Monospace)
          .desired_width(f32::INFINITY)
          .desired_rows(4)
          .interactive(false),
      );
    });
  }

  fn ui_content(
    &mut self,
    ui: &mut Ui,
  ) {
    egui::Panel::left("entropy_sidebar")
      .show_separator_line(true)
      .resizable(false)
      .default_size(150.0)
      .min_size(150.0)
      .show(ui, |ui| {
        self.sidebar(ui);
      });

    egui::CentralPanel::default().show(ui, |ui| {
      self.render_section(ui);
    });
  }

  fn sidebar(
    &mut self,
    ui: &mut Ui,
  ) {
    ScrollArea::vertical()
      .auto_shrink([false, false])
      .scroll_bar_visibility(ScrollBarVisibility::VisibleWhenNeeded)
      .show(ui, |ui| {
        ui.vertical(|ui| {
          ui.add_space(GUI_MARGIN);

          let sections = [
            EntropySection::Settings,
            EntropySection::Rng,
            EntropySection::Qrng,
            EntropySection::Jitter,
            EntropySection::UserMovement,
            EntropySection::Final,
          ];

          for &section in &sections {
            let enabled = match section {
              EntropySection::Settings => true,
              EntropySection::Rng => self.started,
              EntropySection::Qrng => self.rng_saved,
              EntropySection::Jitter => self.qrng_saved,
              EntropySection::UserMovement => self.jitter_saved,
              EntropySection::Final => self.mouse_saved,
            };

            if !enabled {
              ui.add_enabled(false, egui::Button::new(section.label()));

              continue;
            }

            let is_selected = self.selected_section == section;

            let saved = match section {
              EntropySection::Settings => false,
              EntropySection::Final => false,

              EntropySection::Rng => self.rng_saved,
              EntropySection::Qrng => self.qrng_saved,
              EntropySection::Jitter => self.jitter_saved,
              EntropySection::UserMovement => self.mouse_saved,
            };

            let label = if saved {
              RichText::new(format!("[OK] {}", section.label())).color(if ui.theme() == egui::Theme::Dark { Color32::GREEN } else { Color32::RED })
            } else {
              RichText::new(section.label())
            };

            if ui.selectable_label(is_selected, label).clicked() {
              self.selected_section = section;
            }
          }
        });

        ui.add_space(GUI_MARGIN);
        ui.separator();
        ui.add_space(GUI_MARGIN);

        ui.vertical(|ui| {
          ui.label(RichText::new("Progress").strong());
          ui.add_space(GUI_MARGIN);

          ui.label(format!(
            "Saved: {}/4",
            [self.rng_saved, self.qrng_saved, self.jitter_saved, self.mouse_saved]
              .iter()
              .filter(|&&b| b)
              .count()
          ));

          ui.label(format!("Target: {}-bit", self.entropy_length));
        });
      });
  }

  fn render_section(
    &mut self,
    ui: &mut Ui,
  ) {
    ScrollArea::vertical()
      .scroll_bar_visibility(ScrollBarVisibility::VisibleWhenNeeded)
      .show(ui, |ui| match self.selected_section {
        EntropySection::Settings => self.render_settings_panel(ui),
        EntropySection::Rng => self.render_source_panel(ui, EntropySection::Rng),
        EntropySection::Qrng => self.render_source_panel(ui, EntropySection::Qrng),
        EntropySection::Jitter => self.render_source_panel(ui, EntropySection::Jitter),
        EntropySection::UserMovement => self.render_mouse_panel(ui),
        EntropySection::Final => self.render_final_panel(ui, ui.ctx().clone()),
      });
  }

  fn render_settings_panel(
    &mut self,
    ui: &mut Ui,
  ) {
    ui.horizontal(|ui| {
      ui.heading("Settings");

      ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
        if !self.started {
          if ui
            .button(RichText::new("Start").strong())
            .on_hover_text("Start entropy collection")
            .clicked()
          {
            self.started = true;
            self.selected_section = EntropySection::Rng;
          }
        } else {
          ui.label(
            RichText::new("Collection started")
              .color(if ui.theme() == egui::Theme::Dark { Color32::GREEN } else { Color32::RED })
              .small(),
          );
        }
      });
    });

    ui.add_space(GUI_MARGIN);
    ui.separator();
    ui.add_space(GUI_MARGIN);

    ui.label("Entropy length (bits) collected by each source.");
    ui.add_space(GUI_MARGIN);

    let mut len = self.entropy_length as u32;

    let resp = ui.add_enabled(
      !self.started,
      egui::Slider::new(&mut len, Self::ENTROPY_MIN as u32..=Self::ENTROPY_MAX as u32)
        .text("bits")
        .step_by(32.0)
        .logarithmic(true),
    );

    if !self.started || resp.changed() {
      self.entropy_length = len as usize;
    }

    ui.add_space(GUI_MARGIN);

    ui.label(RichText::new(format!("Range: {} ... {} bits", Self::ENTROPY_MIN, Self::ENTROPY_MAX,)));
  }

  fn render_source_panel(
    &mut self,
    ui: &mut Ui,
    section: EntropySection,
  ) {
    ui.horizontal(|ui| {
      ui.heading(section.label());

      ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
        let is_saved = match section {
          EntropySection::Rng => self.rng_saved,
          EntropySection::Qrng => self.qrng_saved,
          EntropySection::Jitter => self.jitter_saved,
          _ => false,
        };

        let is_empty = match section {
          EntropySection::Rng => self.rng_entropy.is_empty(),
          EntropySection::Qrng => self.qrng_entropy.is_empty(),
          EntropySection::Jitter => self.jitter_entropy.is_empty(),
          _ => true,
        };

        let is_randomizing = self.randomizing == Some(section);

        let can_save = !is_saved && !is_empty && !is_randomizing;
        if ui
          .add_enabled(can_save, egui::Button::new("Save & Next"))
          .on_hover_text("Lock this source and advance")
          .clicked()
        {
          self.randomizing = None;
          self.save_and_advance(section);
        }

        let btn_label = if is_randomizing { "Stop" } else { "Randomize" };
        if ui
          .add_enabled(!is_saved, egui::Button::new(btn_label))
          .on_hover_text(if is_randomizing {
            "Stop continuous randomization"
          } else {
            "Start continuous randomization"
          })
          .clicked()
        {
          if is_randomizing {
            self.randomizing = None;
          } else {
            self.randomizing = Some(section);
            self.randomize_source(section);
          }
        }
      });
    });

    ui.separator();
    ui.add_space(GUI_MARGIN);

    // Entropy display via text_group
    match section {
      EntropySection::Rng => {
        Self::text_group(ui, "RNG Entropy", &mut self.rng_entropy, true);
      }
      EntropySection::Qrng => {
        Self::text_group(ui, "QRNG Entropy", &mut self.qrng_entropy, true);
      }
      EntropySection::Jitter => {
        Self::text_group(ui, "Jitter Entropy", &mut self.jitter_entropy, true);
      }
      _ => {}
    }

    if self.randomizing == Some(section) {
      self.randomize_source(section);

      ui.ctx().request_repaint();
    }

    // let is_saved = match section {
    //   EntropySection::Rng => self.rng_saved,
    //   EntropySection::Qrng => self.qrng_saved,
    //   EntropySection::Jitter => self.jitter_saved,
    //   _ => false,
    // };

    //     if is_saved {
    //       ui.add_space(GUI_MARGIN);
    //
    //       ui.label(RichText::new("[OK] Source locked").color(Color32::GREEN));
    //     }
  }

  fn render_mouse_panel(
    &mut self,
    ui: &mut Ui,
  ) {
    ui.horizontal(|ui| {
      ui.heading(EntropySection::UserMovement.label());

      ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
        /*
         * Once saved, this source is permanently locked.
         * Neither Save nor Clear can be used anymore.
         */
        let can_modify = !self.mouse_saved;

        let can_save = can_modify && self.mouse_event_count >= self.entropy_length;

        ui.add_enabled_ui(can_save, |ui| {
          if ui
            .button("Save & Next")
            .on_hover_text(format!("Requires at least {} events", self.entropy_length))
            .clicked()
          {
            self.save_and_advance(EntropySection::UserMovement);
          }
        });

        ui.add_enabled_ui(can_modify, |ui| {
          if ui.button("Clear").on_hover_text("Clear collected mouse entropy").clicked() {
            self.mouse_entropy.zeroize();
            self.mouse_entropy.clear();

            self.mouse_event_count = 0;
            self.last_mouse_pos = None;
            self.last_mouse_digest = None;
          }
        });
      });
    });

    ui.separator();
    ui.add_space(GUI_MARGIN);

    ui.label(
      "Move the mouse randomly inside the area below to collect entropy.\n\
         Move mouse as much as you can. More events = more entropy.",
    );

    let events_needed = self.entropy_length.saturating_sub(self.mouse_event_count);

    ui.label(format!("Minimum events needed: {}", events_needed));

    /*
     * Do not collect any more mouse samples after the
     * source has been saved.
     */
    let response = ui.allocate_response(
      egui::vec2(ui.available_width(), 160.0),
      if self.mouse_saved {
        egui::Sense::hover()
      } else {
        egui::Sense::hover() | egui::Sense::drag()
      },
    );

    if !self.mouse_saved
      && (response.hovered() || response.dragged())
      && let Some(pos) = response.hover_pos()
    {
      self.record_mouse_sample(pos);
    }

    ui.painter().rect_filled(
      response.rect,
      4.0,
      if self.mouse_saved {
        Color32::from_rgb(45, 45, 45)
      } else if self.mouse_event_count > 0 {
        Color32::from_rgb(30, 60, 40)
      } else {
        Color32::from_rgb(40, 40, 40)
      },
    );

    ui.painter().text(
      response.rect.center(),
      egui::Align2::CENTER_CENTER,
      if self.mouse_saved {
        "Source locked"
      } else if self.mouse_event_count == 0 {
        "Move mouse here"
      } else {
        "Collecting..."
      },
      egui::FontId::proportional(16.0),
      Color32::WHITE,
    );

    ui.add_space(GUI_MARGIN);

    Self::text_group(ui, "Mouse Entropy", &mut self.mouse_entropy, true);

    //     if self.mouse_saved {
    //       ui.add_space(GUI_MARGIN);
    //
    //       ui.label(RichText::new("[OK] Source locked").color(if ui.theme() == egui::Theme::Dark {Color32::GREEN} else {Color32::RED}));
    //     }
  }

  fn render_final_panel(
    &mut self,
    ui: &mut Ui,
    ctx: egui::Context,
  ) {
    /*
     * Automatically combine the sources as soon as this
     * panel is reached.
     *
     * No user interaction is required.
     */
    if self.final_entropy.is_empty() {
      self.combine_all_sources();
    }

    ui.horizontal(|ui| {
      ui.heading("Final Combined Entropy");

      ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
        if !self.final_entropy.is_empty() && ui.button(RichText::new("Generate wallet").strong()).clicked() {
          let mut wallet = CryptoWallet::new();

          wallet.seed_secret.raw_entropy = self.final_entropy.clone();

          wallet.seed_secret.entropy_length = Zeroizing::new(self.entropy_length);

          wallet.seed_secret.mnemonic_dictionary = self.mnemonic_dictionary.clone();

          ctx.data_mut(|d| {
            d.insert_temp(egui::Id::new("multi_entropy_wallet"), Zeroizing::new(wallet));
          });

          self.open = false;
        }
      });
    });

    ui.separator();
    ui.add_space(GUI_MARGIN);

    if self.final_entropy.is_empty() {
      ui.label(format!("Unable to produce final entropy ({} bits).", self.entropy_length));
    } else {
      Self::text_group(ui, "Combined Entropy", &mut self.final_entropy, true);
    }
  }

  fn valid_bip39_entropy_bits(
    &mut self,
    bits: usize,
  ) -> bool {
    matches!(bits, 128 | 160 | 192 | 224 | 256)
  }

  fn secure_hmac_sha256(
    &mut self,
    key: &[u8],
    data: &[u8],
  ) -> Zeroizing<Vec<u8>> {
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&hmac_key, data);

    Zeroizing::new(tag.as_ref().to_vec())
  }

  fn secure_hash512(
    &mut self,
    domain: &[u8],
    data: &[u8],
  ) -> Zeroizing<[u8; 64]> {
    let mut hasher = Sha512::new();

    hasher.update(domain);
    hasher.update(data);

    let digest = hasher.finalize();

    let mut out: Zeroizing<[u8; 64]> = Zeroizing::new([0u8; 64]);
    out.copy_from_slice(&digest);

    out
  }

  fn secure_condition_source(
    &mut self,
    source: &[u8],
    domain: &[u8],
  ) -> Zeroizing<Vec<u8>> {
    self.secure_hmac_sha256(domain, source)
  }

  fn randomize_source(
    &mut self,
    section: EntropySection,
  ) {
    let final_bits = self.entropy_length;

    if !self.valid_bip39_entropy_bits(final_bits) {
      match section {
        EntropySection::Rng => {
          self.rng_entropy.zeroize();
          self.rng_entropy.clear();
        }

        EntropySection::Qrng => {
          self.qrng_entropy.zeroize();
          self.qrng_entropy.clear();
        }

        EntropySection::Jitter => {
          self.jitter_entropy.zeroize();
          self.jitter_entropy.clear();
        }

        _ => {}
      }

      return;
    }

    let bytes_needed = final_bits / 8;

    match section {
      EntropySection::Rng => {
        let mut raw = Zeroizing::new(vec![0u8; bytes_needed]);

        if getrandom::fill(raw.as_mut_slice()).is_err() {
          self.rng_entropy.zeroize();
          self.rng_entropy.clear();
          return;
        }

        let conditioned = self.secure_condition_source(raw.as_slice(), b"eQ/source/os-csprng/v2");

        if bytes_needed > conditioned.len() {
          self.rng_entropy.zeroize();
          self.rng_entropy.clear();
          return;
        }

        let bits = bytes_to_bitstring_exact(&conditioned[..bytes_needed], final_bits);

        self.rng_entropy = bits;
      }

      EntropySection::Qrng => {
        // TODO: Implement QRNG
        let mut raw = Zeroizing::new(vec![0u8; bytes_needed]);

        if getrandom::fill(raw.as_mut_slice()).is_err() {
          self.qrng_entropy.zeroize();
          self.qrng_entropy.clear();
          return;
        }

        let conditioned = self.secure_condition_source(raw.as_slice(), b"eQ/source/qrng/v2");

        if bytes_needed > conditioned.len() {
          self.qrng_entropy.zeroize();
          self.qrng_entropy.clear();
          return;
        }

        let bits = bytes_to_bitstring_exact(&conditioned[..bytes_needed], final_bits);

        self.qrng_entropy = bits;
      }

      EntropySection::Jitter => {
        let mut jitter_buf = Zeroizing::new(vec![0u8; bytes_needed]);
        let mut jitter_rng: JitterRng<fn() -> u64> = JitterRng::new_with_timer(get_jitter_time);

        jitter_rng.fill_bytes(jitter_buf.as_mut_slice());

        let conditioned = self.secure_condition_source(jitter_buf.as_slice(), b"eQ/source/jitter/v2");

        if bytes_needed > conditioned.len() {
          self.jitter_entropy.zeroize();
          self.jitter_entropy.clear();
          return;
        }

        let bits = bytes_to_bitstring_exact(&conditioned[..bytes_needed], final_bits);

        self.jitter_entropy = bits;
      }

      _ => {}
    }
  }

  fn record_mouse_sample(
    &mut self,
    pos: egui::Pos2,
  ) {
    if !pos.x.is_finite() || !pos.y.is_finite() {
      return;
    }

    let now_ns: u64 = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .ok()
      .and_then(|d| u64::try_from(d.as_nanos()).ok())
      .unwrap_or(0);

    let (dx, dy) = if let Some((last_x, last_y)) = self.last_mouse_pos {
      ((pos.x as f64) - (last_x as f64), (pos.y as f64) - (last_y as f64))
    } else {
      (0.0f64, 0.0f64)
    };

    if !dx.is_finite() || !dy.is_finite() {
      return;
    }

    const MAX_MOUSE_COORDINATE: f32 = 10_000_000.0;
    const MAX_MOUSE_DELTA: f64 = 1_000_000.0;

    let invalid_position = !pos.x.is_finite() || !pos.y.is_finite() || pos.x.abs() > MAX_MOUSE_COORDINATE || pos.y.abs() > MAX_MOUSE_COORDINATE;

    let invalid_delta = !dx.is_finite() || !dy.is_finite() || dx.abs() > MAX_MOUSE_DELTA || dy.abs() > MAX_MOUSE_DELTA;

    if invalid_position || invalid_delta {
      return;
    }

    self.last_mouse_pos = Some((pos.x, pos.y));

    let event_number = self.mouse_event_count;

    let mut sample = Zeroizing::new(Vec::with_capacity(128));

    sample.extend_from_slice(b"eQ/mouse/raw/v2");
    sample.extend_from_slice(&event_number.to_le_bytes());
    sample.extend_from_slice(&pos.x.to_bits().to_le_bytes());
    sample.extend_from_slice(&pos.y.to_bits().to_le_bytes());
    sample.extend_from_slice(&dx.to_bits().to_le_bytes());
    sample.extend_from_slice(&dy.to_bits().to_le_bytes());
    sample.extend_from_slice(&now_ns.to_le_bytes());

    let mut nonce = [0u8; 16];
    let nonce_ok = getrandom::fill(&mut nonce).is_ok();

    if nonce_ok {
      sample.extend_from_slice(&nonce);
    }

    let digest = self.secure_hash512(b"eQ/mouse/sample-conditioner/v2", sample.as_slice());

    if let Some(ref previous) = self.last_mouse_digest
      && previous.as_slice() == digest.as_slice()
    {
      self.mouse_event_count = self.mouse_event_count.saturating_add(1);

      nonce.zeroize();
      sample.zeroize();

      return;
    }

    self.last_mouse_digest = Some(Zeroizing::new(digest.as_slice().to_vec()));

    let bits_to_store = 64usize.min(self.entropy_length);
    let bytes_to_store = bits_to_store.div_ceil(8);
    let mouse_bits = bytes_to_bitstring_exact(&digest[..bytes_to_store], bits_to_store);

    self.mouse_entropy.push_str(mouse_bits.as_str());
    self.mouse_event_count = self.mouse_event_count.saturating_add(1);

    nonce.zeroize();
    sample.zeroize();
  }

  fn combine_all_sources(&mut self) {
    let final_bits = self.entropy_length;

    if !self.valid_bip39_entropy_bits(final_bits) {
      self.final_entropy.zeroize();
      self.final_entropy.clear();
      return;
    }

    let bytes_needed = final_bits / 8;

    if self.rng_entropy.is_empty() {
      self.final_entropy.zeroize();
      self.final_entropy.clear();
      return;
    }

    let rng_bytes = Zeroizing::new(bitstring_to_bytes(self.rng_entropy.as_str()));

    let qrng_bytes = if !self.qrng_entropy.is_empty() {
      Some(Zeroizing::new(bitstring_to_bytes(self.qrng_entropy.as_str())))
    } else {
      None
    };

    let jitter_bytes = if !self.jitter_entropy.is_empty() {
      Some(Zeroizing::new(bitstring_to_bytes(self.jitter_entropy.as_str())))
    } else {
      None
    };

    let mouse_bytes = if !self.mouse_entropy.is_empty() {
      Some(Zeroizing::new(bitstring_to_bytes(self.mouse_entropy.as_str())))
    } else {
      None
    };

    let mut transcript = Zeroizing::new(Vec::<u8>::new());

    transcript.extend_from_slice(b"eQ/entropy-combiner/v2");
    transcript.extend_from_slice(&(final_bits as u32).to_le_bytes());

    let append_source = |dst: &mut Vec<u8>, label: &[u8], source: &[u8]| {
      dst.extend_from_slice(&(label.len() as u32).to_le_bytes());
      dst.extend_from_slice(label);
      dst.extend_from_slice(&(source.len() as u64).to_le_bytes());
      dst.extend_from_slice(source);
    };

    append_source(transcript.as_mut(), b"os-csprng", rng_bytes.as_slice());

    if let Some(ref qrng) = qrng_bytes {
      append_source(transcript.as_mut(), b"qrng", qrng.as_slice());
    }

    if let Some(ref jitter) = jitter_bytes {
      append_source(transcript.as_mut(), b"jitter", jitter.as_slice());
    }

    if let Some(ref mouse) = mouse_bytes {
      append_source(transcript.as_mut(), b"mouse", mouse.as_slice());
    }

    let master = self.secure_hmac_sha256(b"eQ/master-conditioner/v2", transcript.as_slice());

    let mut output = Zeroizing::new(Vec::<u8>::new());

    let mut counter: u32 = 1;

    while output.len() < bytes_needed {
      let mut info = Zeroizing::new(Vec::<u8>::with_capacity(96));

      info.extend_from_slice(b"eQ/final-output/v2");
      info.extend_from_slice(&(final_bits as u32).to_le_bytes());
      info.extend_from_slice(&counter.to_le_bytes());

      let block = self.secure_hmac_sha256(master.as_slice(), info.as_slice());

      output.extend_from_slice(block.as_slice());

      counter = match counter.checked_add(1) {
        Some(v) => v,
        None => {
          self.final_entropy.zeroize();
          self.final_entropy.clear();
          return;
        }
      };
    }

    output.truncate(bytes_needed);

    let final_bits_string = bytes_to_bitstring_exact(output.as_slice(), final_bits);

    if final_bits_string.len() != final_bits {
      self.final_entropy.zeroize();
      self.final_entropy.clear();
      return;
    }

    self.final_entropy = final_bits_string;
  }
}

impl eframe::App for MultiEntropyWindow {
  fn ui(
    &mut self,
    ui: &mut egui::Ui,
    _frame: &mut eframe::Frame,
  ) {
    egui::CentralPanel::default().show(ui, |ui| {
      ui.heading("Multi Entropy");
      self.show(ui.ctx());
    });
  }
}

fn bytes_to_bitstring_exact(
  bytes: &[u8],
  bit_len: usize,
) -> Zeroizing<String> {
  let mut bitstring = Zeroizing::new(String::with_capacity(bit_len));

  for byte in bytes {
    for i in (0..8).rev() {
      if bitstring.len() >= bit_len {
        return bitstring;
      }
      bitstring.push(if (byte >> i) & 1 == 1 { '1' } else { '0' });
    }
  }

  while bitstring.len() < bit_len {
    bitstring.push('0');
  }

  bitstring
}

fn bitstring_to_bytes(bits: &str) -> Zeroizing<Vec<u8>> {
  let mut bytes = Zeroizing::new(Vec::with_capacity(bits.len().div_ceil(8)));
  let mut current = 0u8;
  let mut count = 0;

  for char in bits.chars() {
    current = (current << 1) | if char == '1' { 1 } else { 0 };
    count += 1;

    if count == 8 {
      bytes.push(current);
      current = 0;
      count = 0;
    }
  }

  if count > 0 {
    current <<= 8 - count;
    bytes.push(current);
  }

  bytes
}

fn get_jitter_time() -> u64 {
  use std::time::{SystemTime, UNIX_EPOCH};

  // TODO: Remove unwrap
  let dur = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

  dur.as_secs() * 1_000_000_000 + dur.subsec_nanos() as u64
}
