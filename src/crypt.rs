// authors = ["Control Owl <eq[at]r-o0-t[dot]wtf>"]
// license = "CC-BY-NC-ND-4.0  [2023-2026]  Control Owl"
// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

use crate::{AppError, CryptoWallet, FunctionOutput, GUI_MARGIN, SeedSecretData, Zeroize, ZeroizeOnDrop};

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

use egui::{self, Align, Layout};
use ring::aead::*;
use ring::pbkdf2::{PBKDF2_HMAC_SHA512, derive};
use ring::rand::{SecureRandom, SystemRandom};
use shamir_share::{Config, ShamirShare, Share};
use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use svg::Document;
use svg::node::element::Rectangle;
use zeroize::Zeroizing;

const WALLET_HEADER: &[u8; 2] = b"eQ";
const WALLET_VERSION: u8 = 1;
const PAYLOAD_VERSION: u8 = 1;
const WALLET_KDF_VERSION: u8 = 1;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const SVG_BOX_SIZE: usize = 16;

pub type SharedWallet = Rc<RefCell<Zeroizing<CryptoWallet>>>;

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

        let rounds = u32::from_le_bytes(data[..4].try_into().unwrap());
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
      KdfParams::Argon2id { iterations, memory_kb, parallelism } => {
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

#[derive(Zeroize, ZeroizeOnDrop, Debug, Clone, Default)]
pub struct SaveWalletDialog {
  pub open: bool,

  pub wallet_name: String,
  pub password: String,
  pub password_confirm: String,

  pub use_advance: bool,
  pub use_sss: bool,
  pub total_images: u8,
  pub threshold: u8,

  pub pixel_redundancy: f32,

  // TODO: Implement zeroize for Rc & RefCell
  #[zeroize(skip)]
  pub wallet_to_save: Option<SharedWallet>,

  // TODO: Implement zeroize for KdfChoice
  #[zeroize(skip)]
  pub kdf_choice: KdfChoice,

  pub pbkdf2_rounds: u32,
  pub argon2_iterations: u32,
  pub argon2_memory_mb: u32,
  pub argon2_parallelism: u32,
}

impl SaveWalletDialog {
  pub fn new() -> Self {
    SaveWalletDialog {
      open: false,

      wallet_name: String::new(),
      password: String::new(),
      password_confirm: String::new(),

      use_advance: false,
      use_sss: false,
      total_images: 1,
      threshold: 1,

      pixel_redundancy: 1.8,

      wallet_to_save: None,

      kdf_choice: KdfChoice::default(),

      pbkdf2_rounds: 1_000_000,
      argon2_iterations: 3,
      argon2_memory_mb: 64,
      argon2_parallelism: 4,
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

  fn save_wallet(&mut self) -> FunctionOutput<()> {
    if let Some(wallet_rc) = &self.wallet_to_save.clone() {
      let wallet_data = wallet_rc.borrow();
      let save_dialog = self.clone();

      let total_images = save_dialog.total_images;
      let threshold = save_dialog.threshold;
      let redundancy = save_dialog.pixel_redundancy;

      if threshold == 0 || total_images == 0 || threshold > total_images {
        return Err(AppError::log("Shamir parameters are set wrong".to_string()));
      }

      if wallet_data.seed_secret.seed.is_empty() || wallet_data.addresses_by_coin.0.is_empty() {
        return Err(AppError::log("Empty wallet, nothing to save".to_string()));
      }

      let encrypted_blob: Zeroizing<Vec<u8>> =
        match encrypt_wallet(wallet_data.clone(), Zeroizing::new(save_dialog.password.clone()), save_dialog.pbkdf2_rounds, save_dialog.kdf_choice) {
          Ok(blob) => blob,
          Err(err) => {
            return Err(AppError::log(format!("Problem with encrypting wallet: {:?}", err)));
          }
        };

      let shamir_config = Config::new().with_integrity_check(false).with_compression(false);

      let shares: Zeroizing<Vec<Vec<u8>>> = if total_images == 1 {
        Zeroizing::new(vec![encrypted_blob.to_vec()])
      } else {
        match shamir_split(encrypted_blob.clone(), Zeroizing::new(total_images), Zeroizing::new(threshold), shamir_config.clone()) {
          Ok(split) => split,
          Err(_) => return Err(AppError::log("Problem with shamir_split")),
        }
      };

      match rfd::FileDialog::new().set_title("Save wallet file(s)").pick_folder() {
        Some(folder) => {
          if !folder.is_dir() {
            return Err(AppError::log("Selected path is not a directory"));
          }

          let base_name = save_dialog.wallet_name.trim();
          let safe_base = base_name.chars().map(|c| if c == '/' || c == '\\' || c == ':' || c.is_control() { '_' } else { c }).collect::<String>();

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

    Ok(())
  }

  fn ui_content(
    &mut self,
    ui: &mut egui::Ui,
  ) -> FunctionOutput<()> {
    egui::ScrollArea::both().scroll_bar_visibility(egui::containers::scroll_area::ScrollBarVisibility::VisibleWhenNeeded).show(ui, |ui| {
      ui.with_layout(Layout::top_down(Align::Center), |ui| {
        ui.add_space(GUI_MARGIN);

        ui.group(|ui| {
          ui.label("Wallet name");
          ui.text_edit_singleline(&mut self.wallet_name);
        });

        ui.add_space(GUI_MARGIN);

        ui.group(|ui| {
          ui.label("Password");
          ui.add(egui::TextEdit::singleline(&mut self.password).password(true));

          ui.label("Confirm password");
          ui.add(egui::TextEdit::singleline(&mut self.password_confirm).password(true));
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

                ui.add(egui::Slider::new(&mut self.total_images, min_images..=max_images).smart_aim(true).trailing_fill(true))
              });

              ui.add_space(GUI_MARGIN);

              ui.horizontal(|ui| {
                ui.label("Threshold:");
                ui.add(egui::Slider::new(&mut self.threshold, min_images..=self.total_images).smart_aim(true).trailing_fill(true))
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

              ui.add(egui::Slider::new(&mut self.pixel_redundancy, min_redundancy..=max_redundancy).smart_aim(true).trailing_fill(true))
            });
          });

          ui.add_space(GUI_MARGIN);
          ui.separator();
          ui.add_space(GUI_MARGIN);

          ui.group(|ui| {
            ui.heading("Key derivation function");
            ui.add_space(GUI_MARGIN);

            egui::ComboBox::from_label("Encryption method").selected_text(format!("{}", self.kdf_choice)).show_ui(ui, |ui| {
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
                    egui::Slider::new(&mut self.argon2_iterations, min_argon2_iterations..=max_argon2_iterations).smart_aim(true).trailing_fill(true),
                  )
                });
                ui.horizontal(|ui| {
                  ui.label("Memory (MB):");
                  ui.add(egui::Slider::new(&mut self.argon2_memory_mb, min_argon2_memory..=max_argon2_memory).smart_aim(true).trailing_fill(true));
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

        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
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
              Err(err) => return Err(AppError::log(format!("Can not save wallet, error: {:?}", err))),
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
  fn update(
    &mut self,
    ctx: &egui::Context,
    _frame: &mut eframe::Frame,
  ) {
    egui::CentralPanel::default().show(ctx, |ui| {
      ui.heading("Save Wallet");

      self.show(ctx);
    });
  }
}

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

#[derive(Zeroize, ZeroizeOnDrop, Default, Debug, Clone)]
pub struct OpenWalletDialog {
  pub open: bool,
  pub password: String,

  // TODO: Improve
  #[zeroize(skip)]
  pub selected_svgs: Vec<String>,

  // TODO: Improve
  #[zeroize(skip)]
  decoded_shares: Zeroizing<Vec<Vec<u8>>>,

  // TODO: Improve
  #[zeroize(skip)]
  pub loaded_wallet: Option<SharedWallet>,
}

impl OpenWalletDialog {
  pub fn new() -> Self {
    Self::default()
  }

  fn try_load_wallet(
    &mut self,
    ctx: &egui::Context,
  ) -> FunctionOutput<()> {
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
      Err(err) => return Err(AppError::log(format!("Problem with decrypting wallet: {:?}", err))),
    };

    let payload = match parse_payload(data) {
      Ok(vector) => Zeroizing::new(vector),
      Err(err) => return Err(AppError::log(format!("Problem with parsing decrypted wallet: {:?}", err))),
    };

    let mut wallet = CryptoWallet::new();
    wallet.seed_secret = Zeroizing::new(payload.seed_secret.clone());
    wallet.address_components.derivation_path.purpose = payload.bip.clone();
    wallet.address_components.derivation_path.last_index = payload.last_index.clone();

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
    ui.with_layout(egui::Layout::top_down_justified(egui::Align::Center), |ui| {
      ui.add_space(GUI_MARGIN);

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
        self.pick_svg_files();
      }

      if !self.selected_svgs.is_empty() && ui.button("Clear selection").clicked() {
        self.selected_svgs.clear();
        self.decoded_shares.clear();
      }

      ui.add_space(GUI_MARGIN);

      ui.horizontal(|ui| {
        ui.label("Password");
        ui.add(egui::TextEdit::singleline(&mut self.password).password(true));
      });

      let can_attempt_load = !self.selected_svgs.is_empty() && !self.password.is_empty();

      if ui.add_enabled(can_attempt_load, egui::Button::new("Load Wallet")).clicked()
        && let Ok(_) = self.try_load_wallet(ctx)
      {
        self.close_and_clear()
      }

      ui.add_space(GUI_MARGIN);

      ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
        if ui.button("Cancel").clicked() {
          self.close_and_clear();
        }
      });
    });
  }

  fn pick_svg_files(&mut self) {
    if let Some(paths) = rfd::FileDialog::new().add_filter("SVG", &["svg"]).set_title("Select wallet file(s)").pick_files() {
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
        Err(err) => return Err(AppError::log(format!("Failed to decode SVG {}: {}", path, err))),
      }
    }

    Ok(())
  }
}

impl eframe::App for OpenWalletDialog {
  fn update(
    &mut self,
    ctx: &egui::Context,
    _frame: &mut eframe::Frame,
  ) {
    egui::CentralPanel::default().show(ctx, |ui| {
      ui.heading("Open Wallet");

      self.show(ctx);
    });
  }
}

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
    return Err(AppError::log(format!("Not enough shares provided: got {:?}, need {:?}", share_bytes.len(), threshold)));
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
    Err(err) => return Err(AppError::log(format!("Failed to combine Shamir shares: {:?}", err))),
  };

  Ok(secret)
}

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

pub fn encrypt_wallet(
  wallet: Zeroizing<CryptoWallet>,
  password: Zeroizing<String>,
  pbkdf2_rounds: u32,
  kdf_choice: KdfChoice,
) -> FunctionOutput<Zeroizing<Vec<u8>>> {
  let rng = SystemRandom::new();

  let mut salt: [u8; 32] = [0u8; SALT_LEN];
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
    KdfChoice::Argon2id => KdfParams::Argon2id { iterations: 3, memory_kb: 64 * 1024, parallelism: 4 },
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
  key.seal_in_place_append_tag(nonce, aad, &mut *ciphertext).map_err(|err| AppError::log(format!("AES-GCM seal failed: {:?}", err)))?;

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
  let kdf_param_len = u32::from_le_bytes(file[offset..offset + 4].try_into().unwrap()) as usize;
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
      let salt_len = u32::from_le_bytes(file[offset..offset + 4].try_into().unwrap()) as usize;
      offset += 4;

      if file.len() < offset + salt_len {
        return Err(AppError::log("Truncated salt"));
      }
      let salt = &file[offset..offset + salt_len];
      offset += salt_len;

      if file.len() < offset + 4 {
        return Err(AppError::log("Missing payload length"));
      }
      let payload_len = u32::from_le_bytes(file[offset..offset + 4].try_into().unwrap()) as usize;
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
      let plaintext = key.open_in_place(nonce, aad, &mut buf).map_err(|_| AppError::log("AES-GCM open failed"))?;

      Ok(Zeroizing::new(plaintext.to_vec()))
    }

    #[cfg(feature = "dev")]
    KdfParams::Argon2id { .. } => Err(AppError::log("Argon2id not yet supported")),
  }
}

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

fn create_svg(
  share: Zeroizing<Vec<u8>>,
  redundancy: f32,
) -> FunctionOutput<Document> {
  let share_len = share.len();
  let min_cells_needed = (share_len as f32 * redundancy).ceil() as usize;

  let possible_grids = [16, 20, 24, 28, 32, 36, 40, 48, 52, 56, 60, 64, 68, 72, 76, 80, 84, 88, 92, 96, 100];
  let grid =
    possible_grids.into_iter().find(|&g| g * g >= min_cells_needed).expect("Payload too large even for 48×48 grid – split into multiple images");

  let cells = grid * grid;
  let size = (grid * SVG_BOX_SIZE) as f32;

  println!("Auto-selected grid: {}×{} ({} cells) for {} bytes {:.2}x redundancy", grid, grid, cells, share_len, cells as f32 / share_len as f32);

  let mut doc = Document::new().set("viewBox", (0, 0, size, size)).set("style", "background:#FFF");

  for (i, &byte) in share.iter().cycle().take(grid * grid).enumerate() {
    let x = (i % grid * SVG_BOX_SIZE) as f32;
    let y = (i / grid * SVG_BOX_SIZE) as f32;

    let r = byte.wrapping_add(40);
    let g = byte.rotate_left(3).wrapping_add(80);
    let b = byte.rotate_right(5).wrapping_add(120);

    let color = format!("#{:02x}{:02x}{:02x}", r, g, b);

    let rect = Rectangle::new().set("x", x).set("y", y).set("width", SVG_BOX_SIZE).set("height", SVG_BOX_SIZE).set("fill", color);

    doc = doc.add(rect);
  }
  Ok(doc)
}

pub fn load_svg(path: &str) -> FunctionOutput<Vec<u8>> {
  let mut content = String::new();
  let parser = svg::open(path, &mut content).map_err(|e| format!("Failed to open SVG: {}", e)).unwrap();

  let mut secret_bytes = Vec::new();

  for event in parser {
    if let svg::parser::Event::Tag(name, _typ, attributes) = event
      && name == "rect"
      && let Some(fill) = attributes.get("fill")
      && let Some(hex) = fill.strip_prefix('#')
      && hex.len() == 6
      && let (Ok(r), Ok(g), Ok(b)) = (u8::from_str_radix(&hex[0..2], 16), u8::from_str_radix(&hex[2..4], 16), u8::from_str_radix(&hex[4..6], 16))
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

  counts.iter().position(|&c| c == 3).map(|i| i as u8).or_else(|| counts.iter().position(|&c| c == 2).map(|i| i as u8))
}

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
  let dict_bytes = wallet.seed_secret.mnemonic_dictionary.as_bytes();
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

fn parse_payload(plain: Zeroizing<Vec<u8>>) -> FunctionOutput<WalletPayload> {
  let mut off = 0usize;

  // 1 Payload version
  let version_bytes = match take(&plain, &mut off, 1) {
    Ok(byte) => byte,
    Err(err) => return Err(AppError::log(format!("reading payload version failed: {:?}", err))),
  };
  let payload_version: u8 = version_bytes[0];

  // 2 Full entropy
  let entropy_len_bytes = match take(&plain, &mut off, 4) {
    Ok(byte) => byte,
    Err(err) => return Err(AppError::log(format!("reading entropy length failed: {:?}", err))),
  };

  let entropy_len_u32 = match read_u32_le(entropy_len_bytes.as_slice()) {
    Ok(length) => length,
    Err(err) => return Err(AppError::log(format!("parsing entropy length failed: {:?}", err))),
  };

  let entropy_len = entropy_len_u32 as usize;

  if entropy_len > (1 << 24) {
    return Err(AppError::log(format!("entropy length too large: {}", entropy_len)));
  }

  let entropy_bytes = match take(&plain, &mut off, entropy_len) {
    Ok(byte) => byte,
    Err(err) => return Err(AppError::log(format!("reading entropy bytes failed: {:?}", err))),
  };

  let entropy = match String::from_utf8(entropy_bytes) {
    Ok(entropy) => entropy,
    Err(err) => return Err(AppError::log(format!("reading entropy failed: {:?}", err))),
  };

  let full_entropy = Zeroizing::new(entropy);

  // 3 Mnemonic dictionary
  let dict_len_bytes = match take(&plain, &mut off, 2) {
    Ok(length) => length,
    Err(err) => return Err(AppError::log(format!("reading dictionary length failed: {:?}", err))),
  };

  let dict_len_u16 = match read_u16_le(dict_len_bytes.as_slice()) {
    Ok(length) => length,
    Err(err) => return Err(AppError::log(format!("parsing dictionary length failed: {:?}", err))),
  };

  let dict_len = dict_len_u16 as usize;

  if dict_len > (1 << 16) {
    return Err(AppError::log(format!("dictionary length too large: {}", dict_len)));
  }

  let dict_bytes = match take(&plain, &mut off, dict_len) {
    Ok(b) => b,
    Err(e) => return Err(AppError::log(format!("reading dictionary bytes failed: {:?}", e))),
  };

  let mnemonic_dictionary = match String::from_utf8(dict_bytes) {
    Ok(dict) => Zeroizing::new(dict),
    Err(err) => return Err(AppError::log(format!("reading dict_bytes failed: {:?}", err))),
  };

  // 4 Mnemonic passphrase
  let pass_len_bytes = match take(&plain, &mut off, 2) {
    Ok(length) => length,
    Err(err) => return Err(AppError::log(format!("reading passphrase length failed: {:?}", err))),
  };

  let pass_len_u16 = match read_u16_le(pass_len_bytes.as_slice()) {
    Ok(length) => length,
    Err(err) => return Err(AppError::log(format!("parsing passphrase length failed: {:?}", err))),
  };

  let pass_len = pass_len_u16 as usize;

  if pass_len > (1 << 16) {
    return Err(AppError::log(format!("passphrase length too large: {}", pass_len)));
  }

  let pass_bytes = match take(&plain, &mut off, pass_len) {
    Ok(byte) => byte,
    Err(err) => return Err(AppError::log(format!("reading passphrase bytes failed: {:?}", err))),
  };

  let mnemonic_passphrase = match String::from_utf8(pass_bytes) {
    Ok(pass) => Zeroizing::new(pass),
    Err(err) => return Err(AppError::log(format!("reading pass_bytes failed: {:?}", err))),
  };

  // 5 Derivation path purpose (u32 LE)
  let bip_bytes = match take(&plain, &mut off, 4) {
    Ok(byte) => byte,
    Err(err) => return Err(AppError::log(format!("reading derivation purpose failed: {:?}", err))),
  };

  let bip_u32 = match read_u32_le(bip_bytes.as_slice()) {
    Ok(bip) => bip,
    Err(err) => return Err(AppError::log(format!("parsing derivation purpose failed: {:?}", err))),
  };

  let bip = Zeroizing::new(bip_u32);

  // 6 Last index (u32 LE)
  let last_index_bytes = match take(&plain, &mut off, 4) {
    Ok(byte) => byte,
    Err(err) => return Err(AppError::log(format!("reading last index failed: {:?}", err))),
  };

  let last_index = match read_u32_le(last_index_bytes.as_slice()) {
    Ok(index) => Zeroizing::new(index),
    Err(err) => return Err(AppError::log(format!("parsing last index failed: {:?}", err))),
  };

  Ok(WalletPayload {
    payload_version,
    seed_secret: SeedSecretData {
      full_entropy,
      mnemonic_dictionary,
      mnemonic_words: Zeroizing::new(String::new()),
      mnemonic_passphrase,
      entropy_source: Zeroizing::new(String::from("SVG")),
      entropy_length: Zeroizing::new(entropy_len),
      raw_entropy: Zeroizing::new(String::new()),
      mnemonic_passphrase_source: Zeroizing::new(String::from("SVG")),
      entropy_checksum: Zeroizing::new(String::new()),
      seed: Zeroizing::new(String::new()),
    },
    bip,
    last_index,
  })
}

fn derive_pbkdf2_key(
  password: &Zeroizing<String>,
  salt: &[u8],
  iterations: u32,
) -> Zeroizing<[u8; 32]> {
  let mut key: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);

  derive(PBKDF2_HMAC_SHA512, std::num::NonZeroU32::new(iterations).expect("iterations > 0"), salt, password.as_bytes(), &mut key[..]);

  key
}

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

#[derive(Zeroize, ZeroizeOnDrop, Debug, Clone, Default)]
struct WalletPayload {
  payload_version: u8,
  seed_secret: SeedSecretData,
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
