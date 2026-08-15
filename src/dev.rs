// authors = ["Control Owl <eq[at]r-o0-t[dot]wtf>"]
// license = "CC-BY-NC-ND-4.0  [2023-2026]  Control Owl"

use crate::{CryptoWallet, GUI_MARGIN, Zeroize, ZeroizeOnDrop, Zeroizing};
use egui::{Color32, Context, RichText, ScrollArea, Ui, scroll_area::ScrollBarVisibility};
use getrandom;
use ring::hmac;
use std::cell::RefCell;
use std::default::Default;
use std::rc::Rc;

pub type SharedWallet = Rc<RefCell<Zeroizing<CryptoWallet>>>;

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize, Default)]
enum EntropySection {
  #[default]
  RNG,
  QRNG,
  Jitter,
  UserMovement,
  Final,
}

impl EntropySection {
  fn label(&self) -> &'static str {
    match self {
      EntropySection::RNG => "RNG (OS CSPRNG)",
      EntropySection::QRNG => "QRNG (ANU)",
      EntropySection::Jitter => "Jitter (CPU timing)",
      EntropySection::UserMovement => "User Movement (mouse + timing)",
      EntropySection::Final => "Final Combined Entropy",
    }
  }
}

#[derive(Zeroize, ZeroizeOnDrop, Debug, Clone)]
pub struct MultiEntropyWindow {
  pub open: bool,
  selected_section: EntropySection,

  pub entropy_length: usize,

  rng_entropy: Zeroizing<String>,
  qrng_entropy: Zeroizing<String>,
  jitter_entropy: Zeroizing<String>,
  mouse_entropy: Zeroizing<String>,

  rng_saved: bool,
  qrng_saved: bool,
  jitter_saved: bool,
  mouse_saved: bool,

  final_entropy: Zeroizing<String>,

  last_mouse_pos: Option<(f32, f32)>,
  mouse_event_count: usize,

  #[zeroize(skip)]
  pub wallet_to_create: Option<SharedWallet>,
}

impl Default for MultiEntropyWindow {
  fn default() -> Self {
    Self::new()
  }
}

impl MultiEntropyWindow {
  pub fn new() -> Self {
    Self {
      open: false,
      selected_section: EntropySection::RNG,
      entropy_length: 256,

      rng_entropy: Zeroizing::new(String::new()),
      qrng_entropy: Zeroizing::new(String::new()),
      jitter_entropy: Zeroizing::new(String::new()),
      mouse_entropy: Zeroizing::new(String::new()),

      rng_saved: false,
      qrng_saved: false,
      jitter_saved: false,
      mouse_saved: false,

      final_entropy: Zeroizing::new(String::new()),

      last_mouse_pos: None,
      mouse_event_count: 0,

      wallet_to_create: None,
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
    egui::Window::new(format!(
      "Multi-Entropy Collector  ({} bits → {} words)",
      self.entropy_length,
      self.entropy_length / 32 * 3
    ))
    .open(&mut open)
    .resizable(true)
    .default_width(720.0)
    .default_height(520.0)
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

  fn ui_content(
    &mut self,
    ui: &mut Ui,
  ) {
    egui::Panel::left("entropy_sidebar").resizable(true).show(ui, |ui| {
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
    ui.heading("Sources");
    ui.separator();

    let sections = [
      EntropySection::RNG,
      EntropySection::QRNG,
      EntropySection::Jitter,
      EntropySection::UserMovement,
      EntropySection::Final,
    ];

    for &section in &sections {
      let enabled = match section {
        EntropySection::Final => self.rng_saved && self.qrng_saved && self.jitter_saved && self.mouse_saved,
        _ => true,
      };

      if !enabled {
        ui.add_enabled(false, egui::Button::new(section.label()));
        continue;
      }

      let is_selected = self.selected_section == section;
      let saved = match section {
        EntropySection::RNG => self.rng_saved,
        EntropySection::QRNG => self.qrng_saved,
        EntropySection::Jitter => self.jitter_saved,
        EntropySection::UserMovement => self.mouse_saved,
        EntropySection::Final => !self.final_entropy.is_empty(),
      };

      let label = if saved {
        format!("[OK] {}", section.label())
      } else {
        section.label().to_string()
      };

      if ui.selectable_label(is_selected, label).clicked() {
        self.selected_section = section;
      }
    }

    ui.add_space(12.0);
    ui.separator();
    ui.label(RichText::new("Progress").strong());
    ui.label(format!(
      "Saved: {}/4 sources",
      [self.rng_saved, self.qrng_saved, self.jitter_saved, self.mouse_saved]
        .iter()
        .filter(|&&b| b)
        .count()
    ));
    ui.label(format!("Target: {} bits", self.entropy_length));
  }

  fn render_section(
    &mut self,
    ui: &mut Ui,
  ) {
    ScrollArea::vertical()
      .auto_shrink([false, false])
      .scroll_bar_visibility(ScrollBarVisibility::AlwaysVisible)
      .show(ui, |ui| {
        ui.add_space(GUI_MARGIN as f32);
        match self.selected_section {
          EntropySection::RNG => self.render_source_panel(ui, EntropySection::RNG),
          EntropySection::QRNG => self.render_source_panel(ui, EntropySection::QRNG),
          EntropySection::Jitter => self.render_source_panel(ui, EntropySection::Jitter),
          EntropySection::UserMovement => self.render_mouse_panel(ui),
          EntropySection::Final => self.render_final_panel(ui, ui.ctx().clone()),
        }
      });
  }

  fn render_source_panel(
    &mut self,
    ui: &mut Ui,
    section: EntropySection,
  ) {
    ui.heading(section.label());
    ui.add_space(8.0);

    let (preview, len, is_empty, is_saved) = match section {
      EntropySection::RNG => {
        let e = &self.rng_entropy;
        let preview = if e.is_empty() {
          String::new()
        } else {
          e.chars().take(64).collect::<String>()
        };
        (preview, e.len(), e.is_empty(), self.rng_saved)
      }
      EntropySection::QRNG => {
        let e = &self.qrng_entropy;
        let preview = if e.is_empty() {
          String::new()
        } else {
          e.chars().take(64).collect::<String>()
        };
        (preview, e.len(), e.is_empty(), self.qrng_saved)
      }
      EntropySection::Jitter => {
        let e = &self.jitter_entropy;
        let preview = if e.is_empty() {
          String::new()
        } else {
          e.chars().take(64).collect::<String>()
        };
        (preview, e.len(), e.is_empty(), self.jitter_saved)
      }
      _ => unreachable!(),
    };

    ui.label(RichText::new("Current entropy (bit-string)").strong());
    if is_empty {
      ui.label(RichText::new("- empty -").italics().color(Color32::GRAY));
    } else {
      ui.monospace(format!("{}… ({} bits)", preview, len));
    }

    ui.add_space(16.0);

    ui.horizontal(|ui| {
      let randomize = ui
        .add_enabled(!is_saved, egui::Button::new("Randomize"))
        .on_hover_text(format!("Generate exactly {} bits for this source", self.entropy_length));
      if randomize.clicked() {
        self.randomize_source(section);
      }

      let save = ui
        .add_enabled(!is_saved && !is_empty, egui::Button::new("Save & Next"))
        .on_hover_text("Lock this source and advance to the next section");
      if save.clicked() {
        self.save_and_advance(section);
      }
    });

    if is_saved {
      ui.add_space(8.0);
      ui.label(RichText::new("[OK] Source locked").color(Color32::GREEN));
    }
  }

  fn render_mouse_panel(
    &mut self,
    ui: &mut Ui,
  ) {
    ui.heading(EntropySection::UserMovement.label());
    ui.add_space(8.0);

    ui.label("Move the mouse randomly inside this window to collect entropy.");
    ui.label(format!("Events collected: {}", self.mouse_event_count));

    let response = ui.allocate_response(egui::vec2(ui.available_width(), 180.0), egui::Sense::hover() | egui::Sense::drag());

    if response.hovered() || response.dragged() {
      if let Some(pos) = response.hover_pos() {
        self.record_mouse_sample(pos);
      }
    }

    ui.painter().rect_filled(
      response.rect,
      4.0,
      if self.mouse_event_count > 0 {
        Color32::from_rgb(30, 60, 40)
      } else {
        Color32::from_rgb(40, 40, 40)
      },
    );
    ui.painter().text(
      response.rect.center(),
      egui::Align2::CENTER_CENTER,
      if self.mouse_event_count == 0 {
        "Move mouse here"
      } else {
        "Collecting…"
      },
      egui::FontId::proportional(16.0),
      Color32::WHITE,
    );

    ui.add_space(12.0);

    ui.label(RichText::new("Current entropy (bit-string)").strong());
    if self.mouse_entropy.is_empty() {
      ui.label(RichText::new("— empty —").italics().color(Color32::GRAY));
    } else {
      let preview: String = self.mouse_entropy.chars().take(64).collect();
      ui.monospace(format!(
        "{}… ({} bits / {} events)",
        preview,
        self.mouse_entropy.len(),
        self.mouse_event_count
      ));
    }

    ui.add_space(16.0);

    ui.horizontal(|ui| {
      if ui.button("Clear mouse buffer").clicked() {
        self.mouse_entropy.zeroize();
        self.mouse_entropy.clear();
        self.mouse_event_count = 0;
        self.last_mouse_pos = None;
      }

      let save = ui
        .add_enabled(!self.mouse_saved && self.mouse_event_count >= 256, egui::Button::new("Save & Next"))
        .on_hover_text("Requires at least 256 events");
      if save.clicked() {
        self.save_and_advance(EntropySection::UserMovement);
      }
    });

    if self.mouse_saved {
      ui.add_space(8.0);
      ui.label(RichText::new("Source locked").color(Color32::GREEN));
    }
  }

  fn render_final_panel(
    &mut self,
    ui: &mut Ui,
    ctx: egui::Context,
  ) {
    ui.heading("Final Combined Entropy");
    ui.add_space(8.0);

    if self.final_entropy.is_empty() {
      ui.label(format!(
        "All sources are saved. Press “Combine” to produce exactly {} bits.",
        self.entropy_length
      ));
      if ui.button("Combine all sources").clicked() {
        self.combine_all_sources();
      }
      return;
    }

    ui.label(RichText::new("Combined entropy (bit-string)").strong());
    let preview: String = self.final_entropy.chars().take(64).collect();
    ui.monospace(format!("{}… ({} bits)", preview, self.final_entropy.len()));

    ui.add_space(16.0);

    if ui.button(RichText::new("Commit to wallet generation").strong()).clicked() {
      let mut wallet = CryptoWallet::new();
      wallet.seed_secret.raw_entropy = self.final_entropy.clone();
      wallet.seed_secret.entropy_length = Zeroizing::new(self.entropy_length);

      ctx.data_mut(|d| {
        d.insert_temp(egui::Id::new("multi_entropy_wallet"), Zeroizing::new(wallet));
      });

      self.open = false;
    }
  }

  fn randomize_source(
    &mut self,
    section: EntropySection,
  ) {
    let bytes_needed = (self.entropy_length + 7) / 8;
    let mut buf = vec![0u8; bytes_needed];

    if getrandom::fill(&mut buf).is_ok() {
      let bit_string = bytes_to_bitstring_exact(&buf, self.entropy_length);

      match section {
        EntropySection::RNG => self.rng_entropy = Zeroizing::new(bit_string),
        EntropySection::QRNG => self.qrng_entropy = Zeroizing::new(bit_string),
        EntropySection::Jitter => self.jitter_entropy = Zeroizing::new(bit_string),
        _ => {}
      }
    }
  }

  fn save_and_advance(
    &mut self,
    section: EntropySection,
  ) {
    match section {
      EntropySection::RNG => {
        self.rng_saved = true;
        self.selected_section = EntropySection::QRNG;
      }
      EntropySection::QRNG => {
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

  fn record_mouse_sample(
    &mut self,
    pos: egui::Pos2,
  ) {
    let now_ns = std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .map(|d| d.as_nanos() as u64)
      .unwrap_or(0);

    let (dx, dy) = if let Some((lx, ly)) = self.last_mouse_pos {
      ((pos.x - lx) as i16, (pos.y - ly) as i16)
    } else {
      (0i16, 0i16)
    };

    self.last_mouse_pos = Some((pos.x, pos.y));

    let mut sample = Vec::with_capacity(12);
    sample.extend_from_slice(&now_ns.to_le_bytes());
    sample.extend_from_slice(&dx.to_le_bytes());
    sample.extend_from_slice(&dy.to_le_bytes());

    let bits = bytes_to_bitstring(&sample);
    self.mouse_entropy.push_str(&bits);
    self.mouse_event_count += 1;
  }

  fn combine_all_sources(&mut self) {
    let mut materials: Vec<&str> = Vec::new();
    if !self.rng_entropy.is_empty() {
      materials.push(&self.rng_entropy);
    }
    if !self.qrng_entropy.is_empty() {
      materials.push(&self.qrng_entropy);
    }
    if !self.jitter_entropy.is_empty() {
      materials.push(&self.jitter_entropy);
    }
    if !self.mouse_entropy.is_empty() {
      materials.push(&self.mouse_entropy);
    }

    if materials.is_empty() {
      return;
    }

    // 1. Per-source Extract
    let mut prks = Vec::new();
    for (i, bit_str) in materials.iter().enumerate() {
      let bytes = bitstring_to_bytes(bit_str);
      let salt = format!("eQ-src-{}", i);
      let key = hmac::Key::new(hmac::HMAC_SHA256, salt.as_bytes());
      let tag = hmac::sign(&key, &bytes);
      prks.extend_from_slice(tag.as_ref());
    }

    // 2. Global Extract
    let global_key = hmac::Key::new(hmac::HMAC_SHA256, b"eQ-multisource-v1");
    let master_tag = hmac::sign(&global_key, &prks);
    let master_prk = master_tag.as_ref();

    // 3. Expand to the exact number of bytes
    let bytes_needed = (self.entropy_length + 7) / 8;
    let expand_key = hmac::Key::new(hmac::HMAC_SHA256, master_prk);

    let mut output_bytes = Vec::with_capacity(bytes_needed);
    let mut counter = 1u8;
    while output_bytes.len() < bytes_needed {
      let mut info = b"eQ-final-entropy".to_vec();
      info.push(counter);
      let tag = hmac::sign(&expand_key, &info);
      output_bytes.extend_from_slice(tag.as_ref());
      counter = counter.wrapping_add(1);
    }
    output_bytes.truncate(bytes_needed);

    let out_bits = bytes_to_bitstring_exact(&output_bytes, self.entropy_length);
    self.final_entropy = Zeroizing::new(out_bits);
  }
}

fn bytes_to_bitstring_exact(
  bytes: &[u8],
  bit_len: usize,
) -> String {
  let mut s = String::with_capacity(bit_len);

  for byte in bytes {
    for i in (0..8).rev() {
      if s.len() >= bit_len {
        return s;
      }
      s.push(if (byte >> i) & 1 == 1 { '1' } else { '0' });
    }
  }

  while s.len() < bit_len {
    s.push('0');
  }

  s
}

fn bytes_to_bitstring(bytes: &[u8]) -> String {
  bytes_to_bitstring_exact(bytes, bytes.len() * 8)
}

fn bitstring_to_bytes(bits: &str) -> Vec<u8> {
  let mut bytes = Vec::with_capacity((bits.len() + 7) / 8);
  let mut current = 0u8;
  let mut count = 0;

  for c in bits.chars() {
    current = (current << 1) | if c == '1' { 1 } else { 0 };
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

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

// #[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
// pub struct PathComponent {
//   pub index: u32,
//   pub hardened: bool,
// }
//
// impl PathComponent {
//   pub fn new(
//     index: u32,
//     hardened: bool,
//   ) -> Self {
//     Self { index, hardened }
//   }
//
//   pub fn hardened(index: u32) -> Self {
//     Self { index, hardened: true }
//   }
//
//   pub fn soft(index: u32) -> Self {
//     Self { index, hardened: false }
//   }
//
//   pub fn to_string_component(&self) -> String {
//     if self.hardened {
//       format!("{}'", self.index)
//     } else {
//       self.index.to_string()
//     }
//   }
// }
//
// #[derive(Debug, Clone, PartialEq, Eq)]
// pub enum Curve {
//   Secp256k1,
//   Ed25519,
//   Sr25519,
//   Bip32Ed25519, // Cardano-style
// }
//
// #[derive(Debug, Clone, Copy, PartialEq, Eq)]
// pub enum DerivationScheme {
//   Bip32,
//   Bip44,
//   Bip86,
//   Slip10,   // common for ed25519
//   Polkadot, // sr25519 / Substrate style
//   Cip1852,  // Cardano bip32-ed25519
// }
//
// #[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
// pub enum DerivationPath {
//   Secp256k1(Secp256k1Path),
//   Ed25519(Ed25519Path),
//   Sr25519(Sr25519Path),
//   Bip32Ed25519(Bip32Ed25519Path),
// }
//
// /// secp256k1 paths
// #[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
// pub enum Secp256k1Path {
//   /// BIP32: m / account' / change' / address{'}
//   Bip32 {
//     account: PathComponent,
//     change: PathComponent,
//     address: PathComponent,
//   },
//
//   /// BIP44: m / 44' / coin' / account' / change / address{'}
//   Bip44 {
//     coin: PathComponent,    // usually hardened
//     account: PathComponent, // usually hardened
//     change: PathComponent,  // usually soft
//     address: PathComponent, // usually soft
//   },
//
//   /// BIP86 (Taproot): m / 86' / coin' / account' / change / address{'}
//   Bip86 {
//     coin: PathComponent,
//     account: PathComponent,
//     change: PathComponent,
//     address: PathComponent,
//   },
// }
//
// /// ed25519 paths
// #[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
// pub enum Ed25519Path {
//   /// BIP32: m / account' / change' / address'
//   Bip32 {
//     account: PathComponent,
//     change: PathComponent,
//     address: PathComponent,
//   },
//
//   /// BIP44: m / 44' / coin' / account' / change' / address'
//   Bip44 {
//     coin: PathComponent,
//     account: PathComponent,
//     change: PathComponent,
//     address: PathComponent,
//   },
//
//   /// SLIP-0010: m / 44' / coin' / address'
//   Slip10 { coin: PathComponent, address: PathComponent },
// }
//
// /// sr25519 / Substrate paths
// #[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
// pub enum Sr25519Path {
//   /// BIP32: m / account' / change' / address'
//   Bip32 {
//     account: PathComponent,
//     change: PathComponent,
//     address: PathComponent,
//   },
//
//   Polkadot {
//     coin: PathComponent,
//     account: PathComponent,
//   },
// }
//
// /// Cardano-style bip32-ed25519 (CIP-1852)
// #[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
// pub enum Bip32Ed25519Path {
//   Cip1852 {
//     coin: PathComponent,
//     account: PathComponent,
//
//     /// 0 = external, 1 = internal, 2 = staking,
//     role: PathComponent,
//     address: PathComponent,
//   },
// }
//
// impl DerivationPath {
//   pub fn to_path_string(&self) -> Zeroizing<String> {
//     let s = match self {
//       DerivationPath::Secp256k1(p) => match p {
//         Secp256k1Path::Bip32 { account, change, address } => {
//           format!(
//             "m/{}/{}/{}",
//             account.to_string_component(),
//             change.to_string_component(),
//             address.to_string_component()
//           )
//         }
//         Secp256k1Path::Bip44 {
//           coin,
//           account,
//           change,
//           address,
//         } => {
//           format!(
//             "m/44'/{}/{}/{}/{}",
//             coin.to_string_component(),
//             account.to_string_component(),
//             change.to_string_component(),
//             address.to_string_component()
//           )
//         }
//         Secp256k1Path::Bip86 {
//           coin,
//           account,
//           change,
//           address,
//         } => {
//           format!(
//             "m/86'/{}/{}/{}/{}",
//             coin.to_string_component(),
//             account.to_string_component(),
//             change.to_string_component(),
//             address.to_string_component()
//           )
//         }
//       },
//
//       DerivationPath::Ed25519(p) => match p {
//         Ed25519Path::Bip32 { account, change, address } => {
//           format!(
//             "m/{}/{}/{}",
//             account.to_string_component(),
//             change.to_string_component(),
//             address.to_string_component()
//           )
//         }
//         Ed25519Path::Bip44 {
//           coin,
//           account,
//           change,
//           address,
//         } => {
//           format!(
//             "m/44'/{}/{}/{}/{}",
//             coin.to_string_component(),
//             account.to_string_component(),
//             change.to_string_component(),
//             address.to_string_component()
//           )
//         }
//         Ed25519Path::Slip10 { coin, address } => {
//           format!("m/44'/{}/{}", coin.to_string_component(), address.to_string_component())
//         }
//       },
//
//       DerivationPath::Sr25519(p) => match p {
//         Sr25519Path::Bip32 { account, change, address } => {
//           format!(
//             "m/{}/{}/{}",
//             account.to_string_component(),
//             change.to_string_component(),
//             address.to_string_component()
//           )
//         }
//         Sr25519Path::Polkadot { coin, account } => {
//           format!("m/44'/{}/{}", coin.to_string_component(), account.to_string_component())
//         }
//       },
//
//       DerivationPath::Bip32Ed25519(Bip32Ed25519Path::Cip1852 {
//         coin,
//         account,
//         role,
//         address,
//       }) => {
//         format!(
//           "m/1852'/{}/{}/{}/{}",
//           coin.to_string_component(),
//           account.to_string_component(),
//           role.to_string_component(),
//           address.to_string_component()
//         )
//       }
//     };
//
//     Zeroizing::new(s)
//   }
//
//   pub fn curve(&self) -> Curve {
//     match self {
//       DerivationPath::Secp256k1(_) => Curve::Secp256k1,
//       DerivationPath::Ed25519(_) => Curve::Ed25519,
//       DerivationPath::Sr25519(_) => Curve::Sr25519,
//       DerivationPath::Bip32Ed25519(_) => Curve::Bip32Ed25519,
//     }
//   }
// }
