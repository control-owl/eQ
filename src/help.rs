use egui::Ui;
use std::default::Default;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::GUI_MARGIN;

#[derive(Zeroize, ZeroizeOnDrop, Debug, Clone, Default)]
pub struct HelpWindow {
  pub open: bool,
  selected_section: HelpSection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize, Default)]
enum HelpSection {
  #[default]
  Overview,
  KeyGeneration,
  QuantumEntropy,
  SecurityFeatures,
  WalletStorage,
}

impl HelpSection {
  fn label(&self) -> &'static str {
    match self {
      HelpSection::Overview => "Overview",
      HelpSection::KeyGeneration => "Key Generation",
      HelpSection::QuantumEntropy => "Quantum Entropy (QRNG)",
      HelpSection::SecurityFeatures => "Security",
      HelpSection::WalletStorage => "Wallet Storage & Export",
    }
  }
}

impl HelpWindow {
  pub fn new() -> Self {
    Self {
      open: false,
      selected_section: HelpSection::Overview,
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

    egui::Window::new("Help")
      .open(&mut open)
      .resizable(true)
      .default_size(ctx.globally_used_rect().size())
      .show(ctx, |ui| {
        let _ = self.ui_content(ui);
      });

    if !open {
      self.close_and_clear();
    }
  }

  fn close_and_clear(&mut self) {
    self.zeroize();

    *self = HelpWindow::new();
  }

  fn ui_content(
    &mut self,
    ui: &mut Ui,
  ) {
    egui::Panel::left("help_sidebar")
      .resizable(true)
      .show_inside(ui, |ui| {
        self.sidebar(ui);
      });

    egui::CentralPanel::default().show_inside(ui, |ui| {
      self.render_section(ui);
    });
  }

  fn sidebar(
    &mut self,
    ui: &mut Ui,
  ) {
    ui.heading("Index");
    ui.separator();

    let sections = [
      HelpSection::Overview,
      HelpSection::KeyGeneration,
      HelpSection::QuantumEntropy,
      HelpSection::SecurityFeatures,
      HelpSection::WalletStorage,
    ];

    for &section in &sections {
      let is_selected = self.selected_section == section;
      if ui.selectable_label(is_selected, section.label()).clicked() {
        self.selected_section = section;
      }
    }
  }

  fn render_section(
    &mut self,
    ui: &mut Ui,
  ) {
    egui::ScrollArea::vertical().show(ui, |ui| match self.selected_section {
      HelpSection::Overview => self.overview(ui),
      HelpSection::KeyGeneration => self.key_generation(ui),
      HelpSection::QuantumEntropy => self.quantum_entropy(ui),
      HelpSection::SecurityFeatures => self.security_features(ui),
      HelpSection::WalletStorage => self.wallet_storage(ui),
    });
  }

  fn overview(
    &self,
    ui: &mut Ui,
  ) {
    ui.heading("Welcome!");
    ui.label("eQ is a high-performance, security-focused cryptographic key generator built with Rust and egui. It provides fast, deterministic, and zero-dependency key generation for 285 cryptocurrencies, with optional quantum-grade entropy sourced from the Australian National University (ANU) Quantum Random Number Generator.");
    ui.add_space(GUI_MARGIN);
    ui.label("This is the second generation of our key generator, following QR2M.");
    ui.add_space(GUI_MARGIN);
    ui.hyperlink_to("GitHub Repository", "https://github.com/control-owl/eQ");
    ui.add_space(GUI_MARGIN);
    ui.label("Designed to be accessible for beginners while powerful enough for advanced users.");
  }

  fn quantum_entropy(
    &self,
    ui: &mut Ui,
  ) {
    ui.label("Quantum-grade entropy (QRNG) option:");
    ui.add_space(GUI_MARGIN);
    ui.label("eQ can source true randomness from the ANU Quantum Random Numbers Server. This service generates randomness from vacuum fluctuations measured via quantum optics - a fundamentally unpredictable physical process.");
    ui.add_space(GUI_MARGIN);
    ui.hyperlink_to("Official ANU QRNG Service", "https://qrng.anu.edu.au");
    ui.add_space(GUI_MARGIN);
    ui.hyperlink_to(
      "API Documentation",
      "https://qrng.anu.edu.au/contact/api-documentation/",
    );
    ui.add_space(GUI_MARGIN);
    ui.label("This provides verifiable, physics-based entropy beyond standard system RNGs.");
  }

  fn security_features(
    &self,
    ui: &mut Ui,
  ) {
    ui.label("Security-First Design:");
    ui.add_space(GUI_MARGIN);
    let bullet = "• ";
    ui.label(format!(
      "{}Full zeroization of sensitive data in memory",
      bullet
    ));
    ui.label(format!(
      "{}Wallets stored as AES-256-GCM encrypted SVG images",
      bullet
    ));
    ui.label(format!(
      "{}Optional Shamir’s Secret Sharing for multi-share wallet splitting",
      bullet
    ));
    ui.label(format!(
      "{}No external dependencies during core key generation (fully offline capable)",
      bullet
    ));
    ui.label(format!("{}Air-gapped version available: eQ-OS", bullet));
    ui.add_space(GUI_MARGIN);
    ui.label("All secrets are handled with care using the zeroize crate.");
  }

  fn key_generation(
    &self,
    ui: &mut Ui,
  ) {
    let max_width = ui.available_width() - GUI_MARGIN;

    ui.heading("Key Generation Process");

    ui.add_space(GUI_MARGIN);

    ui.label("Modern cryptocurrency wallets typically derive cryptographic keys through the following process:");
    ui.label("  1. Generate random entropy");
    ui.label("  2. Convert entropy into mnemonic words (BIP-39)");
    ui.label("  3. Convert the mnemonic (and optional passphrase) into a seed");
    ui.label("  4. Derive private/public key pairs from the seed");
    ui.label("  5. Use the appropriate cryptographic curve, such as secp256k1 or Ed25519");

    ui.add_space(GUI_MARGIN);
    ui.separator();
    ui.add_space(GUI_MARGIN);

    ui.heading("Entropy");

    ui.add_space(GUI_MARGIN);

    ui.label("The process starts with cryptographically secure random data called entropy. The randomness quality is critical because all future keys depend on this entropy, also, the longer, the better ;)");

    ui.add_space(GUI_MARGIN);

    ui.label("Common entropy sizes:");
    ui.add_space(GUI_MARGIN);
    egui::Grid::new("entropy_table")
      .num_columns(2)
      .spacing([GUI_MARGIN, GUI_MARGIN])
      .striped(true)
      .show(ui, |ui| {
        ui.label("Entropy length");
        ui.label("Mnemonic Words");
        ui.end_row();

        ui.label("128 bits");
        ui.label("12 words");
        ui.end_row();

        ui.label("160 bits");
        ui.label("15 words");
        ui.end_row();

        ui.label("192 bits");
        ui.label("18 words");
        ui.end_row();

        ui.label("224 bits");
        ui.label("21 words");
        ui.end_row();

        ui.label("256 bits");
        ui.label("24 words");
        ui.end_row();
      });

    ui.add_space(GUI_MARGIN);

    ui.label("Example:");

    ui.add(
      egui::TextEdit::multiline(&mut "128-bit: 659927443d503c1dda1864c211e7d12b\n\n256-bit: b5d0b44c372e9c433d9567be156b5a80cd004828e74691fe85197db50938a7e3".to_string())
        .interactive(false)
        .desired_width(max_width)
        .font(egui::TextStyle::Monospace)
    );

    ui.add_space(GUI_MARGIN);
    ui.separator();
    ui.add_space(GUI_MARGIN);

    ui.heading("Mnemonic Words (BIP-39)");

    ui.add_space(GUI_MARGIN);

    ui.label("BIP-39 converts entropy into a human-readable list of words.");

    ui.add_space(GUI_MARGIN);

    ui.label("Steps:");
    ui.label("  1. Compute a checksum from the entropy");
    ui.label("  2. Append the checksum bits to the entropy");
    ui.label("  3. Split the resulting bit stream into groups of 11 bits");
    ui.label("  4. Map each 11-bit value to a word from the BIP-39 word list (2048 words)");

    ui.add_space(GUI_MARGIN);

    ui.label("Example:");
    ui.add(egui::TextEdit::multiline(&mut "128-bit entropy:\nhistory jungle affair invest only gravity tilt nut account plate explain note\n\n160-bit entropy:\nphone detail foam syrup local spell vital trap begin stick skin castle neither album soft amount miss film\n\n256-bit entropy:\nwrestle neither effort grit sort drama tribe lava menu early advice domain clutch special define iron pizza rifle fossil steak dwarf nerve immense crumble".to_string())
        .interactive(false)
        .desired_width(max_width)
        .font(egui::TextStyle::Monospace)
        );

    ui.add_space(GUI_MARGIN);
    ui.separator();
    ui.add_space(GUI_MARGIN);

    ui.heading("3. Mnemonic Passphrase");

    ui.add_space(GUI_MARGIN);

    ui.label("BIP-39 supports an optional passphrase. Passphrase is something like a extra word to your mnemonic.");

    ui.add_space(GUI_MARGIN);

    ui.label("Why use a passphrase?");
    let reasons = [
      "Anyone with only the mnemonic cannot access the wallet.",
      "The mnemonic and passphrase together generate the final seed.",
      "Different passphrases create completely different wallets.",
      "It increases the total security of your wallet.",
    ];

    for reason in reasons {
      ui.label(format!("  • {}", reason));
    }

    ui.add_space(GUI_MARGIN);

    ui.label("Downside of using a passphrase:");
    ui.label("  • If the passphrase is lost, the derived wallet cannot be recovered with just a mnemonic words.");

    ui.add_space(GUI_MARGIN);
    ui.separator();
    ui.add_space(GUI_MARGIN);

    ui.heading("Seed Generation");

    ui.add_space(GUI_MARGIN);

    ui.label("The mnemonic and passphrase are transformed into a seed using PBKDF2-HMAC-SHA512:");

    ui.add(
      egui::TextEdit::multiline(&mut "PBKDF2 -> HMAC -> SHA512".to_string())
        .interactive(false)
        .desired_width(max_width)
        .font(egui::TextStyle::Monospace),
    );

    ui.add_space(GUI_MARGIN);

    ui.label("Parameters:");
    let parameters = [
      "Password = mnemonic sentence",
      "Salt = \"mnemonic\" + passphrase",
      "Iterations = 2048",
      "Output length = 512 bits",
    ];

    for param in parameters {
      ui.label(format!("  • {}", param));
    }

    ui.add_space(GUI_MARGIN);

    ui.label("Result:");
    ui.add(
      egui::TextEdit::multiline(
        &mut "3fa4a8ccc3c5734874a7d378492b0479c5de893d3c677884cd2a4d038a7bb4068c4cc22225c8a684f43bfe37777b073008f6cd1b9c63fddbb9ba286abd26a01e".to_string(),
      )
      .interactive(false)
      .desired_width(max_width)
      .font(egui::TextStyle::Monospace),
    );

    ui.add_space(GUI_MARGIN);
    ui.separator();
    ui.add_space(GUI_MARGIN);


    ui.heading("Key Generation with secp256k1");

    ui.add_space(GUI_MARGIN);

    ui.label("Used by Bitcoin, Ethereum, Litecoin and many EVM chains.");

    ui.add_space(GUI_MARGIN);
    ui.label("Flow:");
    ui.add(egui::TextEdit::multiline(&mut "Entropy -> Mnemonic -> Seed -> Master Private Key -> Child Private Key -> secp256k1 Public Key".to_string())
       .interactive(false)
        .desired_width(max_width)
        .font(egui::TextStyle::Monospace)
        );
    ui.add_space(GUI_MARGIN);
    ui.label("Private key: 256-bit integer (1 ≤ private_key < curve_order)");
    ui.label("Public key = private_key x G");

    ui.add_space(GUI_MARGIN);
    ui.separator();
    ui.add_space(GUI_MARGIN);
    
    ui.heading("Key Generation with Ed25519");
    ui.add_space(GUI_MARGIN);
    ui.label("Used by Solana, Cardano, Near, Aptos, Sui etc.");
    ui.add_space(GUI_MARGIN);
    ui.label("After seed generation, Ed25519-specific derivation (often SLIP-0010) is applied.");
    ui.add_space(GUI_MARGIN);
    ui.label("Flow:");
    ui.add(
      egui::TextEdit::multiline(
        &mut "Entropy -> Mnemonic -> Seed -> Ed25519 Private Key -> Ed25519 Public Key".to_string(),
      )
      .interactive(false)
      .desired_width(max_width)
      .font(egui::TextStyle::Monospace),
    );

    ui.add_space(20.0);
    ui.label("eQ automates this entire process with one click while giving you full control over entropy source and passphrase.");
  }

  fn wallet_storage(
    &self,
    ui: &mut Ui,
  ) {
    ui.label("Wallet Storage:");
    ui.add_space(GUI_MARGIN);
    ui.label("Wallets are saved as AES-256-GCM encrypted SVG image files.");
    ui.add_space(GUI_MARGIN);
    ui.label("This unique format allows visual verification and easy backup.");
    ui.add_space(GUI_MARGIN);
    ui.label(
      "Optional Shamir's Secret Sharing lets you split the wallet into multiple secure shares.",
    );
  }
}

impl eframe::App for HelpWindow {
  fn ui(
    &mut self,
    ui: &mut egui::Ui,
    _frame: &mut eframe::Frame,
  ) {
    egui::CentralPanel::default().show_inside(ui, |ui| {
      ui.heading("Help");
      self.show(ui.ctx());
    });
  }
}
