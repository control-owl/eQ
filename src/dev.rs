// authors = ["Control Owl <eq[at]r-o0-t[dot]wtf>"]
// license = "CC-BY-NC-ND-4.0  [2023-2026]  Control Owl"

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

use crate::{FunctionOutput, GUI_MARGIN, Zeroize, ZeroizeOnDrop, Zeroizing};
use egui::{self, Align, Layout};

#[derive(Zeroize, ZeroizeOnDrop, Debug, Clone, Default)]
pub struct ShowSecretsDialog {
  pub open: bool,

  pub entropy: Zeroizing<String>,
  pub entropy_checksum: Zeroizing<String>,
  pub full_entropy: Zeroizing<String>,

  pub mnemonic_words: Zeroizing<String>,
  pub mnemonic_passphrase: Zeroizing<String>,
  pub seed: Zeroizing<String>,

  pub master_secp256k1_private_key: Zeroizing<String>,
  pub master_secp256k1_public_key: Zeroizing<String>,

  pub master_ed25519_private_key: Zeroizing<String>,
  pub master_ed25519_public_key: Zeroizing<String>,

  selected_tab: Tab,
}

#[derive(PartialEq, Eq, Clone, Copy, Zeroize, Debug)]
enum Tab {
  Entropy,
  Seed,
  MasterKeys,
}

impl Default for Tab {
  fn default() -> Self {
    Tab::Entropy
  }
}

impl ShowSecretsDialog {
  pub fn new() -> Self {
    Self {
      open: false,

      entropy: Zeroizing::new(String::new()),
      entropy_checksum: Zeroizing::new(String::new()),
      full_entropy: Zeroizing::new(String::new()),

      mnemonic_words: Zeroizing::new(String::new()),
      mnemonic_passphrase: Zeroizing::new(String::new()),
      seed: Zeroizing::new(String::new()),

      master_secp256k1_private_key: Zeroizing::new(String::new()),
      master_secp256k1_public_key: Zeroizing::new(String::new()),

      master_ed25519_private_key: Zeroizing::new(String::new()),
      master_ed25519_public_key: Zeroizing::new(String::new()),

      selected_tab: Tab::Entropy,
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
      ui.selectable_value(&mut self.selected_tab, Tab::Entropy, "Entropy");
      ui.selectable_value(&mut self.selected_tab, Tab::Seed, "Seed");
      ui.selectable_value(&mut self.selected_tab, Tab::MasterKeys, "Master Keys");
    });

    ui.separator();

    egui::ScrollArea::both().scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::VisibleWhenNeeded).show(ui, |ui| {
      ui.with_layout(Layout::top_down(Align::Center), |ui| match self.selected_tab {
        Tab::Entropy => self.ui_entropy(ui),
        Tab::Seed => self.ui_seed(ui),
        Tab::MasterKeys => self.ui_master_keys(ui),
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
  fn update(
    &mut self,
    ctx: &egui::Context,
    _frame: &mut eframe::Frame,
  ) {
    egui::CentralPanel::default().show(ctx, |ui| {
      ui.heading("Wallet secrets");
      self.show(ctx);
    });
  }
}
