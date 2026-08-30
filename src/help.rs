use egui::Ui;
use egui_commonmark::{CommonMarkCache, CommonMarkViewer};
use std::default::Default;
use zeroize::Zeroize;
use zeroize::ZeroizeOnDrop;

use crate::GUI_MARGIN;

#[derive(Zeroize, ZeroizeOnDrop, Debug, Default)]
pub struct HelpWindow {
  pub open: bool,
  selected_section: HelpSection,

  #[zeroize(skip)]
  markdown_cache: CommonMarkCache,
}

impl Clone for HelpWindow {
  fn clone(&self) -> Self {
    Self {
      open: self.open,
      selected_section: self.selected_section,
      markdown_cache: CommonMarkCache::default(),
    }
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize, Default)]
enum HelpSection {
  #[default]
  Overview,
  KeyGeneration,
  Anu,
  StatusBar,
  WalletFile,
  SupportedCoins,
  Changelog,
  Donations,
}

impl HelpSection {
  fn label(&self) -> &'static str {
    match self {
      HelpSection::Overview => "Overview",
      HelpSection::KeyGeneration => "Key Generation",
      HelpSection::Anu => "ANU QRNG",
      HelpSection::StatusBar => "Status Bar",
      HelpSection::WalletFile => "Wallet File",
      HelpSection::SupportedCoins => "Supported Coins",
      HelpSection::Changelog => "Changelog",
      HelpSection::Donations => "Donations",
    }
  }

  fn filename(&self) -> &'static str {
    match self {
      HelpSection::Overview => "overview.md",
      HelpSection::KeyGeneration => "key_generation.md",
      HelpSection::Anu => "anu.md",
      HelpSection::StatusBar => "status_bar.md",
      HelpSection::WalletFile => "wallet_file.md",
      HelpSection::SupportedCoins => "supported_coins.md",
      HelpSection::Changelog => "changelog.md",
      HelpSection::Donations => "donations.md",
    }
  }
}

impl HelpWindow {
  pub fn new() -> Self {
    Self {
      open: false,
      selected_section: HelpSection::Overview,
      markdown_cache: CommonMarkCache::default(),
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
      // .default_size(ctx.globally_used_rect().size())
      .show(ctx, |ui| {
        egui_extras::install_image_loaders(ui.ctx());
        self.ui_content(ui);
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
    egui::Panel::left("help_sidebar").resizable(true).show(ui, |ui| {
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
    ui.heading("Index");
    ui.separator();

    let sections = [
      HelpSection::Overview,
      HelpSection::KeyGeneration,
      HelpSection::Anu,
      HelpSection::StatusBar,
      HelpSection::WalletFile,
      HelpSection::SupportedCoins,
      HelpSection::Changelog,
      HelpSection::Donations,
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
    ui.style_mut().url_in_tooltip = true;

    egui::ScrollArea::both()
      .content_margin(egui::Margin::same(GUI_MARGIN as i8))
      .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::VisibleWhenNeeded)
      .show(ui, |ui| {
        ui.take_available_width();

        match e_q::get_doc_from_resources(self.selected_section.filename()) {
          Ok(content) => {
            CommonMarkViewer::new().default_implicit_uri_scheme("bytes://").show(
              ui,
              &mut self.markdown_cache,
              content.contents_utf8().unwrap_or("Error"),
            );
          }
          Err(e) => {
            ui.colored_label(egui::Color32::RED, format!("Could not load {}: {}", self.selected_section.filename(), e));
          }
        }
      });
  }
}

impl eframe::App for HelpWindow {
  fn ui(
    &mut self,
    ui: &mut egui::Ui,
    _frame: &mut eframe::Frame,
  ) {
    egui::CentralPanel::default().show(ui, |ui| {
      ui.heading("Help");
      self.show(ui.ctx());
    });
  }
}
