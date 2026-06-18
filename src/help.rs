use egui::Ui;
use egui_commonmark::{CommonMarkCache, CommonMarkViewer};
use std::default::Default;
use std::fs;
use zeroize::{Zeroize, ZeroizeOnDrop};

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
  WalletFile,
  StatusBar,
  ANU,
}

impl HelpSection {
  fn label(&self) -> &'static str {
    match self {
      HelpSection::Overview => "Overview",
      HelpSection::KeyGeneration => "Key Generation",
      HelpSection::WalletFile => "Wallet File",
      HelpSection::StatusBar => "Status Bar",
      HelpSection::ANU => "ANU QRNG",
    }
  }

  fn filename(&self) -> &'static str {
    match self {
      HelpSection::Overview => "overview.md",
      HelpSection::KeyGeneration => "key_generation.md",
      HelpSection::WalletFile => "wallet_file.md",
      HelpSection::StatusBar => "status_bar.md",
      HelpSection::ANU => "anu.md",
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
      .default_size(ctx.globally_used_rect().size())
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
      HelpSection::ANU,
      HelpSection::StatusBar,
      HelpSection::WalletFile,
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

    egui::ScrollArea::vertical()
      .content_margin(egui::Margin::same(GUI_MARGIN as i8))
      .show(ui, |ui| {
        let doc_path = format!("doc/{}", self.selected_section.filename());

        match fs::read_to_string(&doc_path) {
          Ok(content) => {
            CommonMarkViewer::new().show(ui, &mut self.markdown_cache, &content);
          }
          Err(e) => {
            ui.colored_label(
              egui::Color32::RED,
              format!("Could not load {}: {}", doc_path, e),
            );
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
    egui::CentralPanel::default().show_inside(ui, |ui| {
      ui.heading("Help");
      self.show(ui.ctx());
    });
  }
}
