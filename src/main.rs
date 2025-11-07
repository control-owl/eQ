// authors = ["Control Owl <eq[at]r-o0-t[dot]wtf>"]
// license = "CC-BY-NC-ND-4.0  [2023-2025]  Control Owl"

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// −·−· −−− ·−−· −·−− ·−· ·· −−· ···· −  −·−· −−− −· − ·−· −−− ·−··  −−− ·−− ·−·· 

use eframe::egui;
use egui::{ComboBox, Frame, Theme, Visuals};
use egui_extras::{Column, TableBuilder};
use std::collections::VecDeque;
use std::io::BufRead;

mod keys;

// −·−· −−− ·−−· −·−− ·−· ·· −−· ···· −  −·−· −−− −· − ·−· −−− ·−··  −−− ·−− ·−·· 

pub type FunctionOutput<T> = Result<T, AppError>;
const GUI_MARGIN: usize = 10;

// −·−· −−− ·−−· −·−− ·−· ·· −−· ···· −  −·−· −−− −· − ·−· −−− ·−··  −−− ·−− ·−·· 

#[derive(Debug)]
pub enum AppError {
  Io(std::io::Error),
  Custom(String),
}

impl std::fmt::Display for AppError {
  fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
    match self {
      AppError::Io(err) => write!(f, "IO error: {err}"),
      AppError::Custom(msg) => write!(f, "{msg}"),
    }
  }
}

fn d3bug(message: &str, msg_type: &str) {
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

// −·−· −−− ·−−· −·−− ·−· ·· −−· ···· −  −·−· −−− −· − ·−· −−− ·−··  −−− ·−− ·−·· 

#[derive(Debug, Clone)]
struct CryptoApp {
  gui_settings: GuiSettings,
  address_data: VecDeque<AddressTable>,
  entropy_source: String,
  derivation_path: u32,
  max_rows: usize,
  wallet_settings: WalletSettings,
}

impl CryptoApp {
  fn new() -> Self {
    let get_max_rows = e_q::get_free_memory_size();
    let address_data = VecDeque::with_capacity(get_max_rows);

    // Sample data, testing table look
    // address_data.push_back(AddressTable {
    //   index: 0,
    //   coin: "BITCOIN".into(),
    //   path: "m/44'/0'/0'/0/0'".into(),
    //   address: "1A1z...".into(),
    //   public_key: "02f...".into(),
    //   private_key: "5J1F...".into(),
    // });

    // TODO: Get values from local config
    Self {
      gui_settings: GuiSettings::new(),
      address_data,
      entropy_source: "RNG".to_string(),
      derivation_path: 44,
      max_rows: get_max_rows,
      wallet_settings: WalletSettings::new(),
    }
  }

  fn dropdown_entropy_width(&self, ui: &egui::Ui) -> f32 {
    let text = "Entropy Source";
    let font_id = ui
      .style()
      .text_styles
      .get(&egui::TextStyle::Button)
      .unwrap()
      .clone();
    let galley =
      ui.fonts_mut(|font| font.layout_no_wrap(text.into(), font_id, ui.style().visuals.text_color()));
    galley.size().x + 250.0
  }

  fn render_entropy_dropdown(&mut self, ui: &mut egui::Ui) {
    Frame::group(ui.style()).show(ui, |ui| {
      ui.vertical(|ui| {
        ComboBox::from_label("Entropy Source")
          .selected_text(&self.entropy_source)
          .show_ui(ui, |ui| {
            ui.selectable_value(&mut self.entropy_source, "RNG".to_string(), "RNG");
            ui.selectable_value(&mut self.entropy_source, "QRNG".to_string(), "QRNG");
            ui.selectable_value(&mut self.entropy_source, "File".to_string(), "File");
          });

        let font_id = ui.style().text_styles[&egui::TextStyle::Body].clone();
        let color = ui.style().visuals.text_color();
        let descriptions = [
          " Uses your device's built-in random number generator.",
          " Uses quantum processes to create highly unpredictable numbers.",
          " Uses the content of a file you provide as a source of randomness.",
        ];

        if ui.available_width()
          > e_q::calculate_max_text_width(ui, &descriptions, font_id.clone(), color)
        {
          ui.add_space(GUI_MARGIN as f32);

          ui.vertical(|ui| {
            ui.horizontal_wrapped(|ui| {
              ui.spacing_mut().item_spacing.x = 0.0;
              ui.code("RNG:");
              ui.label(descriptions[0]);
            });

            ui.horizontal_wrapped(|ui| {
              ui.spacing_mut().item_spacing.x = 0.0;
              ui.code("QRNG:");
              ui.label(descriptions[1]);
            });

            ui.horizontal_wrapped(|ui| {
              ui.spacing_mut().item_spacing.x = 0.0;
              ui.code("File:");
              ui.label(descriptions[2]);
            });
          });
        }
      });
    });
  }

  fn dropdown_derivation_width(&self, ui: &egui::Ui) -> f32 {
    let text = "Derivation Path";
    let font_id = ui
      .style()
      .text_styles
      .get(&egui::TextStyle::Button)
      .unwrap()
      .clone();
    let galley =
      ui.fonts_mut(|font| font.layout_no_wrap(text.into(), font_id, ui.style().visuals.text_color()));
    galley.size().x + 250.0
  }

  fn render_derivation_dropdown(&mut self, ui: &mut egui::Ui) {
    Frame::group(ui.style()).show(ui, |ui| {
      ui.vertical(|ui| {
        ComboBox::from_label("Derivation Path")
          .selected_text(self.derivation_path.to_string())
          .show_ui(ui, |ui| {
            ui.selectable_value(&mut self.derivation_path, 32, "32");
            ui.selectable_value(&mut self.derivation_path, 44, "44");
          });

        let font_id = ui.style().text_styles[&egui::TextStyle::Body].clone();
        let color = ui.style().visuals.text_color();
        let descriptions = [
          " Classic hierarchical wallet derivation.",
          " Structured derivation path used for multi-coin wallets.",
        ];

        if ui.available_width()
          > e_q::calculate_max_text_width(ui, &descriptions, font_id.clone(), color)
        {
          ui.add_space(GUI_MARGIN as f32);

          ui.vertical(|ui| {
            ui.horizontal_wrapped(|ui| {
              ui.spacing_mut().item_spacing.x = 0.0;
              ui.code("32:");
              ui.label(descriptions[0]);
            });

            ui.horizontal_wrapped(|ui| {
              ui.spacing_mut().item_spacing.x = 0.0;
              ui.code("44:");
              ui.label(descriptions[1]);
            });
          });
        }
      });
    });
  }

  fn render_wallet_header(&mut self, ui: &mut egui::Ui) {
    egui::MenuBar::new().ui(ui, |ui| {
      ui.menu_button("File", |ui| {
        if ui.button("New").clicked() {
          // TODO: Create new wallet window
        }

        if ui.button("Open").clicked() {
          // TODO: Create open wallet window
        }

        if ui.button("Save").clicked() {
          // TODO: Create save wallet window
        }

        ui.separator();

        if ui.button("Quit").clicked() {
          ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
        }
      });

      ui.menu_button("Zoom", |ui| {
        if ui.button("Zoom In").clicked() {
          self.gui_settings.zoom_factor = (self.gui_settings.zoom_factor + 0.1).clamp(0.5, 2.0);
          ui.ctx().set_zoom_factor(self.gui_settings.zoom_factor);
        }
        if ui.button("Zoom Out").clicked() {
          self.gui_settings.zoom_factor = (self.gui_settings.zoom_factor - 0.1).clamp(0.5, 2.0);
          ui.ctx().set_zoom_factor(self.gui_settings.zoom_factor);
        }

        ui.separator();

        if ui.button("Reset Zoom").clicked() {
          self.gui_settings.zoom_factor = 1.0;
          ui.ctx().set_zoom_factor(self.gui_settings.zoom_factor);
        }
      });

      ui.menu_button("Theme", |ui| {
        if ui.button("Light").clicked() {
          self.gui_settings.theme = "Light".to_string();
        }

        if ui.button("Dark").clicked() {
          self.gui_settings.theme = "Dark".to_string();
        }

        // TODO: Detecting system theme not working
        // ui.separator();
        //
        // if ui.button("System").clicked() {
        //   self.gui_settings.theme = "System".to_string();
        // }
      });
    });

    ui.vertical_centered(|ui| {
      ui.heading("Your entropy, your crypto, your control");
    });

    ui.add_space(GUI_MARGIN as f32);

    let entropy_width = self.dropdown_entropy_width(ui);
    let derivation_width = self.dropdown_derivation_width(ui);
    let total_needed = entropy_width + GUI_MARGIN as f32 + derivation_width;
    let available = ui.available_width();

    if available >= total_needed {
      ui.horizontal_top(|ui| {
        self.render_entropy_dropdown(ui);
        ui.add_space(GUI_MARGIN as f32);
        self.render_derivation_dropdown(ui);
      });
    } else {
      ui.vertical(|ui| {
        self.render_entropy_dropdown(ui);
        ui.add_space(GUI_MARGIN as f32);
        self.render_derivation_dropdown(ui);
      });
    }
  }

  fn render_wallet_table(&mut self, ui: &mut egui::Ui) {
    let available_height = ui.available_height();
    let font = egui::FontId::monospace(12.0);
    let row_height = font.size + GUI_MARGIN as f32;

    TableBuilder::new(ui)
      .striped(true)
      .resizable(true)
      .scroll_bar_visibility(egui::containers::scroll_area::ScrollBarVisibility::VisibleWhenNeeded)
      .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
      .min_scrolled_height(0.0)
      .max_scroll_height(available_height)
      .animate_scrolling(true)
      .column(Column::auto()) // Index
      .column(Column::remainder().at_least(100.0)) // Coin
      .column(Column::remainder().at_least(100.0)) // Path
      .column(Column::remainder().at_least(120.0)) // Address
      .column(Column::remainder().at_least(120.0)) // Public Key
      .column(Column::remainder().at_least(120.0)) // Private Key
      .header(row_height, |mut header| {
        for title in [
          "Index",
          "Coin Name",
          "Path",
          "Address",
          "Public Key",
          "Private Key",
        ] {
          header.col(|ui| {
            ui.heading(title);
          });
        }
      })
      .body(|body| {
        body.rows(row_height, self.address_data.len(), |mut row| {
          let address_row = &self.address_data[row.index()];

          row.col(|ui| {
            ui.label(address_row.index.to_string());
          });
          row.col(|ui| {
            ui.label(&address_row.coin);
          });
          row.col(|ui| {
            ui.label(&address_row.path);
          });
          row.col(|ui| {
            ui.label(&address_row.address);
          });
          row.col(|ui| {
            ui.label(&address_row.public_key);
          });
          row.col(|ui| {
            ui.label(&address_row.private_key);
          });
        });
      });
  }

  fn render_wallet_footer(&mut self, ui: &mut egui::Ui) -> FunctionOutput<()> {
    let total_width = ui.available_width();

    ui.horizontal(|ui| {
      let font_id = ui.style().text_styles[&egui::TextStyle::Body].clone();
      let color = ui.style().visuals.text_color();
      let button_descriptions = [
        "Generate Wallet",
        "Delete Wallet",
      ];

      ui.add_space(GUI_MARGIN as f32);

      let button_length = e_q::calculate_max_text_width(ui, &button_descriptions, font_id.clone(), color);
      ui.add_space((total_width / 2.0) - button_length - (4.0 * GUI_MARGIN as f32 / 2.0));
      
      if self.address_data.len() < self.max_rows {
        if ui.button(button_descriptions[0]).clicked() {
          // let next_index = self.address_data.back().map_or(0, |r| r.index + 1);

          // 1. Detect source
          let entropy_source = self.get_entropy_source();
          println!("Entropy source: {entropy_source}");
          
          // 2. Generate seed
          let (entropy, mnemonic_words, seed) = keys::generate_seed(&entropy_source, None, None, None);
          println!("Entropy: {}", entropy);
          println!("Mnemonic words: {}", mnemonic_words);
          println!("Seed: {}", seed);
          
          // 3. Generate master keys
          let (master_private_bytes, master_public_bytes, master_chain_code_bytes) = match keys::generate_master_keys_secp256k1(&seed, None, None) {
            Ok(value) => value,
            Err(err) => {
              return Err(AppError::Custom(format!("Problem with generating master keys: {}", err)));
            }
          };

          println!("Master private keys bytes: {:?}", master_private_bytes);
          let master_private_key_encoded = bs58::encode(&master_private_bytes).into_string();
          println!("Master private keys: {:?}", master_private_key_encoded);

          println!("Master public keys bytes: {:?}", master_public_bytes);
          let master_public_key_encoded = bs58::encode(&master_public_bytes).into_string();
          println!("Master public keys: {:?}", master_public_key_encoded);

          // 4. Detect DP
          let derivation_path = self.get_derivation_path();
          println!("Derivation path: {derivation_path}");
          
          // TODO: Get coin index
          let resource_path = std::path::Path::new("coin").join("ECDB.csv");
          let resource_path_str = resource_path.to_str().unwrap_or_default();
          let my_public = e_q::get_file_from_resources(resource_path_str);
          // let brain_batch = Arc::new(Mutex::new(BrainBatch::new(BatchConfig::from_speed(1.0))));

          if let Ok(file) = my_public {
            let reader = std::io::BufReader::new(file.contents());

            for line in reader.lines() {
              let line = line.unwrap_or("0".to_string());
              let columns: Vec<&str> = line.split(',').collect();

              if columns.len() > 1 && columns[0] == "1" {
                let active_coin_index = columns[1].parse().unwrap_or(0);

                let derivation_path = match derivation_path {
                  32 => String::from("m/0'/0'/0'"),
                  _ => format!("m/44'/{}'/0'/0/0'", active_coin_index),
                };

                let magic_ingredients = keys::AddressHocusPokus {
                  coin_index: active_coin_index,
                  derivation_path: derivation_path.clone(),
                  master_private_key_bytes: master_private_bytes.clone(),
                  master_chain_code_bytes: master_chain_code_bytes.to_vec(),
                  public_key_hash: columns[8].parse().unwrap_or("".to_string()),
                  key_derivation: columns[4].parse().unwrap_or("".to_string()),
                  wallet_import_format: columns[10].parse().unwrap_or("".to_string()),
                  hash: columns[5].parse().unwrap_or("".to_string()),
                };

                if let Ok(Some(address)) = keys::generate_address(magic_ingredients) {
                  self.address_data.push_back(AddressTable {
                    index: columns[1].parse().unwrap_or(0),
                    coin: columns[3].into(),
                    path: derivation_path.into(),
                    address: address.address.into(),
                    public_key: address.public_key.into(),
                    private_key: address.private_key.into(),
                  });
                }
              }
            }
          }
        }
      } else {
        ui.label("Memory limit reached—cannot generate more addresses.");
      }

      ui.add_space(GUI_MARGIN as f32);

      if ui.button(button_descriptions[1]).clicked() {
        self.address_data.clear();
        Ok(())
      } else {
        return Err(AppError::Custom("Can not clear address_data".to_string()))
      }
    });
    
    Ok(())

  }

  fn get_entropy_source(&mut self) -> String {
    self.entropy_source.clone()
  }

  fn get_derivation_path(&mut self) -> u32 {
    self.derivation_path.clone()
  }

}

impl eframe::App for CryptoApp {
  fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
    match self.gui_settings.theme.as_str() {
      "Dark" => {
        ctx.set_visuals(egui::Visuals::dark());
      }
      "Light" => {
        ctx.set_visuals(egui::Visuals::light());
      }
      _ => {
        // TODO: Not working, system_theme always returns 'None'
        let system_theme = ctx.input(|i| i.raw.system_theme);
        match system_theme {
          Some(Theme::Dark) => ctx.set_visuals(Visuals::dark()),
          Some(Theme::Light) => ctx.set_visuals(Visuals::light()),
          None => {
            // eprintln!("System theme detection failed, using Light fallback");
            ctx.set_visuals(Visuals::light());
          }
        }
      }
    }

    egui::TopBottomPanel::top("header").show(ctx, |ui| {
      ui.add_space(GUI_MARGIN as f32);
      self.render_wallet_header(ui);
      ui.add_space(GUI_MARGIN as f32);
    });

    egui::TopBottomPanel::bottom("footer").show(ctx, |ui| {
      ui.add_space(GUI_MARGIN as f32);
      let _ = self.render_wallet_footer(ui);
      ui.add_space(GUI_MARGIN as f32);
    });

    egui::CentralPanel::default().show(ctx, |ui| {
      egui::ScrollArea::horizontal()
      .scroll_bar_visibility(egui::containers::scroll_area::ScrollBarVisibility::VisibleWhenNeeded)
      .show(ui, |ui| {
          ui.set_height(ui.available_height());
          self.render_wallet_table(ui);
      });
    });

    // TODO: Reduce refresh by heavy writes, check if this is working
    // ctx.request_repaint_after(std::time::Duration::from_millis(100));
  }
}

#[derive(Debug, Clone)]
struct GuiSettings {
  theme: String,
  _language: String,
  zoom_factor: f32,
}

impl GuiSettings {
  fn new() -> Self {
    GuiSettings {
      theme: "System".to_string(),
      _language: "English".to_string(),
      zoom_factor: 1.0,
    }
  }
}

#[derive(Debug, Clone)]
struct AddressTable {
  index: u32,
  coin: String,
  path: String,
  address: String,
  public_key: String,
  private_key: String,
}

#[derive(Clone, Debug)]
struct WalletSettings {
  entropy_string: Option<String>,
  entropy_checksum: Option<String>,
  mnemonic_words: Option<String>,
  mnemonic_passphrase: Option<String>,
  seed: Option<String>,
  master_private_key: Option<String>,
  master_public_key: Option<String>,
  master_private_key_bytes: Option<Vec<u8>>,
  master_chain_code_bytes: Option<Vec<u8>>,
  master_public_key_bytes: Option<Vec<u8>>,
  coin_index: Option<u32>,
  coin_name: Option<String>,
  wallet_import_format: Option<String>,
  public_key_hash: Option<String>,
  key_derivation: Option<String>,
  hash: Option<String>,
}

impl WalletSettings {
  fn new() -> Self {
    Self {
      entropy_string: None,
      entropy_checksum: None,
      mnemonic_words: None,
      mnemonic_passphrase: None,
      seed: None,
      master_private_key: None,
      master_public_key: None,
      master_private_key_bytes: None,
      master_chain_code_bytes: None,
      master_public_key_bytes: None,
      coin_index: None,
      coin_name: None,
      wallet_import_format: None,
      public_key_hash: None,
      key_derivation: None,
      hash: None,
    }
  }
}

// −·−· −−− ·−−· −·−− ·−· ·· −−· ···· −  −·−· −−− −· − ·−· −−− ·−··  −−− ·−− ·−·· 

fn main() -> Result<(), eframe::Error> {
  let options = eframe::NativeOptions {
    viewport: egui::ViewportBuilder::default()
      .with_inner_size([800.0, 600.0])
      .with_min_inner_size([220.0, 320.0]),
    ..Default::default()
  };

  eframe::run_native(
    "eQ",
    options,
    Box::new(|_cc| Ok(Box::new(CryptoApp::new()))),
  )
}
