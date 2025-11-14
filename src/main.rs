// authors = ["Control Owl <eq[at]r-o0-t[dot]wtf>"]
// license = "CC-BY-NC-ND-4.0  [2023-2025]  Control Owl"

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// −·−· −−− ·−−· −·−− ·−· ·· −−· ···· −  −·−· −−− −· − ·−· −−− ·−··  −−− ·−− ·−··

use eframe::egui;
use egui::{ComboBox, Frame, Visuals};
use egui_extras::{Column, TableBuilder};
use std::collections::VecDeque;
use std::io::BufRead;

mod keys;
mod test_vectors;

#[cfg(feature = "dev")]
mod dev;

// −·−· −−− ·−−· −·−− ·−· ·· −−· ···· −  −·−· −−− −· − ·−· −−− ·−··  −−− ·−− ·−··

const APP_NAME: Option<&str> = option_env!("CARGO_PKG_NAME");
const APP_DESCRIPTION: Option<&str> = option_env!("CARGO_PKG_DESCRIPTION");
const APP_VERSION: Option<&str> = option_env!("CARGO_PKG_VERSION");
const _APP_AUTHOR: Option<&str> = option_env!("CARGO_PKG_AUTHORS");

pub type FunctionOutput<T> = Result<T, AppError>;

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

pub fn d3bug(message: &str, msg_type: &str) {
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

const GUI_MARGIN: usize = 10;

// −·−· −−− ·−−· −·−− ·−· ·· −−· ···· −  −·−· −−− −· − ·−· −−− ·−··  −−− ·−− ·−··

#[derive(Debug, Clone, Default)]
pub struct SeedData {
  pub entropy: String,
  pub entropy_checksum: String,
  pub full_entropy: String,
  pub mnemonic_words: String,
  pub mnemonic_passphrase: String,
  pub seed: String,
}

#[derive(Debug, Clone, Default)]
pub struct MasterKeyData {
  pub master_private_key_encoded: String,
  pub master_private_key_bytes: Vec<u8>,
  pub master_public_key_encoded: String,
  pub master_public_key_bytes: Vec<u8>,
  pub master_chain_code_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct AddressData {
  pub coin_index: u32,
  pub derivation_path: String,
  pub master_private_key_bytes: Vec<u8>,
  pub master_chain_code_bytes: Vec<u8>,
  pub public_key_hash: String,
  pub key_derivation: String,
  pub wallet_import_format: String,
  pub hash: String,
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

#[derive(Debug, Clone)]
struct GuiSettings {
  theme: String,
  _language: String,
  zoom_factor: f32,
  reversed_sorting: bool,
  active_sort_column: Option<u32>,
}

impl GuiSettings {
  fn new() -> Self {
    GuiSettings {
      theme: "System".to_string(),
      _language: "English".to_string(),
      zoom_factor: 1.0,
      reversed_sorting: false,
      active_sort_column: None,
    }
  }
}

#[derive(Debug, Clone)]
struct CryptoWallet {
  gui_settings: GuiSettings,
  address_data: VecDeque<AddressTable>,
  entropy_source: String,
  bip: u32,
  max_rows: usize,
}

impl CryptoWallet {
  fn new() -> Self {
    let get_max_rows = e_q::get_free_memory_size();
    let address_data = VecDeque::with_capacity(get_max_rows);

    // TODO: Get values from local config
    Self {
      gui_settings: GuiSettings::new(),
      address_data,
      entropy_source: "RNG".to_string(),
      bip: 44,
      max_rows: get_max_rows,
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

    let galley = ui
      .fonts_mut(|font| font.layout_no_wrap(text.into(), font_id, ui.style().visuals.text_color()));
    galley.size().x + 250.0
  }

  fn render_entropy_dropdown(&mut self, ui: &mut egui::Ui) {
    Frame::group(ui.style()).show(ui, |ui| {
      ui.vertical(|ui| {
        ComboBox::from_label("Entropy Source")
          .selected_text(&self.entropy_source)
          .show_ui(ui, |ui| {
            ui.selectable_value(&mut self.entropy_source, "RNG".to_string(), "RNG");

            #[cfg(feature = "dev")]
            ui.selectable_value(&mut self.entropy_source, "QRNG".to_string(), "QRNG");

            #[cfg(feature = "dev")]
            ui.selectable_value(&mut self.entropy_source, "File".to_string(), "File");
          });

        let font_id = ui.style().text_styles[&egui::TextStyle::Body].clone();
        let color = ui.style().visuals.text_color();
        let descriptions = [
          " Uses your device's built-in random number generator.",
          #[cfg(feature = "dev")]
          " Uses quantum processes to create highly unpredictable numbers.",
          #[cfg(feature = "dev")]
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

            #[cfg(feature = "dev")]
            ui.horizontal_wrapped(|ui| {
              ui.spacing_mut().item_spacing.x = 0.0;
              ui.code("QRNG:");
              ui.label(descriptions[1]);
            });

            #[cfg(feature = "dev")]
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

    let galley = ui
      .fonts_mut(|font| font.layout_no_wrap(text.into(), font_id, ui.style().visuals.text_color()));
    galley.size().x + 250.0
  }

  fn render_derivation_dropdown(&mut self, ui: &mut egui::Ui) {
    Frame::group(ui.style()).show(ui, |ui| {
      ui.vertical(|ui| {
        ComboBox::from_label("Derivation Path")
          .selected_text(self.bip.to_string())
          .show_ui(ui, |ui| {
            ui.selectable_value(&mut self.bip, 32, "32");
            ui.selectable_value(&mut self.bip, 44, "44");
          });

        let font_id = ui.style().text_styles[&egui::TextStyle::Body].clone();
        let color = ui.style().visuals.text_color();
        let descriptions = [
          " Classic hierarchical wallet derivation. Only secp256k1 coins",
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

      ui.menu_button("Help", |ui| {
        if ui.button("About").clicked() {
          // TODO: Create about window
        }

        if ui.button("Version").clicked() {
          // TODO: Create version window
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

    let mut sorted_data: Vec<_> = self.address_data.iter().cloned().collect();
    let mut index_sorting = false;
    let mut coin_sorting = false;

    if self.gui_settings.reversed_sorting {
      if let Some(column) = self.gui_settings.active_sort_column {
        match column {
          0 => index_sorting = true,
          1 => coin_sorting = true,
          _ => {}
        }
      }

      if index_sorting {
        sorted_data.sort_by_key(|address| std::cmp::Reverse(address.index));
      } else if coin_sorting {
        sorted_data.sort_by_key(|address| std::cmp::Reverse(address.coin.clone()));
      }
    } else {
      if let Some(column) = self.gui_settings.active_sort_column {
        match column {
          0 => index_sorting = true,
          1 => coin_sorting = true,
          _ => {}
        }
      }

      if index_sorting {
        sorted_data.sort_by_key(|address| address.index);
      } else if coin_sorting {
        sorted_data.sort_by_key(|address| address.coin.clone());
      }
    }

    TableBuilder::new(ui)
      .striped(true)
      .resizable(true)
      .scroll_bar_visibility(egui::containers::scroll_area::ScrollBarVisibility::VisibleWhenNeeded)
      .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
      .min_scrolled_height(0.0)
      .max_scroll_height(available_height)
      .animate_scrolling(true)
      .column(Column::auto())
      .column(Column::remainder().at_least(100.0))
      .column(Column::remainder().at_least(100.0))
      .column(Column::remainder().at_least(120.0))
      .column(Column::remainder().at_least(120.0))
      .column(Column::remainder().at_least(120.0))
      .header(row_height, |mut header| {
        header.col(|ui| {
          egui::Sides::new().show(
            ui,
            |ui| {
              ui.strong("Index");
            },
            |ui| {
              if ui
                .button(if self.gui_settings.reversed_sorting {
                  "⬆"
                } else {
                  "⬇"
                })
                .clicked()
              {
                self.gui_settings.reversed_sorting ^= true;
                self.gui_settings.active_sort_column = Some(0);
              }
            },
          );
        });

        header.col(|ui| {
          egui::Sides::new().show(
            ui,
            |ui| {
              ui.strong("Coin");
            },
            |ui| {
              if ui
                .button(if self.gui_settings.reversed_sorting {
                  "⬆"
                } else {
                  "⬇"
                })
                .clicked()
              {
                self.gui_settings.reversed_sorting ^= true;
                self.gui_settings.active_sort_column = Some(1);
              }
            },
          );
        });

        header.col(|ui| {
          ui.strong("Path");
        });

        header.col(|ui| {
          ui.strong("Address");
        });

        header.col(|ui| {
          ui.strong("Public Key");
        });

        header.col(|ui| {
          ui.strong("Private Key");
        });
      })
      .body(|body| {
        body.rows(row_height, sorted_data.len(), |mut row| {
          let address_row = &sorted_data[row.index()];

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
      let button_descriptions = ["Generate Wallet", "Delete Wallet"];

      ui.add_space(GUI_MARGIN as f32);

      let button_length =
        e_q::calculate_max_text_width(ui, &button_descriptions, font_id.clone(), color);
      ui.add_space((total_width / 2.0) - button_length - (4.0 * GUI_MARGIN as f32 / 2.0));

      if self.address_data.len() < self.max_rows {
        if ui.button(button_descriptions[0]).clicked() {
          let entropy_source = self.get_entropy_source();
          let seed = match keys::generate_seed(&entropy_source, None, None, None) {
            Ok(values) => values,
            Err(err) => {
              return Err(AppError::Custom(format!(
                "Problem with generating seed: {}",
                err
              )));
            }
          };

          let master_keys_secp256k1 =
            match keys::generate_master_keys_secp256k1(&seed.seed, None, None) {
              Ok(values) => values,
              Err(err) => {
                return Err(AppError::Custom(format!(
                  "Problem with generating secp256k1 master keys: {}",
                  err
                )));
              }
            };

          d3bug(
            &format!("master_keys_secp256k1 {master_keys_secp256k1:?}"),
            "debug",
          );

          #[cfg(feature = "dev")]
          let master_keys_ed25519 = match dev::generate_master_keys_ed25519(&seed.seed) {
            Ok(values) => values,
            Err(err) => {
              return Err(AppError::Custom(format!(
                "Problem with generating ed25519 master keys: {}",
                err
              )));
            }
          };

          #[cfg(feature = "dev")]
          d3bug(
            &format!("master_keys_ed25519 {master_keys_ed25519:?}"),
            "debug",
          );

          let bip = self.get_bip();
          let resource_path = std::path::Path::new("coin").join("ECDB.csv");
          let resource_path_str = resource_path.to_str().unwrap_or_default();
          let ecdb_file = e_q::get_file_from_resources(resource_path_str);

          if let Ok(file) = ecdb_file {
            let reader = std::io::BufReader::new(file.contents());
            let mut next_index = 1;

            for line in reader.lines() {
              let line = line.unwrap_or("0".to_string());
              let columns: Vec<&str> = line.split(',').collect();

              let active_coins = if cfg!(feature = "dev") { 2 } else { 1 };

              if columns.len() > 1 && columns[0] == active_coins.to_string() {
                let key_derivation = columns[4].parse().unwrap_or("".to_string());
                let active_coin_index = columns[1].parse().unwrap_or(0);
                let derivation_path = match bip {
                  32 => String::from("m/0'/0'/0'"),
                  _ => format!("m/44'/{}'/0'/0/0'", active_coin_index),
                };

                match key_derivation.as_str() {
                  "secp256k1" => {
                    let magic_ingredients = AddressData {
                      coin_index: active_coin_index,
                      derivation_path: derivation_path.clone(),
                      master_private_key_bytes: master_keys_secp256k1
                        .master_private_key_bytes
                        .clone(),
                      master_chain_code_bytes: master_keys_secp256k1
                        .master_chain_code_bytes
                        .clone(),
                      public_key_hash: columns[8].parse().unwrap_or("".to_string()),
                      key_derivation: columns[4].parse().unwrap_or("".to_string()),
                      wallet_import_format: columns[10].parse().unwrap_or("".to_string()),
                      hash: columns[5].parse().unwrap_or("".to_string()),
                    };

                    if let Ok(address) = keys::generate_secp256k1_address(magic_ingredients) {
                      self.address_data.push_back(AddressTable {
                        index: next_index,
                        coin: columns[3].into(),
                        path: derivation_path,
                        address: address.address,
                        public_key: address.public_key,
                        private_key: address.private_key,
                      });
                    }
                  }
                  #[cfg(feature = "dev")]
                  "ed25519" => {
                    let derivation_path =
                      String::from(format!("m/44'/{}'/0'/0'", active_coin_index));

                    let magic_ingredients = AddressData {
                      coin_index: active_coin_index,
                      derivation_path: derivation_path.clone(),
                      master_private_key_bytes: master_keys_ed25519
                        .master_private_key_bytes
                        .clone(),
                      master_chain_code_bytes: master_keys_ed25519.master_chain_code_bytes.clone(),
                      public_key_hash: columns[8].parse().unwrap_or("".to_string()),
                      key_derivation: columns[4].parse().unwrap_or("".to_string()),
                      wallet_import_format: columns[10].parse().unwrap_or("".to_string()),
                      hash: columns[5].parse().unwrap_or("".to_string()),
                    };

                    if let Ok(address) = dev::generate_ed25519_address(magic_ingredients) {
                      self.address_data.push_back(AddressTable {
                        index: next_index,
                        coin: columns[3].into(),
                        path: derivation_path,
                        address: address.address,
                        public_key: address.public_key,
                        private_key: address.private_key,
                      });
                    }
                  }
                  _ => {
                    return Err(AppError::Custom(format!(
                      "Unsupported key derivation method: {}",
                      key_derivation
                    )));
                  }
                }

                next_index += 1;
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
        Err(AppError::Custom("Can not clear address_data".to_string()))
      }
    });

    Ok(())
  }

  fn get_entropy_source(&mut self) -> String {
    self.entropy_source.clone()
  }

  fn get_bip(&mut self) -> u32 {
    self.bip
  }
}

impl eframe::App for CryptoWallet {
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
        // let system_theme = ctx.input(|i| i.raw.system_theme);
        // match system_theme {
        //   Some(Theme::Dark) => ctx.set_visuals(Visuals::dark()),
        //   Some(Theme::Light) => ctx.set_visuals(Visuals::light()),
        //   None => {
        // eprintln!("System theme detection failed, using Light fallback");
        ctx.set_visuals(Visuals::light());
        //   }
        // }
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
        .scroll_bar_visibility(
          egui::containers::scroll_area::ScrollBarVisibility::VisibleWhenNeeded,
        )
        .show(ui, |ui| {
          ui.set_height(ui.available_height());
          self.render_wallet_table(ui);
        });
    });

    // TODO: Reduce refresh by heavy writes, check if this is working
    // ctx.request_repaint_after(std::time::Duration::from_millis(100));
  }
}

// −·−· −−− ·−−· −·−− ·−· ·· −−· ···· −  −·−· −−− −· − ·−· −−− ·−··  −−− ·−− ·−··

fn set_app_icon() -> FunctionOutput<egui::IconData> {
  let resource_path = std::path::Path::new("logo").join("logo.png");
  let resource_path_str = resource_path.to_str().unwrap_or_default();

  let icon_file = match e_q::get_file_from_resources(resource_path_str) {
    Ok(file) => file,
    Err(err) => {
      return Err(AppError::Custom(format!(
        "Problem with finding app logo file: {}",
        err
      )));
    }
  };

  let app_icon = match eframe::icon_data::from_png_bytes(&icon_file.contents()) {
    Ok(icon) => icon,
    Err(err) => {
      return Err(AppError::Custom(format!(
        "Problem with reading app logo icon: {}",
        err
      )));
    }
  };

  Ok(app_icon)
}

fn set_app_title() -> FunctionOutput<String> {
  let feature = e_q::get_active_app_feature();

  let title = format!(
    "{} - {} {} ({})",
    APP_NAME.unwrap_or("eQ"),
    APP_DESCRIPTION.unwrap_or_default(),
    APP_VERSION.unwrap_or_default(),
    feature
  );

  Ok(title)
}

fn main() -> FunctionOutput<Result<(), eframe::Error>> {
  let app_icon = match set_app_icon() {
    Ok(icon) => icon,
    Err(err) => {
      return Err(AppError::Custom(format!(
        "Problem with setting app logo icon: {}",
        err
      )));
    }
  };

  let app_title = match set_app_title() {
    Ok(title) => title,
    Err(err) => {
      return Err(AppError::Custom(format!(
        "Problem with setting app title: {}",
        err
      )));
    }
  };

  let options = eframe::NativeOptions {
    viewport: egui::ViewportBuilder::default()
      .with_inner_size([800.0, 600.0])
      .with_icon(app_icon)
      .with_app_id("eQ")
      .with_min_inner_size([220.0, 320.0]),
    ..Default::default()
  };

  Ok(eframe::run_native(
    &app_title,
    options,
    Box::new(|_cc| Ok(Box::new(CryptoWallet::new()))),
  ))
}
