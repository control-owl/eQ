use eframe::egui;
use egui::{ComboBox, Frame};
use egui_extras::{Column, TableBuilder};
use std::collections::VecDeque;

const GUI_MARGIN: usize = 10;

#[derive(Debug)]
struct AddressTable {
  index: u32,
  coin: String,
  path: String,
  address: String,
  public_key: String,
  private_key: String,
}

#[derive(Default)]
struct CryptoWallet {
  address_data: VecDeque<AddressTable>,
  entropy_source: String,
  derivation_path: u32,
  max_rows: usize,
}

impl CryptoWallet {
  fn new() -> Self {
    let get_max_rows = eQ_lib::get_free_memory_size();
    let mut address_data = VecDeque::with_capacity(get_max_rows);

    // Sample data, testing table look
    address_data.push_back(AddressTable {
      index: 0,
      coin: "BITCOIN".into(),
      path: "m/44'/0'/0'/0/0'".into(),
      address: "1A1z...".into(),
      public_key: "02f...".into(),
      private_key: "5J1F...".into(),
    });

    // TODO: Get values from local config
    Self {
      address_data,
      entropy_source: "RNG".to_string(),
      derivation_path: 44,
      max_rows: get_max_rows,
    }
  }

  fn render_wallet_header(&mut self, ui: &mut egui::Ui) {
    ui.vertical_centered(|ui| {
      ui.heading("Your crypto, your entropy, your control");
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

  fn dropdown_entropy_width(&self, ui: &egui::Ui) -> f32 {
    let text = "Entropy Source";
    let font_id = ui
      .style()
      .text_styles
      .get(&egui::TextStyle::Button)
      .unwrap()
      .clone();
    let galley =
      ui.fonts(|font| font.layout_no_wrap(text.into(), font_id, ui.style().visuals.text_color()));
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
          " Uses your device’s built-in random number generator.",
          " Uses quantum processes to create highly unpredictable numbers.",
          " Uses the content of a file you provide as a source of randomness.",
        ];

        if ui.available_width()
          > eQ_lib::calculate_max_text_width(ui, &descriptions, font_id.clone(), color)
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
      ui.fonts(|font| font.layout_no_wrap(text.into(), font_id, ui.style().visuals.text_color()));
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
          > eQ_lib::calculate_max_text_width(ui, &descriptions, font_id.clone(), color)
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

  fn render_wallet_table(&mut self, ui: &mut egui::Ui) {
    let available_height = ui.available_height();

    TableBuilder::new(ui)
      .resizable(true)
      .scroll_bar_visibility(egui::containers::scroll_area::ScrollBarVisibility::AlwaysHidden)
      .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
      .min_scrolled_height(0.0)
      .max_scroll_height(available_height)
      .animate_scrolling(false)
      .column(Column::auto()) // Index
      .column(Column::remainder().at_least(100.0)) // Coin
      .column(Column::remainder().at_least(100.0)) // Path
      .column(Column::remainder().at_least(120.0)) // Address
      .column(Column::remainder().at_least(120.0)) // Public Key
      .column(Column::remainder().at_least(120.0)) // Private Key
      .header(GUI_MARGIN as f32, |mut header| {
        for title in [
          "Index",
          "Coin Name",
          "Path",
          "Address",
          "Public Key",
          "Private Key",
        ] {
          header.col(|ui| {
            ui.label(title);
          });
        }
      })
      .body(|body| {
        body.rows(GUI_MARGIN as f32, self.address_data.len(), |mut row| {
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

  fn render_wallet_footer(&mut self, ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
      if self.address_data.len() < self.max_rows {
        if ui.button("Generate wallet").clicked() {
          let next_index = self.address_data.back().map_or(0, |r| r.index + 1);

          // TODO: Generate new wallet

          // Sample data
          self.address_data.push_back(AddressTable {
            index: next_index,
            coin: "ETHEREUM CLASSIC".into(),
            path: "m/44'/61'/0'/0/0'".into(),
            address: "0xdFe31394A33c9C1c7D9FC9b33E90fdc3a0D7FBd1".into(),
            public_key: "0x0212a96b15c77f95473d4c6d2c0efe5eb287684be1a6a0243cff1c7d6571e8c3fb"
              .into(),
            private_key: "0x85f7ac69dc2bbf45d6145823ec161f7177ec83ce7fd112e3fa38015b89d".into(),
          });
        }
      } else {
        ui.label("Memory limit reached—cannot generate more addresses.");
        ui.add_space(GUI_MARGIN as f32);
      }

      if ui.button("Delete wallet").clicked() {
        self.address_data.clear();
      }
    });
  }
}

impl eframe::App for CryptoWallet {
  fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
    egui::TopBottomPanel::top("header").show(ctx, |ui| {
      ui.add_space(GUI_MARGIN as f32);
      self.render_wallet_header(ui);
      ui.add_space(GUI_MARGIN as f32);
    });

    egui::CentralPanel::default().show(ctx, |ui| {
      egui::ScrollArea::both().show(ui, |ui| {
        ui.set_height(ui.available_height() - (GUI_MARGIN as f32 * 4.0));
        self.render_wallet_table(ui);
      });
    });

    egui::TopBottomPanel::bottom("footer").show(ctx, |ui| {
      ui.add_space(GUI_MARGIN as f32);
      self.render_wallet_footer(ui);
      ui.add_space(GUI_MARGIN as f32);
    });

    // Reduce refresh by heavy writes
    // ctx.request_repaint_after(std::time::Duration::from_millis(100));
  }
}

fn main() -> Result<(), eframe::Error> {
  let options = eframe::NativeOptions {
    viewport: egui::ViewportBuilder::default()
      .with_inner_size([800.0, 600.0])
      .with_min_inner_size([250.0, 300.0]),
    ..Default::default()
  };

  eframe::run_native(
    "eQ",
    options,
    Box::new(|_cc| Ok(Box::new(CryptoWallet::new()))),
  )
}
