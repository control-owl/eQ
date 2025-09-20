use eframe::egui;
use egui::{ComboBox, Frame};
use egui_extras::{TableBuilder, Column};
use std::collections::VecDeque;

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

    Self {
      address_data,
      entropy_source: "RNG".to_string(),
      derivation_path: 44,
      max_rows: get_max_rows,
    }
  }

  fn render_table(&mut self, ui: &mut egui::Ui) {
    TableBuilder::new(ui)
      .striped(true)
      .resizable(true)
      .column(Column::auto()) // Index
      .column(Column::remainder().at_least(100.0)) // Coin
      .column(Column::remainder().at_least(100.0)) // Path
      .column(Column::remainder().at_least(120.0)) // Address
      .column(Column::remainder().at_least(120.0)) // Public Key
      .column(Column::remainder().at_least(120.0)) // Private Key
      .header(22.0, |mut header| {
        for title in ["Index", "Coin Name", "Path", "Address", "Public Key", "Private Key"] {
          header.col(|ui| { ui.label(title); });
        }
      })
      .body(|body| {
        body.rows(20.0, self.address_data.len(), |mut row| {
          let address_row = &self.address_data[row.index()];

          row.col(|ui| { ui.label(address_row.index.to_string()); });
          row.col(|ui| { ui.label(&address_row.coin); });
          row.col(|ui| { ui.label(&address_row.path); });
          row.col(|ui| { ui.label(&address_row.address); });
          row.col(|ui| { ui.label(&address_row.public_key); });
          row.col(|ui| { ui.label(&address_row.private_key); });
        });
      });
  }

  fn render_controls(&mut self, ui: &mut egui::Ui) {
    ui.horizontal_centered(|ui| {
      if self.address_data.len() < self.max_rows {
        if ui.button("Generate wallet").clicked() {
          let next_index = self.address_data.back().map_or(0, |r| r.index + 1);

          // TODO: Generate new wallet

          // Sample data
          self.address_data.push_back(AddressTable {
            index: next_index,
            coin: "ETHEREUM CLASSIC LONG TEXT".into(),
            path: "m/44'/61'/0'/0/0'".into(),
            address: "0xdFe31394A33c9C1c7D9FC9b33E90fdc3a0D7FBd1".into(),
            public_key: "0x0212a96b15c77f95473d4c6d2c0efe5eb287684be1a6a0243cff1c7d6571e8c3fb".into(),
            private_key: "0x85f7ac69dc2bbf45d6145823ec161f7177ec83ce7fd112e3fa38015b89d".into(),
          });
        }
      } else {
        ui.label("Memory limit reached—cannot generate more wallets.");
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
      ui.horizontal_centered(|ui| {
        Frame::group(ui.style()).show(ui, |ui| {
          ComboBox::from_label("Entropy Source")
            .selected_text(&self.entropy_source)
            .show_ui(ui, |ui| {
              ui.selectable_value(&mut self.entropy_source, "RNG".to_string(), "RNG");
              ui.selectable_value(&mut self.entropy_source, "QRNG".to_string(), "QRNG");
              ui.selectable_value(&mut self.entropy_source, "File".to_string(), "File");
            });
        });

        Frame::group(ui.style()).show(ui, |ui| {
          ComboBox::from_label("Derivation Path")
            .selected_text(self.derivation_path.to_string())
            .show_ui(ui, |ui| {
              ui.selectable_value(&mut self.derivation_path, 32, "32");
              ui.selectable_value(&mut self.derivation_path, 44, "44");
            });
        });
      });
    });

    egui::CentralPanel::default().show(ctx, |ui| {
      egui::ScrollArea::both().show(ui, |ui| {
        self.render_table(ui);
      });
    });

    egui::TopBottomPanel::bottom("footer").show(ctx, |ui| {
        self.render_controls(ui);
    });

    // Avoid redrawing too often when inserting rows
    ctx.request_repaint_after(std::time::Duration::from_millis(100));
  }
}

fn main() -> Result<(), eframe::Error> {
  let options = eframe::NativeOptions {
    viewport: egui::ViewportBuilder::default()
      .with_inner_size([800.0, 600.0]),
    ..Default::default()
  };

  eframe::run_native(
    "eQ",
    options,
    Box::new(|_cc| Ok(Box::new(CryptoWallet::new())))
  )
}