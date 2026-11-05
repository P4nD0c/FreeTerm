#![windows_subsystem = "windows"]

mod app;
mod look;
mod model;
mod secure;
mod sftp;
mod terminal;

use eframe::egui;

fn main() -> eframe::Result {
    let args: Vec<String> = std::env::args().collect();
    let shot = args
        .iter()
        .position(|a| a == "--screenshot")
        .and_then(|i| args.get(i + 1))
        .map(std::path::PathBuf::from);
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("FreeTerm")
            .with_inner_size([1508.0, 956.0])
            .with_min_inner_size([960.0, 600.0])
            .with_decorations(false)
            .with_resizable(true),
        ..Default::default()
    };
    eframe::run_native("FreeTerm", options, Box::new(move |cc| {
        let mut a = app::App::new(cc, shot);
        a.apply_test_view(&cc.egui_ctx);
        Ok(Box::new(a))
    }))
}
