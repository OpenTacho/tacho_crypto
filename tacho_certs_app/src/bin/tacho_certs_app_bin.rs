use tacho_certs_app::MyApp;

fn main() -> eframe::Result {
    eframe::run_native(
        "tacho_certs_app",
        Default::default(),
        Box::new(|cc| Ok(Box::new(MyApp::new(cc)))),
    )
}
