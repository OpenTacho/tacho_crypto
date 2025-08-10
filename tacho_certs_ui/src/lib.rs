use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

use egui::{Id, Vec2, Window};
use eyre::Context;
use tacho_g2_crypto::cert::{g2cert::TachographCertificate, g2certraw::TachographCertificateRaw};

use crate::{cert::certedit::RawOrParsedCert, editctx::TachoEditCtx, editwidget::EditWidget};

pub mod cert;
pub mod editctx;
pub mod editwidget;
pub mod util;

pub struct CertsWindows {
    pub frame_counter: u64,
    pub certs: Vec<RawOrParsedCert>,
}

impl Default for CertsWindows {
    fn default() -> Self {
        Self {
            certs: Vec::new(),
            frame_counter: 0,
        }
    }
}

impl CertsWindows {
    pub fn load_certs_from_dir(&mut self, certs_dir_path: &Path) -> eyre::Result<()> {
        let readdir = fs::read_dir(certs_dir_path).wrap_err("fs::read_dir")?;

        for entry in readdir {
            let entry = entry?;

            let path = entry.path();
            self.load_cert(&path).wrap_err("load_cert")?;
            if self.certs.len() >= 4 {
                break;
            }
        }

        Ok(())
    }

    fn load_cert(&mut self, path: &Path) -> eyre::Result<()> {
        let cert_bytes = {
            let mut buf = Vec::new();
            let mut f = File::open(path)?;
            f.read_to_end(&mut buf)?;
            buf
        };

        let cert_raw = TachographCertificateRaw::from_bytes(&cert_bytes)
            .wrap_err("TachographCertificateRaw::from_bytes")?;
        let cert = TachographCertificate::from_raw(&cert_raw)?;

        self.certs.push(cert.into());
        Ok(())
    }

    /// Show the app ui (menu bar and windows).
    pub fn ui(&mut self, ctx: &egui::Context) {
        self.frame_counter += 1;

        if self.frame_counter == 2 {
            self.load_certs_from_dir(&PathBuf::from("tacho_g2_msca_downloader/certs"))
                .unwrap();
        }

        let mut tctx = TachoEditCtx::default();
        for (index, cert) in self.certs.iter_mut().enumerate() {
            let id = Id::new(5000 + index);

            let window = Window::new("Cert");

            let _win_resp = window
                .id(id)
                .default_size(Vec2::new(300.0, 400.0))
                .show(ctx, |ui| {
                    cert.edit_ui(ui, id.with("cert_content"), &mut tctx)
                });
        }
    }
}
