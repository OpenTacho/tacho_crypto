use std::io::Write;

use axum::{
    Json, Router,
    body::Bytes,
    http::StatusCode,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use tacho_g2_crypto::cert::{g2certraw::TachographCertificateRaw, hexslice::HexDisplay};

#[tokio::main]
async fn main() {
    // initialize tracing
    tracing_subscriber::fmt::init();

    let sign_url_arg = std::env::args().nth(1);
    let sign_url = sign_url_arg.as_deref().unwrap_or("/sign");

    let app = Router::new()
        .route("/", get(get_root))
        .route(sign_url, post(post_sign));

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn get_root() -> &'static str {
    "Tachograph G1 + G2 certificate sigining server (MSCA)"
}

async fn post_sign(payload: Bytes) -> (StatusCode, Bytes) {
    let mut resp = Vec::new();
    use std::io::Write;

    let request_id = b"00";
    write!(
        &mut resp,
        "<cert-response request_id=\"{}\">",
        HexDisplay(request_id)
    )
    .ok();

    let ca_cert_chr = [0u8; 8];
    let eq_cert_chr = [0u8; 8];

    let ca_cert = todo!();
    let eq_cert = todo!();

    write_cert_as_xml(&mut resp, 0, ca_cert_chr, ca_cert);
    write_cert_as_xml(&mut resp, 1, eq_cert_chr, eq_cert);
    write!(&mut resp, "</cert-response>").ok();

    // this will be converted into a JSON response
    // with a status code of `201 Created`
    (StatusCode::CREATED, resp.into())
}

fn write_cert_as_xml(mut writer: impl Write, cert_type: u8, cert_chr: [u8; 8], cert: &[u8]) {
    write!(
        writer,
        "<cert type=\"{cert_type}\" chr=\"{}\">",
        HexDisplay(&cert_chr)
    )
    .ok();

    write!(writer, "{}", HexDisplay(&cert)).ok();

    write!(writer, "</cert>").ok();
}
