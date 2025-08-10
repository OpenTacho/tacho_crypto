use std::{
    fs::{File, create_dir_all},
    io::Write,
};

use eyre::OptionExt;
use reqwest::Client;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    println!("Downloading MSCA cert list");
    let client = Client::new();
    let body = client
        .get("https://dtc.jrc.ec.europa.eu/dtc_public_key_certificates_st.php.html")
        .send()
        .await?
        .text()
        .await?;

    let _ = create_dir_all("certs");

    for line in body.lines() {
        if line.contains("Download certificate file") {
            println!("{line}");

            let mut href = line.splitn(2, "href=\"");

            let href = href
                .nth(1)
                .ok_or_eyre("'Download certificate file' does not have href=")?;
            let href = href
                .split("\"")
                .next()
                .ok_or_eyre("'Download certificate file' href does not end in \"")?;

            let url = format!("https://dtc.jrc.ec.europa.eu/{href}");

            let cert_body = client.get(url).send().await?.bytes().await?;

            println!("cert_body len: {}", cert_body.len());

            let filename = href.rsplit_once('/').map(|s| s.1).unwrap_or(href);
            {
                let mut file = File::create(format!("certs/{filename}"))?;
                file.write_all(&cert_body)?;
            }
        }
    }

    Ok(())
}
