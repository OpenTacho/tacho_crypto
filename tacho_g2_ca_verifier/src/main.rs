use der::Encode;
use std::{
    env,
    fs::{self, File},
    io::Read,
    path::Path,
};

use chrono::{DateTime, Months, Utc};
use eyre::{Context, OptionExt, ensure};
use tacho_g2_crypto::cert::{
    equipmenttype::G2EquipmentType,
    g2cert::{TachoCurveDomain, TachographCertificate},
    g2certraw::TachographCertificateRaw,
};

pub mod getrandom_impl;

fn main() -> eyre::Result<()> {
    let certs_dir_arg = env::args().nth(1);
    let certs_dir = certs_dir_arg
        .as_deref()
        .unwrap_or("./tacho_g2_msca_downloader/certs");
    let readdir = fs::read_dir(certs_dir).unwrap();

    let utc_now: DateTime<Utc> = Utc::now();

    let ca_cert_bytes = include_bytes!("ERCA Gen2 (1) Root Certificate.bin");

    let ca_cert_raw =
        TachographCertificateRaw::from_bytes(ca_cert_bytes).wrap_err("ca cert from_bytes")?;
    let ca_cert = TachographCertificate::from_raw(&ca_cert_raw).wrap_err("ca cert from_raw")?;

    for entry in readdir {
        let entry = entry?;

        let path = entry.path();
        if path.as_os_str().to_string_lossy().contains("ignore") {
            continue;
        }
        let cert =
            analyze_cert(&path, &utc_now).wrap_err_with(|| format!("analyze_cert {:?}", path))?;
        validate_cert(&cert, &ca_cert).wrap_err_with(|| format!("validate_cert {:?}", path))?;
    }
    Ok(())
}

fn analyze_cert(path: &Path, utc_now: &DateTime<Utc>) -> eyre::Result<TachographCertificate> {
    let cert_bytes = {
        let mut buf = Vec::new();
        let mut f = File::open(path)?;
        f.read_to_end(&mut buf)?;
        buf
    };

    let cert_raw = TachographCertificateRaw::from_bytes(&cert_bytes)
        .wrap_err("TachographCertificateRaw::from_bytes")?;
    let cert = TachographCertificate::from_raw(&cert_raw)?;
    let authority_kid = cert
        .body
        .holder_reference
        .as_authority()
        .ok_or_eyre("holder_reference.as_authority None")?;
    let cha = &cert.body.holder_authorisation;
    let _car = &cert.body.authority_reference;
    let year_from_effective = cert
        .body
        .effective_date
        .timestamp
        .checked_add_months(Months::new(12))
        .unwrap();

    let allowed_domains = [
        TachoCurveDomain::NistSecp256r1,
        TachoCurveDomain::BrainpoolP256r1,
    ];

    ensure!(cha.equipment_type == G2EquipmentType::MemberStateCA);
    ensure!(cert.body.effective_date.timestamp < *utc_now);
    ensure!(year_from_effective < cert.body.expiration_date.timestamp);
    ensure!(allowed_domains.contains(&cert.body.public_key.public_point.domain()));

    ensure!(cert.raw_builder().to_raw()? == cert_raw);
    println!(
        "CHR: {authority_kid:?} CHA: {cha:?} {:?} len: {}",
        cert.body.public_key.public_point.domain(),
        cert_raw.encoded_len()?
    );
    //println!("CAR: {car:?}");

    // if authority_kid.additional_info != [0xFF, 0xFF] {
    //     println!(
    //         "additional info: {:?}",
    //         String::from_utf8_lossy(&authority_kid.additional_info)
    //     );
    // }
    Ok(cert)
}

fn validate_cert(
    cert: &TachographCertificate,
    ca_cert: &TachographCertificate,
) -> eyre::Result<()> {
    cert.verify_with(ca_cert)
        .wrap_err("cert.verify_with(ca_cert)")?;

    Ok(())
}
