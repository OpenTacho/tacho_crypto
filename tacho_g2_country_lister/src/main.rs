use eyre::{Context, OptionExt, bail};

const COUNTRY_LIST: &str = "
No Info, ,(00)H,,,
Albania,AL,(02)H,,,
Andorra,AND,(03)H,,,
Armenia,ARM,(04)H,,,
Austria,A,(01)H,,,
Azerbaijan,AZ,(05)H,,,
Belarus,BY,(09)H,,,
Belgium,B,(06)H,,,
Bosnia Herzegovina,BIH,(08)H,,,
Bulgaria,BG,(07)H,,,
Croatia,HR,(19)H,,,
Cyprus,CY,(0B)H,,,
Czech Republic,CZ,(0C)H,,,
Denmark,DK,(0E)H,,,
Estonia,EST,(10)H,,,
Faroe Islands,FR,(14)H,,,
Finland,FIN,(12)H,,,
France,F,(11)H,,,
Georgia,GE,(16)H,,,
Germany,D,(0D)H,,,
Greece,GR,(17)H,,,
Hungary,H,(18)H,,,
Iceland,IS,(1C)H,,,
Ireland,IRL,(1B)H,,,
Italy,I,(1A)H,,,
Kazakhstan,KZ,(1D)H,,,
Kyrgyz Republic,KG,(38)H,,,
Latvia,LV,(20)H,,,
Liechtenstein,FL,(13)H,,,
Lithuania,LT,(1F)H,,,
Luxembourg,L,(1E)H,,,
Malta,M,(21)H,,,
Moldova,MD,(23)H,,,
Monaco,MC,(22)H,,,
Montenegro,MNE,(34)H,,,
Netherlands,NL,(26)H,,,
North Macedonia,MK,(24)H,,,
Norway,N,(25)H,,,
Poland,PL,(28)H,,,
Portugal,P,(27)H,,,
Romania,RO,(29)H,,,
Russia,RUS,(2B)H,,,
San Marino,RSM,(2A)H,,,
Serbia,SRB,(35)H,,,
Slovakia,SK,(2D)H,,,
Slovenia,SLO,(2E)H,,,
Spain,E,(0F)H,,,
Sweden,S,(2C)H,,,
Switzerland,CH,(0A)H,,,
Tajikistan,TJ,(37)H,,,
Turkiye,TR,(30)H,,,
Turkmenistan,TM,(2F)H,,,
Ukraine,UA,(31)H,,,
United Kingdom,UK,(15)H,,,
Uzbekistan,UZ,(36)H,,,
Vatican City,V,(32)H,,,
Yugoslavia,YU,(33)H,,,
European Community,EC,(FD)H,,,
Rest of Europe,EUR,(FE)H,,,
Rest of the World,WLD,(FF)H,,,
";

fn main() -> eyre::Result<()> {
    use std::fmt::Write;
    let mut names_enum_buf = String::new();
    let mut match_enum_buf = String::new();
    let mut match_bytes_buf = String::new();
    let mut id_buf = String::new();
    for country_line in COUNTRY_LIST.lines() {
        if country_line.is_empty() {
            continue;
        }
        let mut row = country_line.split(",");
        let country = row.next().ok_or_eyre("country column")?;
        let alpha_code = row.next().ok_or_eyre("alpha_code column")?;
        let numeric = row.next().ok_or_eyre("numeric column")?;

        let numeric = numeric
            .strip_prefix("(")
            .ok_or_eyre("numeric strip prefix (")?;
        let numeric = numeric
            .strip_suffix(")H")
            .ok_or_eyre("numeric strip suffix )H")?;

        let alpha_code = format!("{alpha_code: <3}");

        if alpha_code.len() != 3 {
            bail!("alpha_code too long: {alpha_code:?}");
        }

        let numeric = u8::from_str_radix(numeric, 16)
            .wrap_err_with(|| format!("parse country {country:?}"))?;

        let country_enum = country.replace(" ", "");
        let country_id = country.replace(" ", "_").to_ascii_uppercase();
        let country_id = format!("{country_id}_ID");

        writeln!(&mut names_enum_buf, "{country_enum},")?;

        writeln!(
            &mut match_enum_buf,
            "Self::{country_enum} => ids::{country_id},"
        )?;

        writeln!(
            &mut match_bytes_buf,
            "ids::{country_id} => Self::{country_enum},"
        )?;

        let alpha_code = alpha_code.as_bytes();

        let country_bytes = [numeric, alpha_code[0], alpha_code[1], alpha_code[2]];

        writeln!(
            &mut id_buf,
            "pub const {country_id}: [u8; 4] = {country_bytes:#02x?};"
        )?;
    }
    println!("{names_enum_buf}");
    println!("{match_enum_buf}");
    println!("{match_bytes_buf}");
    println!("{id_buf}");
    Ok(())
}
