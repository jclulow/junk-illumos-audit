use std::{io::Read, path::PathBuf};

use anyhow::{bail, Result};

mod events;
mod parser;

#[derive(Debug)]
struct AuditLog {
    start: String,
    end: Option<String>,
    hostname: String,
    path: PathBuf,
}

fn main() -> Result<()> {
    let a = getopts::Options::new()
        .parsing_style(getopts::ParsingStyle::StopAtFirstFree)
        .parse(std::env::args().skip(1))?;

    if a.free.len() != 1 {
        bail!("specify audit file directory");
    }

    let events = events::Events::new()?;

    let dir = PathBuf::from(&a.free[0]);

    let rd = std::fs::read_dir(&dir)?;
    let mut ents = rd
        .map(|ent| {
            let ent = ent?;

            let ft = ent.file_type()?;
            if !ft.is_file() {
                bail!("unexpected item in bagging area: {ent:?}");
            }

            let Some(name) = ent.file_name().to_str().map(str::to_string) else {
                bail!("invalid file name: {ent:?}");
            };

            let t = name.split('.').collect::<Vec<_>>();
            if t.len() != 3 {
                bail!("weird file name: {ent:?}");
            }

            Ok(AuditLog {
                start: t[0].to_string(),
                end: if t[1] == "not_terminated" {
                    None
                } else {
                    Some(t[1].to_string())
                },
                hostname: t[2].to_string(),
                path: ent.path().to_path_buf(),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    ents.sort_by(|a, b| a.start.cmp(&b.start));

    for e in ents {
        let mut p = parser::Parser::new(&events);
        let mut f = std::fs::File::open(&e.path)?;
        let mut br = std::io::BufReader::new(f);

        println!("AUDIT LOG = {e:?}");

        loop {
            let mut buf = vec![0u8];
            match br.read(&mut buf) {
                Ok(0) => {
                    println!("EOF");
                    break;
                }
                Ok(1) => {
                    if let Some(rec) = p.push(buf[0])? {
                        println!("RECORD = {rec:#x?}");
                        println!("  DATA = {:#x?}", rec.data()?);
                    }
                }
                Ok(n) => panic!("what? {n}"),
                Err(e) => {
                    eprintln!("file read error: {e}");
                    break;
                }
            }
        }

        println!();
    }

    Ok(())
}
