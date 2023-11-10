use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use anyhow::{bail, Context, Result};

#[derive(Clone)]
pub struct Events(Arc<HashMap<u16, Event>>);

#[derive(Debug, Clone)]
pub struct Event {
    pub id: u16,
    pub name: String,
    pub desc: String,
    pub classes: HashSet<String>,
}

impl Events {
    pub fn new() -> Result<Events> {
        Self::new_from_str(
            std::fs::read_to_string("/etc/security/audit_event")?.as_str(),
        )
    }

    pub fn new_from_str(data: &str) -> Result<Events> {
        Ok(Events(Arc::new(
            data.lines()
                .map(parse_line)
                .collect::<Result<Vec<_>>>()
                .with_context(|| format!("line {data:?}"))?
                .into_iter()
                .filter_map(|ev| ev)
                .map(|ev| (ev.id, ev))
                .collect(),
        )))
    }

    pub fn lookup(&self, id: u16) -> Result<&Event> {
        if let Some(ev) = self.0.get(&id) {
            Ok(ev)
        } else {
            bail!("unknown event 0x{id:x}");
        }
    }
}

enum State {
    Number,
    Name,
    Desc,
    Class,
}

fn parse_line(l: &str) -> Result<Option<Event>> {
    let mut num = String::new();
    let mut name = String::new();
    let mut desc = String::new();
    let mut class = String::new();
    let mut classes = HashSet::new();
    let mut s = State::Number;

    for c in l.chars() {
        if c == '#' {
            break;
        }

        match s {
            State::Number => {
                if c.is_ascii_digit() {
                    num.push(c);
                } else if c == ':' {
                    s = State::Name;
                } else {
                    bail!("unexpected char in number field {c:?}");
                }
            }
            State::Name => {
                if c == ':' {
                    s = State::Desc;
                } else if c.is_ascii_graphic() {
                    name.push(c);
                } else {
                    bail!("unexpected char in name field {c:?}");
                }
            }
            State::Desc => {
                if c == ':' {
                    s = State::Class;
                } else if c.is_ascii_graphic() || c == ' ' {
                    desc.push(c);
                } else {
                    bail!("unexpected char in desc field {c:?}");
                }
            }
            State::Class => {
                if c == ',' {
                    if !class.is_empty() {
                        classes.insert(class);
                        class = String::new();
                    }
                } else if c.is_ascii_graphic() && c != ':' {
                    class.push(c);
                } else {
                    bail!("unexpected char in desc field {c:?}");
                }
            }
        }
    }

    if num.trim().is_empty() {
        return Ok(None);
    }

    if !class.is_empty() {
        classes.insert(class);
    }

    Ok(Some(Event { id: num.parse()?, name, desc, classes }))
}
