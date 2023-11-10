use std::{ffi::CStr, net::IpAddr};

use anyhow::{bail, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::collections::BTreeSet;

use crate::events::{Event, Events};

const NBITSMINOR32: u32 = 18;
const NBITSMINOR64: u64 = 32;
const MAXMAJ64: u64 = u32::MAX as u64;
const MAXMIN64: u64 = u32::MAX as u64;
const MAXMAJ32: u32 = 0x3FFF;
const MAXMIN32: u32 = 0x3FFFF;

pub mod tok {
    pub mod ctl {
        pub const INVALID: u8 = 0x0;
        pub const OTHER_FILE32: u8 = 0x11;
        pub const OTHER_FILE: u8 = OTHER_FILE32;
        pub const OHEADER: u8 = 0x12;
        pub const TRAILER: u8 = 0x13;
        pub const HEADER32: u8 = 0x14;
        pub const HEADER: u8 = HEADER32;
        pub const HEADER32_EX: u8 = 0x15;
        pub const HEADER64_EX: u8 = 0x79;
        pub const TRAILER_MAGIC: u16 = 0xB105;
    }
    pub mod data {
        pub const AUT_TEXT: u8 = 0x28;
        pub const AUT_RETURN32: u8 = 0x27;
        pub const AUT_RETURN64: u8 = 0x72;
        pub const AUT_SUBJECT32: u8 = 0x24;
        pub const AUT_SUBJECT64: u8 = 0x75;
        pub const AUT_PATH: u8 = 0x23;
        pub const AUT_ATTR64: u8 = 0x73;
        pub const AUT_EXEC_ARGS: u8 = 0x3c;
        pub const AUT_ZONENAME: u8 = 0x60;
        pub const AUT_UAUTH: u8 = 0x3f;
        pub const AUT_FMRI: u8 = 0x20;
    }
    pub mod iptype {
        pub const IPV4: u32 = 4;
        pub const IPV6: u32 = 16;
    }
    pub mod modifiers {
        pub const PAD_READ: u16 = 0x0001;
        pub const PAD_WRITE: u16 = 0x0002;
        pub const PAD_NONATTR: u16 = 0x4000;
        pub const PAD_FAILURE: u16 = 0x8000;
        pub const PAD_SPRIVUSE: u16 = 0x0080;
        pub const PAD_FPRIVUSE: u16 = 0x0100;
    }
}

pub struct Parser {
    buf: BytesMut,
    state: State,
    events: Events,
}

enum State {
    Pre,

    PreFile,
    FileNameString { token: u8, sec: u32, usec: u32, namelen: usize },

    PreHeader,
    Header64Ex { rem: usize },
    Header32Ex { rem: usize },
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Modifiers {
    Read,
    Write,
    PrivilegeUsed,
    PrivilegeFailed,
    NonAttributable,
    Failure,
}

impl Modifiers {
    fn set_from_bits(bits: u16) -> Result<BTreeSet<Modifiers>> {
        use tok::modifiers::*;

        let mut out = BTreeSet::new();

        if bits & PAD_READ != 0 {
            out.insert(Modifiers::Read);
        }
        if bits & PAD_WRITE != 0 {
            out.insert(Modifiers::Write);
        }
        if bits & PAD_NONATTR != 0 {
            out.insert(Modifiers::NonAttributable);
        }
        if bits & PAD_FAILURE != 0 {
            out.insert(Modifiers::Failure);
        }
        if bits & PAD_SPRIVUSE != 0 {
            out.insert(Modifiers::PrivilegeUsed);
        }
        if bits & PAD_FPRIVUSE != 0 {
            out.insert(Modifiers::PrivilegeFailed);
        }

        let extra = bits
            & !(PAD_READ
                | PAD_WRITE
                | PAD_NONATTR
                | PAD_FAILURE
                | PAD_SPRIVUSE
                | PAD_FPRIVUSE);
        if extra != 0 {
            bail!("unknown event modifier bits: 0x{extra:x}");
        }

        Ok(out)
    }
}

#[derive(Debug)]
pub enum Record {
    FileToken {
        sec: u32,
        usec: u32,
        name: Option<String>,
    },
    Header64Ex {
        version: u8,
        evtype: Event,
        evmod: BTreeSet<Modifiers>,
        addr: IpAddr,
        sec: u64,
        nsec: u64,
        bytes: Bytes,
    },
    Header32Ex {
        version: u8,
        evtype: Event,
        evmod: BTreeSet<Modifiers>,
        addr: IpAddr,
        sec: u32,
        nsec: u32,
        bytes: Bytes,
    },
}

#[derive(Debug)]
pub enum DataToken {
    Text {
        text: String,
    },
    Subject {
        audit_uid: u32,
        uid: u32,
        gid: u32,
        ruid: u32,
        rgid: u32,
        pid: u32,
        sid: u32,
        major: u32,
        minor: u32,
        machine: std::net::Ipv4Addr,
    },
    Return32 {
        number: i8,
        value: i32,
    },
    Return64 {
        number: i8,
        value: i64,
    },
    Path {
        path: String,
    },
    Attribute {
        mode: u32,
        uid: u32,
        gid: u32,
        fsid: u32,
        node_id: u64,
        device_id: u64,
    },
    ExecArgs {
        args: Vec<String>,
    },
    ZoneName {
        zonename: String,
    },
    UseOfAuth {
        /**
         * The name of an rbac(7) authorisation; e.g., "solaris.smf.modify".
         */
        auth: String,
    },
    Fmri {
        /**
         * An SMF FMRI that identifies the target of the action.
         */
        fmri: String,
    },
}

impl Parser {
    pub fn new(events: &Events) -> Parser {
        Parser {
            buf: Default::default(),
            state: State::Pre,
            events: events.clone(),
        }
    }

    pub fn push(&mut self, b: u8) -> Result<Option<Record>> {
        self.buf.put_u8(b);

        match self.state {
            State::Pre => {
                assert_eq!(self.buf.len(), 1);

                self.state = match self.buf[0] {
                    tok::ctl::OTHER_FILE32 => State::PreFile,
                    tok::ctl::HEADER32_EX | tok::ctl::HEADER64_EX => {
                        State::PreHeader
                    }
                    other => bail!("unknown token type 0x{other:x}"),
                };
                Ok(None)
            }
            State::PreFile => {
                /*
                 * The file token consists of:
                 *  token ID                1 byte
                 *  seconds of time         4 bytes
                 *  microseconds of time    4 bytes
                 *  file name length        2 bytes
                 *  file pathname           N bytes + 1 terminating NULL byte
                 *
                 * Wait for all of the fixed length portions to arrive.
                 */
                if self.buf.len() < 1 + 4 + 4 + 2 {
                    return Ok(None);
                }

                let token = self.buf.get_u8();
                if token != tok::ctl::OTHER_FILE32 {
                    bail!("unexpected file token ID 0x{token:x}");
                }
                let sec = self.buf.get_u32();
                let usec = self.buf.get_u32();
                let namelen = self.buf.get_u16().try_into().unwrap();

                self.buf.clear();
                self.state =
                    State::FileNameString { token, sec, usec, namelen };

                Ok(None)
            }
            State::PreHeader => {
                /*
                 * HEADER64_EX and HEADER32_EX both begin with a 1 byte token ID
                 * and a 4 byte record length.
                 */
                if self.buf.len() < 1 + 4 {
                    return Ok(None);
                }

                let token = self.buf.get_u8();
                let reclen: usize = self.buf.get_u32().try_into().unwrap();

                self.buf.clear();
                self.state = match token {
                    tok::ctl::HEADER64_EX => {
                        State::Header64Ex { rem: reclen - (1 + 4) }
                    }
                    tok::ctl::HEADER32_EX => {
                        State::Header32Ex { rem: reclen - (1 + 4) }
                    }
                    _ => unreachable!(),
                };
                return Ok(None);
            }
            State::FileNameString { sec, usec, namelen, .. } => {
                if self.buf.len() < namelen {
                    return Ok(None);
                }

                let name = match CStr::from_bytes_with_nul(&self.buf) {
                    Ok(cstr) => match cstr.to_str() {
                        Ok(s) => {
                            if s.is_empty() {
                                None
                            } else {
                                Some(s.to_string())
                            }
                        }
                        Err(e) => bail!("invalid file name string: {e}"),
                    },
                    Err(e) => bail!("invalid file name string: {e}"),
                };

                self.buf.clear();
                self.state = State::PreHeader;
                Ok(Some(Record::FileToken { sec, usec, name }))
            }
            State::Header64Ex { rem } => {
                if self.buf.len() < rem {
                    return Ok(None);
                }

                let version = self.buf.get_u8();
                if version != 2 {
                    bail!("unexpected header version {version}");
                }
                let evtype = self.buf.get_u16();
                let evmod = self.buf.get_u16();
                let addrtype = self.buf.get_u32();

                let addr = if addrtype == tok::iptype::IPV4 {
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                        self.buf.get_u8(),
                        self.buf.get_u8(),
                        self.buf.get_u8(),
                        self.buf.get_u8(),
                    ))
                } else if addrtype == tok::iptype::IPV6 {
                    std::net::IpAddr::V6(std::net::Ipv6Addr::new(
                        self.buf.get_u16(),
                        self.buf.get_u16(),
                        self.buf.get_u16(),
                        self.buf.get_u16(),
                        self.buf.get_u16(),
                        self.buf.get_u16(),
                        self.buf.get_u16(),
                        self.buf.get_u16(),
                    ))
                } else {
                    bail!("invalid address type 0x{addrtype:x}");
                };

                let sec = self.buf.get_u64();
                let nsec = self.buf.get_u64();

                let bytes = self.buf.copy_to_bytes(self.buf.remaining());

                self.buf.clear();
                self.state = State::Pre;
                return Ok(Some(Record::Header64Ex {
                    version,
                    evtype: self.events.lookup(evtype)?.clone(),
                    evmod: Modifiers::set_from_bits(evmod)?,
                    addr,
                    sec,
                    nsec,
                    bytes,
                }));
            }
            State::Header32Ex { rem } => {
                if self.buf.len() < rem {
                    return Ok(None);
                }

                let version = self.buf.get_u8();
                if version != 2 {
                    bail!("unexpected header version {version}");
                }
                let evtype = self.buf.get_u16();
                let evmod = self.buf.get_u16();
                let addrtype = self.buf.get_u32();

                let addr = if addrtype == tok::iptype::IPV4 {
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                        self.buf.get_u8(),
                        self.buf.get_u8(),
                        self.buf.get_u8(),
                        self.buf.get_u8(),
                    ))
                } else if addrtype == tok::iptype::IPV6 {
                    std::net::IpAddr::V6(std::net::Ipv6Addr::new(
                        self.buf.get_u16(),
                        self.buf.get_u16(),
                        self.buf.get_u16(),
                        self.buf.get_u16(),
                        self.buf.get_u16(),
                        self.buf.get_u16(),
                        self.buf.get_u16(),
                        self.buf.get_u16(),
                    ))
                } else {
                    bail!("invalid address type 0x{addrtype:x}");
                };

                let sec = self.buf.get_u32();
                let nsec = self.buf.get_u32();

                let bytes = self.buf.copy_to_bytes(self.buf.remaining());

                self.buf.clear();
                self.state = State::Pre;
                return Ok(Some(Record::Header32Ex {
                    version,
                    evtype: self.events.lookup(evtype)?.clone(),
                    evmod: Modifiers::set_from_bits(evmod)?,
                    addr,
                    sec,
                    nsec,
                    bytes,
                }));
            }
        }
    }
}

impl Record {
    pub fn data(&self) -> Result<Vec<DataToken>> {
        match self {
            Record::FileToken { .. } => Ok(Default::default()),
            Record::Header64Ex { bytes, .. }
            | Record::Header32Ex { bytes, .. } => {
                let mut p = DataParser::new();

                Ok(bytes
                    .iter()
                    .map(|b| Ok(p.push(*b)?))
                    .collect::<Result<Vec<_>>>()?
                    .into_iter()
                    .filter_map(|ev| ev)
                    .collect())
            }
        }
    }
}

enum DataState {
    Pre,
    Text,
    TextString { len: usize },
    Subject { wide: bool },
    Return32,
    Return64,
    Path,
    PathString { len: usize },
    Attribute64,
    ExecArgs,
    ExecArgsString { count: usize },
    ZoneName,
    ZoneNameString { len: usize },
    UseOfAuth,
    UseOfAuthString { len: usize },
    Fmri,
    FmriString { len: usize },
}

struct DataParser {
    buf: BytesMut,
    args: Vec<String>,
    state: DataState,
}

impl DataParser {
    pub fn new() -> DataParser {
        DataParser {
            buf: Default::default(),
            args: Default::default(),
            state: DataState::Pre,
        }
    }

    fn get_cstr(&mut self) -> Result<String> {
        match CStr::from_bytes_with_nul(&self.buf) {
            Ok(cstr) => match cstr.to_str() {
                Ok(s) => {
                    let s = s.to_string();
                    self.buf.advance(self.buf.len());
                    Ok(s)
                }
                Err(e) => bail!("invalid text string: {e}"),
            },
            Err(e) => bail!("invalid text string: {e}"),
        }
    }

    pub fn push(&mut self, b: u8) -> Result<Option<DataToken>> {
        self.buf.put_u8(b);

        match self.state {
            DataState::Pre => {
                assert_eq!(self.buf.len(), 1);

                self.state = match self.buf[0] {
                    tok::data::AUT_TEXT => DataState::Text,
                    tok::data::AUT_SUBJECT32 => {
                        DataState::Subject { wide: false }
                    }
                    tok::data::AUT_SUBJECT64 => {
                        DataState::Subject { wide: true }
                    }
                    tok::data::AUT_RETURN32 => DataState::Return32,
                    tok::data::AUT_RETURN64 => DataState::Return64,
                    tok::data::AUT_PATH => DataState::Path,
                    tok::data::AUT_ATTR64 => DataState::Attribute64,
                    tok::data::AUT_EXEC_ARGS => DataState::ExecArgs,
                    tok::data::AUT_ZONENAME => DataState::ZoneName,
                    tok::data::AUT_UAUTH => DataState::UseOfAuth,
                    tok::data::AUT_FMRI => DataState::Fmri,
                    other => bail!("unknown data token type 0x{other:x}"),
                };
                Ok(None)
            }
            DataState::Text => {
                if self.buf.len() < 1 + 2 {
                    return Ok(None);
                }

                let _token = self.buf.get_u8();
                let len = self.buf.get_u16().try_into().unwrap();

                self.state = DataState::TextString { len };
                Ok(None)
            }
            DataState::TextString { len } => {
                if self.buf.len() < len {
                    return Ok(None);
                }

                let text = self.get_cstr()?;

                self.state = DataState::Pre;
                Ok(Some(DataToken::Text { text }))
            }
            DataState::Subject { wide } => {
                let tidsz = if wide { 8 } else { 4 };
                if self.buf.len() < 1 + 7 * 4 + tidsz + 4 {
                    return Ok(None);
                }

                if wide {
                    assert_eq!(self.buf.get_u8(), tok::data::AUT_SUBJECT64);
                } else {
                    assert_eq!(self.buf.get_u8(), tok::data::AUT_SUBJECT32);
                }

                let audit_uid = self.buf.get_u32();
                let uid = self.buf.get_u32();
                let gid = self.buf.get_u32();
                let ruid = self.buf.get_u32();
                let rgid = self.buf.get_u32();
                let pid = self.buf.get_u32();
                let sid = self.buf.get_u32();
                let (major, minor) = if wide {
                    let tid = self.buf.get_u64();
                    (
                        (tid >> NBITSMINOR64).try_into().unwrap(),
                        (tid & MAXMIN64).try_into().unwrap(),
                    )
                } else {
                    let tid = self.buf.get_u32();
                    (
                        (tid >> NBITSMINOR32).try_into().unwrap(),
                        (tid & MAXMIN32).try_into().unwrap(),
                    )
                };
                let machine = std::net::Ipv4Addr::new(
                    self.buf.get_u8(),
                    self.buf.get_u8(),
                    self.buf.get_u8(),
                    self.buf.get_u8(),
                );

                assert!(self.buf.is_empty());
                self.state = DataState::Pre;
                Ok(Some(DataToken::Subject {
                    audit_uid,
                    uid,
                    gid,
                    ruid,
                    rgid,
                    pid,
                    sid,
                    major,
                    minor,
                    machine,
                }))
            }
            DataState::Return32 => {
                if self.buf.len() < 1 + 1 + 4 {
                    return Ok(None);
                }

                assert_eq!(self.buf.get_u8(), tok::data::AUT_RETURN32);

                let number = self.buf.get_i8();
                let value = self.buf.get_i32();

                assert!(self.buf.is_empty());
                self.state = DataState::Pre;
                self.buf.clear();
                Ok(Some(DataToken::Return32 { number, value }))
            }
            DataState::Return64 => {
                if self.buf.len() < 1 + 1 + 8 {
                    return Ok(None);
                }

                assert_eq!(self.buf.get_u8(), tok::data::AUT_RETURN64);

                let number = self.buf.get_i8();
                let value = self.buf.get_i64();

                assert!(self.buf.is_empty());
                self.state = DataState::Pre;
                self.buf.clear();
                Ok(Some(DataToken::Return64 { number, value }))
            }
            DataState::Path => {
                if self.buf.len() < 1 + 2 {
                    return Ok(None);
                }

                assert_eq!(self.buf.get_u8(), tok::data::AUT_PATH);

                let len = self.buf.get_u16().try_into().unwrap();

                self.state = DataState::PathString { len };
                Ok(None)
            }
            DataState::PathString { len } => {
                if self.buf.len() < len {
                    return Ok(None);
                }

                let path = self.get_cstr()?;

                self.state = DataState::Pre;
                self.buf.clear();
                Ok(Some(DataToken::Path { path }))
            }
            DataState::Attribute64 => {
                if self.buf.len() < 1 + 4 * 4 + 2 * 8 {
                    return Ok(None);
                }

                assert_eq!(self.buf.get_u8(), tok::data::AUT_ATTR64);

                let mode = self.buf.get_u32();
                let uid = self.buf.get_u32();
                let gid = self.buf.get_u32();
                let fsid = self.buf.get_u32();
                let node_id = self.buf.get_u64();
                let device_id = self.buf.get_u64();

                assert!(self.buf.is_empty());
                self.state = DataState::Pre;
                Ok(Some(DataToken::Attribute {
                    mode,
                    uid,
                    gid,
                    fsid,
                    node_id,
                    device_id,
                }))
            }
            DataState::ExecArgs => {
                if self.buf.len() < 1 + 4 {
                    return Ok(None);
                }

                assert_eq!(self.buf.get_u8(), tok::data::AUT_EXEC_ARGS);

                let count = self.buf.get_u32().try_into().unwrap();

                self.args.clear();
                assert!(self.buf.is_empty());

                if count == 0 {
                    self.state = DataState::Pre;
                    Ok(Some(DataToken::ExecArgs { args: Default::default() }))
                } else {
                    self.state = DataState::ExecArgsString { count };
                    Ok(None)
                }
            }
            DataState::ExecArgsString { count } => {
                if self.buf[self.buf.len() - 1] != b'\0' {
                    return Ok(None);
                }

                let s = self.get_cstr()?;

                self.args.push(s);
                let count = count.checked_sub(1).unwrap();

                if count == 0 {
                    self.state = DataState::Pre;
                    let args = std::mem::take(&mut self.args);
                    Ok(Some(DataToken::ExecArgs { args }))
                } else {
                    self.state = DataState::ExecArgsString { count };
                    Ok(None)
                }
            }
            DataState::ZoneName => {
                if self.buf.len() < 1 + 2 {
                    return Ok(None);
                }

                assert_eq!(self.buf.get_u8(), tok::data::AUT_ZONENAME);

                let len = self.buf.get_u16().try_into().unwrap();

                self.state = DataState::ZoneNameString { len };
                Ok(None)
            }
            DataState::ZoneNameString { len } => {
                if self.buf.len() < len {
                    return Ok(None);
                }

                let zonename = self.get_cstr()?;

                self.state = DataState::Pre;
                self.buf.clear();
                Ok(Some(DataToken::ZoneName { zonename }))
            }
            DataState::UseOfAuth => {
                if self.buf.len() < 1 + 2 {
                    return Ok(None);
                }

                assert_eq!(self.buf.get_u8(), tok::data::AUT_UAUTH);

                let len = self.buf.get_u16().try_into().unwrap();

                self.state = DataState::UseOfAuthString { len };
                Ok(None)
            }
            DataState::UseOfAuthString { len } => {
                if self.buf.len() < len {
                    return Ok(None);
                }

                let auth = self.get_cstr()?;

                self.state = DataState::Pre;
                self.buf.clear();
                Ok(Some(DataToken::UseOfAuth { auth }))
            }
            DataState::Fmri => {
                if self.buf.len() < 1 + 2 {
                    return Ok(None);
                }

                assert_eq!(self.buf.get_u8(), tok::data::AUT_FMRI);

                let len = self.buf.get_u16().try_into().unwrap();

                self.state = DataState::FmriString { len };
                Ok(None)
            }
            DataState::FmriString { len } => {
                if self.buf.len() < len {
                    return Ok(None);
                }

                let fmri = self.get_cstr()?;

                self.state = DataState::Pre;
                self.buf.clear();
                Ok(Some(DataToken::Fmri { fmri }))
            }
        }
    }
}
