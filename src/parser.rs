use std::{ffi::CStr, mem::size_of, net::IpAddr};

use anyhow::{bail, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::collections::BTreeSet;

use crate::events::{Event, Events};

#[allow(unused)]
pub mod devnums {
    pub const NBITSMINOR32: u32 = 18;
    pub const NBITSMINOR64: u64 = 32;
    pub const MAXMAJ64: u64 = u32::MAX as u64;
    pub const MAXMIN64: u64 = u32::MAX as u64;
    pub const MAXMAJ32: u32 = 0x3FFF;
    pub const MAXMIN32: u32 = 0x3FFFF;
}

#[allow(unused)]
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
        pub const AUT_UPRIV: u8 = 0x39;
        pub const AUT_FMRI: u8 = 0x20;
        pub const AUT_ARG32: u8 = 0x2D;
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

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Modifiers {
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

impl Record {
    pub fn data(&self) -> Result<Vec<DataToken>> {
        match self {
            Record::FileToken { .. } => Ok(Default::default()),
            Record::Header64Ex { bytes, .. }
            | Record::Header32Ex { bytes, .. } => {
                let mut p = DataParser::new(bytes.clone());
                let mut out = Vec::new();

                while let Some(dt) = p.pull()? {
                    out.push(dt);
                }

                Ok(out)
            }
        }
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
    FileNameString { sec: u32, usec: u32, namelen: usize },

    PreHeader,
    Header64Ex { rem: usize },
    Header32Ex { rem: usize },
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
                    State::FileNameString { sec, usec, namelen };

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
            State::FileNameString { sec, usec, namelen } => {
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

#[derive(Debug)]
pub enum DataToken {
    Text(String),
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
    Path(String),
    Attribute {
        mode: u32,
        uid: u32,
        gid: u32,
        fsid: u32,
        node_id: u64,
        device_id: u64,
    },
    ExecArgs(Vec<String>),
    ZoneName(String),
    /**
     * The name of an rbac(7) authorisation; e.g., "solaris.smf.modify".
     */
    UseOfAuth(String),
    UseOfPriv {
        success: bool,
        privs: String,
    },
    /**
     * An SMF FMRI that identifies the target of the action.
     */
    Fmri(String),
    Arg {
        num: u8,
        value: u32,
        desc: String,
    },
}

struct DataParser {
    fin: bool,
    error: Option<String>,
    input: Bytes,
}

impl DataParser {
    pub fn new(input: Bytes) -> DataParser {
        DataParser { fin: false, error: None, input }
    }

    pub fn pull(&mut self) -> Result<Option<DataToken>> {
        if let Some(e) = &self.error {
            bail!("{e}");
        }

        if self.fin {
            return Ok(None);
        }

        if !self.input.has_remaining() {
            self.fin = true;
            return Ok(None);
        }

        let res = match self.input.get_u8() {
            tok::data::AUT_TEXT => self.pull_text(),
            tok::data::AUT_SUBJECT32 => self.pull_subject(false),
            tok::data::AUT_SUBJECT64 => self.pull_subject(true),
            tok::data::AUT_RETURN32 => self.pull_return32(),
            tok::data::AUT_RETURN64 => self.pull_return64(),
            tok::data::AUT_PATH => self.pull_path(),
            tok::data::AUT_ATTR64 => self.pull_attr64(),
            tok::data::AUT_EXEC_ARGS => self.pull_exec_args(),
            tok::data::AUT_ZONENAME => self.pull_zonename(),
            tok::data::AUT_UAUTH => self.pull_uauth(),
            tok::data::AUT_UPRIV => self.pull_upriv(),
            tok::data::AUT_FMRI => self.pull_fmri(),
            tok::data::AUT_ARG32 => self.pull_arg(),
            other => bail!("unknown data token type 0x{other:x}"),
        };

        match res {
            Ok(res) => Ok(Some(res)),
            Err(e) => {
                self.error = Some(e.to_string());
                Err(e)
            }
        }
    }

    fn pull_string(&mut self) -> Result<String> {
        let mut arg: Vec<u8> = Vec::new();

        while self.input.has_remaining() {
            let b = self.input.get_u8();
            if b == b'\0' {
                break;
            }
            arg.push(b);
        }

        Ok(String::from_utf8(arg)?)
    }

    fn pull_adr_string(&mut self) -> Result<String> {
        if self.input.remaining() < size_of::<u16>() {
            bail!("partial string");
        }

        let len: usize = self.input.get_u16().try_into().unwrap();
        if self.input.remaining() < len {
            bail!("partial string");
        }

        match CStr::from_bytes_with_nul(&self.input[0..len]) {
            Ok(cstr) => match cstr.to_str() {
                Ok(s) => {
                    let s = s.to_string();
                    self.input.advance(len);
                    Ok(s)
                }
                Err(e) => bail!("invalid string: {e}"),
            },
            Err(e) => bail!("invalid string: {e}"),
        }
    }

    fn pull_text(&mut self) -> Result<DataToken> {
        Ok(DataToken::Text(self.pull_adr_string()?))
    }

    fn pull_path(&mut self) -> Result<DataToken> {
        Ok(DataToken::Path(self.pull_adr_string()?))
    }

    fn pull_zonename(&mut self) -> Result<DataToken> {
        Ok(DataToken::ZoneName(self.pull_adr_string()?))
    }

    fn pull_uauth(&mut self) -> Result<DataToken> {
        Ok(DataToken::UseOfAuth(self.pull_adr_string()?))
    }

    fn pull_fmri(&mut self) -> Result<DataToken> {
        Ok(DataToken::Fmri(self.pull_adr_string()?))
    }

    fn pull_arg(&mut self) -> Result<DataToken> {
        if self.input.remaining() < size_of::<u8>() + size_of::<u32>() {
            bail!("partial arg32");
        }

        let num = self.input.get_u8();
        let value = self.input.get_u32();
        let desc = self.pull_adr_string()?;

        Ok(DataToken::Arg { num, value, desc })
    }

    fn pull_exec_args(&mut self) -> Result<DataToken> {
        if self.input.remaining() < size_of::<u32>() {
            bail!("partial exec args");
        }

        let count = self.input.get_u32().try_into().unwrap();
        let mut args = Vec::new();

        while args.len() < count {
            args.push(self.pull_string()?);
        }

        if args.len() != count {
            bail!("partial exec args");
        }

        Ok(DataToken::ExecArgs(args))
    }

    fn pull_subject(&mut self, wide: bool) -> Result<DataToken> {
        let tidsz = if wide { size_of::<u64>() } else { size_of::<u32>() };
        if self.input.remaining()
            < 7 * size_of::<u32>() + tidsz + size_of::<u32>()
        {
            bail!("partial subject");
        }

        let audit_uid = self.input.get_u32();
        let uid = self.input.get_u32();
        let gid = self.input.get_u32();
        let ruid = self.input.get_u32();
        let rgid = self.input.get_u32();
        let pid = self.input.get_u32();
        let sid = self.input.get_u32();
        let (major, minor) = if wide {
            let tid = self.input.get_u64();
            (
                (tid >> devnums::NBITSMINOR64).try_into().unwrap(),
                (tid & devnums::MAXMIN64).try_into().unwrap(),
            )
        } else {
            let tid = self.input.get_u32();
            (
                (tid >> devnums::NBITSMINOR32).try_into().unwrap(),
                (tid & devnums::MAXMIN32).try_into().unwrap(),
            )
        };
        let machine = std::net::Ipv4Addr::new(
            self.input.get_u8(),
            self.input.get_u8(),
            self.input.get_u8(),
            self.input.get_u8(),
        );

        Ok(DataToken::Subject {
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
        })
    }

    fn pull_return32(&mut self) -> Result<DataToken> {
        if self.input.remaining() < size_of::<u32>() {
            bail!("partial return");
        }

        let number = self.input.get_i8();
        let value = self.input.get_i32();

        Ok(DataToken::Return32 { number, value })
    }

    fn pull_return64(&mut self) -> Result<DataToken> {
        if self.input.remaining() < size_of::<u64>() {
            bail!("partial return");
        }

        let number = self.input.get_i8();
        let value = self.input.get_i64();

        Ok(DataToken::Return64 { number, value })
    }

    fn pull_attr64(&mut self) -> Result<DataToken> {
        if self.input.len() < 4 * size_of::<u32>() + 2 * size_of::<u64>() {
            bail!("partial attribute");
        }

        let mode = self.input.get_u32();
        let uid = self.input.get_u32();
        let gid = self.input.get_u32();
        let fsid = self.input.get_u32();
        let node_id = self.input.get_u64();
        let device_id = self.input.get_u64();

        Ok(DataToken::Attribute { mode, uid, gid, fsid, node_id, device_id })
    }

    fn pull_upriv(&mut self) -> Result<DataToken> {
        if !self.input.has_remaining() {
            bail!("partial upriv");
        }

        let success = self.input.get_u8() != 0;
        let privs = self.pull_adr_string()?;

        Ok(DataToken::UseOfPriv { success, privs })
    }
}
