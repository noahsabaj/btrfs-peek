//! The helper: a Windows service that lets one account read btrfs partitions
//! without an elevated terminal.
//!
//! Only administrators may open a raw disk on Windows. The service runs as
//! LocalSystem, opens a partition for reading when asked over a local named
//! pipe, and hands back bytes. It refuses everything that is not a btrfs
//! partition, and like the rest of the crate it never opens a device for
//! writing.
//!
//! The wire protocol lives here, generic over `Read + Write`, so it is tested
//! on every OS, as is what the service accepts as an update of itself
//! (`update.rs`). The service, the pipe and the install live in `windows.rs`.

// On other OSes only the tests use the protocol; the service is Windows-only.
#![cfg_attr(not(windows), allow(dead_code))]

use crate::disk::{Superblock, SUPER_OFFSET, SUPER_SIZE};
use std::fs::File;
use std::io::{self, Read, Write};

mod update;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::Remote;

pub use update::{Update, Version};

pub const PROTOCOL: u8 = 1;
const VERSION: &str = env!("CARGO_PKG_VERSION");

const OPEN: u8 = 1;
const READ: u8 = 2;
/// Added after protocol 1 shipped; older services answer "unknown operation 3".
const UPDATE: u8 = 3;

const OK: u8 = 0;
const NOT_FOUND: u8 = 1;
const REFUSED: u8 = 2;
const ERROR: u8 = 3;

/// Longest path an OPEN may carry; partition paths are a few dozen bytes.
const MAX_PATH: usize = 1024;
/// Largest READ; matches the device layer's largest single read.
pub const MAX_READ: usize = 4 << 20;
/// Longest text reply (version, error) a client accepts.
const MAX_MESSAGE: usize = 64 << 10;

#[derive(clap::Subcommand)]
pub enum Action {
    /// Install or update the helper service and start it (elevated terminal, once).
    Install {
        /// Account allowed to use it (default: the account running this command).
        #[arg(long)]
        sid: Option<String>,
    },
    /// Stop and remove the helper service (elevated terminal).
    Uninstall,
    /// Exit 0 if the helper is installed and answering, else 1.
    Status,
    /// Have the service update itself to the latest signed release now (any terminal).
    Update,
    /// What the Windows service manager runs.
    #[command(hide = true)]
    Serve {
        #[arg(long)]
        sid: String,
    },
}

#[cfg(windows)]
pub fn run(action: &Action, json: bool) -> anyhow::Result<()> {
    windows::run(action, json)
}

#[cfg(not(windows))]
pub fn run(_action: &Action, _json: bool) -> anyhow::Result<()> {
    anyhow::bail!(
        "the helper is for Windows; on Linux, add yourself to the `disk` group (or run as root)"
    )
}

/// Whether `p` names a partition the helper may open: `\\.\HarddiskNPartitionM`
/// with M >= 1. Partition 0 is the whole disk, and anything else (files,
/// `\\?\` paths, GLOBALROOT, volume GUIDs) could name more than a partition.
pub fn partition_path_ok(p: &str) -> bool {
    let p = p.to_ascii_lowercase();
    let Some(rest) = p.strip_prefix(r"\\.\harddisk") else {
        return false;
    };
    let Some((disk, part)) = rest.split_once("partition") else {
        return false;
    };
    number_ok(disk) && number_ok(part) && part != "0"
}

/// One to three decimal digits, no leading zero except "0" itself.
fn number_ok(n: &str) -> bool {
    (1..=3).contains(&n.len())
        && n.bytes().all(|b| b.is_ascii_digit())
        && (n == "0" || !n.starts_with('0'))
}

/// SIDs come from the command line and go into the pipe's security
/// descriptor, so only the plain `S-1-...` form is accepted.
pub fn sid_ok(sid: &str) -> bool {
    sid.len() < 200
        && sid.len() > 4
        && sid.starts_with("S-1-")
        && sid[4..].bytes().all(|b| b.is_ascii_digit() || b == b'-')
}

/// Why the server would not open a path.
#[derive(Debug)]
pub enum Refusal {
    NotFound(String),
    Refused(String),
    Failed(String),
}

impl Refusal {
    fn status(&self) -> u8 {
        match self {
            Refusal::NotFound(_) => NOT_FOUND,
            Refusal::Refused(_) => REFUSED,
            Refusal::Failed(_) => ERROR,
        }
    }
    fn message(&self) -> &str {
        match self {
            Refusal::NotFound(m) | Refusal::Refused(m) | Refusal::Failed(m) => m,
        }
    }
}

/// What the service opens: a btrfs partition, for reading, and nothing else.
pub fn open_partition(path: &str) -> Result<File, Refusal> {
    if !partition_path_ok(path) {
        return Err(Refusal::Refused(format!(
            r"{path}: the helper opens only partitions named \\.\HarddiskNPartitionM (M >= 1)"
        )));
    }
    let file = File::open(path).map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => Refusal::NotFound(format!("{path}: no such partition")),
        _ => Refusal::Failed(format!("{path}: {e}")),
    })?;
    let mut space = Vec::new();
    let sb = aligned(&mut space, SUPER_SIZE);
    let mut done = 0;
    while done < sb.len() {
        match crate::dev::read_at(&file, &mut sb[done..], SUPER_OFFSET + done as u64) {
            Ok(0) => break,
            Ok(n) => done += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(Refusal::Failed(format!("{path}: {e}"))),
        }
    }
    if done < sb.len() || Superblock::parse(sb).is_err() {
        return Err(Refusal::Refused(format!("{path}: not a btrfs partition")));
    }
    Ok(file)
}

/// Page alignment satisfies every device's buffer rule.
const BUFFER_ALIGN: usize = 4096;

/// A `len`-byte buffer inside `space` starting on a page boundary. Raw devices
/// refuse a misaligned buffer (os error 87), and an allocation is only
/// guaranteed byte alignment.
fn aligned(space: &mut Vec<u8>, len: usize) -> &mut [u8] {
    space.resize(len + BUFFER_ALIGN, 0);
    let start = space.as_ptr().align_offset(BUFFER_ALIGN);
    &mut space[start..start + len]
}

fn respond(s: &mut impl Write, status: u8, payload: &[u8]) -> io::Result<()> {
    let mut msg = Vec::with_capacity(5 + payload.len());
    msg.push(status);
    msg.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    msg.extend_from_slice(payload);
    s.write_all(&msg)
}

/// Reads one byte; `None` when the other side has hung up.
fn read_byte(s: &mut impl Read) -> io::Result<Option<u8>> {
    let mut b = [0u8];
    loop {
        match s.read(&mut b) {
            Ok(0) => return Ok(None),
            Ok(_) => return Ok(Some(b[0])),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

fn read_u32(s: &mut impl Read) -> io::Result<u32> {
    let mut b = [0u8; 4];
    s.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn read_u64(s: &mut impl Read) -> io::Result<u64> {
    let mut b = [0u8; 8];
    s.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

/// How a client's session ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Ended {
    Closed,
    /// An UPDATE installed a new build and the session was closed after the
    /// reply, so it does not hold up the restart onto it.
    Updated,
}

/// Serves one client until it hangs up. `open` decides what may be opened;
/// `update` is what an UPDATE runs.
pub fn serve_client<S: Read + Write>(
    mut s: S,
    open: impl Fn(&str) -> Result<File, Refusal>,
    update: impl Fn() -> io::Result<Update>,
) -> io::Result<Ended> {
    let closed = |r: io::Result<()>| r.map(|()| Ended::Closed);
    let Some(proto) = read_byte(&mut s)? else {
        return Ok(Ended::Closed);
    };
    if proto != PROTOCOL {
        let msg = format!("this helper speaks protocol {PROTOCOL}, the client {proto}: install the helper again with the same btrfs-peek");
        return closed(respond(&mut s, ERROR, msg.as_bytes()));
    }
    respond(&mut s, OK, VERSION.as_bytes())?;
    let mut file: Option<File> = None;
    let mut space = Vec::new();
    while let Some(op) = read_byte(&mut s)? {
        match op {
            OPEN => {
                let len = read_u32(&mut s)? as usize;
                if len > MAX_PATH {
                    let msg = format!("path longer than {MAX_PATH} bytes");
                    return closed(respond(&mut s, ERROR, msg.as_bytes()));
                }
                let mut path = vec![0u8; len];
                s.read_exact(&mut path)?;
                if file.is_some() {
                    respond(
                        &mut s,
                        ERROR,
                        b"a device is already open on this connection",
                    )?;
                    continue;
                }
                let Ok(path) = String::from_utf8(path) else {
                    respond(&mut s, ERROR, b"the path is not UTF-8")?;
                    continue;
                };
                match open(&path) {
                    Ok(f) => {
                        file = Some(f);
                        respond(&mut s, OK, b"")?;
                    }
                    Err(r) => respond(&mut s, r.status(), r.message().as_bytes())?,
                }
            }
            READ => {
                let off = read_u64(&mut s)?;
                let len = read_u32(&mut s)? as usize;
                if len > MAX_READ {
                    let msg = format!("reads are at most {MAX_READ} bytes");
                    respond(&mut s, ERROR, msg.as_bytes())?;
                    continue;
                }
                let Some(f) = &file else {
                    respond(&mut s, ERROR, b"READ before OPEN")?;
                    continue;
                };
                let data = aligned(&mut space, len);
                match crate::dev::read_at(f, data, off) {
                    Ok(n) => {
                        let mut head = [OK, 0, 0, 0, 0];
                        head[1..].copy_from_slice(&(n as u32).to_le_bytes());
                        s.write_all(&head)?;
                        s.write_all(&data[..n])?;
                    }
                    Err(e) => respond(&mut s, ERROR, e.to_string().as_bytes())?,
                }
            }
            UPDATE => match update() {
                Ok(u) => {
                    respond(&mut s, OK, u.to_string().as_bytes())?;
                    if let Update::Installed(_) = u {
                        return Ok(Ended::Updated);
                    }
                }
                Err(e) => respond(&mut s, ERROR, e.to_string().as_bytes())?,
            },
            other => {
                let msg = format!("unknown operation {other}");
                return closed(respond(&mut s, ERROR, msg.as_bytes()));
            }
        }
    }
    Ok(Ended::Closed)
}

fn status_error(status: u8, msg: String) -> io::Error {
    match status {
        NOT_FOUND => io::Error::new(io::ErrorKind::NotFound, msg),
        REFUSED => io::Error::new(
            io::ErrorKind::InvalidData,
            format!("the helper refused: {msg}"),
        ),
        ERROR => io::Error::other(msg),
        _ => io::Error::new(
            io::ErrorKind::InvalidData,
            format!("the helper sent an unknown status {status}"),
        ),
    }
}

/// A client's connection to the helper.
pub struct Session<S> {
    s: S,
}

impl<S: Read + Write> Session<S> {
    /// Handshakes; returns the session and the server's version.
    pub fn start(mut s: S) -> io::Result<(Session<S>, String)> {
        s.write_all(&[PROTOCOL])?;
        let mut session = Session { s };
        let version = session.reply()?;
        Ok((session, String::from_utf8_lossy(&version).into_owned()))
    }

    pub fn open(&mut self, path: &str) -> io::Result<()> {
        if path.len() > MAX_PATH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("path longer than {MAX_PATH} bytes"),
            ));
        }
        let mut req = vec![OPEN];
        req.extend_from_slice(&(path.len() as u32).to_le_bytes());
        req.extend_from_slice(path.as_bytes());
        self.s.write_all(&req)?;
        self.reply().map(drop)
    }

    pub fn read_at(&mut self, buf: &mut [u8], off: u64) -> io::Result<usize> {
        let len = buf.len().min(MAX_READ);
        let mut req = vec![READ];
        req.extend_from_slice(&off.to_le_bytes());
        req.extend_from_slice(&(len as u32).to_le_bytes());
        self.s.write_all(&req)?;
        let (status, n) = self.header()?;
        if status != OK {
            let msg = self.message(n)?;
            return Err(status_error(status, msg));
        }
        if n > len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("the helper sent {n} bytes for a read of {len}"),
            ));
        }
        self.s.read_exact(&mut buf[..n])?;
        Ok(n)
    }

    /// Asks the service to update itself to the latest signed release; its
    /// reply, and the version it installed if it did. `version` is the one
    /// the handshake returned, for the error an older service gives.
    pub fn update(&mut self, version: &str) -> io::Result<(String, Option<Version>)> {
        self.s.write_all(&[UPDATE])?;
        let reply = match self.reply() {
            Ok(r) => String::from_utf8_lossy(&r).into_owned(),
            Err(e) if e.to_string() == format!("unknown operation {UPDATE}") => {
                return Err(io::Error::other(format!(
                    "this helper ({version}) predates self-update; run `btrfs-peek helper install` from an elevated terminal once more"
                )));
            }
            Err(e) => return Err(e),
        };
        let installed = update::installed_version(&reply);
        Ok((reply, installed))
    }

    fn header(&mut self) -> io::Result<(u8, usize)> {
        let mut h = [0u8; 5];
        self.s.read_exact(&mut h)?;
        let len = u32::from_le_bytes(h[1..5].try_into().unwrap());
        Ok((h[0], len as usize))
    }

    fn message(&mut self, n: usize) -> io::Result<String> {
        if n > MAX_MESSAGE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("the helper sent a {n}-byte message"),
            ));
        }
        let mut b = vec![0u8; n];
        self.s.read_exact(&mut b)?;
        Ok(String::from_utf8_lossy(&b).into_owned())
    }

    /// A short reply: its payload if OK, else the error it carries.
    fn reply(&mut self) -> io::Result<Vec<u8>> {
        let (status, n) = self.header()?;
        let msg = self.message(n)?;
        if status != OK {
            return Err(status_error(status, msg));
        }
        Ok(msg.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::path::PathBuf;

    #[test]
    fn partition_path_ok_accepts_only_numbered_partitions() {
        assert!(partition_path_ok(r"\\.\Harddisk0Partition6"));
        assert!(partition_path_ok(r"\\.\harddisk12partition3"));
        assert!(partition_path_ok(r"\\.\HARDDISK999PARTITION128"));
        for bad in [
            r"\\.\Harddisk0Partition0",
            r"\\.\PhysicalDrive0",
            r"C:\x.img",
            r"\\?\GLOBALROOT\Device\Harddisk0\Partition6",
            r"\\?\Harddisk0Partition6",
            r"\\.\Harddisk0Partition6\..\x",
            r"\\.\Harddisk0Partition06",
            r"\\.\Harddisk00Partition6",
            r"\\.\Harddisk01Partition6",
            r"\\.\HarddiskPartition6",
            r"\\.\Harddisk0Partition",
            r"\\.\Harddisk0Partition6x",
            r"\\.\Harddisk0Partition6 ",
            r"\\.\Harddisk1000Partition1",
            r"\\.\Harddisk0Partition1000",
            r"\\.\Harddisk0Partition-1",
            "",
        ] {
            assert!(!partition_path_ok(bad), "{bad} was accepted");
        }
    }

    #[test]
    fn sid_ok_accepts_only_plain_sids() {
        assert!(sid_ok("S-1-5-21-1004336348-1177238915-682003330-1001"));
        assert!(sid_ok("S-1-5-18"));
        for bad in [
            "",
            "S-1-",
            "s-1-5-18",
            "S-1-5-18)(A;;GA;;;WD)",
            "WD",
            "S-1-5 18",
        ] {
            assert!(!sid_ok(bad), "{bad} was accepted");
        }
        assert!(!sid_ok(&format!("S-1-{}", "1".repeat(200))));
    }

    fn temp(name: &str, data: &[u8]) -> PathBuf {
        let p =
            std::env::temp_dir().join(format!("btrfs-peek-helper-{}-{name}", std::process::id()));
        std::fs::write(&p, data).unwrap();
        p
    }

    /// Treats the path as a file, so the protocol can be tested without a disk.
    pub(super) fn test_open(path: &str) -> Result<File, Refusal> {
        if path.ends_with("refuse-me") {
            return Err(Refusal::Refused("refuse-me: not allowed".into()));
        }
        File::open(path).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => Refusal::NotFound(format!("{path}: not found")),
            _ => Refusal::Failed(e.to_string()),
        })
    }

    /// A service that is always up to date.
    pub(super) fn test_update() -> io::Result<Update> {
        Ok(Update::UpToDate(Version::running()))
    }

    /// One server thread per connection, like the service; `update` is what
    /// an UPDATE gets.
    fn tcp_server_with(
        update: fn() -> io::Result<Update>,
    ) -> (std::net::SocketAddr, std::sync::mpsc::Receiver<Ended>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let (s, tx) = (s.unwrap(), tx.clone());
                std::thread::spawn(move || {
                    if let Ok(ended) = serve_client(s, test_open, update) {
                        let _ = tx.send(ended);
                    }
                });
            }
        });
        (addr, rx)
    }

    fn tcp_server() -> std::net::SocketAddr {
        tcp_server_with(test_update).0
    }

    /// The whole client-visible protocol, over any connector.
    pub(super) fn exercise<S: Read + Write>(connect: impl Fn() -> S, tag: &str) {
        let data: Vec<u8> = (0..10_000u32).map(|i| (i * 7 % 251) as u8).collect();
        let file = temp(&format!("{tag}-data"), &data);
        let path = file.to_str().unwrap();

        let (mut s, version) = Session::start(connect()).unwrap();
        assert_eq!(version, VERSION);

        // A read before OPEN is an error, and the session survives it.
        let mut buf = vec![0u8; 100];
        let e = s.read_at(&mut buf, 0).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::Other);
        assert!(e.to_string().contains("before OPEN"), "{e}");

        s.open(path).unwrap();
        assert_eq!(s.read_at(&mut buf, 0).unwrap(), 100);
        assert_eq!(buf, data[..100]);
        assert_eq!(s.read_at(&mut buf, 5000).unwrap(), 100);
        assert_eq!(buf, data[5000..5100]);
        // Short at the end of the device, then nothing past it.
        assert_eq!(s.read_at(&mut buf, 9950).unwrap(), 50);
        assert_eq!(buf[..50], data[9950..]);
        assert_eq!(s.read_at(&mut buf, 20_000).unwrap(), 0);

        // One OPEN per connection; the session goes on.
        let e = s.open(path).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::Other);
        assert_eq!(s.read_at(&mut buf, 0).unwrap(), 100);

        // An UPDATE with nothing newer leaves the session going.
        let (reply, installed) = s.update(&version).unwrap();
        assert_eq!(reply, format!("up to date ({VERSION})"));
        assert_eq!(installed, None);
        assert_eq!(s.read_at(&mut buf, 0).unwrap(), 100);
        drop(s);

        let (mut s, _) = Session::start(connect()).unwrap();
        let missing = file.with_extension("missing");
        let e = s.open(missing.to_str().unwrap()).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
        let e = s.open("refuse-me").unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        assert!(e.to_string().starts_with("the helper refused: "), "{e}");
        drop(s);

        // A client that speaks another protocol is told why.
        let mut raw = connect();
        raw.write_all(&[PROTOCOL + 1]).unwrap();
        let mut s = Session { s: raw };
        let e = s.reply().unwrap_err();
        assert!(
            e.to_string()
                .contains("this helper speaks protocol 1, the client 2"),
            "{e}"
        );

        std::fs::remove_file(&file).unwrap();
    }

    #[test]
    fn protocol_round_trip_over_tcp() {
        let addr = tcp_server();
        exercise(|| TcpStream::connect(addr).unwrap(), "tcp");
    }

    /// Like a raw device, an unbuffered file refuses a misaligned buffer, so
    /// this fails if the server reads into anything but an aligned buffer.
    #[cfg(windows)]
    #[test]
    fn reads_work_on_a_device_that_wants_aligned_buffers() {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_NO_BUFFERING: u32 = 0x2000_0000;
        let data: Vec<u8> = (0..16_384u32).map(|i| (i * 13 % 251) as u8).collect();
        let file = temp("unbuffered", &data);
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            let open = |p: &str| {
                std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(FILE_FLAG_NO_BUFFERING)
                    .open(p)
                    .map_err(|e| Refusal::Failed(e.to_string()))
            };
            serve_client(s, open, test_update)
        });
        let (mut s, _) = Session::start(TcpStream::connect(addr).unwrap()).unwrap();
        s.open(file.to_str().unwrap()).unwrap();
        let mut buf = vec![0u8; 4096];
        assert_eq!(s.read_at(&mut buf, 4096).unwrap(), 4096);
        assert_eq!(buf, data[4096..8192]);
        drop(s);
        std::fs::remove_file(&file).unwrap();
    }

    #[test]
    fn an_update_that_installs_ends_the_session_after_its_reply() {
        let (addr, ended) =
            tcp_server_with(|| Ok(Update::Installed(Version::parse("9.8.7").unwrap())));
        let (mut s, version) = Session::start(TcpStream::connect(addr).unwrap()).unwrap();
        let (reply, installed) = s.update(&version).unwrap();
        assert_eq!(reply, "updated to 9.8.7; restarting when idle");
        assert_eq!(installed, Version::parse("9.8.7"));
        let mut rest = Vec::new();
        s.s.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty());
        let ended = ended
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap();
        assert_eq!(ended, Ended::Updated);
    }

    #[test]
    fn a_failed_update_is_an_error_and_the_session_goes_on() {
        let (addr, ended) =
            tcp_server_with(|| Err(io::Error::other("curl: (6) Could not resolve host")));
        let (mut s, version) = Session::start(TcpStream::connect(addr).unwrap()).unwrap();
        let e = s.update(&version).unwrap_err();
        assert_eq!(e.to_string(), "curl: (6) Could not resolve host");
        // Still answering: a READ before OPEN gets its own error.
        let e = s.read_at(&mut [0u8; 10], 0).unwrap_err();
        assert!(e.to_string().contains("before OPEN"), "{e}");
        drop(s);
        let ended = ended
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap();
        assert_eq!(ended, Ended::Closed);
    }

    /// A service from before UPDATE existed, as 0.2.0 answers it.
    #[test]
    fn an_old_service_is_told_apart() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            assert_eq!(read_byte(&mut s).unwrap(), Some(PROTOCOL));
            respond(&mut s, OK, b"0.2.0").unwrap();
            let op = read_byte(&mut s).unwrap().unwrap();
            let msg = format!("unknown operation {op}");
            respond(&mut s, ERROR, msg.as_bytes()).unwrap();
        });
        let (mut s, version) = Session::start(TcpStream::connect(addr).unwrap()).unwrap();
        assert_eq!(version, "0.2.0");
        let e = s.update(&version).unwrap_err();
        assert_eq!(
            e.to_string(),
            "this helper (0.2.0) predates self-update; run `btrfs-peek helper install` from an elevated terminal once more"
        );
    }

    #[test]
    fn oversized_requests_are_refused() {
        let addr = tcp_server();
        let mut raw = TcpStream::connect(addr).unwrap();
        raw.write_all(&[PROTOCOL]).unwrap();
        let mut s = Session { s: raw };
        s.reply().unwrap();
        // A READ larger than MAX_READ is an error, and the session goes on.
        let mut req = vec![READ];
        req.extend_from_slice(&0u64.to_le_bytes());
        req.extend_from_slice(&(MAX_READ as u32 + 1).to_le_bytes());
        s.s.write_all(&req).unwrap();
        assert_eq!(s.reply().unwrap_err().kind(), io::ErrorKind::Other);
        // A path longer than MAX_PATH ends the connection.
        let mut req = vec![OPEN];
        req.extend_from_slice(&(MAX_PATH as u32 + 1).to_le_bytes());
        s.s.write_all(&req).unwrap();
        assert_eq!(s.reply().unwrap_err().kind(), io::ErrorKind::Other);
        let mut rest = Vec::new();
        s.s.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty());
    }
}
